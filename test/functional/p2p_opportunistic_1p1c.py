#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test opportunistic 1p1c package submission logic.
"""

from decimal import Decimal
import random
import time

from test_framework.blocktools import MAX_STANDARD_TX_WEIGHT
from test_framework.mempool_util import (
    fill_mempool,
)
from test_framework.messages import (
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    CTxInWitness,
    MAX_BIP125_RBF_SEQUENCE,
    MSG_WTX,
    msg_inv,
    msg_tx,
    tx_from_hex,
)
from test_framework.p2p import (
    NONPREF_PEER_TX_DELAY,
    P2PInterface,
    TXID_RELAY_DELAY,
)
from test_framework.script import (
    CScript,
    OP_NOP,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)

# 1sat/vB feerate denominated in BTC/KvB
FEERATE_1SAT_VB = Decimal("0.00001000")
# Number of seconds to wait to ensure no getdata is received
GETDATA_WAIT = 60

def cleanup(func):
    def wrapper(self, *args, **kwargs):
        try:
            func(self, *args, **kwargs)
        finally:
            self.nodes[0].disconnect_p2ps()
            # Do not clear the node's mempool, as each test requires mempool min feerate > min
            # relay feerate. However, do check that this is the case.
            assert self.nodes[0].getmempoolinfo()["mempoolminfee"] > self.nodes[0].getnetworkinfo()["relayfee"]
            # Ensure we do not try to spend the same UTXOs in subsequent tests, as they will look like RBF attempts.
            self.wallet.rescan_utxos(include_mempool=True)

            # Resets if mocktime was used
            self.nodes[0].setmocktime(0)
    return wrapper

class PackageRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "-datacarriersize=100000",
            "-maxmempool=5",
        ]]
        self.supports_cli = False

    def create_tx_below_mempoolminfee(self, wallet):
        """Create a 1-input 1sat/vB transaction using a confirmed UTXO. Decrement and use
        self.sequence so that subsequent calls to this function result in unique transactions."""

        self.sequence -= 1
        assert_greater_than(self.nodes[0].getmempoolinfo()["mempoolminfee"], FEERATE_1SAT_VB)

        return wallet.create_self_transfer(fee_rate=FEERATE_1SAT_VB, sequence=self.sequence, confirmed_only=True)

    @cleanup
    def test_basic_child_then_parent(self):
        node = self.nodes[0]
        self.log.info("Check that opportunistic 1p1c logic works when child is received before parent")

        low_fee_parent = self.create_tx_below_mempoolminfee(self.wallet)
        high_fee_child = self.wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"], fee_rate=20*FEERATE_1SAT_VB)

        peer_sender = node.add_p2p_connection(P2PInterface())

        # 1. Child is received first (perhaps the low feerate parent didn't meet feefilter or the requests were sent to different nodes). It is missing an input.
        high_child_wtxid_int = int(high_fee_child["tx"].getwtxid(), 16)
        peer_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=high_child_wtxid_int)]))
        peer_sender.wait_for_getdata([high_child_wtxid_int])
        peer_sender.send_and_ping(msg_tx(high_fee_child["tx"]))

        # 2. Node requests the missing parent by txid.
        parent_txid_int = int(low_fee_parent["txid"], 16)
        peer_sender.wait_for_getdata([parent_txid_int])

        # 3. Sender relays the parent. Parent+Child are evaluated as a package and accepted.
        peer_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))

        # 4. Both transactions should now be in mempool.
        node_mempool = node.getrawmempool()
        assert low_fee_parent["txid"] in node_mempool
        assert high_fee_child["txid"] in node_mempool

        node.disconnect_p2ps()

    @cleanup
    def test_basic_parent_then_child(self, wallet):
        node = self.nodes[0]
        low_fee_parent = self.create_tx_below_mempoolminfee(wallet)
        high_fee_child = wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"], fee_rate=20*FEERATE_1SAT_VB)

        peer_sender = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1, connection_type="outbound-full-relay")
        peer_ignored = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=2, connection_type="outbound-full-relay")

        # 1. Parent is relayed first. It is too low feerate.
        parent_wtxid_int = int(low_fee_parent["tx"].getwtxid(), 16)
        peer_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=parent_wtxid_int)]))
        peer_sender.wait_for_getdata([parent_wtxid_int])
        peer_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))
        assert low_fee_parent["txid"] not in node.getrawmempool()

        # Send again from peer_ignored, check that it is ignored
        peer_ignored.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=parent_wtxid_int)]))
        assert "getdata" not in peer_ignored.last_message

        # 2. Child is relayed next. It is missing an input.
        high_child_wtxid_int = int(high_fee_child["tx"].getwtxid(), 16)
        peer_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=high_child_wtxid_int)]))
        peer_sender.wait_for_getdata([high_child_wtxid_int])
        peer_sender.send_and_ping(msg_tx(high_fee_child["tx"]))

        # 3. Node requests the missing parent by txid.
        # It should do so even if it has previously rejected that parent for being too low feerate.
        parent_txid_int = int(low_fee_parent["txid"], 16)
        peer_sender.wait_for_getdata([parent_txid_int])

        # 4. Sender re-relays the parent. Parent+Child are evaluated as a package and accepted.
        peer_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))

        # 5. Both transactions should now be in mempool.
        node_mempool = node.getrawmempool()
        assert low_fee_parent["txid"] in node_mempool
        assert high_fee_child["txid"] in node_mempool

    @cleanup
    def test_low_and_high_child(self, wallet):
        node = self.nodes[0]
        low_fee_parent = self.create_tx_below_mempoolminfee(wallet)
        # This feerate is above mempoolminfee, but not enough to also bump the low feerate parent.
        feerate_just_above = node.getmempoolinfo()["mempoolminfee"]
        med_fee_child = wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"], fee_rate=feerate_just_above)
        high_fee_child = wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"], fee_rate=999*FEERATE_1SAT_VB)

        peer_sender = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1, connection_type="outbound-full-relay")
        peer_ignored = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=2, connection_type="outbound-full-relay")

        self.log.info("Check that tx caches low fee parent + low fee child package rejections")

        # 1. Send parent, rejected for being low feerate.
        parent_wtxid_int = int(low_fee_parent["tx"].getwtxid(), 16)
        peer_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=parent_wtxid_int)]))
        peer_sender.wait_for_getdata([parent_wtxid_int])
        peer_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))
        assert low_fee_parent["txid"] not in node.getrawmempool()

        # Send again from peer_ignored, check that it is ignored
        peer_ignored.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=parent_wtxid_int)]))
        assert "getdata" not in peer_ignored.last_message

        # 2. Send an (orphan) child that has a higher feerate, but not enough to bump the parent.
        med_child_wtxid_int = int(med_fee_child["tx"].getwtxid(), 16)
        peer_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=med_child_wtxid_int)]))
        peer_sender.wait_for_getdata([med_child_wtxid_int])
        peer_sender.send_and_ping(msg_tx(med_fee_child["tx"]))

        # 3. Node requests the orphan's missing parent.
        parent_txid_int = int(low_fee_parent["txid"], 16)
        peer_sender.wait_for_getdata([parent_txid_int])

        # 4. The low parent + low child are submitted as a package. They are not accepted due to low package feerate.
        peer_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))

        assert low_fee_parent["txid"] not in node.getrawmempool()
        assert med_fee_child["txid"] not in node.getrawmempool()

        # If peer_ignored announces the low feerate child, it should be ignored
        peer_ignored.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=med_child_wtxid_int)]))
        assert "getdata" not in peer_ignored.last_message
        # If either peer sends the parent again, package evaluation should not be attempted
        peer_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))
        peer_ignored.send_and_ping(msg_tx(low_fee_parent["tx"]))

        assert low_fee_parent["txid"] not in node.getrawmempool()
        assert med_fee_child["txid"] not in node.getrawmempool()

        # 5. Send the high feerate (orphan) child
        high_child_wtxid_int = int(high_fee_child["tx"].getwtxid(), 16)
        peer_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=high_child_wtxid_int)]))
        peer_sender.wait_for_getdata([high_child_wtxid_int])
        peer_sender.send_and_ping(msg_tx(high_fee_child["tx"]))

        # 6. Node requests the orphan's parent, even though it has already been rejected, both by
        # itself and with a child. This is necessary, otherwise high_fee_child can be censored.
        parent_txid_int = int(low_fee_parent["txid"], 16)
        peer_sender.wait_for_getdata([parent_txid_int])

        # 7. The low feerate parent + high feerate child are submitted as a package.
        peer_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))

        # 8. Both transactions should now be in mempool
        node_mempool = node.getrawmempool()
        assert low_fee_parent["txid"] in node_mempool
        assert high_fee_child["txid"] in node_mempool
        assert med_fee_child["txid"] not in node_mempool

    @cleanup
    def test_orphan_consensus_failure(self):
        self.log.info("Check opportunistic 1p1c logic requires parent and child to be from the same peer")
        node = self.nodes[0]
        low_fee_parent = self.create_tx_below_mempoolminfee(self.wallet)
        coin = low_fee_parent["new_utxo"]
        address = node.get_deterministic_priv_key().address
        # Create raw transaction spending the parent, but with no signature (a consensus error).
        hex_orphan_no_sig = node.createrawtransaction([{"txid": coin["txid"], "vout": coin["vout"]}], {address : coin["value"] - Decimal("0.0001")})
        tx_orphan_bad_wit = tx_from_hex(hex_orphan_no_sig)
        tx_orphan_bad_wit.wit.vtxinwit.append(CTxInWitness())
        tx_orphan_bad_wit.wit.vtxinwit[0].scriptWitness.stack = [b'garbage']

        bad_orphan_sender = node.add_p2p_connection(P2PInterface())
        parent_sender = node.add_p2p_connection(P2PInterface())

        # 1. Child is received first. It is missing an input.
        child_wtxid_int = int(tx_orphan_bad_wit.getwtxid(), 16)
        bad_orphan_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=child_wtxid_int)]))
        bad_orphan_sender.wait_for_getdata([child_wtxid_int])
        bad_orphan_sender.send_and_ping(msg_tx(tx_orphan_bad_wit))

        # 2. Node requests the missing parent by txid.
        parent_txid_int = int(low_fee_parent["txid"], 16)
        bad_orphan_sender.wait_for_getdata([parent_txid_int])

        # 3. A different peer relays the parent. Package is not evaluated because the transactions
        # were not sent from the same peer.
        parent_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))

        # 4. Transactions should not be in mempool.
        node_mempool = node.getrawmempool()
        assert low_fee_parent["txid"] not in node_mempool
        assert tx_orphan_bad_wit.rehash() not in node_mempool

        # 5. Have the other peer send the tx too, so that tx_orphan_bad_wit package is attempted.
        bad_orphan_sender.send_message(msg_tx(low_fee_parent["tx"]))
        bad_orphan_sender.wait_for_disconnect()

        # The peer that didn't provide the orphan should not be disconnected.
        parent_sender.sync_with_ping()

    @cleanup
    def test_parent_consensus_failure(self):
        self.log.info("Check opportunistic 1p1c logic with consensus-invalid parent causes disconnect of the correct peer")
        node = self.nodes[0]
        low_fee_parent = self.create_tx_below_mempoolminfee(self.wallet)
        high_fee_child = self.wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"], fee_rate=999*FEERATE_1SAT_VB)

        # Create invalid version of parent with a bad signature.
        tx_parent_bad_wit = tx_from_hex(low_fee_parent["hex"])
        tx_parent_bad_wit.wit.vtxinwit.append(CTxInWitness())
        tx_parent_bad_wit.wit.vtxinwit[0].scriptWitness.stack = [b'garbage']

        package_sender = node.add_p2p_connection(P2PInterface())
        fake_parent_sender = node.add_p2p_connection(P2PInterface())

        # 1. Child is received first. It is missing an input.
        child_wtxid_int = int(high_fee_child["tx"].getwtxid(), 16)
        package_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=child_wtxid_int)]))
        package_sender.wait_for_getdata([child_wtxid_int])
        package_sender.send_and_ping(msg_tx(high_fee_child["tx"]))

        # 2. Node requests the missing parent by txid.
        parent_txid_int = int(tx_parent_bad_wit.rehash(), 16)
        package_sender.wait_for_getdata([parent_txid_int])

        # 3. A different node relays the parent. The parent is first evaluated by itself and
        # rejected for being too low feerate. It is not evaluated as a package because the child was
        # sent from a different peer, so we don't find out that the child is consensus-invalid.
        fake_parent_sender.send_and_ping(msg_tx(tx_parent_bad_wit))

        # 4. Transactions should not be in mempool.
        node_mempool = node.getrawmempool()
        assert tx_parent_bad_wit.rehash() not in node_mempool
        assert high_fee_child["txid"] not in node_mempool

        self.log.info("Check that fake parent does not cause orphan to be deleted and real package can still be submitted")
        # 5. Child-sending should not have been punished and the orphan should remain in orphanage.
        # It can send the "real" parent transaction, and the package is accepted.
        parent_wtxid_int = int(low_fee_parent["tx"].getwtxid(), 16)
        package_sender.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=parent_wtxid_int)]))
        package_sender.wait_for_getdata([parent_wtxid_int])
        package_sender.send_and_ping(msg_tx(low_fee_parent["tx"]))

        node_mempool = node.getrawmempool()
        assert low_fee_parent["txid"] in node_mempool
        assert high_fee_child["txid"] in node_mempool

    @cleanup
    def test_multiple_parents(self):
        self.log.info("Check that node does not request more than 1 previously-rejected low feerate parent")

        node = self.nodes[0]
        node.setmocktime(int(time.time()))

        # 2-parent-1-child package where both parents are below mempool min feerate
        parent_low_1 = self.create_tx_below_mempoolminfee(self.wallet_nonsegwit)
        parent_low_2 = self.create_tx_below_mempoolminfee(self.wallet_nonsegwit)
        child_bumping = self.wallet_nonsegwit.create_self_transfer_multi(
            utxos_to_spend=[parent_low_1["new_utxo"], parent_low_2["new_utxo"]],
            fee_per_output=999*parent_low_1["tx"].get_vsize(),
        )

        peer_sender = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1, connection_type="outbound-full-relay")

        # 1. Send both parents. Each should be rejected for being too low feerate.
        # Send unsolicited so that we can later check that no "getdata" was ever received.
        peer_sender.send_and_ping(msg_tx(parent_low_1["tx"]))
        peer_sender.send_and_ping(msg_tx(parent_low_2["tx"]))

        # parent_low_1 and parent_low_2 are rejected for being low feerate.
        assert parent_low_1["txid"] not in node.getrawmempool()
        assert parent_low_2["txid"] not in node.getrawmempool()

        # 2. Send child.
        peer_sender.send_and_ping(msg_tx(child_bumping["tx"]))

        # 3. Node should not request any parents, as it should recognize that it will not accept
        # multi-parent-1-child packages.
        node.bumpmocktime(GETDATA_WAIT)
        peer_sender.sync_with_ping()
        assert "getdata" not in peer_sender.last_message

    @cleanup
    def test_other_parent_in_mempool(self):
        self.log.info("Check opportunistic 1p1c fails if child already has another parent in mempool")
        node = self.nodes[0]

        # This parent needs CPFP
        parent_low = self.create_tx_below_mempoolminfee(self.wallet)
        # This parent does not need CPFP and can be submitted alone ahead of time
        parent_high = self.wallet.create_self_transfer(fee_rate=FEERATE_1SAT_VB*10, confirmed_only=True)
        child = self.wallet.create_self_transfer_multi(
            utxos_to_spend=[parent_high["new_utxo"], parent_low["new_utxo"]],
            fee_per_output=999*parent_low["tx"].get_vsize(),
        )

        peer_sender = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1, connection_type="outbound-full-relay")

        # 1. Send first parent which will be accepted.
        peer_sender.send_and_ping(msg_tx(parent_high["tx"]))
        assert parent_high["txid"] in node.getrawmempool()

        # 2. Send child.
        peer_sender.send_and_ping(msg_tx(child["tx"]))

        # 3. Node requests parent_low. However, 1p1c fails because package-not-child-with-unconfirmed-parents
        parent_low_txid_int = int(parent_low["txid"], 16)
        peer_sender.wait_for_getdata([parent_low_txid_int])
        peer_sender.send_and_ping(msg_tx(parent_low["tx"]))

        node_mempool = node.getrawmempool()
        assert parent_high["txid"] in node_mempool
        assert parent_low["txid"] not in node_mempool
        assert child["txid"] not in node_mempool

        # Same error if submitted through submitpackage without parent_high
        package_hex_missing_parent = [parent_low["hex"], child["hex"]]
        result_missing_parent = node.submitpackage(package_hex_missing_parent)
        assert_equal(result_missing_parent["package_msg"], "package-not-child-with-unconfirmed-parents")

    def create_large_orphan(self):
        """Create huge orphan transaction"""
        tx = CTransaction()
        # Nonexistent UTXO
        tx.vin = [CTxIn(COutPoint(random.randrange(1 << 256), random.randrange(1, 100)))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([OP_NOP] * 390000)]
        tx.vout = [CTxOut(100, CScript([OP_RETURN, b'a' * 20]))]
        return tx

    def create_small_orphan(self):
        """Create small orphan transaction"""
        tx = CTransaction()
        # Nonexistent UTXO
        tx.vin = [CTxIn(COutPoint(random.randrange(1 << 256), random.randrange(1, 100)))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([OP_NOP] * 5)]
        tx.vout = [CTxOut(100, CScript([OP_RETURN, b'a' * 3]))]
        return tx

    @cleanup
    def test_orphanage_dos_large(self):
        self.log.info("Test that the node can still resolve orphans when peers use lots of orphanage space")
        node = self.nodes[0]
        node.setmocktime(int(time.time()))

        peer_normal = node.add_p2p_connection(P2PInterface())
        peer_doser = node.add_p2p_connection(P2PInterface())

        self.log.info("Create very large orphans to be sent by DoSy peers (may take a while)")
        large_orphans = [self.create_large_orphan() for _ in range(100)]
        # Check to make sure these are orphans, within max standard size (to be accepted into the orphanage)
        for large_orphan in large_orphans:
            assert_greater_than_or_equal(100000, large_orphan.get_vsize())
            assert_greater_than(MAX_STANDARD_TX_WEIGHT, large_orphan.get_weight())
            assert_greater_than_or_equal(3 * large_orphan.get_vsize(), 2 * 100000)
            testres = node.testmempoolaccept([large_orphan.serialize().hex()])
            assert not testres[0]["allowed"]
            assert_equal(testres[0]["reject-reason"], "missing-inputs")

        num_individual_dosers = 20
        self.log.info(f"Connect {num_individual_dosers} peers and send a very large orphan from each one")
        # This test assumes that unrequested transactions are processed (skipping inv and
        # getdata steps because they require going through request delays)
        # Connect 20 peers and have each of them send a large orphan.
        for large_orphan in large_orphans[:num_individual_dosers]:
            peer_doser_individual = node.add_p2p_connection(P2PInterface())
            peer_doser_individual.send_and_ping(msg_tx(large_orphan))
            node.bumpmocktime(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
            peer_doser_individual.wait_for_getdata([large_orphan.vin[0].prevout.hash])

        # Make sure that these transactions are going through the orphan handling codepaths.
        # Subsequent rounds will not wait for getdata because the time mocking will cause the
        # normal package request to time out.
        self.wait_until(lambda: len(node.getorphantxs()) == num_individual_dosers)

        self.log.info("Send an orphan from a non-DoSy peer. Its orphan should not be evicted.")
        low_fee_parent = self.create_tx_below_mempoolminfee(self.wallet)
        high_fee_child = self.wallet.create_self_transfer(
            utxo_to_spend=low_fee_parent["new_utxo"],
            fee_rate=20*FEERATE_1SAT_VB,
            target_vsize=100000
        )

        # Announce
        orphan_wtxid = high_fee_child["wtxid"]
        orphan_tx = high_fee_child["tx"]
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))

        # Wait for getdata
        peer_normal.send_and_ping(msg_inv([orphan_inv]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        peer_normal.wait_for_getdata([int(orphan_wtxid, 16)])
        peer_normal.send_and_ping(msg_tx(orphan_tx))

        # Wait for parent request
        parent_txid_int = int(low_fee_parent["txid"], 16)
        node.bumpmocktime(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer_normal.wait_for_getdata([parent_txid_int])

        self.log.info("Send another round of very large orphans from a DoSy peer")
        for large_orphan in large_orphans[60:]:
            peer_doser.send_and_ping(msg_tx(large_orphan))

        # Something was evicted; the orphanage does not contain all large orphans + the 1p1c child
        self.wait_until(lambda: len(node.getorphantxs()) < len(large_orphans) + 1)

        self.log.info("Provide the orphan's parent. This 1p1c package should be successfully accepted.")
        peer_normal.send_and_ping(msg_tx(low_fee_parent["tx"]))
        assert_equal(node.getmempoolentry(orphan_tx.rehash())["ancestorcount"], 2)

    @cleanup
    def test_orphanage_dos_many(self):
        self.log.info("Test that the node can still resolve orphans when peers are sending tons of orphans")
        node = self.nodes[0]
        node.setmocktime(int(time.time()))

        peer_normal = node.add_p2p_connection(P2PInterface())

        batch_size = 100
        num_peers = 10
        # Each of the num_peers peers creates a distinct set of orphans
        many_orphans = [self.create_small_orphan() for _ in range(batch_size * num_peers)]

        self.log.info(f"Send sets of {batch_size} orphans from {num_peers} DoSy peers (may take a while)")
        for peernum in range(num_peers):
            peer_doser_batch = node.add_p2p_connection(P2PInterface())
            for tx in many_orphans[batch_size*peernum : batch_size*(peernum+1)]:
                # Don't sync with ping or wait for responses, because it dramatically increases the
                # runtime of this test.
                peer_doser_batch.send_message(msg_tx(tx))

        # Something was evicted
        self.wait_until(lambda: len(node.getorphantxs()) < batch_size * num_peers)

        self.log.info("Send an orphan from a non-DoSy peer. Its orphan should not be evicted.")
        low_fee_parent = self.create_tx_below_mempoolminfee(self.wallet)
        high_fee_child = self.wallet.create_self_transfer(
            utxo_to_spend=low_fee_parent["new_utxo"],
            fee_rate=20*FEERATE_1SAT_VB,
            target_vsize=100000
        )

        # Announce
        orphan_wtxid = high_fee_child["wtxid"]
        orphan_tx = high_fee_child["tx"]
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))

        # Wait for getdata
        peer_normal.send_and_ping(msg_inv([orphan_inv]))
        node.bumpmocktime(NONPREF_PEER_TX_DELAY)
        peer_normal.wait_for_getdata([int(orphan_wtxid, 16)])
        peer_normal.send_and_ping(msg_tx(orphan_tx))

        # Wait for parent request
        parent_txid_int = int(low_fee_parent["txid"], 16)
        node.bumpmocktime(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer_normal.wait_for_getdata([parent_txid_int])

        shared_orphans = [self.create_small_orphan() for _ in range(batch_size)]
        self.log.info(f"Send the same {batch_size} orphans from {num_peers} DoSy peers (may take a while)")
        for _ in range(num_peers):
            peer_doser_shared = node.add_p2p_connection(P2PInterface())
            for orphan in shared_orphans:
                peer_doser_shared.send_message(msg_tx(orphan))

        # Something was evicted; the orphanage does not contain all DoS orphans + the 1p1c child
        self.wait_until(lambda: len(node.getorphantxs()) < batch_size * num_peers + len(shared_orphans) + 1)

        self.log.info("Provide the orphan's parent. This 1p1c package should be successfully accepted.")
        peer_normal.send_and_ping(msg_tx(low_fee_parent["tx"]))
        assert orphan_tx.rehash() in node.getrawmempool()
        assert_equal(node.getmempoolentry(orphan_tx.rehash())["ancestorcount"], 2)

    def run_test(self):
        node = self.nodes[0]
        # To avoid creating transactions with the same txid (can happen if we set the same feerate
        # and reuse the same input as a previous transaction that wasn't successfully submitted),
        # we give each subtest a different nSequence for its transactions.
        self.sequence = MAX_BIP125_RBF_SEQUENCE

        self.wallet = MiniWallet(node)
        self.wallet_nonsegwit = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        self.generate(self.wallet_nonsegwit, 10)
        self.generate(self.wallet, 20)

        fill_mempool(self, node)

        self.log.info("Check opportunistic 1p1c logic when parent (txid != wtxid) is received before child")
        self.test_basic_parent_then_child(self.wallet)

        self.log.info("Check opportunistic 1p1c logic when parent (txid == wtxid) is received before child")
        self.test_basic_parent_then_child(self.wallet_nonsegwit)

        self.log.info("Check opportunistic 1p1c logic when child is received before parent")
        self.test_basic_child_then_parent()

        self.log.info("Check opportunistic 1p1c logic when 2 candidate children exist (parent txid != wtxid)")
        self.test_low_and_high_child(self.wallet)

        self.log.info("Check opportunistic 1p1c logic when 2 candidate children exist (parent txid == wtxid)")
        self.test_low_and_high_child(self.wallet_nonsegwit)

        self.test_orphan_consensus_failure()
        self.test_parent_consensus_failure()
        self.test_multiple_parents()
        self.test_other_parent_in_mempool()

        self.test_orphanage_dos_large()
        self.test_orphanage_dos_many()


if __name__ == '__main__':
    PackageRelayTest(__file__).main()
