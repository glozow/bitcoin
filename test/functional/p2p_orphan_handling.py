#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
- A delay is added to parent requests because they are by txid.
- Requests for orphan parents include ones that are not AlreadyHaveTx. This means old confirmed
  parents may be requested.
- The node does not give up on orphans if the peer responds to a parent request with notfound. This
  means that if a parent is an old confirmed transaction (in which notfound is expected), the
  orphan should still be resolved.
- Rejected parents can cause an orphan to be dropped, but it depends on the reason and only based
  on txid.
- Rejected parents can cause an orphan to be rejected too.
- Requests for orphan parents should be de-duplicated with "regular" txrequest. If a missing parent
  has the same hash as an in-flight request, it shouldn't be requested.
- Multiple orphans with overlapping parents should not cause duplicated parent requests.
"""

import time

from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_WITNESS_FLAG,
    MSG_WITNESS_TX,
    MSG_WTX,
    msg_getdata,
    msg_inv,
    msg_notfound,
    msg_tx,
    tx_from_hex,
)
from test_framework.p2p import (
    GETDATA_TX_INTERVAL,
    NONPREF_PEER_TX_DELAY,
    ORPHAN_ANCESTOR_GETDATA_INTERVAL,
    OVERLOADED_PEER_TX_DELAY,
    p2p_lock,
    P2PTxInvStore,
    TXID_RELAY_DELAY,
)
from test_framework.util import (
    assert_equal,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)

# Time to fastforward (using setmocktime) before waiting for the node to send getdata(tx) in response
# to an inv(tx), in seconds. This delay includes all possible delays + 1, so it should only be used
# when the value of the delay is not interesting. If we want to test that the node waits x seconds
# for one peer and y seconds for another, use specific values instead.
TXREQUEST_TIME_SKIP = NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY + OVERLOADED_PEER_TX_DELAY + 1

# Time to fastfoward (using setmocktime) in between subtests to ensure they do not interfere with
# one another, in seconds. Equal to 12 hours, which is enough to expire anything that may exist
# (though nothing should since state should be cleared) in p2p data structures.
LONG_TIME_SKIP = 12 * 60 * 60

def cleanup(func):
    def wrapper(self):
        try:
            func(self)
        finally:
            # Clear mempool
            self.generate(self.nodes[0], 1)
            self.nodes[0].disconnect_p2ps()
            self.mocktime += LONG_TIME_SKIP
            self.nodes[0].setmocktime(self.mocktime)
    return wrapper

class PeerTxRelayer(P2PTxInvStore):
    """A P2PTxInvStore that also remembers all of the getdata and tx messages it receives."""
    def __init__(self):
        super().__init__()
        self._tx_received = []
        self._getdata_received = []

    @property
    def tx_received(self):
        with p2p_lock:
            return self._tx_received

    @property
    def getdata_received(self):
        with p2p_lock:
            return self._getdata_received

    def on_tx(self, message):
        self._tx_received.append(message)

    def on_getdata(self, message):
        self._getdata_received.append(message)

    def wait_for_parent_requests(self, txids):
        """Wait for requests for missing parents by txid with witness data (MSG_WITNESS_TX or
        WitnessTx). Requires that the getdata message match these txids exactly; all txids must be
        requested and no additional requests are allowed."""
        def test_function():
            last_getdata = self.last_message.get('getdata')
            if not last_getdata:
                return False
            return len(last_getdata.inv) == len(txids) and all([item.type == MSG_WITNESS_TX and item.hash in txids for item in last_getdata.inv])
        self.wait_until(test_function, timeout=10)

    def assert_message_ignored(self, message):
        """Check that the node does not respond to this message with any of
        getdata, inv, tx.
        """
        prev_lastmessage = self.last_message
        self.send_and_ping(message)
        after_lastmessage = self.last_message
        for msgtype in ["getdata", "inv", "tx"]:
            if msgtype not in prev_lastmessage:
                assert msgtype not in after_lastmessage
            else:
                assert_equal(prev_lastmessage[msgtype], after_lastmessage[msgtype])

    def assert_never_requested(self, txhash):
        """Check that the node has never sent us a getdata for this hash (int type)"""
        for getdata in self.getdata_received:
            for request in getdata.inv:
                assert request.hash != txhash

class OrphanHandlingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[]]
        self.mocktime = int(time.time())

    def create_parent_and_child(self):
        """Create package with 1 parent and 1 child, normal fees (no cpfp)."""
        parent = self.wallet.create_self_transfer()
        child = self.wallet.create_self_transfer(utxo_to_spend=parent['new_utxo'])
        return child["tx"].getwtxid(), child["tx"], parent["tx"]

    def fastforward(self, seconds):
        """Convenience helper function to fast-forward, so we don't need to keep track of the
        starting time when we call setmocktime."""
        self.mocktime += seconds
        self.nodes[0].setmocktime(self.mocktime)

    def relay_transaction(self, peer, tx):
        """Relay transaction using MSG_WTX"""
        wtxid = int(tx.getwtxid(), 16)
        peer.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=wtxid)]))
        self.fastforward(TXREQUEST_TIME_SKIP)
        peer.wait_for_getdata([wtxid])
        peer.send_and_ping(msg_tx(tx))

    @cleanup
    def test_orphan_handling_prefer_outbound(self):
        self.log.info("Test that the node prefers requesting from outbound peers")
        node = self.nodes[0]
        orphan_wtxid, orphan_tx, parent_tx = self.create_package()
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))

        peer_inbound = node.add_p2p_connection(PeerTxRelayer())
        peer_inbound.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(TXREQUEST_TIME_SKIP)
        peer_inbound.wait_for_getdata([int(orphan_wtxid, 16)])

        # Both peers send invs for the orphan, so the node an expect both to know its ancestors.
        peer_outbound = node.add_outbound_p2p_connection(PeerTxRelayer(), p2p_idx=1)
        peer_outbound.send_and_ping(msg_inv([orphan_inv]))

        # The outbound peer should be preferred for getting orphan parents
        peer_inbound.send_and_ping(msg_tx(orphan_tx))
        peer_outbound.wait_for_getdata_txids([int(parent_tx.rehash(), 16)])
        # There should be no request to the inbound peer
        outbound_getdata_received = peer_outbound.getdata_received.pop()
        assert outbound_getdata_received not in peer_inbound.getdata_received

        self.log.info("Test that, if the preferred peer doesn't respond, the node sends another request")
        self.fastforward(ORPHAN_ANCESTOR_GETDATA_INTERVAL)
        peer_inbound.sync_with_ping()
        peer_inbound.wait_for_getdata_txids([int(parent_tx.rehash(), 16)])

    @cleanup
    def test_announcers_before_and_after(self):
        self.log.info("Test that the node uses all peers who announced the tx prior to realizing it's an orphan")
        node = self.nodes[0]
        orphan_wtxid, orphan_tx, parent_tx = self.create_package()
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))

        # Announces before tx is sent, disconnects while node is requesting parents
        peer_early_disconnected = node.add_outbound_p2p_connection(PeerTxRelayer(), p2p_idx=2)
        # Announces before tx is sent, doesn't respond to parent request
        peer_early_unresponsive = node.add_p2p_connection(PeerTxRelayer())

        # Announces after tx is sent
        peer_late_announcer = node.add_p2p_connection(PeerTxRelayer())

        # Both peers send invs for the orphan, so the node an expect both to know its ancestors.
        peer_early_disconnected.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(TXREQUEST_TIME_SKIP)
        peer_early_disconnected.wait_for_getdata([int(orphan_wtxid, 16)])
        peer_early_unresponsive.send_and_ping(msg_inv([orphan_inv]))
        peer_early_disconnected.send_and_ping(msg_tx(orphan_tx))
        self.fastforward(NONPREF_PEER_TX_DELAY)

        # Peer disconnects before responding to request
        peer_early_disconnected.wait_for_getdata_txids([int(parent_tx.rehash(), 16)])
        peer_early_disconnected.peer_disconnect()
        peer_early_unresponsive.wait_for_getdata_txids([int(parent_tx.rehash(), 16)])

        self.log.info("Test that the node uses peers who announce the tx after realizing it's an orphan")
        peer_late_announcer.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(ORPHAN_ANCESTOR_GETDATA_INTERVAL)
        peer_early_unresponsive.sync_with_ping()
        peer_late_announcer.wait_for_getdata_txids([int(parent_tx.rehash(), 16)])

    @cleanup
    def test_arrival_timing_orphan(self):
        self.log.info("Test orphan handling delays")
        node = self.nodes[0]
        tx_real = self.wallet.create_self_transfer()
        # Fake orphan spends a nonexistent output of tx_real
        tx_fake_orphan = self.wallet.create_self_transfer(
            utxo_to_spend={"txid": tx_real["txid"], "vout": 10, "value": tx_real["new_utxo"]["value"]}
        )
        # Real orphan with its real parent
        orphan_wtxid, orphan_tx, parent_tx = self.create_parent_and_child()

        peer_spy = node.add_p2p_connection(PeerTxRelayer())
        # This transaction is an orphan because it is missing inputs.
        # The node should not immediately respond with a request for orphan parents.
        # Also, no request should be sent later because it will be resolved by
        # the time the request is scheduled to be sent.
        peer_spy.assert_message_ignored(msg_tx(tx_fake_orphan["tx"]))
        # This transaction is also an orphan. Its parent should be requested later.
        peer_spy.assert_message_ignored(msg_tx(orphan_tx))

        # Node receives transaction. It attempts to obfuscate the exact timing at which this
        # transaction entered its mempool.
        node.sendrawtransaction(tx_real["hex"])
        # Spy peer should not be able to query the node for the parent yet, since it hasn't been
        # announced / insufficient time has elapsed.
        parent_inv = CInv(t=MSG_WTX, h=int(tx_real["tx"].getwtxid(), 16))
        peer_spy.assert_message_ignored(msg_getdata([parent_inv]))

        # The real orphan's parent should be requested, but not until the request delay elapses.
        peer_spy.assert_never_requested(int(parent_tx.rehash(), 16))
        self.fastforward(NONPREF_PEER_TX_DELAY)
        peer_spy.assert_never_requested(int(parent_tx.rehash(), 16))
        # Request is scheduled with this delay because it is by txid and this
        # not a preferred relay peer.
        self.fastforward(TXID_RELAY_DELAY)
        peer_spy.sync_with_ping()

        self.log.info("Test parent requests don't reveal whether the parent was present when the orphan arrived")
        # The node should have sent a request for the "real" orphan's parent.
        # None of the fake orphans should have resulted in a parent request.
        assert_equal(1, len(peer_spy.getdata_received))
        assert_equal(MSG_TX | MSG_WITNESS_FLAG, peer_spy.getdata_received[0].inv[0].type)
        assert_equal(int(parent_tx.rehash(), 16), peer_spy.getdata_received[0].inv[0].hash)

    @cleanup
    def test_orphan_rejected_parents_exceptions(self):
        node = self.nodes[0]
        peer1 = node.add_p2p_connection(PeerTxRelayer())
        peer2 = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test orphan handling when nonsegwit parent paid 0 fee")
        parent_low_fee_nonsegwit = self.wallet_nonsegwit.create_self_transfer(fee_rate=0)
        assert_equal(parent_low_fee_nonsegwit["txid"], parent_low_fee_nonsegwit["tx"].getwtxid())
        parent_other = self.wallet_nonsegwit.create_self_transfer()
        child_nonsegwit = self.wallet_nonsegwit.create_self_transfer_multi(
            utxos_to_spend=[parent_other["new_utxo"], parent_low_fee_nonsegwit["new_utxo"]])

        # Relay the parent. It should be rejected because it pays 0 fees.
        self.relay_transaction(peer1, parent_low_fee_nonsegwit["tx"])
        assert parent_low_fee_nonsegwit["txid"] not in node.getrawmempool()

        # Relay the child. It should not be accepted because it has missing inputs.
        # Its parent should not be requested because its hash (txid == wtxid) has been added to the rejection filter.
        with node.assert_debug_log(['not keeping orphan with rejected parents {}'.format(child_nonsegwit["txid"])]):
            self.relay_transaction(peer2, child_nonsegwit["tx"])
        assert child_nonsegwit["txid"] not in node.getrawmempool()

        # No parents are requested.
        self.fastforward(GETDATA_TX_INTERVAL)
        peer1.assert_never_requested(int(parent_other["txid"], 16))
        peer2.assert_never_requested(int(parent_other["txid"], 16))
        peer2.assert_never_requested(int(parent_low_fee_nonsegwit["txid"], 16))

        self.log.info("Test orphan handling when segwit parent paid 0 fee")
        parent_low_fee = self.wallet.create_self_transfer(fee_rate=0)
        child_low_fee = self.wallet.create_self_transfer(utxo_to_spend=parent_low_fee["new_utxo"])

        # Relay the low fee parent. It should not be accepted.
        self.relay_transaction(peer1, parent_low_fee["tx"])
        assert parent_low_fee["txid"] not in node.getrawmempool()

        # Relay the child. It should not be accepted because it has missing inputs.
        self.relay_transaction(peer2, child_low_fee["tx"])
        assert child_low_fee["txid"] not in node.getrawmempool()

        # The parent should be requested because even though the txid commits to the fee, it doesn't
        # commit to the feerate. Delayed because it's by txid and this is not a preferred relay peer.
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer2.wait_for_getdata([int(parent_low_fee["tx"].rehash(), 16)])

        self.log.info("Test orphan handling when parent's witness is stripped")
        parent_normal = self.wallet.create_self_transfer()
        parent1_witness_stripped = tx_from_hex(parent_normal["tx"].serialize_without_witness().hex())
        child_invalid_witness = self.wallet.create_self_transfer(utxo_to_spend=parent_normal["new_utxo"])

        # Relay the parent with witness stripped. It should not be accepted.
        self.relay_transaction(peer1, parent1_witness_stripped)
        assert_equal(parent_normal["txid"], parent1_witness_stripped.rehash())
        assert parent1_witness_stripped.rehash() not in node.getrawmempool()

        # Relay the child. It should not be accepted because it has missing inputs.
        self.relay_transaction(peer2, child_invalid_witness["tx"])
        assert child_invalid_witness["txid"] not in node.getrawmempool()

        # The parent should be requested. Delayed because it's by txid and this is not a preferred relay peer.
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer2.wait_for_getdata([int(parent_normal["tx"].rehash(), 16)])

        # parent_normal can be relayed again even though parent1_witness_stripped was rejected
        self.relay_transaction(peer1, parent_normal["tx"])
        assert_equal(set(node.getrawmempool()), set([parent_normal["txid"], child_invalid_witness["txid"]]))

    @cleanup
    def test_orphan_multiple_parents(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test orphan parent requests with a mixture of confirmed, in-mempool and missing parents")
        # This UTXO confirmed a long time ago.
        utxo_conf_old = self.wallet.send_self_transfer(from_node=node)["new_utxo"]
        txid_conf_old = utxo_conf_old["txid"]
        self.generate(self.wallet, 10)

        # Create a fake reorg to trigger BlockDisconnected, which resets the rolling bloom filter.
        # The alternative is to mine thousands of transactions to push it out of the filter.
        last_block = node.getbestblockhash()
        node.invalidateblock(last_block)
        self.generate(node, 1)
        node.syncwithvalidationinterfacequeue()

        # This UTXO confirmed recently.
        utxo_conf_recent = self.wallet.send_self_transfer(from_node=node)["new_utxo"]
        self.generate(node, 1)

        # This UTXO is unconfirmed and in the mempool.
        assert_equal(len(node.getrawmempool()), 0)
        mempool_tx = self.wallet.send_self_transfer(from_node=node)
        utxo_unconf_mempool = mempool_tx["new_utxo"]

        # This UTXO is unconfirmed and missing.
        missing_tx = self.wallet.create_self_transfer()
        utxo_unconf_missing = missing_tx["new_utxo"]

        orphan = self.wallet.create_self_transfer_multi(utxos_to_spend=[utxo_conf_old,
            utxo_conf_recent, utxo_unconf_mempool, utxo_unconf_missing])

        self.relay_transaction(peer, orphan["tx"])
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer.sync_with_ping()
        assert_equal(len(peer.last_message["getdata"].inv), 2)
        peer.wait_for_parent_requests([int(txid_conf_old, 16), int(missing_tx["txid"], 16)])

        # Even though the peer would send a notfound for the "old" confirmed transaction, the node
        # doesn't give up on the orphan. Once all of the missing parents are received, it should be
        # submitted to mempool.
        peer.send_message(msg_notfound(vec=[CInv(MSG_WITNESS_TX, int(txid_conf_old, 16))]))
        peer.send_and_ping(msg_tx(missing_tx["tx"]))
        peer.sync_with_ping()
        assert_equal(node.getmempoolentry(orphan["txid"])["ancestorcount"], 3)

    @cleanup
    def test_orphans_overlapping_parents(self):
        node = self.nodes[0]
        # In the process of relaying inflight_parent_AB
        peer_txrequest = node.add_p2p_connection(PeerTxRelayer())
        # Sends the orphans
        peer_orphans = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test handling of multiple orphans with missing parents that are already being requested")
        # Parent of child_A only
        missing_parent_A = self.wallet_nonsegwit.create_self_transfer()
        # Parents of child_A and child_B
        missing_parent_AB = self.wallet_nonsegwit.create_self_transfer()
        inflight_parent_AB = self.wallet_nonsegwit.create_self_transfer()
        # Parent of child_B only
        missing_parent_B = self.wallet_nonsegwit.create_self_transfer()
        child_A = self.wallet_nonsegwit.create_self_transfer_multi(
            utxos_to_spend=[missing_parent_A["new_utxo"], missing_parent_AB["new_utxo"], inflight_parent_AB["new_utxo"]]
        )
        child_B = self.wallet_nonsegwit.create_self_transfer_multi(
            utxos_to_spend=[missing_parent_B["new_utxo"], missing_parent_AB["new_utxo"], inflight_parent_AB["new_utxo"]]
        )

        # The wtxid and txid need to be the same for the node to recognize that the missing input
        # and in-flight request for inflight_parent_AB are the same transaction.
        assert_equal(inflight_parent_AB["txid"], inflight_parent_AB["tx"].getwtxid())

        # Announce inflight_parent_AB and wait for getdata
        peer_txrequest.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=int(inflight_parent_AB["tx"].getwtxid(), 16))]))
        self.fastforward(NONPREF_PEER_TX_DELAY)
        peer_txrequest.wait_for_getdata([int(inflight_parent_AB["tx"].getwtxid(), 16)])

        self.log.info("The node should not request a parent if it has an in-flight txrequest")
        # Relay orphan child_A
        self.relay_transaction(peer_orphans, child_A["tx"])
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        # Both missing parents should be requested.
        peer_orphans.wait_for_parent_requests([int(missing_parent_A["txid"], 16), int(missing_parent_AB["txid"], 16)])

        self.log.info("The node should not request a parent if it has an in-flight orphan parent request")
        # Relay orphan child_B
        self.relay_transaction(peer_orphans, child_B["tx"])
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        # Only missing_parent_B should be requested. Not inflight_parent_AB or missing_parent_AB
        # because they are already being requested from peer_orphans.
        peer_orphans.wait_for_parent_requests([int(missing_parent_B["txid"], 16)])
        peer_orphans.assert_never_requested(int(inflight_parent_AB["txid"], 16))

    @cleanup
    def test_orphan_of_orphan(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test handling of an orphan with a parent who is another orphan")
        missing_grandparent = self.wallet_nonsegwit.create_self_transfer()
        missing_parent_orphan = self.wallet_nonsegwit.create_self_transfer(utxo_to_spend=missing_grandparent["new_utxo"])
        missing_parent = self.wallet_nonsegwit.create_self_transfer()
        orphan = self.wallet_nonsegwit.create_self_transfer_multi(utxos_to_spend=[missing_parent["new_utxo"], missing_parent_orphan["new_utxo"]])

        # The node should put missing_parent_orphan into the orphanage and request missing_grandparent
        self.relay_transaction(peer, missing_parent_orphan["tx"])
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer.wait_for_parent_requests([int(missing_grandparent["txid"], 16)])

        # The node should put the orphan into the orphanage and request missing_parent, skipping
        # missing_parent_orphan because it already has it in the orphanage.
        self.relay_transaction(peer, orphan["tx"])
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer.wait_for_parent_requests([int(missing_parent["txid"], 16)])

    @cleanup
    def test_orphan_inherit_rejection(self):
        node = self.nodes[0]
        peer1 = node.add_p2p_connection(PeerTxRelayer())
        peer2 = node.add_p2p_connection(PeerTxRelayer())
        peer3 = node.add_p2p_connection(PeerTxRelayer())

        self.log.info("Test orphan handling when nonsegwit parent paid 0 fee")
        parent_low_fee_nonsegwit = self.wallet_nonsegwit.create_self_transfer(fee_rate=0)
        assert_equal(parent_low_fee_nonsegwit["txid"], parent_low_fee_nonsegwit["tx"].getwtxid())
        child = self.wallet.create_self_transfer(utxo_to_spend=parent_low_fee_nonsegwit["new_utxo"])
        grandchild = self.wallet.create_self_transfer(utxo_to_spend=child["new_utxo"])
        assert child["txid"] != child["tx"].getwtxid()
        assert grandchild["txid"] != grandchild["tx"].getwtxid()

        # Relay the parent. It should be rejected because it pays 0 fees.
        self.relay_transaction(peer1, parent_low_fee_nonsegwit["tx"])

        # Relay the child. It should be rejected for having missing parents.
        with node.assert_debug_log(['not keeping orphan with rejected parents {}'.format(child["txid"])]):
            self.relay_transaction(peer1, child["tx"])
        assert_equal(0, len(node.getrawmempool()))
        peer1.assert_never_requested(parent_low_fee_nonsegwit["txid"])

        # Grandchild should also not be requested because its parent has been rejected.
        with node.assert_debug_log(['not keeping orphan with rejected parents {}'.format(grandchild["txid"])]):
            self.relay_transaction(peer2, grandchild["tx"])
        assert_equal(0, len(node.getrawmempool()))
        peer2.assert_never_requested(child["txid"])
        peer2.assert_never_requested(child["tx"].getwtxid())

        # The child should never be requested, even if announced again.
        peer3.send_and_ping(msg_inv([CInv(t=MSG_TX, h=int(child["txid"], 16))]))
        peer3.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=int(child["tx"].getwtxid(), 16))]))
        self.fastforward(TXREQUEST_TIME_SKIP)
        peer3.assert_never_requested(child["txid"])
        peer3.assert_never_requested(child["tx"].getwtxid())


    def run_test(self):
        # Need to make an initial setmocktime otherwise may fail intermittently
        self.fastforward(0)
        self.wallet_nonsegwit = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_P2PK)
        self.generate(self.wallet_nonsegwit, 10)
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)
        self.test_arrival_timing_orphan()
        self.test_orphan_rejected_parents_exceptions()
        self.test_orphan_multiple_parents()
        self.test_orphans_overlapping_parents()
        self.test_orphan_of_orphan()
        self.test_orphan_inherit_rejection()
        self.test_orphan_handling_prefer_outbound()
        self.test_announcers_before_and_after()


if __name__ == '__main__':
    OrphanHandlingTest().main()
