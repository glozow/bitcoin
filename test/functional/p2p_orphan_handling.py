#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
"""

import random
import time

from test_framework.messages import (
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MSG_TX,
    MSG_WITNESS_FLAG,
    MSG_WITNESS_TX,
    MSG_WTX,
    msg_getdata,
    msg_inv,
    msg_tx,
    tx_from_hex,
)
from test_framework.p2p import (
    NONPREF_PEER_TX_DELAY,
    OVERLOADED_PEER_TX_DELAY,
    p2p_lock,
    P2PTxInvStore,
    TXID_RELAY_DELAY,
)
from test_framework.script import (
    CScript,
    OP_FALSE,
    OP_NOP,
    OP_RETURN,
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

    def wait_for_getdata_txids(self, txids):
        def test_function():
            last_getdata = self.last_message.get('getdata')
            if not last_getdata:
                return False
            return all([item.type == MSG_WITNESS_TX and item.hash in txids for item in last_getdata.inv])
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
        """Create package with 1 parent and 1 child, normal fees (no cpfp).
        """
        parent = self.wallet.create_self_transfer()
        child = self.wallet.create_self_transfer(utxo_to_spend=parent['new_utxo'])
        return child["tx"].getwtxid(), child["tx"], parent["tx"]

    def create_large_orphan(self):
        """Create huge orphan transaction"""
        tx = CTransaction()
        # Nonexistent UTXO
        tx.vin = [CTxIn(COutPoint(random.randrange(1 << 256), random.randrange(1, 100)))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([OP_NOP] * 390000)]
        tx.vout = [CTxOut(100, CScript([OP_RETURN, b'a' * 20]))]
        return tx

    def fastforward(self, seconds):
        """Convenience helper function to fast-forward, so we don't need to keep track of the
        starting time when we call setmocktime."""
        self.mocktime += seconds
        self.nodes[0].setmocktime(self.mocktime)

    def relay_transaction(self, peer, tx):
        """Relay transaction using MSG_WTX"""
        wtxid = int(tx.getwtxid(), 16)
        peer.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=wtxid)]))
        self.fastforward(10)
        peer.wait_for_getdata([wtxid])
        peer.send_and_ping(msg_tx(tx))

    @cleanup
    def test_arrival_timing_orphan(self):
        self.log.info("Test leak of arrival timing through orphan handling")
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
        # Request is scheduled with this delay because it is by txid and this
        # not a preferred relay peer.
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer_spy.sync_with_ping()

        # The node should have sent a request for the "real" orphan's parent.
        # None of the fake orphans should have resulted in a parent request.
        assert_equal(1, len(peer_spy.getdata_received))
        assert_equal(MSG_TX | MSG_WITNESS_FLAG, peer_spy.getdata_received[0].inv[0].type)
        assert_equal(int(parent_tx.rehash(), 16), peer_spy.getdata_received[0].inv[0].hash)

    @cleanup
    def test_orphan_rejected_parents(self):
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
        self.relay_transaction(peer2, child_nonsegwit["tx"])
        assert child_nonsegwit["txid"] not in node.getrawmempool()

        # No parents are requested.
        self.fastforward(60)
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

        # Delayed because it's by txid and this is not a preferred relay peer.
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

        # Delayed because it's by txid and this is not a preferred relay peer.
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer2.wait_for_getdata([int(parent_normal["tx"].rehash(), 16)])

        # parent_normal can be relayed again even though parent1_witness_stripped was rejected
        self.relay_transaction(peer1, parent_normal["tx"])
        assert_equal(set(node.getrawmempool()), set([parent_normal["txid"], child_invalid_witness["txid"]]))


    def run_test(self):
        # Need to make an initial setmocktime otherwise may fail intermittently
        self.fastforward(0)
        self.wallet_nonsegwit = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_P2PK)
        self.generate(self.wallet_nonsegwit, 10)
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)
        self.test_arrival_timing_orphan()
        self.test_orphan_rejected_parents()


if __name__ == '__main__':
    OrphanHandlingTest().main()
