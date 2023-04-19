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
)
from test_framework.p2p import (
    NONPREF_PEER_TX_DELAY,
    ORPHAN_ANCESTOR_GETDATA_INTERVAL,
    OVERLOADED_PEER_TX_DELAY,
    p2p_lock,
    P2PTxInvStore,
    TXID_RELAY_DELAY,
)
from test_framework.script import (
    CScript,
    OP_NOP,
    OP_RETURN,
)
from test_framework.util import (
    assert_equal,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import (
    MiniWallet,
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

    def create_package(self):
        """Create package with 1 parent and 1 child, normal fees (no cpfp).
        """
        parent = self.wallet.create_self_transfer()
        child = self.wallet.create_self_transfer(utxo_to_spend=parent['new_utxo'])
        orphan_wtxid = child["tx"].getwtxid()
        orphan_tx = child["tx"]
        parent_tx = parent["tx"]
        return orphan_wtxid, orphan_tx, parent_tx

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
        self.log.info("Test leak of arrival timing through orphan handling")
        node = self.nodes[0]
        tx_real = self.wallet.create_self_transfer()
        tx_fake_orphans = [self.wallet.create_self_transfer(
            utxo_to_spend={"txid": tx_real["txid"], "vout": i + 10, "value": tx_real["new_utxo"]["value"]}
        ) for i in range(3)]
        # Real orphan
        orphan_wtxid, orphan_tx, parent_tx = self.create_package()

        peer_spy = node.add_p2p_connection(PeerTxRelayer())
        # This transaction is an orphan because the node hasn't seen the parent yet.
        # The node should not immediately respond with a request for orphan parents.
        # It will be added to the orphan resolution tracker, but no request should be sent later
        # because it will be resolved by the time the request is scheduled to be sent.
        peer_spy.assert_message_ignored(msg_tx(tx_fake_orphans[0]["tx"]))
        # This transaction is also an orphan. It will be added to the orphan resolution tracker, and
        # its parent should be requested later.
        peer_spy.assert_message_ignored(msg_tx(orphan_tx))
        # This fake orphan transaction should be treated exactly the same as fake orphan 0.
        peer_spy.assert_message_ignored(msg_tx(tx_fake_orphans[1]["tx"]))

        # Node receives transaction. It attempts to obfuscate the exact timing at which this
        # transaction entered its mempool.
        node.sendrawtransaction(tx_real["hex"])
        # This transaction is not an orphan. The node should also not send any response.
        peer_spy.assert_message_ignored(msg_tx(tx_fake_orphans[2]["tx"]))

        # Spy peer should not be able to query the node for the parent yet, since it hasn't been
        # announced and insufficient time has elapsed.
        parent_inv = CInv(t=MSG_WTX, h=int(tx_real["tx"].getwtxid(), 16))
        peer_spy.assert_message_ignored(msg_getdata([parent_inv]))

        # The real orphan's parent should be requested, but not until the request delay elapses.
        peer_spy.assert_never_requested(int(parent_tx.rehash(), 16))
        self.fastforward(TXID_RELAY_DELAY + NONPREF_PEER_TX_DELAY)
        for _ in range(len(tx_fake_orphans)):
            # Ensure all of the orphans are processed
            peer_spy.sync_with_ping()

        # The node should have sent a request for the "real" orphan's parent.
        # None of the fake orphans should have resulted in a parent request.
        assert_equal(1, len(peer_spy.getdata_received))
        assert_equal(MSG_TX | MSG_WITNESS_FLAG, peer_spy.getdata_received[0].inv[0].type)
        assert_equal(int(parent_tx.rehash(), 16), peer_spy.getdata_received[0].inv[0].hash)


    def run_test(self):
        self.nodes[0].setmocktime(self.mocktime)
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)
        self.test_orphan_handling_prefer_outbound()
        self.test_announcers_before_and_after()
        self.test_arrival_timing_orphan()


if __name__ == '__main__':
    OrphanHandlingTest().main()
