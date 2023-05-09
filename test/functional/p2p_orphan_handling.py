#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
"""

from decimal import Decimal
import random
import time

from test_framework.messages import (
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MSG_WITNESS_TX,
    MSG_WTX,
    msg_inv,
    msg_tx,
)
from test_framework.p2p import (
    NONPREF_PEER_TX_DELAY,
    ORPHAN_ANCESTOR_GETDATA_INTERVAL,
    p2p_lock,
    P2PTxInvStore,
    TXID_RELAY_DELAY,
    UNCONDITIONAL_RELAY_DELAY,
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
    COIN,
    MiniWallet,
)

def cleanup(func):
    def wrapper(self):
        try:
            func(self)
        finally:
            # Clear mempool
            self.generate(self.nodes[0], 1)
            self.nodes[0].disconnect_p2ps()
            self.nodes[0].setmocktime(self.starttime)
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

class OrphanHandlingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[]]
        self.starttime = int(time.time())
        self.mocktime = self.starttime

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
        node = self.nodes[0]
        orphan_wtxid, orphan_tx, parent_tx = self.create_package()
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))

        peer_inbound = node.add_p2p_connection(PeerTxRelayer())
        peer_outbound = node.add_outbound_p2p_connection(PeerTxRelayer(), p2p_idx=1)

        peer_inbound.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
        peer_inbound.wait_for_getdata([int(orphan_wtxid, 16)])
        # Both peers send invs for the orphan, so the node an expect both to know its ancestors.
        peer_outbound.send_and_ping(msg_inv([orphan_inv]))
        peer_inbound.send_and_ping(msg_tx(orphan_tx))
        self.fastforward(NONPREF_PEER_TX_DELAY)

        self.log.info("Test that the node prefers requesting from outbound peers")
        # The outbound peer should be preferred for getting orphan parents
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
        self.fastforward(NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY)
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
    def test_orphanage_dos(self):
        self.log.info("Test that the node can still resolve orphans when a peer is using lots of orphanage space")
        self.restart_node(0, extra_args=["-maxorphantx=3"])
        node = self.nodes[0]
        peer_doser = node.add_p2p_connection(PeerTxRelayer())
        peer_normal = node.add_p2p_connection(PeerTxRelayer())

        large_orphans = [self.create_large_orphan() for _ in range(4)]
        # Check to make sure these are orphans, within max standard size (to be accepted into the orphanage), and that 3 of them
        # would make peer_doser an overloaded orphanage occupant.
        for large_orphan in large_orphans:
            assert_greater_than_or_equal(100000, large_orphan.get_vsize())
            assert_greater_than_or_equal(3 * large_orphan.get_vsize(), 2 * 100000)
            testres = node.testmempoolaccept([large_orphan.serialize().hex()])
            assert not testres[0]["allowed"]
            assert_equal(testres[0]["reject-reason"], "missing-inputs")

        # Send the first 3 large orphans from peer_doser
        self.log.info("Send very large orphans from one DoSy peer, reaching maximum orphanage capacity")
        for large_orphan in large_orphans[:3]:
            peer_doser.send_message(msg_inv([CInv(t=MSG_WTX, h=int(large_orphan.getwtxid(), 16))]))
            self.log.info("Sent large orphan inv {}".format(large_orphan.getwtxid()))
            self.fastforward(30)
            peer_doser.wait_for_getdata([int(large_orphan.getwtxid(), 16)])
            peer_doser.send_and_ping(msg_tx(large_orphan))
            self.log.info("Sent large orphan tx {}".format(large_orphan.getwtxid()))
            self.fastforward(30)
            peer_doser.wait_for_getdata([large_orphan.vin[0].prevout.hash])
            self.log.info("Got parent request for orphan tx {}".format(large_orphan.getwtxid()))

        self.log.info("Send a normal orphan from another peer, triggering orphanage eviction")
        orphan_wtxid, orphan_tx, parent_tx = self.create_package()
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))
        self.log.info("sent normal orphan inv {}".format(orphan_wtxid))
        peer_normal.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(30)
        peer_normal.wait_for_getdata([int(orphan_wtxid, 16)])
        # This is the 4th orphan added to the orphanage, exceeding the maximum of 3.
        # peer_normal is protected from eviction because it's not taking up a huge amount of space in the orphanage.
        peer_normal.send_and_ping(msg_tx(orphan_tx))
        self.log.info("Sent normal orphan tx {}".format(orphan_wtxid))
        self.fastforward(30)
        peer_normal.wait_for_getdata([int(parent_tx.rehash(), 16)])
        self.log.info("Got parent request for orphan tx {}".format(orphan_wtxid))

        # peer_normal hasn't sent the parent yet.
        # Send another large orphan from peer_doser, exceeding the maximum of 3.
        # peer_normal is protected from eviction because it's not taking up a huge amount of space in the orphanage.
        self.log.info("Send another very large orphan from the DoSy peer, triggering orphanage eviction again")
        large_orphan = large_orphans[3]
        peer_doser.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=int(large_orphan.getwtxid(), 16))]))
        self.fastforward(40)
        self.log.info("Sent large orphan inv {}".format(large_orphan.getwtxid()))
        peer_doser.wait_for_getdata([int(large_orphan.getwtxid(), 16)])
        peer_doser.send_and_ping(msg_tx(large_orphan))
        self.log.info("Sent large orphan tx {}".format(large_orphan.getwtxid()))
        self.fastforward(30)
        peer_doser.wait_for_getdata([large_orphan.vin[0].prevout.hash])
        self.log.info("Got parent request for orphan tx {}".format(large_orphan.getwtxid()))

        self.log.info("Provide the normal orphan's parent. The orphan should have been kept and now processed.")
        peer_normal.send_and_ping(msg_tx(parent_tx))
        assert_equal(node.getmempoolentry(orphan_tx.rehash())["ancestorcount"], 2)
        assert_equal(node.getmempoolentry(parent_tx.rehash())["descendantcount"], 2)


    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)
        self.test_orphan_handling_prefer_outbound()
        self.test_announcers_before_and_after()
        # self.test_orphanage_dos()


if __name__ == '__main__':
    OrphanHandlingTest().main()
