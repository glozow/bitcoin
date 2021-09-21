#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test ability to relay transactions after they have been replaced from mempool."""

from decimal import Decimal
import time

from test_framework.messages import (
    BIP125_SEQUENCE_NUMBER,
    CInv,
)
from test_framework.p2p import (
    msg_getdata,
    MSG_TX,
    MSG_WTX,
    P2PTxInvStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet

class P2PTxRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], []]

    def request_and_get_result(self, node, peer, txid, expect_notfound=False):
        # Send a getdata from peer and wait for response
        request = msg_getdata()
        request.inv.append(CInv(MSG_TX, int(txid, 16)))
        peer.send_and_ping(request)
        if expect_notfound:
            peer.wait_for_notfound()
        else:
            peer.wait_for_tx(txid)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(self.nodes[0])
        self.wallet.generate(1)
        shared_utxo = self.wallet.get_utxo()
        self.wallet.generate(100)

        spy_peer = node.add_p2p_connection(P2PTxInvStore())

        # Tx A
        self.log.info("Create transaction A and wait for the node to start relaying it")
        txa = self.wallet.create_self_transfer(
            from_node=node,
            utxo_to_spend=shared_utxo,
            sequence=BIP125_SEQUENCE_NUMBER,
            fee_rate=Decimal("0.0001")
        )
        node.sendrawtransaction(txa["hex"], 0)
        spy_peer.wait_for_tx(txa["txid"])
        self.request_and_get_result(node, spy_peer, txa["txid"])

        node.setmocktime(int(time.time() + 15 * 60))

        # Tx B
        self.log.info("Replace A with B")
        txb = self.wallet.create_self_transfer(
            from_node=node,
            utxo_to_spend=shared_utxo,
            sequence=BIP125_SEQUENCE_NUMBER,
            fee_rate=Decimal("0.001")
        )
        self.connect_nodes(0, 1)
        # Submit B to node1 instead of node0 so that node0 receives it on P2P
        self.nodes[1].sendrawtransaction(txb["hex"], 0)
        self.sync_all()

        self.log.info("Check that the node no longer has A in its mempool, but will still relay it when requested")
        assert txa["txid"] not in node.getrawmempool()
        self.request_and_get_result(node, spy_peer, txa["txid"])
        self.request_and_get_result(node, spy_peer, txa["txid"])
        self.request_and_get_result(node, spy_peer, txa["txid"])
        self.request_and_get_result(node, spy_peer, txa["txid"])

        self.log.info("Check that the node stops relaying A after a while")
        node.setmocktime(int(time.time() + 15 * 60))
        self.request_and_get_result(node, spy_peer, txa["txid"], expect_notfound = True)

if __name__ == '__main__':
    P2PTxRelayTest().main()
