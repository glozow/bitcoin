#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test that package works successfully in a "network" of nodes. Send various packages from different
nodes on a network in which some nodes have already received some of the transactions (and submitted
them to mempool, kept them as orphans or rejected them as too-low-feerate transactions). The
packages should be received and accepted by all transactions on the network.
"""

from decimal import Decimal
from test_framework.messages import (
    CInv,
    MSG_WTX,
    msg_inv,
    msg_tx,
)
from test_framework.p2p import (
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
)
from test_framework.wallet import (
    COIN,
    DEFAULT_FEE,
    MiniWallet,
)

class PackageRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        self.extra_args = [["-packagerelay=1"]] * self.num_nodes

    def create_packages(self):
        # Basic 1-parent-1-child package
        low_fee_parent = self.wallet.create_self_transfer(fee=0, fee_rate=0)
        child = self.wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxo"])
        package_hex = [low_fee_parent["hex"], child["hex"]]
        self.packages_to_submit[2].append(package_hex)
        self.transactions_to_presend[0] = [low_fee_parent["tx"]]
        self.transactions_to_presend[4] = [child["tx"]]
        self.total_txns += 2

        # Diamond shape: 1 grandparent, 2 parents, 1 child
        diamond_grandparent = self.wallet.create_self_transfer_multi(num_outputs=2, fee_per_output=0)
        diamond_parent1 = self.wallet.create_self_transfer(utxo_to_spend=diamond_grandparent["new_utxos"][0], fee=0, fee_rate=0)
        diamond_parent2 = self.wallet.create_self_transfer(utxo_to_spend=diamond_grandparent["new_utxos"][1], fee=0, fee_rate=0)
        diamond_child = self.wallet.create_self_transfer_multi(utxos_to_spend=[diamond_parent1["new_utxo"], diamond_parent2["new_utxo"]])
        self.packages_to_submit[3].append([diamond_grandparent["hex"], diamond_parent1["hex"], diamond_parent2["hex"], diamond_child["hex"]])
        self.nodes[0].prioritisetransaction(diamond_grandparent["txid"], 0, COIN)
        self.transactions_to_presend[0] += [diamond_grandparent["tx"]]
        self.total_txns += 4

        # Two 1-parent-1-child packages with overlapping ancestors
        low_fee_parent = self.wallet.create_self_transfer_multi(num_outputs=2, fee_per_output=0)
        child1 = self.wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxos"][0])
        child2 = self.wallet.create_self_transfer(utxo_to_spend=low_fee_parent["new_utxos"][1])
        self.packages_to_submit[0].append([low_fee_parent["hex"], child1["hex"]])
        self.packages_to_submit[4].append([low_fee_parent["hex"], child2["hex"]])
        self.transactions_to_presend[1] = [child1["tx"]]
        self.total_txns += 3

        # 3 generation parent + child + grandchild
        normal_parent = self.wallet.create_self_transfer()
        normal_child = self.wallet.create_self_transfer(utxo_to_spend=normal_parent["new_utxo"])
        normal_grandchild = self.wallet.create_self_transfer(utxo_to_spend=normal_child["new_utxo"])
        self.packages_to_submit[3].append([normal_parent["hex"], normal_child["hex"], normal_grandchild["hex"]])
        self.transactions_to_presend[2] = [normal_parent["tx"]]
        self.transactions_to_presend[3] = [normal_child["tx"]]
        self.total_txns += 3

        # 3 generation parent(0fee) + child(0fee) + grandchild
        parent_0 = self.wallet.create_self_transfer(fee=0, fee_rate=0)
        child_0 = self.wallet.create_self_transfer(utxo_to_spend=parent_0["new_utxo"], fee=0, fee_rate=0)
        grandchild_bumper = self.wallet.create_self_transfer(utxo_to_spend=child_0["new_utxo"])
        self.packages_to_submit[2].append([parent_0["hex"], child_0["hex"], grandchild_bumper["hex"]])
        self.transactions_to_presend[0] += [parent_0["tx"]]
        self.transactions_to_presend[1] += [child_0["tx"]]
        self.transactions_to_presend[2] += [child_0["tx"]]
        self.transactions_to_presend[3] += [grandchild_bumper["tx"]]
        self.total_txns += 3

    def run_test(self):
        self.ctr = 0
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 100)

        self.packages_to_submit = [[]] * self.num_nodes
        self.transactions_to_presend = [[]] * self.num_nodes
        self.total_txns = 0

        self.log.info("Create transactions and then mature the coinbases")
        self.create_packages()
        self.generate(self.wallet, 100)

        self.peers = []
        for i in range(self.num_nodes):
            # Add outbound connections for faster relay
            self.peers.append(self.nodes[i].add_outbound_p2p_connection(P2PInterface(), p2p_idx=i, connection_type="outbound-full-relay"))

        self.log.info("Pre-send some transactions to nodes")
        for i in range(self.num_nodes):
            peer = self.peers[i]
            for tx in self.transactions_to_presend[i]:
                inv = CInv(t=MSG_WTX, h=int(tx.getwtxid(), 16))
                peer.send_and_ping(msg_inv([inv]))
                peer.wait_for_getdata([int(tx.getwtxid(), 16)])
                peer.send_and_ping(msg_tx(tx))

        self.log.info("Submit full packages to their respective nodes")
        for i in range(self.num_nodes):
            for package_hex in self.packages_to_submit[i]:
                self.nodes[i].submitpackage(package_hex)

        self.log.info("Wait for mempools to sync")
        self.sync_mempools(timeout=90)
        assert all([node.getmempoolinfo()["size"] == self.total_txns for node in self.nodes])


if __name__ == '__main__':
    PackageRelayTest().main()
