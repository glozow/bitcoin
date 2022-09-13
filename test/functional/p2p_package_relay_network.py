#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test package relay messages"""

from decimal import Decimal
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
        self.num_nodes = 3
        self.extra_args = [["-packagerelay=1"]] * self.num_nodes

    def create_package(self, parent_coins=None, fees=None):
        assert_equal(parent_coins == None, fees == None)
        if not parent_coins:
            num_parents = 2
            parent_coins = self.coins[:num_parents]
            del self.coins[:num_parents]
            fees = [DEFAULT_FEE, 0, 10 * DEFAULT_FEE]
        # All feerates should be specified
        assert_equal(len(parent_coins) + 1, len(fees))
        self.ctr += 1
        child_inputs = []
        package_hex = []
        package_txns = []
        for i in range(len(parent_coins)):
            parent_result = self.wallet.create_self_transfer(
                fee_rate=0,
                fee=fees[i],
                utxo_to_spend=parent_coins[i],
                version=3
            )
        child_inputs.append(parent_result["new_utxo"])
        package_hex.append(parent_result["hex"])
        package_txns.append(parent_result["tx"])
        child_result = self.wallet.create_self_transfer_multi(
            utxos_to_spend=child_inputs,
            num_outputs=1,
            fee_per_output=int(fees[-1] * COIN),
            version=3
        )
        package_hex.append(child_result["hex"])
        package_txns.append(child_result["tx"])
        return package_hex, package_txns

    def test_package_relay_basic(self):
        self.log.info("Test end-to-end package relay with multiple nodes")
        for node in self.nodes:
            assert all([peer["relaytxpackages"] for peer in node.getpeerinfo()])
            assert_greater_than_or_equal(node.getmempoolinfo()["mempoolminfee"], Decimal("0.00001"))

        self.log.info("Send the package to node0")
        package_hex, package_txns = self.create_package()
        self.nodes[0].submitpackage(package_hex)
        assert all([tx.rehash() in self.nodes[0].getrawmempool() for tx in package_txns])

        self.log.info("Wait until all nodes have the package in their mempools")
        self.sync_mempools()
        for node in self.nodes:
            mempool = node.getrawmempool()
            assert all([tx.rehash() in mempool for tx in package_txns])
        self.generate(self.nodes[0], 1)

    def test_package_rbf_propagation(self):
        self.log.info("Test that package RBFs propagate")
        num_parents = 1
        parent_coins = self.coins[:num_parents]
        del self.coins[:num_parents]
        package_hex_low, package_txns_low = self.create_package(parent_coins, [DEFAULT_FEE, DEFAULT_FEE])
        package_hex_high, package_txns_high = self.create_package(parent_coins, [0, 10 * DEFAULT_FEE])

        self.log.info("Submit package to node1 and wait for node0 to have it")
        self.nodes[1].submitpackage(package_hex_low)
        self.sync_mempools()
        assert all([tx.rehash() in self.nodes[0].getrawmempool() for tx in package_txns_low])
        assert all([tx.rehash() in self.nodes[1].getrawmempool() for tx in package_txns_low])
        self.log.info("Submit higher-feerate, conflicting package to node0 and wait for node1 to have it")
        self.nodes[0].submitpackage(package_hex_high)
        self.sync_mempools()
        assert all([tx.rehash() in self.nodes[0].getrawmempool() for tx in package_txns_high])
        assert all([tx.rehash() in self.nodes[1].getrawmempool() for tx in package_txns_high])

    def run_test(self):
        self.ctr = 0
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 60)
        self.coins = self.wallet.get_utxos(mark_as_spent=False)
        self.generate(self.wallet, 100)

        self.test_package_relay_basic()
        # doesn't work yet
        # self.test_package_rbf_propagation()



if __name__ == '__main__':
    PackageRelayTest().main()
