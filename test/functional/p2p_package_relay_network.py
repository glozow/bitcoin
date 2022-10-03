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
            )
        child_inputs.append(parent_result["new_utxo"])
        package_hex.append(parent_result["hex"])
        package_txns.append(parent_result["tx"])
        child_result = self.wallet.create_self_transfer_multi(
            utxos_to_spend=child_inputs,
            num_outputs=1,
            fee_per_output=int(fees[-1] * COIN),
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

    def run_test(self):
        self.ctr = 0
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 60)
        self.coins = self.wallet.get_utxos(mark_as_spent=False)
        self.generate(self.wallet, 100)

        self.test_package_relay_basic()



if __name__ == '__main__':
    PackageRelayTest().main()
