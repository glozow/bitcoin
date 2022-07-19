#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal
from random import choice

from test_framework.address import (
    ADDRESS_BCRT1_P2WSH_OP_TRUE,
    ADDRESS_BCRT1_UNSPENDABLE,
)
from test_framework.messages import (
    MAX_BIP125_RBF_SEQUENCE,
    tx_from_hex,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    create_child_with_parents,
    DEFAULT_FEE,
    make_chain,
)

class PackageRBFTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def assert_mempool_contents(self, expected=None, unexpected=None):
        """Assert that all transactions in expected are in the mempool,
        and all transactions in unexpected are not in the mempool.
        """
        if not expected:
            expected = []
        if not unexpected:
            unexpected = []
        assert set(unexpected).isdisjoint(expected)
        mempool = self.nodes[0].getrawmempool(verbose=False)
        for tx in expected:
            assert tx.rehash() in mempool
        for tx in unexpected:
            assert tx.rehash() not in mempool

    def create_simple_package(self, parent_coins, parent_fee=0, child_fee=DEFAULT_FEE, version=2):
        """Create a child-with-parents package using the parent_coins passed in.
        Each coin in parent_coins will be used to fund one parent transaction.
        Thus, the package will contain len(parent_coins) parents and 1 child.
        Default fee for the parent transactions is 0.
        The child will have a fee of 0.0001BTC*len(parent_coins) unless otherwise specified.

        returns tuple (hex serialized txns, CTransaction objects)
        """
        node = self.nodes[0]
        package_hex = []
        package_txns = []
        values = []
        scripts = []
        # Create the parents
        for coin in parent_coins:
            value = coin["amount"]
            txid = coin["txid"]
            (tx, txhex, value, spk) = make_chain(node, self.address, self.privkeys, txid, value, 0, None, parent_fee, version)
            package_hex.append(txhex)
            package_txns.append(tx)
            values.append(value)
            scripts.append(spk)
        # Subtract the fee that will automatically be applied. Pass in the fee difference.
        child_hex = create_child_with_parents(node, self.address, self.privkeys, package_txns, values, scripts, child_fee, version)
        package_hex.append(child_hex)
        package_txns.append(tx_from_hex(child_hex))
        return package_hex, package_txns

    def create_package_heavy(self, parent_coins):
        """Create a package with a parent for each coin in parent_coins as inputs.
        Each parent will have 3 outputs and slightly higher fees.
        There will be 1 child of all the parent transactions (a package can only have 1 child).
        Default fee for each parent transaction is 0.0001001
        Default fee for the child transaction is 0.0001BTC*num_parents

        returns tuple (package_hex, package_txns)
        """
        node = self.nodes[0]
        package_hex = []
        package_txns = []
        values = []
        scripts = []
        # Create the parents
        for coin in parent_coins:
            value = coin["amount"]
            txid = coin["txid"]
            # Subtract a tiny additional amount to increase the absolute fee
            amount_each = (value - Decimal("0.0001001")) / 3
            inputs = [{"txid": txid, "vout": 0, "sequence": MAX_BIP125_RBF_SEQUENCE}]
            outputs = {
                self.address : amount_each,
                ADDRESS_BCRT1_P2WSH_OP_TRUE: amount_each,
                ADDRESS_BCRT1_UNSPENDABLE: amount_each,
            }
            rawtx = node.createrawtransaction(inputs, outputs)
            txhex = node.signrawtransactionwithkey(rawtx, self.privkeys)["hex"]
            package_hex.append(txhex)
            tx = tx_from_hex(txhex)
            package_txns.append(tx)
            values.append(amount_each)
            scripts.append(tx.vout[0].scriptPubKey.hex())
        # This function will use the first output of each parent
        child_hex = create_child_with_parents(node, self.address, self.privkeys, package_txns, values, scripts)
        package_hex.append(child_hex)
        package_txns.append(tx_from_hex(child_hex))
        return package_hex, package_txns

    def create_package_many_conflicts(self, parent_coins):
        """Create a family of transactions using the parent_coins passed in (should have > 100).
        The goal here is to have more than 100 dependencies so we hit the BIP125 Rule 5 limit.
        Every 10 coins will be used to fund 1 parent transaction, so num_parents = parent_coins/10
        There will be 1 child of all the parent transactions.
        Default fee for each transaction is 0.0001BTC.

        returns tuple (package_hex, package_txns)
        """
        assert_greater_than_or_equal(len(parent_coins), 100)
        node = self.nodes[0]

        # Create a package that spends 10 coins per parent
        package_hex = []
        package_txns = []
        values = []
        scripts = []
        # Create the parents
        for i in range(len(parent_coins) // 10):
            my_coins = parent_coins[10*i : 10*i+10]
            inputs = [{"txid": coin["txid"], "vout": 0} for coin in my_coins]
            my_value = sum([coin["amount"] for coin in my_coins]) - DEFAULT_FEE
            outputs = {self.address: my_value}
            raw_parent = node.createrawtransaction(inputs, outputs)
            signed_parent = node.signrawtransactionwithkey(raw_parent, self.privkeys)
            assert signed_parent["complete"]
            package_hex.append(signed_parent["hex"])
            parent_tx = tx_from_hex(signed_parent["hex"])
            package_txns.append(parent_tx)
            values.append(my_value)
            scripts.append(parent_tx.vout[0].scriptPubKey.hex())
        # Subtract the fee that will automatically be applied. Pass in the fee difference.
        child_hex = create_child_with_parents(node, self.address, self.privkeys, package_txns, values, scripts)
        package_hex.append(child_hex)
        package_txns.append(tx_from_hex(child_hex))
        return package_hex, package_txns

    def run_test(self):
        self.log.info("Generate blocks to create UTXOs")
        node = self.nodes[0]
        self.privkeys = [node.get_deterministic_priv_key().key]
        self.address = node.get_deterministic_priv_key().address
        self.coins = []
        # The last 100 coinbase transactions are premature
        for b in self.generatetoaddress(node, 262, self.address)[:-100]:
            coinbase = node.getblock(blockhash=b, verbosity=2)["tx"][0]
            self.coins.append({
                "txid": coinbase["txid"],
                "amount": coinbase["vout"][0]["value"],
                "scriptPubKey": coinbase["vout"][0]["scriptPubKey"],
            })

        self.test_package_rbf_basic()
        self.test_package_rbf_bip125_signaling()
        self.test_package_rbf_v3()
        self.test_package_rbf_additional_fees()
        self.test_package_rbf_max_conflicts()
        self.test_package_rbf_conflicting_conflicts()
        self.test_package_rbf_partial()
        self.test_ephemeral_dust()

    def test_package_rbf_basic(self):
        self.log.info("Test that packages can RBF")
        node = self.nodes[0]
        # Reuse the same coins so that the transactions conflict with one another.
        num_parents = 2
        parent_coins = self.coins[:num_parents]
        del self.coins[:num_parents]
        (package_hex1, package_txns1) = self.create_simple_package(parent_coins, DEFAULT_FEE, DEFAULT_FEE)
        (package_hex2, package_txns2) = self.create_simple_package(parent_coins, 0, DEFAULT_FEE * 5)
        node.submitpackage(package_hex1)
        self.assert_mempool_contents(expected=package_txns1, unexpected=package_txns2)

        submitres = node.submitpackage(package_hex2)
        submitres["replaced-transactions"] == [tx.rehash() for tx in package_txns1]
        self.assert_mempool_contents(expected=package_txns2, unexpected=package_txns1)
        self.generate(node, 1)

    def test_package_rbf_bip125_signaling(self):
        self.log.info("Test that all replacement candidates in package RBF must signal replaceability")
        node = self.nodes[0]
        num_parents = 20
        parent_coins = self.coins[:num_parents]
        del self.coins[:num_parents]
        (package_hex, package_txns) = self.create_simple_package(parent_coins, 0, DEFAULT_FEE * 3)

        # Submit transactions to the mempool be replaced
        singleton_txns = []
        # Create 1 transaction per coin and submit to mempool.
        for coin in parent_coins[1:]:
            txid = coin["txid"]
            value = coin["amount"]
            (tx, txhex, _, _) = make_chain(node, self.address, self.privkeys, txid, value)
            node.sendrawtransaction(txhex)
            singleton_txns.append(tx)

        # Create single transaction that doesn't signal replaceability
        coin = parent_coins[0]
        txid = coin["txid"]
        value = coin["amount"]
        inputs = [{"txid": txid, "vout": 0, "sequence": MAX_BIP125_RBF_SEQUENCE + 1}]
        outputs = {self.address: value - DEFAULT_FEE}
        rawtx = node.createrawtransaction(inputs, outputs)
        txhex = node.signrawtransactionwithkey(rawtx, self.privkeys)["hex"]
        node.sendrawtransaction(txhex)

        self.assert_mempool_contents(expected=[tx_from_hex(txhex)] + singleton_txns, unexpected=package_txns)
        assert_raises_rpc_error(-26, "txn-mempool-conflict", node.submitpackage, package_hex)
        self.assert_mempool_contents(expected=[tx_from_hex(txhex)] + singleton_txns, unexpected=package_txns)
        self.generate(node, 1)

    def test_package_rbf_v3(self):
        self.log.info("Test that v3 transactions automatically signal replaceability")
        node = self.nodes[0]
        # Create single transaction that doesn't signal BIP125 but has nVersion=3
        coin = self.coins[0]
        del self.coins[0]
        txid = coin["txid"]
        value = coin["amount"]
        inputs = [{"txid": txid, "vout": 0, "sequence": MAX_BIP125_RBF_SEQUENCE + 1}]
        outputs = {self.address: value - DEFAULT_FEE}
        tx_v3_no_bip125 = tx_from_hex(node.createrawtransaction(inputs, outputs))
        tx_v3_no_bip125.nVersion = 3
        txhex = node.signrawtransactionwithkey(tx_v3_no_bip125.serialize().hex(), self.privkeys)["hex"]
        node.sendrawtransaction(txhex)
        self.assert_mempool_contents(expected=[tx_from_hex(txhex)])

        self.log.info("Test that v3 transactions must be replaced by v3 transactions")
        package_hex_v2, package_txns_v2 = self.create_simple_package([coin], 0, DEFAULT_FEE * 2, version=2)
        assert_raises_rpc_error(-26, "txn-mempool-conflict", node.submitpackage, package_hex_v2)
        package_hex_v3, package_txns_v3 = self.create_simple_package([coin], 0, DEFAULT_FEE * 2, version=3)
        node.submitpackage(package_hex_v3)
        self.assert_mempool_contents(expected=package_txns_v3, unexpected=[tx_v3_no_bip125])
        self.generate(node, 1)

    def test_package_rbf_additional_fees(self):
        self.log.info("Check Package RBF must increase the absolute fee")
        node = self.nodes[0]
        num_parents = 10
        parent_coins = self.coins[:num_parents]
        del self.coins[:num_parents]
        (package_hex1, package_txns1) = self.create_package_heavy(parent_coins)
        node.submitpackage(package_hex1)
        self.assert_mempool_contents(expected=package_txns1)
        # Package 2 has a higher feerate but lower absolute fee
        package2_parent_fee = Decimal("0.00010005")
        package2_absolute_fee = package2_parent_fee * 10 + DEFAULT_FEE
        (package_hex2, package_txns2) = self.create_simple_package(parent_coins, package2_parent_fee)
        assert_greater_than_or_equal(node.getmempoolinfo()["total_fee"], package2_absolute_fee)
        assert_raises_rpc_error(-25, "package RBF failed: insufficient fee", node.submitpackage, package_hex2)
        self.assert_mempool_contents(expected=package_txns1, unexpected=package_txns2)
        # Package 3 has a higher feerate and absolute fee
        (package_hex3, package_txns3) = self.create_simple_package(parent_coins, Decimal("0.0002"))
        node.submitpackage(package_hex3)
        self.assert_mempool_contents(expected=package_txns3, unexpected=package_txns1 + package_txns2)
        self.generate(node, 1)

        self.log.info("Check Package RBF must pay for the entire package's bandwidth")
        num_parents = 2
        parent_coins = self.coins[:num_parents]
        del self.coins[:num_parents]
        (package_hex1, package_txns1) = self.create_simple_package(parent_coins, Decimal("0.0001"), Decimal("0.0001"))
        (package_hex2, package_txns2) = self.create_simple_package(parent_coins, 0, Decimal("0.00030001"))
        node.submitpackage(package_hex1)
        self.assert_mempool_contents(expected=package_txns1, unexpected=package_txns2)
        assert_raises_rpc_error(-25, "package RBF failed: insufficient fee", node.submitpackage, package_hex2)
        self.assert_mempool_contents(expected=package_txns1, unexpected=package_txns2)
        self.generate(node, 1)

    def test_package_rbf_max_conflicts(self):
        node = self.nodes[0]
        self.log.info("Check Package RBF cannot replace more than 100 transactions")
        num_parents = 110
        parent_coins = self.coins[:num_parents]
        del self.coins[:num_parents]
        (package_hex, package_txns) = self.create_package_many_conflicts(parent_coins)
        singleton_txns = []
        # Create 1 transaction per coin and submit to mempool.
        for coin in parent_coins:
            txid = coin["txid"]
            value = coin["amount"]
            # Low fee
            (tx, txhex, _, _) = make_chain(node, ADDRESS_BCRT1_P2WSH_OP_TRUE, self.privkeys, txid, value, 0, None, Decimal("0.00001"))
            node.sendrawtransaction(txhex)
            singleton_txns.append(tx)
        self.assert_mempool_contents(expected=singleton_txns, unexpected=package_txns)
        assert_raises_rpc_error(-25, "package RBF failed: too many potential replacements",
                node.submitpackage, package_hex)
        self.generate(node, 1)

    def test_package_rbf_conflicting_conflicts(self):
        node = self.nodes[0]
        self.log.info("Check that different package transactions cannot share the same conflicts")
        num_parents = 5
        parent_coins = self.coins[:num_parents]
        del self.coins[:num_parents]
        (package_hex1, package_txns1) = self.create_simple_package(parent_coins, DEFAULT_FEE, DEFAULT_FEE)
        (package_hex2, package_txns2) = self.create_simple_package(parent_coins, Decimal("0.00009"), DEFAULT_FEE * num_parents)
        (package_hex3, package_txns3) = self.create_simple_package(parent_coins, 0, DEFAULT_FEE * 5 * num_parents)
        node.submitpackage(package_hex1)
        self.assert_mempool_contents(expected=package_txns1)
        # The first two transactions have the same conflicts
        package_duplicate_conflicts_hex = [package_hex2[0]] + package_hex3
        # Note that this won't actually go into the RBF logic, because static package checks will
        # detect that two package transactions conflict with each other. Either way, this must fail.
        assert_raises_rpc_error(-25, "conflict-in-package", node.submitpackage, package_duplicate_conflicts_hex)
        self.assert_mempool_contents(expected=package_txns1, unexpected=package_txns2 + package_txns3)
        # The RBFs should otherwise work.
        submitres2 = node.submitpackage(package_hex2)
        submitres2["replaced-transactions"] == [tx.rehash() for tx in package_txns1]
        self.assert_mempool_contents(expected=package_txns2, unexpected=package_txns1)
        submitres3 = node.submitpackage(package_hex3)
        submitres3["replaced-transactions"] == [tx.rehash() for tx in package_txns2]
        self.assert_mempool_contents(expected=package_txns3, unexpected=package_txns2)

    def test_package_rbf_partial(self):
        self.log.info("Test that package RBF works when a transaction was already submitted")
        node = self.nodes[0]
        num_parents = 10
        parent_coins = self.coins[:num_parents]
        del self.coins[:num_parents]
        (package_hex1, package_txns1) = self.create_simple_package(parent_coins, DEFAULT_FEE, DEFAULT_FEE)
        (package_hex2, package_txns2) = self.create_simple_package(parent_coins, DEFAULT_FEE * 3, DEFAULT_FEE * 3)
        node.submitpackage(package_hex1)
        self.assert_mempool_contents(expected=package_txns1, unexpected=package_txns2)
        # Submit a random parent on its own. It should have no trouble replacing the previous
        # transaction(s) because the fee is tripled.
        node.sendrawtransaction(choice(package_hex2[:-1]))
        node.submitpackage(package_hex2)
        self.assert_mempool_contents(expected=package_txns2, unexpected=package_txns1)
        self.generate(node, 1)

    def test_ephemeral_dust(self):
        self.log.info("Test ephemeral dust (experimental)")
        node = self.nodes[0]
        coins = self.coins[:2]
        del self.coins[:2]

        # parent
        txid = coins[0]["txid"]
        value = coins[0]["amount"]
        inputs = [{"txid": txid, "vout": 0, "sequence": MAX_BIP125_RBF_SEQUENCE + 1}]
        # ephemeral output. transaction fee = 0
        outputs = {self.address: 0}
        tx_ephemeral_output = tx_from_hex(node.createrawtransaction(inputs, outputs))
        tx_ephemeral_output.nVersion = 3
        hex_parent = node.signrawtransactionwithkey(tx_ephemeral_output.serialize().hex(), self.privkeys)["hex"]
        tx_parent = tx_from_hex(hex_parent)

        # child
        txid = coins[1]["txid"]
        value = coins[1]["amount"]
        inputs = [{"txid": txid, "vout": 0, "sequence": MAX_BIP125_RBF_SEQUENCE + 1},
                  {"txid": tx_parent.rehash(), "vout": 0, "sequence": MAX_BIP125_RBF_SEQUENCE + 1}]
        # high transaction fee
        outputs = {self.address: value - DEFAULT_FEE * 3}
        tx_ephemeral_output_spender = tx_from_hex(node.createrawtransaction(inputs, outputs))
        tx_ephemeral_output_spender.nVersion = 3
        hex_child = node.signrawtransactionwithkey(tx_ephemeral_output_spender.serialize().hex(), self.privkeys)["hex"]
        tx_child = tx_from_hex(hex_child)

        print("tx_parent: ".format(tx_parent.rehash()))
        print("tx_child: ".format(tx_child.rehash()))

        node.submitpackage([hex_parent, hex_child])
        self.assert_mempool_contents(expected=[tx_parent.rehash(), tx_child.rehash()])



if __name__ == "__main__":
    PackageRBFTest().main()
