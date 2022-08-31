#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.messages import (
    MAX_BIP125_RBF_SEQUENCE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    DEFAULT_FEE,
    MiniWallet,
)

class MempoolAcceptV3(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def check_mempool(self, txids):
        """Assert exact contents of the node's mempool (by txid)."""
        mempool_contents = self.nodes[0].getrawmempool()
        assert_equal(len(txids), len(mempool_contents))
        assert all([txid in txids for txid in mempool_contents])

    def test_v3_acceptance(self):
        node = self.nodes[0]
        self.log.info("Test acceptance of V3 transactions")
        tx_v3_normal = self.wallet.send_self_transfer(from_node=node, version=3)
        self.check_mempool([tx_v3_normal["txid"]])

        self.log.info("Test a child of V3 transaction must also be V3")
        tx_child_v2 = self.wallet.create_self_transfer(utxo_to_spend=tx_v3_normal["new_utxo"], version=2)
        assert_raises_rpc_error(-26, "non-v3-tx-spends-v3", node.sendrawtransaction, tx_child_v2["hex"])
        self.check_mempool([tx_v3_normal["txid"]])

        tx_child_v3 = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_v3_normal["new_utxo"], version=3)
        self.check_mempool([tx_v3_normal["txid"], tx_child_v3["txid"]])

        self.log.info("Test a V3 transaction cannot have more than 1 descendant")
        tx_grandchild_v3 = self.wallet.create_self_transfer(utxo_to_spend=tx_child_v3["new_utxo"], version=3)
        assert_raises_rpc_error(-26, "would exceed descendant count limit", node.sendrawtransaction, tx_grandchild_v3["hex"])
        self.check_mempool([tx_v3_normal["txid"], tx_child_v3["txid"]])
        # Clear mempool by mining a block.
        self.generate(node, 1)

        self.log.info("Test a child of a V3 transaction cannot be more than 1000vB")
        self.restart_node(0, extra_args=["-datacarriersize=1000"])
        tx_v3_parent_normal = self.wallet.send_self_transfer(from_node=node, version=3)
        self.check_mempool([tx_v3_parent_normal["txid"]])
        tx_v3_child_heavy = self.wallet.create_self_transfer(
            utxo_to_spend=tx_v3_parent_normal["new_utxo"],
            target_weight=4004,
            version=3
        )
        assert_greater_than_or_equal(tx_v3_child_heavy["tx"].get_vsize(), 1000)
        assert_raises_rpc_error(-26, "v3-tx-nonstandard, v3 child tx is too big", node.sendrawtransaction, tx_v3_child_heavy["hex"])
        self.check_mempool([tx_v3_parent_normal["txid"]])
        # tx has no descendants
        assert_equal(node.getmempoolentry(tx_v3_parent_normal["txid"])["descendantcount"], 1)

        self.log.info("Test that, during replacements, only the new transaction counts for V3 descendant limit")
        tx_v3_child_almost_heavy = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE,
            utxo_to_spend=tx_v3_parent_normal["new_utxo"],
            target_weight=3987,
            version=3
        )
        assert_greater_than_or_equal(1000, tx_v3_child_almost_heavy["tx"].get_vsize())
        self.check_mempool([tx_v3_parent_normal["txid"], tx_v3_child_almost_heavy["txid"]])
        assert_equal(node.getmempoolentry(tx_v3_parent_normal["txid"])["descendantcount"], 2)
        tx_v3_child_almost_heavy_rbf = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE * 2,
            utxo_to_spend=tx_v3_parent_normal["new_utxo"],
            target_weight=3500,
            version=3
        )
        assert_greater_than_or_equal(tx_v3_child_almost_heavy["tx"].get_vsize() + tx_v3_child_almost_heavy_rbf["tx"].get_vsize(), 1000)
        self.check_mempool([tx_v3_parent_normal["txid"], tx_v3_child_almost_heavy_rbf["txid"]])
        assert_equal(node.getmempoolentry(tx_v3_parent_normal["txid"])["descendantcount"], 2)

        # Clear mempool by mining a block.
        self.generate(node, 1)

    def test_v3_replacement(self):
        node = self.nodes[0]
        self.log.info("Test V3 transactions may be replaced by V3 transactions")
        utxo_v3_bip125 = self.wallet.get_utxo()
        tx_v3_bip125 = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE,
            utxo_to_spend=utxo_v3_bip125,
            sequence=MAX_BIP125_RBF_SEQUENCE,
            version=3
        )
        self.check_mempool([tx_v3_bip125["txid"]])

        tx_v3_bip125_rbf = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE * 2,
            utxo_to_spend=utxo_v3_bip125,
            version=3
        )
        self.check_mempool([tx_v3_bip125_rbf["txid"]])

        self.log.info("Test V3 transactions may be replaced by V2 transactions")
        tx_v3_bip125_rbf_v2 = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE * 3,
            utxo_to_spend=utxo_v3_bip125,
            version=2
        )
        self.check_mempool([tx_v3_bip125_rbf_v2["txid"]])

        self.log.info("Test that replacements cannot cause violation of inherited V3")
        utxo_v3_parent = self.wallet.get_utxo()
        tx_v3_parent = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE,
            utxo_to_spend=utxo_v3_parent,
            version=3
        )
        tx_v3_child = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE,
            utxo_to_spend=tx_v3_parent["new_utxo"],
            version=3
        )
        self.check_mempool([tx_v3_bip125_rbf_v2["txid"], tx_v3_parent["txid"], tx_v3_child["txid"]])

        tx_v3_child_rbf_v2 = self.wallet.create_self_transfer(
            fee_rate=DEFAULT_FEE * 2,
            utxo_to_spend=tx_v3_parent["new_utxo"],
            version=2
        )
        assert_raises_rpc_error(-26, "non-v3-tx-spends-v3", node.sendrawtransaction, tx_v3_child_rbf_v2["hex"])
        self.check_mempool([tx_v3_bip125_rbf_v2["txid"], tx_v3_parent["txid"], tx_v3_child["txid"]])

        # Clear mempool by mining a block.
        self.generate(node, 1)

        self.log.info("Test V3 transactions that don't signal BIP125 are replaceable")
        assert_equal(node.getmempoolinfo()["fullrbf"], False)
        utxo_v3_no_bip125 = self.wallet.get_utxo()
        tx_v3_no_bip125 = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE,
            utxo_to_spend=utxo_v3_no_bip125,
            sequence=MAX_BIP125_RBF_SEQUENCE + 1,
            version=3
        )

        self.check_mempool([tx_v3_no_bip125["txid"]])
        assert not node.getmempoolentry(tx_v3_no_bip125["txid"])["bip125-replaceable"]
        tx_v3_no_bip125_rbf = self.wallet.send_self_transfer(
            from_node=node,
            fee_rate=DEFAULT_FEE * 2,
            utxo_to_spend=utxo_v3_no_bip125,
            version=3
        )
        self.check_mempool([tx_v3_no_bip125_rbf["txid"]])
        # Clear mempool by mining a block.
        self.generate(node, 1)

    def test_v3_reorg(self):
        node = self.nodes[0]
        self.log.info("Test that, during a reorg, transactions that now violate v3 rules are evicted")
        tx_v2_block = self.wallet.send_self_transfer(from_node=node, version=2)
        tx_v3_block = self.wallet.send_self_transfer(from_node=node, version=3)
        assert_equal(set(node.getrawmempool()), set([tx_v3_block["txid"], tx_v2_block["txid"]]))

        block = self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])
        tx_v2_from_v3 = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_v3_block["new_utxo"], version=2)
        tx_v3_from_v2 = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_v2_block["new_utxo"], version=3)
        assert_equal(set(node.getrawmempool()), set([tx_v2_from_v3["txid"], tx_v3_from_v2["txid"]]))
        node.invalidateblock(block[0])
        assert_equal(set(node.getrawmempool()), set([tx_v3_block["txid"], tx_v2_block["txid"]]))

    def run_test(self):
        self.log.info("Generate blocks to create UTXOs")
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 110)
        self.test_v3_acceptance()
        self.test_v3_replacement()
        self.test_v3_reorg()


if __name__ == "__main__":
    MempoolAcceptV3().main()
