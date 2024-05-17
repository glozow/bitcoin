#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test descendant package tracking carve-out allowing one final transaction in
   an otherwise-full package as long as it has only one parent and is <= 10k in
   size.
"""

from test_framework.messages import (
    DEFAULT_ANCESTOR_LIMIT,
    WITNESS_SCALE_FACTOR,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


class MempoolPackagesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-maxorphantx=1000"]]

    def chain_tx(self, utxos_to_spend, *, num_outputs=1):
        return self.wallet.send_self_transfer_multi(
            from_node=self.nodes[0],
            utxos_to_spend=utxos_to_spend,
            num_outputs=num_outputs)['new_utxos']

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        # DEFAULT_ANCESTOR_LIMIT transactions off a confirmed tx should be fine
        chain = []
        utxo = self.wallet.get_utxo()
        for _ in range(4):
            utxo, utxo2 = self.chain_tx([utxo], num_outputs=2)
            chain.append(utxo2)
        for _ in range(DEFAULT_ANCESTOR_LIMIT - 4):
            utxo, = self.chain_tx([utxo])
            chain.append(utxo)
        second_chain, = self.chain_tx([self.wallet.get_utxo()])

        # Check mempool has DEFAULT_ANCESTOR_LIMIT + 1 transactions in it
        assert_equal(len(self.nodes[0].getrawmempool()), DEFAULT_ANCESTOR_LIMIT + 1)

        # Adding one more transaction on to the chain should fail.
        assert_raises_rpc_error(-26, "too-long-mempool-chain, too many unconfirmed ancestors [limit: 25]", self.chain_tx, [utxo])
        # ...even if it chains on from some point in the middle of the chain.
        assert_raises_rpc_error(-26, "too-long-mempool-chain, too many descendants", self.chain_tx, [chain[2]])
        assert_raises_rpc_error(-26, "too-long-mempool-chain, too many descendants", self.chain_tx, [chain[1]])
        # ...even if it chains on to two parent transactions with one in the chain.
        assert_raises_rpc_error(-26, "too-long-mempool-chain, too many descendants", self.chain_tx, [chain[0], second_chain])
        # ...especially if its > 40k weight
        assert_raises_rpc_error(-26, "too-long-mempool-chain, too many descendants", self.chain_tx, [chain[0]], num_outputs=350)
        # But not if it chains directly off the first transaction
        replacable_tx = self.wallet.send_self_transfer_multi(from_node=self.nodes[0], utxos_to_spend=[chain[0]])['tx']
        # and the second chain should work just fine
        self.chain_tx([second_chain])

        # Make sure we can RBF the chain which used our carve-out rule
        replacable_tx.vout[0].nValue -= 1000000
        self.nodes[0].sendrawtransaction(replacable_tx.serialize().hex())

        # Finally, check that we added two transactions
        assert_equal(len(self.nodes[0].getrawmempool()), DEFAULT_ANCESTOR_LIMIT + 3)

        # Check nondefault limits
        self.restart_node(0, extra_args=["-limitdescendantsize=10", "-datacarriersize=10000"])
        node = self.nodes[0]
        self.log.info("Test decreased limitdescendantsize")
        desc_limit_vb = 10000
        # We have to lower the descendant limit because bulk_tx doesn't work with larger numbers.
        # But this theoretically would work for the default size too (100KvB parent + 10KvB child)
        weight_within_desc = (desc_limit_vb - 10) * WITNESS_SCALE_FACTOR
        tx_parent = self.wallet.send_self_transfer(
            from_node=node,
            target_weight=weight_within_desc,
        )
        tx_child = self.wallet.create_self_transfer(
            utxo_to_spend=tx_parent["new_utxo"],
            target_weight=weight_within_desc,
        )
        assert_greater_than(desc_limit_vb, tx_parent["tx"].get_vsize())
        assert_greater_than(desc_limit_vb, tx_child["tx"].get_vsize())
        assert_greater_than(tx_parent["tx"].get_vsize() + tx_child["tx"].get_vsize(), desc_limit_vb)

        # Carve out grants a free +10KvB even if this isn't the second child. It doesn't check, just
        # loosens the descendant limits, sets ancestor limit to 2, and sees if it passes.
        # Even though the descendant limit is 10KvB, you can have a 1p1c of size just under 20KvB.
        # assert_raises_rpc_error(-26, f"too-long-mempool-chain, exceeds descendant size limit for tx {tx_parent['txid']}", node.sendrawtransaction, tx_child["hex"])
        node.sendrawtransaction(tx_child["hex"])
        assert_greater_than(node.getmempoolentry(tx_parent["txid"])["descendantsize"], 19000)
        self.generate(node, 1)


if __name__ == '__main__':
    MempoolPackagesTest().main()
