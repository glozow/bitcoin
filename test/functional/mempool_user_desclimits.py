#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test user-elected descendant limits."""

from copy import deepcopy
from decimal import Decimal

from test_framework.address import (
    ADDRESS_BCRT1_P2WSH_OP_TRUE,
    ADDRESS_BCRT1_UNSPENDABLE,
)
from test_framework.messages import (
    BIP125_SEQUENCE_NUMBER,
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    tx_from_hex,
    SEQUENCE_FINAL,
    WITNESS_SCALE_FACTOR,
)
from test_framework.script import (
    CScript,
    OP_DROP,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.script_util import (
    DUMMY_P2WPKH_SCRIPT,
    DUMMY_2_P2WPKH_SCRIPT,
)
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    bulk_transaction,
    create_child_with_parents,
    make_chain,
    MiniWallet,
    DEFAULT_FEE,
)


class UserDescendantLimitsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            [
                "-userdescendantlimits=1",
                "-acceptnonstdtxn",
            ],
        ]
        self.supports_cli = False

    def make_utxo(self, node, amount, confirmed=True, scriptPubKey=DUMMY_P2WPKH_SCRIPT):
        """Create a txout with a given amount and scriptPubKey

        confirmed - txouts created will be confirmed in the blockchain;
                    unconfirmed otherwise.
        """
        txid, n = self.wallet.send_to(from_node=node, scriptPubKey=scriptPubKey, amount=amount)

        # If requested, ensure txouts are confirmed.
        if confirmed:
            mempool_size = len(node.getrawmempool())
            while mempool_size > 0:
                self.generate(node, 1)
                new_size = len(node.getrawmempool())
                # Error out if we have something stuck in the mempool, as this
                # would likely be a bug.
                assert new_size < mempool_size
                mempool_size = new_size

        return COutPoint(int(txid, 16), n)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        # the pre-mined test framework chain contains coinbase outputs to the
        # MiniWallet's default address in blocks 76-100 (see method
        # BitcoinTestFramework._initialize_chain())
        self.wallet.rescan_utxos()

        self.log.info("Generate blocks to create UTXOs")
        node = self.nodes[0]
        self.privkeys = [node.get_deterministic_priv_key().key]
        self.address = node.get_deterministic_priv_key().address
        self.coins = []
        # The last 100 coinbase transactions are premature
        for b in self.generatetoaddress(node, 110, self.address)[:-100]:
            coinbase = node.getblock(blockhash=b, verbosity=2)["tx"][0]
            self.coins.append({
                "txid": coinbase["txid"],
                "amount": coinbase["vout"][0]["value"],
                "scriptPubKey": coinbase["vout"][0]["scriptPubKey"],
            })

        self.log.info("Test descendant limits")
        node = self.nodes[0]
        assert_equal(0, node.getmempoolinfo()["size"])
        weight_too_big = 5000 * WITNESS_SCALE_FACTOR
        weight_just_under = 4000 * WITNESS_SCALE_FACTOR
        high_fee = Decimal("0.0001")

        self.log.info("Test user-elected descendant limits")
        first_coin = self.coins.pop()
        parent_value = first_coin["amount"] - high_fee
        inputs = [{"txid": first_coin["txid"], "vout": 0, "sequence": 0xffffffff}]
        outputs = [{self.address : parent_value}]
        parent_signed = node.signrawtransactionwithkey(hexstring=node.createrawtransaction(inputs, outputs), privkeys=self.privkeys)
        node.sendrawtransaction(parent_signed["hex"])
        parent_tx = tx_from_hex(parent_signed["hex"])
        parent_txid = parent_tx.rehash()
        parent_spk = parent_tx.vout[0].scriptPubKey.hex()
        parent_value = Decimal(parent_tx.vout[0].nValue) / COIN
        parent_entry = node.getmempoolentry(parent_txid)
        assert parent_entry["user-descendant-limits"]

        child_tx = CTransaction()
        prevtxs = [{
            "txid": parent_txid,
            "vout": 0,
            "scriptPubKey": parent_spk,
            "amount": parent_value,
        }]
        (child_unsigned, unsigned_hex, _, _) = make_chain(node, self.address, self.privkeys, parent_txid, parent_value, 0, parent_spk, high_fee)
        # Don't signal user descendant limits on this one
        child_unsigned.vin[0].nSequence = 0
        huge_child_tx = bulk_transaction(child_unsigned, node, weight_too_big, self.privkeys, prevtxs)
        assert_raises_rpc_error(-26, "BIPX-descendant-limit", node.sendrawtransaction, huge_child_tx.serialize().hex())

        child_tx = bulk_transaction(child_unsigned, node, weight_just_under, self.privkeys, prevtxs)
        node.sendrawtransaction(child_tx.serialize().hex())
        child_txid = child_tx.rehash()
        child_spk = child_tx.vout[0].scriptPubKey.hex()
        child_value = Decimal(child_tx.vout[0].nValue) / COIN


        assert_equal(2, node.getmempoolinfo()["size"])
        parent_entry = node.getmempoolentry(parent_txid)
        child_entry = node.getmempoolentry(child_txid)
        # descendant size is more than twice the size of original. we have a floor of 5000
        assert parent_entry["vsize"] * 2 < parent_entry["descendantsize"]
        assert parent_entry["descendantsize"] < 5000
        assert child_entry["user-descendant-limits"] == False

        (tx_small, _, _, _) = make_chain(node, self.address, self.privkeys, child_txid, child_value, 0, child_spk, high_fee)
        prevtxs = [{
            "txid": child_txid,
            "vout": 0,
            "scriptPubKey": child_spk,
            "amount": child_value,
        }]
        remaining_weight = WITNESS_SCALE_FACTOR * (5000 - parent_entry["descendantsize"] + 1)
        tx_grandchild = bulk_transaction(tx_small, node, remaining_weight, self.privkeys, prevtxs)
        # the parent (indirect ancestor) will exceed descendant limits this way
        assert_raises_rpc_error(-26, "BIPX-descendant-limit", node.sendrawtransaction, tx_grandchild.serialize().hex())


if __name__ == '__main__':
    UserDescendantLimitsTest().main()
