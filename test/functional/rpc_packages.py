#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""RPCs that handle raw transaction packages."""

from decimal import Decimal
from io import BytesIO
import random

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    BIP125_SEQUENCE_NUMBER,
    COIN,
    CTransaction,
    CTxInWitness,
)
from test_framework.script import (
    CScript,
    OP_TRUE,
)
from test_framework.util import (
    assert_equal,
    hex_str_to_bytes,
)

class RPCPackagesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        self.log.info("Generate blocks to create UTXOs")
        node = self.nodes[0]
        self.privkeys = [node.get_deterministic_priv_key().key]
        self.address = node.get_deterministic_priv_key().address
        self.coins = []
        # The last 100 coinbase transactions are premature
        for b in node.generatetoaddress(200, self.address)[:100]:
            coinbase = node.getblock(blockhash=b, verbosity=2)["tx"][0]
            self.coins.append({
                "txid": coinbase["txid"],
                "amount": coinbase["vout"][0]["value"],
                "scriptPubKey": coinbase["vout"][0]["scriptPubKey"],
            })

        # Create some transactions that can be reused throughout the test. Never submit these to mempool.
        self.independent_txns_hex = []
        self.independent_txns_testres = []
        for _ in range(3):
            coin = self.coins.pop()
            rawtx = node.createrawtransaction([{"txid" : coin["txid"], "vout" : 0}],
                {self.address : coin["amount"] - Decimal("0.0001")})
            signedtx = node.signrawtransactionwithkey(hexstring=rawtx, privkeys=self.privkeys)
            assert signedtx["complete"]
            testres = node.testmempoolaccept([signedtx["hex"]])
            assert testres[0]["allowed"]
            self.independent_txns_hex.append(signedtx["hex"])
            # testmempoolaccept returns a list of length one, avoid creating a 2D list
            self.independent_txns_testres.append(testres[0])

        self.test_independent()
        self.test_chain()
        self.test_chain_limits()
        self.test_descendant_limits()
        self.test_ancestor_limits()
        self.test_multiple_children()
        self.test_multiple_parents()
        self.test_conflicting()

    def chain_transaction(self, parent_txid, value, n=0, parent_locking_script=None):
        """Build a transaction that spends parent_txid.vout[n] and produces one output with amount=value.
        Return tuple (CTransaction object, raw hex, scriptPubKey of the output created).
        """
        node = self.nodes[0]
        inputs = [{"txid" : parent_txid, "vout" : n}]
        outputs = {self.address : value}
        rawtx = node.createrawtransaction(inputs, outputs)
        prevtxs = [{
            "txid": parent_txid,
            "vout": n,
            "scriptPubKey": parent_locking_script,
            "amount": value + Decimal("0.0001"),
        }] if parent_locking_script else None
        signedtx = node.signrawtransactionwithkey(hexstring=rawtx, privkeys=self.privkeys, prevtxs=prevtxs)
        tx = CTransaction()
        assert signedtx["complete"]
        tx.deserialize(BytesIO(hex_str_to_bytes(signedtx["hex"])))
        return (tx, signedtx["hex"], tx.vout[0].scriptPubKey.hex())

    def test_independent(self):
        self.log.info("Test multiple independent transactions in a package")
        node = self.nodes[0]
        assert_equal(self.independent_txns_testres, node.testmempoolaccept(rawtxs=self.independent_txns_hex))

        self.log.info("Test an otherwise valid package with an extra garbage tx appended")
        garbage_tx = node.createrawtransaction([{"txid": "00" * 32, "vout": 5}], {self.address: 1})
        tx = CTransaction()
        tx.deserialize(BytesIO(hex_str_to_bytes(garbage_tx)))
        testres_bad = node.testmempoolaccept(self.independent_txns_hex + [garbage_tx])
        testres_independent_ids = [{"txid": res["txid"], "wtxid": res["wtxid"]} for res in self.independent_txns_testres]
        assert_equal(testres_bad, testres_independent_ids + [
            {"txid": tx.rehash(), "wtxid": tx.getwtxid(), "allowed": False, "reject-reason": "missing-inputs"}
        ])

        self.log.info("Check testmempoolaccept tells us when some transactions completed validation successfully")
        coin = self.coins.pop()
        tx_bad_sig_hex = node.createrawtransaction([{"txid" : coin["txid"], "vout" : 0}],
                                           {self.address : coin["amount"] - Decimal("0.0001")})
        tx_bad_sig = CTransaction()
        tx_bad_sig.deserialize(BytesIO(hex_str_to_bytes(tx_bad_sig_hex)))
        testres_bad_sig = node.testmempoolaccept(self.independent_txns_hex + [tx_bad_sig_hex])
        assert_equal(testres_bad_sig, self.independent_txns_testres + [{
            "txid": tx_bad_sig.rehash(),
            "wtxid": tx_bad_sig.getwtxid(), "allowed": False,
            "reject-reason": "mandatory-script-verify-flag-failed (Operation not valid with the current stack size)"
        }])

        self.log.info("Check testmempoolaccept reports txns in packages that exceed max feerate")
        coin = self.coins.pop()
        tx_high_fee_raw = node.createrawtransaction([{"txid" : coin["txid"], "vout" : 0}],
                                           {self.address : coin["amount"] - Decimal("0.999")})
        tx_high_fee_signed = node.signrawtransactionwithkey(hexstring=tx_high_fee_raw, privkeys=self.privkeys)
        assert tx_high_fee_signed["complete"]
        tx_high_fee = CTransaction()
        tx_high_fee.deserialize(BytesIO(hex_str_to_bytes(tx_high_fee_signed["hex"])))
        testres_high_fee = node.testmempoolaccept([tx_high_fee_signed["hex"]])
        assert_equal(testres_high_fee, [
            {"txid": tx_high_fee.rehash(), "wtxid": tx_high_fee.getwtxid(), "allowed": False, "reject-reason": "max-fee-exceeded"}
        ])
        testres_package_high_fee = node.testmempoolaccept(self.independent_txns_hex + [tx_high_fee_signed["hex"]])
        assert_equal(testres_package_high_fee, self.independent_txns_testres + testres_high_fee)

    def test_chain(self):
        node = self.nodes[0]
        first_coin = self.coins.pop()

        # Chain of 25 transactions
        parent_locking_script = None
        txid = first_coin["txid"]
        chain_hex = []
        chain_txns = []
        value = first_coin["amount"]

        for _ in range(25):
            value -= Decimal("0.0001") # Deduct reasonable fee
            (tx, txhex, parent_locking_script) = self.chain_transaction(txid, value, 0, parent_locking_script)
            txid = tx.rehash()
            chain_hex.append(txhex)
            chain_txns.append(tx)

        self.log.info("Check that testmempoolaccept requires packages to be sorted by dependency")
        testres_multiple_unsorted = node.testmempoolaccept(rawtxs=chain_hex[::-1])
        assert_equal(testres_multiple_unsorted,
                     [{"txid": chain_txns[-1].rehash(), "wtxid": chain_txns[-1].getwtxid(), "allowed": False, "reject-reason": "missing-inputs"}]
                     + [{"txid": tx.rehash(), "wtxid": tx.getwtxid()} for tx in chain_txns[::-1]][1:])

        self.log.info("Testmempoolaccept a chain of 25 transactions")
        testres_multiple = node.testmempoolaccept(rawtxs=chain_hex)

        testres_single = []
        # Test accept and then submit each one individually, which should be identical to package test accept
        for rawtx in chain_hex:
            testres = node.testmempoolaccept([rawtx])
            testres_single.append(testres[0])
            # Submit the transaction now so its child should have no problem validating
            node.sendrawtransaction(rawtx)
        assert_equal(testres_single, testres_multiple)

        # Clean up by clearing the mempool
        node.generate(1)

    def test_chain_limits_helper(self, mempool_count, package_count):
        node = self.nodes[0]
        first_coin = self.coins.pop()
        parent_locking_script = None
        txid = first_coin["txid"]
        chain_hex = []
        chain_txns = []
        value = first_coin["amount"]

        for i in range(mempool_count + package_count):
            value -= Decimal("0.0001") # Deduct reasonable fee
            (tx, txhex, parent_locking_script) = self.chain_transaction(txid, value, 0, parent_locking_script)
            txid = tx.rehash()
            if i < mempool_count:
                node.sendrawtransaction(txhex)
                assert_equal(node.getrawmempool(verbose=True)[txid]["ancestorcount"], i + 1)
            else:
                chain_hex.append(txhex)
                chain_txns.append(tx)
        testres_too_long = node.testmempoolaccept(rawtxs=chain_hex)
        for txres in testres_too_long:
            assert_equal(txres["reject-reason"], "package-too-long-mempool-chain")

        # Clear mempool and check that the package passes now
        node.generate(1)
        assert all([res["allowed"] for res in node.testmempoolaccept(rawtxs=chain_hex)])

    def test_chain_limits(self):
        """Create chains from mempool and package transactions that are longer than 25,
        but only if both in-mempool and in-package transactions are considered together.
        These should not return too-long-mempool-chain (individual transactions don't have
        too many in-mempool ancesotrs) but package-too-long-mempool-chain.
        This checks that both mempool and in-package transactions are taken into account when
        calculating ancestors/descendant limits.
        """
        self.log.info("Check that in-package ancestors count for mempool ancestor limits")

        # 24 transactions in the mempool and 2 in the package. The parent in the package has
        # 24 in-mempool ancestors and 1 in-package descendant. The child has 0 direct parents
        # in the mempool, but 25 in-mempool and in-package ancestors in total.
        self.test_chain_limits_helper(24, 2)
        # 2 transactions in the mempool and 24 in the package.
        self.test_chain_limits_helper(2, 24)
        # 13 transactions in the mempool and 13 in the package.
        self.test_chain_limits_helper(13, 13)

    def test_descendant_limits(self):
        """Create an 'A' shaped package with 25 transactions in the mempool and 2 in the package:
                    M1
                   ^  ^
                 M2a  M2b
                .       .
               .         .
              .           .
             M11a          ^
            ^              M12b
           ^                 ^
          Pa                  Pb
        The top ancestor in the package exceeds descendant limits but only if the in-mempool and in-package
        descendants are all considered together (24 including in-mempool descendants and 26 including both
        package transactions).
        """
        node = self.nodes[0]
        self.log.info("Check that in-mempool and in-package descendants are calculated properly in packages")
        # Top parent in mempool, M1
        first_coin = self.coins.pop()
        parent_value = (first_coin["amount"] - Decimal("0.0002")) / 2 # Deduct reasonable fee and make 2 outputs
        inputs = [{"txid" : first_coin["txid"], "vout" : 0}]
        outputs = [{self.address : parent_value}, {ADDRESS_BCRT1_P2WSH_OP_TRUE : parent_value}]
        rawtx = node.createrawtransaction(inputs, outputs)

        parent_signed = node.signrawtransactionwithkey(hexstring=rawtx, privkeys=self.privkeys)
        parent_tx = CTransaction()
        assert parent_signed["complete"]
        parent_tx.deserialize(BytesIO(hex_str_to_bytes(parent_signed["hex"])))
        parent_txid = parent_tx.rehash()
        node.sendrawtransaction(parent_signed["hex"])

        package_hex = []

        # Chain A
        parent_locking_script = parent_tx.vout[0].scriptPubKey.hex()
        value = parent_value
        txid = parent_txid
        for i in range(12):
            value -= Decimal("0.0001") # deduct reasonable fee
            (tx, txhex, parent_locking_script) = self.chain_transaction(txid, value, 0, parent_locking_script)
            txid = tx.rehash()
            if i < 11: # M2a... M11a
                node.sendrawtransaction(txhex)
            else: # Pa
                package_hex.append(txhex)

        # Chain B
        value = parent_value - Decimal("0.0001")
        rawtx_b = node.createrawtransaction([{"txid" : parent_txid, "vout" : 1}], {self.address : value})
        tx_child_b = CTransaction()
        tx_child_b.deserialize(BytesIO(hex_str_to_bytes(rawtx_b)))
        tx_child_b.wit.vtxinwit = [CTxInWitness()]
        tx_child_b.wit.vtxinwit[0].scriptWitness.stack = [CScript([OP_TRUE])]
        tx_child_b_hex = tx_child_b.serialize().hex()
        node.sendrawtransaction(tx_child_b_hex)
        parent_locking_script = tx_child_b.vout[0].scriptPubKey.hex()
        txid = tx_child_b.rehash()
        for i in range(12):
            value -= Decimal("0.0001") # Deduct reasonable fee
            (tx, txhex, parent_locking_script) = self.chain_transaction(txid, value, 0, parent_locking_script)
            txid = tx.rehash()
            if i < 11: # M3b... M12b
                node.sendrawtransaction(txhex)
            else: # Pb
                package_hex.append(txhex)

        testres_too_long = node.testmempoolaccept(rawtxs=package_hex)
        for txres in testres_too_long:
            assert_equal(txres["reject-reason"], "package-too-long-mempool-chain")

        # Clear mempool and check that the package passes now
        node.generate(1)
        assert all([res["allowed"] for res in node.testmempoolaccept(rawtxs=package_hex)])

    def create_child_with_parents(self, parents_tx, values, locking_scripts):
        """Creates a transaction that spends the first output of each parent in parents_tx."""
        num_parents = len(parents_tx)
        total_value = sum(values)
        inputs = [{"txid" : tx.rehash(), "vout" : 0} for tx in parents_tx]
        outputs = {self.address : total_value - num_parents * Decimal("0.0001")}
        rawtx_child = self.nodes[0].createrawtransaction(inputs, outputs)
        prevtxs = []
        for i in range(num_parents):
            prevtxs.append({"txid": parents_tx[i].rehash(), "vout" : 0, "scriptPubKey" : locking_scripts[i], "amount" : values[i]})
        signedtx_child = self.nodes[0].signrawtransactionwithkey(hexstring=rawtx_child, privkeys=self.privkeys, prevtxs=prevtxs)
        assert signedtx_child["complete"]
        return signedtx_child["hex"]

    def test_ancestor_limits(self):
        """Create a 'V' shaped chain with 24 transactions in the mempool and 3 in the package:
        M1a                    M1b
         ^                     ^
          M2a                M2b
           .                 .
            .               .
             .             .
             M12a        M12b
               ^         ^
                Pa     Pb
                 ^    ^
                   Pc
        The lowest descendant, Pc, exceeds ancestor limits, but only if the in-mempool
        and in-package ancestors are all considered together.
        """
        node = self.nodes[0]
        package_hex = []
        parents_tx = []
        values = []
        parent_locking_scripts = []

        self.log.info("Check that in-mempool and in-package ancestors are calculated properly for package transactions.")

        # Two chains of 13 transactions each
        for _ in range(2):
            parent_locking_script = None
            top_coin = self.coins.pop()
            txid = top_coin["txid"]
            value = top_coin["amount"]
            for i in range(13):
                value -= Decimal("0.0001") # Deduct reasonable fee
                (tx, txhex, parent_locking_script) = self.chain_transaction(txid, value, 0, parent_locking_script)
                txid = tx.rehash()
                if i < 12:
                    node.sendrawtransaction(txhex)
                else: # Save the 13th transaction for the package
                    package_hex.append(txhex)
                    parents_tx.append(tx)
                    parent_locking_scripts.append(parent_locking_script)
                    values.append(value)

        # Child Pc
        child_hex = self.create_child_with_parents(parents_tx, values, parent_locking_scripts)
        package_hex.append(child_hex)

        testres_too_long = node.testmempoolaccept(rawtxs=package_hex)
        for txres in testres_too_long:
            assert_equal(txres["reject-reason"], "package-too-long-mempool-chain")

        # Clear mempool and check that the package passes now
        node.generate(1)
        assert all([res["allowed"] for res in node.testmempoolaccept(rawtxs=package_hex)])

    def test_multiple_children(self):
        node = self.nodes[0]

        self.log.info("Testmempoolaccept a package in which a transaction has two children within the package")
        first_coin = self.coins.pop()
        value = (first_coin["amount"] - Decimal("0.0002")) / 2 # Deduct reasonable fee and make 2 outputs
        inputs = [{"txid" : first_coin["txid"], "vout" : 0}]
        outputs = [{self.address : value}, {ADDRESS_BCRT1_P2WSH_OP_TRUE : value}]
        rawtx = node.createrawtransaction(inputs, outputs)

        parent_signed = node.signrawtransactionwithkey(hexstring=rawtx, privkeys=self.privkeys)
        parent_tx = CTransaction()
        assert parent_signed["complete"]
        parent_tx.deserialize(BytesIO(hex_str_to_bytes(parent_signed["hex"])))
        parent_txid = parent_tx.rehash()
        assert node.testmempoolaccept([parent_signed["hex"]])[0]["allowed"]

        parent_locking_script_a = parent_tx.vout[0].scriptPubKey.hex()
        child_value = value - Decimal("0.0001")

        # Child A
        (_, tx_child_a_hex, _) = self.chain_transaction(parent_txid, child_value, 0, parent_locking_script_a)
        assert not node.testmempoolaccept([tx_child_a_hex])[0]["allowed"]

        # Child B
        rawtx_b = node.createrawtransaction([{"txid" : parent_txid, "vout" : 1}], {self.address : child_value})
        tx_child_b = CTransaction()
        tx_child_b.deserialize(BytesIO(hex_str_to_bytes(rawtx_b)))
        tx_child_b.wit.vtxinwit = [CTxInWitness()]
        tx_child_b.wit.vtxinwit[0].scriptWitness.stack = [CScript([OP_TRUE])]
        tx_child_b_hex = tx_child_b.serialize().hex()
        assert not node.testmempoolaccept([tx_child_b_hex])[0]["allowed"]

        self.log.info("Testmempoolaccept with entire package, should work with children in either order")
        testres_multiple_ab = node.testmempoolaccept(rawtxs=[parent_signed["hex"], tx_child_a_hex, tx_child_b_hex])
        testres_multiple_ba = node.testmempoolaccept(rawtxs=[parent_signed["hex"], tx_child_b_hex, tx_child_a_hex])
        assert all([testres["allowed"] for testres in testres_multiple_ab + testres_multiple_ba])

        testres_single = []
        # Test accept and then submit each one individually, which should be identical to package testaccept
        for rawtx in [parent_signed["hex"], tx_child_a_hex, tx_child_b_hex]:
            testres = node.testmempoolaccept([rawtx])
            testres_single.append(testres[0])
            # Submit the transaction now so its child should have no problem validating
            node.sendrawtransaction(rawtx)
        assert_equal(testres_single, testres_multiple_ab)

    def test_multiple_parents(self):
        node = self.nodes[0]

        self.log.info("Testmempoolaccept a package in which a transaction has multiple parents within the package")
        for num_parents in [2, 10, 24]:
            # Test a package with num_parents parents and 1 child transaction.
            package_hex = []
            parents_tx = []
            values = []
            parent_locking_scripts = []
            for _ in range(num_parents):
                parent_coin = self.coins.pop()
                value = parent_coin["amount"] - Decimal("0.0001") # Deduct reasonable fee
                (tx, txhex, parent_locking_script) = self.chain_transaction(parent_coin["txid"], value)
                package_hex.append(txhex)
                parents_tx.append(tx)
                values.append(value)
                parent_locking_scripts.append(parent_locking_script)
            child_hex = self.create_child_with_parents(parents_tx, values, parent_locking_scripts)
            # Package accept should work with the parents in any order (as long as parents come before child)
            random.shuffle(package_hex)
            package_hex.append(child_hex)
            testres_multiple = node.testmempoolaccept(rawtxs=package_hex)
            assert all([testres["allowed"] for testres in testres_multiple])

            testres_single = []
            # Test accept and then submit each one individually, which should be identical to package testaccept
            for rawtx in package_hex:
                testres_single.append(node.testmempoolaccept([rawtx])[0])
                # Submit the transaction now so its child should have no problem validating
                node.sendrawtransaction(rawtx)

    def test_conflicting(self):
        node = self.nodes[0]
        prevtx = self.coins.pop()
        inputs = [{"txid" : prevtx["txid"], "vout" : 0}]
        output1 = {node.get_deterministic_priv_key().address: 50 - 0.00125}
        output2 = {ADDRESS_BCRT1_P2WSH_OP_TRUE: 50 - 0.00125}

        # tx1 and tx2 share the same inputs
        rawtx1 = node.createrawtransaction(inputs, output1)
        rawtx2 = node.createrawtransaction(inputs, output2)
        signedtx1 = node.signrawtransactionwithkey(hexstring=rawtx1, privkeys=self.privkeys)
        signedtx2 = node.signrawtransactionwithkey(hexstring=rawtx2, privkeys=self.privkeys)
        tx1 = CTransaction()
        tx1.deserialize(BytesIO(hex_str_to_bytes(signedtx1["hex"])))
        tx2 = CTransaction()
        tx2.deserialize(BytesIO(hex_str_to_bytes(signedtx2["hex"])))
        assert signedtx1["complete"]
        assert signedtx2["complete"]

        # Ensure tx1 and tx2 are valid by themselves
        assert node.testmempoolaccept([signedtx1["hex"]])[0]["allowed"]
        assert node.testmempoolaccept([signedtx2["hex"]])[0]["allowed"]

        self.log.info("Test duplicate transactions in the same package")
        testres = node.testmempoolaccept([signedtx1["hex"], signedtx1["hex"]])
        assert_equal(testres, [
            {"txid": tx1.rehash(), "wtxid": tx1.getwtxid(), "allowed": False, "reject-reason": "conflict-in-package"},
            {"txid": tx1.rehash(), "wtxid": tx1.getwtxid(), "allowed": False, "reject-reason": "conflict-in-package"}
        ])

        self.log.info("Test conflicting transactions in the same package")
        testres = node.testmempoolaccept([signedtx1["hex"], signedtx2["hex"]])
        assert_equal(testres, [
            {"txid": tx1.rehash(), "wtxid": tx1.getwtxid()},
            {"txid": tx2.rehash(), "wtxid": tx2.getwtxid(), "allowed": False, "reject-reason": "conflict-in-package"}
        ])


if __name__ == "__main__":
    RPCPackagesTest().main()
