#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test package relay messages"""

import time

from test_framework.messages import (
    msg_getpkgtxns,
    msg_pkgtxns,
    msg_sendpackages,
    msg_verack,
    msg_wtxidrelay,
    MSG_WTX,
)
from test_framework.p2p import (
    p2p_lock,
    P2PInterface,
    P2PDataStore,
    UNCONDITIONAL_RELAY_DELAY,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import (
    COIN,
    DEFAULT_FEE,
    MiniWallet,
)

class PeerPackageRelayer(P2PDataStore):
    def __init__(self):
        super().__init__()
        self.pkgtxns_received = []
        self.txns_received = []

    def on_pkgtxns(self, message):
        super().on_pkgtxns(message)
        self.pkgtxns_received.append(message)

    def on_tx(self, message):
        super().on_tx(message)
        self.txns_received.append(message.tx)

class PackageRelayer(P2PInterface):
    def __init__(self, send_sendpackages=True, send_wtxidrelay=True):
        super().__init__()
        # List versions of each sendpackages received
        self._sendpackages_received = []
        self._send_sendpackages = send_sendpackages
        self._send_wtxidrelay = send_wtxidrelay

    @property
    def sendpackages_received(self):
        with p2p_lock:
            return self._sendpackages_received

    def on_version(self, message):
        if self._send_wtxidrelay:
            self.send_message(msg_wtxidrelay())
        if self._send_sendpackages:
            self.send_message(msg_sendpackages())
        self.send_message(msg_verack())
        self.nServices = message.nServices

    def on_sendpackages(self, message):
        self._sendpackages_received.append(message.version)

class PackageRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-packagerelay=1"]]

    def create_package(self):
        """Create package with these transactions:
        - Parent 1: version=3, fee=default
        - Parent 2: version=3, fee=0
        - Child:    version=3, fee=high
        """
        parent1 = self.wallet.create_self_transfer(version=3)
        parent2 = self.wallet.create_self_transfer(fee_rate=0, fee=0, version=3)
        child = self.wallet.create_self_transfer_multi(
            utxos_to_spend=[parent1['new_utxo'], parent2["new_utxo"]],
            num_outputs=1,
            fee_per_output=int(DEFAULT_FEE * COIN),
            version=3
        )
        package_hex = [parent1["hex"], parent2["hex"], child["hex"]]
        package_txns = [parent1["tx"], parent2["tx"], child["tx"]]
        package_wtxids = [tx.getwtxid() for tx in package_txns]
        return package_hex, package_txns, package_wtxids

    def test_sendpackages(self):
        self.log.info("Test sendpackages during version handshake")
        node = self.nodes[0]
        peer_normal = node.add_p2p_connection(PackageRelayer())
        assert_equal(node.getpeerinfo()[0]["bytesrecv_per_msg"]["sendpackages"], 28)
        assert_equal(node.getpeerinfo()[0]["bytessent_per_msg"]["sendpackages"], 28)
        assert node.getpeerinfo()[0]["relaytxpackages"]
        assert_equal(peer_normal.sendpackages_received, [0])
        node.disconnect_p2ps()

        self.log.info("Test sendpackages without wtxid relay")
        node = self.nodes[0]
        peer_no_wtxidrelay = node.add_p2p_connection(PackageRelayer(send_wtxidrelay=False))
        assert_equal(node.getpeerinfo()[0]["bytesrecv_per_msg"]["sendpackages"], 28)
        assert_equal(node.getpeerinfo()[0]["bytessent_per_msg"]["sendpackages"], 28)
        assert_equal(peer_no_wtxidrelay.sendpackages_received, [0])
        assert not node.getpeerinfo()[0]["relaytxpackages"]
        node.disconnect_p2ps()

        self.log.info("Test sendpackages is sent even so")
        node = self.nodes[0]
        peer_no_sendpackages = node.add_p2p_connection(PackageRelayer(send_sendpackages=False))
        # Sendpackages should still be sent
        assert_equal(node.getpeerinfo()[0]["bytessent_per_msg"]["sendpackages"], 28)
        assert "sendpackages" not in node.getpeerinfo()[0]["bytesrecv_per_msg"]
        assert_equal(peer_no_sendpackages.sendpackages_received, [0])
        assert not node.getpeerinfo()[0]["relaytxpackages"]
        node.disconnect_p2ps()

        self.log.info("Test disconnection if sendpackages is sent after version handshake")
        peer_sendpackages_after_verack = node.add_p2p_connection(P2PInterface())
        peer_sendpackages_after_verack.send_message(msg_sendpackages())
        peer_sendpackages_after_verack.wait_for_disconnect()

    def test_pkgtxns(self):
        node = self.nodes[0]
        package_hex, package_txns, package_wtxids = self.create_package()
        node.submitpackage(package_hex)
        for tx in package_txns:
            assert node.getmempoolentry(tx.rehash())
        node.setmocktime(int(time.time() + UNCONDITIONAL_RELAY_DELAY))

        peer_requester = node.add_p2p_connection(PackageRelayer())
        getpkgtxns_request = msg_getpkgtxns([int(wtxid, 16) for wtxid in package_wtxids])
        peer_requester.send_and_ping(getpkgtxns_request)
        assert_equal(node.getpeerinfo()[0]["bytesrecv_per_msg"]["getpkgtxns"], 25 + len(package_txns) * 32)
        assert_equal(node.getpeerinfo()[0]["bytessent_per_msg"]["pkgtxns"], 25 + sum(len(tx.serialize()) for tx in package_txns))

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)

        self.test_sendpackages()
        self.test_pkgtxns()


if __name__ == '__main__':
    PackageRelayTest().main()
