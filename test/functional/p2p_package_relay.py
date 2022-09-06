#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test package relay messages"""

from test_framework.messages import (
    msg_sendpackages,
    msg_verack,
    msg_wtxidrelay,
)
from test_framework.p2p import (
    p2p_lock,
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

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

    def run_test(self):
        self.test_sendpackages()

if __name__ == '__main__':
    PackageRelayTest().main()
