#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test package relay messages"""

import time

from test_framework.messages import (
    CInv,
    MSG_ANCPKGINFO,
    MSG_WTX,
    msg_ancpkginfo,
    msg_getdata,
    msg_sendpackages,
    msg_verack,
    msg_wtxidrelay,
)
from test_framework.p2p import (
    p2p_lock,
    P2PTxInvStore,
    UNCONDITIONAL_RELAY_DELAY,
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

def cleanup(func):
    def wrapper(self):
        try:
            func(self)
        finally:
            # Clear mempool
            self.generate(self.nodes[0], 1)
            self.nodes[0].disconnect_p2ps()
            self.nodes[0].setmocktime(self.starttime)
    return wrapper

class PackageRelayer(P2PTxInvStore):
    def __init__(self, send_sendpackages=True, send_wtxidrelay=True):
        super().__init__()
        # List versions of each sendpackages received
        self._sendpackages_received = []
        self._send_sendpackages = send_sendpackages
        self._send_wtxidrelay = send_wtxidrelay
        self._ancpkginfo_received = []
        self._tx_received = []

    @property
    def sendpackages_received(self):
        with p2p_lock:
            return self._sendpackages_received

    @property
    def ancpkginfo_received(self):
        with p2p_lock:
            return self._ancpkginfo_received

    @property
    def tx_received(self):
        with p2p_lock:
            return self._tx_received

    def on_version(self, message):
        if self._send_wtxidrelay:
            self.send_message(msg_wtxidrelay())
        if self._send_sendpackages:
            self.send_message(msg_sendpackages())
        self.send_message(msg_verack())
        self.nServices = message.nServices

    def on_sendpackages(self, message):
        self._sendpackages_received.append(message.version)

    def on_ancpkginfo(self, message):
        self._ancpkginfo_received.append(message.wtxids)

    def on_tx(self, message):
        self._tx_received.append(message)

class PackageRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-packagerelay=1"]]
        self.starttime = int(time.time())
        self.mocktime = self.starttime

    def create_package(self):
        """Create package with these transactions:
        - Parent 1: fee=default
        - Parent 2: fee=0
        - Child:    fee=high
        """
        parent1 = self.wallet.create_self_transfer()
        parent2 = self.wallet.create_self_transfer(fee_rate=0, fee=0)
        child = self.wallet.create_self_transfer_multi(
            utxos_to_spend=[parent1['new_utxo'], parent2["new_utxo"]],
            num_outputs=1,
            fee_per_output=int(DEFAULT_FEE * COIN)
        )
        package_hex = [parent1["hex"], parent2["hex"], child["hex"]]
        package_txns = [parent1["tx"], parent2["tx"], child["tx"]]
        package_wtxids = [tx.getwtxid() for tx in package_txns]
        return package_hex, package_txns, package_wtxids

    def fastforward(self, seconds):
        """Convenience helper function to fast-forward, so we don't need to keep track of the
        starting time when we call setmocktime."""
        self.mocktime += seconds
        self.nodes[0].setmocktime(self.mocktime)

    @cleanup
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
        peer_sendpackages_after_verack = node.add_p2p_connection(P2PTxInvStore())
        peer_sendpackages_after_verack.send_message(msg_sendpackages())
        peer_sendpackages_after_verack.wait_for_disconnect()

    @cleanup
    def test_ancpkginfo_requests(self):
        node = self.nodes[0]
        peer_info_requester = node.add_p2p_connection(PackageRelayer())
        package_hex, package_txns, package_wtxids = self.create_package()
        node.submitpackage(package_hex)

        assert_equal(node.getmempoolentry(package_txns[-1].rehash())["ancestorcount"], 3)

        self.log.info("Test that ancpkginfo requests for unannounced transactions are ignored until UNCONDITIONAL_RELAY_DELAY elapses")
        tx_request = msg_getdata([CInv(t=MSG_WTX, h=int(package_wtxids[-1], 16))])
        peer_info_requester.send_and_ping(tx_request)
        assert not peer_info_requester.tx_received
        child_ancpkginfo_request = msg_getdata([CInv(t=MSG_ANCPKGINFO, h=int(package_wtxids[-1], 16))])
        peer_info_requester.send_and_ping(child_ancpkginfo_request)
        assert not peer_info_requester.ancpkginfo_received

        self.fastforward(UNCONDITIONAL_RELAY_DELAY)
        peer_info_requester.send_and_ping(tx_request)
        assert_greater_than_or_equal(len(peer_info_requester.tx_received), 1)

        self.log.info("Test that node responds to ancpkginfo request with ancestor package wtxids")
        peer_info_requester.send_and_ping(child_ancpkginfo_request)
        assert_greater_than_or_equal(len(peer_info_requester.ancpkginfo_received), 1)
        last_ancpkginfo_received = peer_info_requester.ancpkginfo_received.pop()
        assert all([int(wtxid, 16) in last_ancpkginfo_received for wtxid in package_wtxids])
        # When a tx has no unconfirmed ancestors, ancpkginfo just contains its own wtxid
        for i in range(len(package_txns) - 1):
            parent_ancpkginfo_request = msg_getdata([CInv(t=MSG_ANCPKGINFO, h=int(package_wtxids[i], 16))])
            peer_info_requester.send_and_ping(parent_ancpkginfo_request)
            assert_equal([int(package_wtxids[i], 16)], peer_info_requester.ancpkginfo_received.pop())

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)

        self.test_sendpackages()
        self.test_ancpkginfo_requests()


if __name__ == '__main__':
    PackageRelayTest().main()
