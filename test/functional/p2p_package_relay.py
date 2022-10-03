#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test package relay messages and net processing logic on a singular node.
This has its own test because it requires lots of setmocktimeing and that's hard to coordinate
across multiple nodes.
"""

from decimal import Decimal
import time

from test_framework.messages import (
    CInv,
    MSG_ANCPKGINFO,
    msg_ancpkginfo,
    msg_feefilter,
    msg_getdata,
    msg_getpkgtxns,
    msg_inv,
    msg_pkgtxns,
    msg_sendpackages,
    msg_tx,
    msg_verack,
    msg_wtxidrelay,
    MSG_WTX,
)
from test_framework.p2p import (
    NONPREF_PEER_TX_DELAY,
    p2p_lock,
    P2PTxInvStore,
    P2PDataStore,
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

class PackageRelayer(P2PTxInvStore):
    def __init__(self, send_sendpackages=True, send_wtxidrelay=True):
        super().__init__()
        # List versions of each sendpackages received
        self._sendpackages_received = []
        self._send_sendpackages = send_sendpackages
        self._send_wtxidrelay = send_wtxidrelay
        self._ancpkginfo_received = []
        self._getdata_received = []
        self._tx_received = []
        self._getpkgtxns_received = []
        self._pkgtxns_received = []

    @property
    def sendpackages_received(self):
        with p2p_lock:
            return self._sendpackages_received

    @property
    def ancpkginfo_received(self):
        with p2p_lock:
            return self._ancpkginfo_received

    @property
    def getdata_received(self):
        with p2p_lock:
            return self._getdata_received

    @property
    def tx_received(self):
        with p2p_lock:
            return self._tx_received

    @property
    def getpkgtxns_received(self):
        with p2p_lock:
            return self._getpkgtxns_received

    @property
    def pkgtxns_received(self):
        with p2p_lock:
            return self._pkgtxns_received

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

    def on_getdata(self, message):
        self._getdata_received.append(message)

    def on_tx(self, message):
        self._tx_received.append(message)

    def on_getpkgtxns(self, message):
        self._getpkgtxns_received.append(message)

    def on_pkgtxns(self, message):
        self._pkgtxns_received.append(message)

    def wait_for_getpkgtxns(self, expected_wtxids, timeout=60):
        def test_function():
            return self.last_message.get("getpkgtxns") and \
                all([int(wtxid, 16) in self.last_message["getpkgtxns"].hashes for wtxid in expected_wtxids])
        self.wait_until(test_function, timeout=timeout)

    def relay_package(self, node, package_txns, package_wtxids):
        node.setmocktime(int(time.time()))
        # Relay (orphan) child
        orphan_tx = package_txns[-1]
        orphan_wtxid = package_wtxids[-1]
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))
        self.send_and_ping(msg_inv([orphan_inv]))
        node.setmocktime(int(time.time()) + 25)
        assert_equal(self.getdata_received.pop().inv, [orphan_inv])
        self.send_and_ping(msg_tx(orphan_tx))
        # Relay package info
        node.setmocktime(int(time.time()) + 30)
        last_getdata_received = self.getdata_received.pop()
        assert_equal(last_getdata_received.inv, [CInv(MSG_ANCPKGINFO, int(orphan_wtxid, 16))])
        self.send_and_ping(msg_ancpkginfo([int(wtxid, 16) for wtxid in package_wtxids]))
        node.setmocktime(int(time.time()) + 35)
        # Relay package tx data
        last_getpkgtxns_received = self.getpkgtxns_received.pop()
        assert all([int(wtxid, 16) in last_getpkgtxns_received.hashes for wtxid in package_wtxids])
        self.send_and_ping(msg_pkgtxns(package_txns))
        assert all([tx.rehash() in node.getrawmempool() for tx in package_txns])


class PackageProcessingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-packagerelay=1"]]

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
            fee_per_output=int(DEFAULT_FEE * COIN),
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
        peer_sendpackages_after_verack = node.add_p2p_connection(P2PTxInvStore())
        peer_sendpackages_after_verack.send_message(msg_sendpackages())
        peer_sendpackages_after_verack.wait_for_disconnect()

    def test_pkgtxns(self):
        self.log.info("Test nodes respond to getpkgtxns with pkgtxns")
        node = self.nodes[0]
        node.setmocktime(int(time.time()))
        package_hex, package_txns, package_wtxids = self.create_package()
        peer_originator = node.add_p2p_connection(PackageRelayer())
        pkgtxns_message = msg_pkgtxns(package_txns)
        peer_originator.send_and_ping(pkgtxns_message)
        assert_equal(node.getpeerinfo()[0]["bytesrecv_per_msg"]["pkgtxns"], 25 + sum(len(tx.serialize()) for tx in package_txns))
        for tx in package_txns:
            assert node.getmempoolentry(tx.rehash())
        node.setmocktime(int(time.time() + UNCONDITIONAL_RELAY_DELAY))

        peer_requester = node.add_p2p_connection(PackageRelayer())
        getpkgtxns_request = msg_getpkgtxns([int(wtxid, 16) for wtxid in package_wtxids])
        peer_requester.send_and_ping(getpkgtxns_request)
        # FIXME: make sure the response is correct. assert_equal doesn't work.
        assert_equal(node.getpeerinfo()[1]["bytesrecv_per_msg"]["getpkgtxns"], 25 + len(package_txns) * 32)
        assert_equal(node.getpeerinfo()[1]["bytessent_per_msg"]["pkgtxns"], 25 + sum(len(tx.serialize()) for tx in package_txns))
        node.disconnect_p2ps()
        self.generate(node, 1, sync_fun=self.no_op)

    def test_ancpkginfo_requests(self):
        node = self.nodes[0]
        peer_info_requester = node.add_p2p_connection(PackageRelayer())
        node.setmocktime(int(time.time()))
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

        node.setmocktime(int(time.time() + UNCONDITIONAL_RELAY_DELAY + 60))
        peer_info_requester.send_and_ping(tx_request)
        peer_info_requester.wait_for_tx(package_txns[-1].rehash())

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
        node.disconnect_p2ps()
        self.generate(node, 1, sync_fun=self.no_op)

    def test_package_data_requests(self):
        # TODO: once unsolicited ancpkginfo are disallowed, need to have the node give special
        # permissions to these peers
        node = self.nodes[0]
        self.log.info("Test that node uses ancpkginfo to send getpkgtxns request")
        node.setmocktime(int(time.time()))
        peer_package_relayer = node.add_p2p_connection(PackageRelayer())
        _, package_txns, package_wtxids = self.create_package()
        unsolicited_packageinfo = msg_ancpkginfo([int(wtxid, 16) for wtxid in package_wtxids]) 
        peer_package_relayer.send_and_ping(unsolicited_packageinfo)
        self.log.info("Test that no request is sent until tx request delay elapses")
        assert not len(peer_package_relayer.getpkgtxns_received)
        node.setmocktime(int(time.time() + NONPREF_PEER_TX_DELAY + 10))
        peer_package_relayer.sync_with_ping()
        assert_equal(node.getpeerinfo()[0]["bytesrecv_per_msg"]["ancpkginfo"], 25 + len(package_txns) * 32)
        # assert_equal(node.getpeerinfo()[0]["bytessent_per_msg"]["getpkgtxns"], 25 + len(package_txns) * 32)
        # last_getpkgtxns_received = peer_package_relayer.getpkgtxns_received.pop()
        # assert all([int(wtxid, 16) in last_getpkgtxns_received.hashes for wtxid in package_wtxids])
        peer_package_relayer.wait_for_getpkgtxns(package_wtxids)
        node.disconnect_p2ps()

        self.log.info("Test that node prefers to download package txns from outbound over inbound peers")
        node.setmocktime(int(time.time()))
        peer_inbound = node.add_p2p_connection(PackageRelayer())
        peer_outbound = node.add_outbound_p2p_connection(PackageRelayer(), p2p_idx=1, connection_type="outbound-full-relay")
        _, _, package_wtxids1 = self.create_package()
        unsolicited_ancpkginfo = msg_ancpkginfo([int(wtxid, 16) for wtxid in package_wtxids1])
        peer_inbound.send_and_ping(unsolicited_ancpkginfo)
        peer_outbound.send_and_ping(unsolicited_ancpkginfo)
        peer_outbound.sync_with_ping()
        assert not len(peer_inbound.getpkgtxns_received)
        last_getpkgtxns_received_outbound = peer_outbound.getpkgtxns_received.pop()
        assert all([int(wtxid, 16) in last_getpkgtxns_received_outbound.hashes for wtxid in package_wtxids1])
        self.log.info("Test that, after the request expires, the node will try to getpkgtxns from other peers that announced it")
        # Note that the outbound peer has not responded. After that request expires, the node should
        # request from the inbound peer, and not re-request from the outbound peer.
        node.setmocktime(int(time.time()) + 90)
        peer_inbound.sync_with_ping()
        peer_outbound.sync_with_ping()
        assert not len(peer_outbound.getpkgtxns_received)
        # last_getpkgtxns_received_inbound = peer_inbound.getpkgtxns_received.pop()
        # assert all([int(wtxid, 16) in last_getpkgtxns_received_inbound.hashes for wtxid in package_wtxids1])
        peer_inbound.wait_for_getpkgtxns(package_wtxids1, timeout=90)

        self.log.info("Test that, when package txns are announced also individually, the node only requests the tx from one at a time")
        node.setmocktime(int(time.time()))
        _, package_txns2, package_wtxids2 = self.create_package()
        unsolicited_ancpkginfo = msg_ancpkginfo([int(wtxid, 16) for wtxid in package_wtxids2])
        parent_tx_inv = msg_inv([CInv(t=MSG_WTX, h=int(package_wtxids2[0], 16))])
        peer_inbound.send_and_ping(unsolicited_ancpkginfo)
        peer_outbound.send_and_ping(parent_tx_inv)
        assert_equal(peer_outbound.getdata_received.pop().inv, parent_tx_inv.inv)
        parent_tx_message = msg_tx(package_txns2[0])
        self.log.info("Test that, after receiving a tx, the node won't request the tx again in getpkgtxns")
        peer_outbound.send_and_ping(parent_tx_message)
        node.setmocktime(int(time.time()) + 60)
        peer_inbound.sync_with_ping()
        peer_outbound.sync_with_ping()
        last_getpkgtxns_received_inbound = peer_inbound.getpkgtxns_received.pop()
        assert_equal(len(last_getpkgtxns_received_inbound.hashes), len(package_txns2) - 1)
        assert all([int(wtxid, 16) in last_getpkgtxns_received_inbound.hashes for wtxid in package_wtxids2[1:]])
        node.disconnect_p2ps()
        self.generate(node, 1, sync_fun=self.no_op)

    def test_receiver_initiated(self):
        self.log.info("Test that nodes deal with orphans by requesting ancestor package info")
        node = self.nodes[0]
        peer_package_relayer = node.add_outbound_p2p_connection(PackageRelayer(), p2p_idx=2, connection_type="outbound-full-relay")
        package_hex, package_txns, package_wtxids = self.create_package()
        orphan_tx = package_txns[-1]
        orphan_wtxid = package_wtxids[-1]
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))
        peer_package_relayer.send_and_ping(msg_inv([orphan_inv]))
        assert_equal(peer_package_relayer.getdata_received.pop().inv, [orphan_inv])
        peer_package_relayer.send_and_ping(msg_tx(orphan_tx))
        last_getdata_received = peer_package_relayer.getdata_received.pop()
        assert_equal(last_getdata_received.inv, [CInv(MSG_ANCPKGINFO, int(orphan_wtxid, 16))])
        peer_package_relayer.send_and_ping(msg_ancpkginfo([int(wtxid, 16) for wtxid in package_wtxids]))
        last_getpkgtxns_received = peer_package_relayer.getpkgtxns_received.pop()
        assert all([int(wtxid, 16) in last_getpkgtxns_received.hashes for wtxid in package_wtxids])
        peer_package_relayer.send_and_ping(msg_pkgtxns(package_txns))
        self.wait_until(lambda: all([tx.rehash() in node.getrawmempool() for tx in package_txns]))
        node.disconnect_p2ps()
        self.generate(node, 1, sync_fun=self.no_op)

    def test_package_tx_announcements(self):
        self.log.info("Test end-to-end package relay logic")
        node = self.nodes[0]
        peer_package_relayer_outbound = node.add_outbound_p2p_connection(PackageRelayer(), p2p_idx=3, connection_type="outbound-full-relay")
        peer_package_originator = node.add_outbound_p2p_connection(PackageRelayer(), p2p_idx=4, connection_type="outbound-full-relay")
        peer_package_relayer_inbound = node.add_p2p_connection(PackageRelayer())
        peer_normal = node.add_p2p_connection(P2PTxInvStore())
        assert_equal(len(node.getpeerinfo()), 4)
        # send 1 sat/vbyte fee filter
        for peer in node.p2ps:
            peer.send_and_ping(msg_feefilter(1000))

        node.setmocktime(int(time.time()))
        assert node.getpeerinfo()[0]["relaytxpackages"]
        assert node.getpeerinfo()[1]["relaytxpackages"]
        assert node.getpeerinfo()[2]["relaytxpackages"]
        assert not node.getpeerinfo()[3]["relaytxpackages"]

        self.log.info("Test packages through rpc")
        # package that is submitted through p2p
        package_hex, package_txns, package_wtxids = self.create_package()
        peer_package_originator.relay_package(node, package_txns, package_wtxids)
        assert all([tx.rehash() in node.getrawmempool() for tx in package_txns])

        self.log.info("Test that the high-feerate parent and child are announced, but not the 0-fee parent")
        node.setmocktime(int(time.time()) + UNCONDITIONAL_RELAY_DELAY + 160)
        parent_high_wtxid, parent_low_wtxid, orphan_wtxid = package_wtxids
        peers_expecting_invs = [peer_package_relayer_outbound, peer_package_relayer_inbound, peer_normal]
        for peer in peers_expecting_invs:
            peer.sync_with_ping()
            assert int(orphan_wtxid, 16) in peer.get_invs()
            assert int(parent_high_wtxid, 16) in peer.get_invs()
            assert int(parent_low_wtxid, 16) not in peer.get_invs()
        node.disconnect_p2ps()
        self.generate(node, 1, sync_fun=self.no_op)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)

        self.test_sendpackages()
        self.test_pkgtxns()
        self.test_ancpkginfo_requests()
        self.test_package_data_requests()
        self.test_receiver_initiated()
        self.test_package_tx_announcements()


if __name__ == '__main__':
    PackageProcessingTest().main()
