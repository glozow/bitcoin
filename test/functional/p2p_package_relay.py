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
    MSG_TX,
    MSG_WITNESS_TX,
    MSG_WTX,
    msg_ancpkginfo,
    msg_feefilter,
    msg_getdata,
    msg_inv,
    msg_notfound,
    msg_sendpackages,
    msg_tx,
    msg_verack,
    msg_wtxidrelay,
)
from test_framework.p2p import (
    NONPREF_PEER_TX_DELAY,
    ORPHAN_ANCESTOR_GETDATA_INTERVAL,
    p2p_lock,
    P2PTxInvStore,
    TXID_RELAY_DELAY,
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
        self._getdata_received = []

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

    @property
    def getdata_received(self):
        with p2p_lock:
            return self._getdata_received

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

    def on_getdata(self, message):
        self._getdata_received.append(message)

    def wait_for_getancpkginfo(self, wtxid16):
        def test_function():
            last_getdata = self.last_message.get('getdata')
            if not last_getdata:
                return False
            return last_getdata.inv[0].hash == wtxid16 and last_getdata.inv[0].type == MSG_ANCPKGINFO
        self.wait_until(test_function, timeout=10)

    def wait_for_getdata_txids(self, txids):
        def test_function():
            last_getdata = self.last_message.get('getdata')
            if not last_getdata:
                return False
            return all([item.type == MSG_WITNESS_TX and item.hash in txids for item in last_getdata.inv])
        self.wait_until(test_function, timeout=10)

class PackageRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-packagerelay=1"]]
        self.starttime = int(time.time())
        self.mocktime = self.starttime

    def create_package(self, cpfp=True):
        """Create package with these transactions:
        - Parent 1: fee=default
        - Parent 2: fee=0 if cpfp, else default
        - Child:    fee=high
        """
        parent1 = self.wallet.create_self_transfer()
        parent2 = self.wallet.create_self_transfer(fee_rate=0, fee=0) if cpfp else self.wallet.create_self_transfer()
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
        package_hex, package_txns, package_wtxids = self.create_package(cpfp=False)
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

    @cleanup
    def test_orphan_get_ancpkginfo(self):
        self.log.info("Test that nodes deal with orphans by requesting ancestor package info")
        node = self.nodes[0]
        package_hex, package_txns, package_wtxids = self.create_package()
        orphan_tx = package_txns[-1]
        orphan_wtxid = package_wtxids[-1]

        peer_package_relayer = node.add_p2p_connection(PackageRelayer())
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))
        peer_package_relayer.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(NONPREF_PEER_TX_DELAY + 1)
        peer_package_relayer.wait_for_getdata([int(orphan_wtxid, 16)])
        peer_package_relayer.send_and_ping(msg_tx(orphan_tx))

        self.fastforward(NONPREF_PEER_TX_DELAY + 1)
        peer_package_relayer.sync_with_ping()
        peer_package_relayer.wait_for_getancpkginfo(int(orphan_wtxid, 16))
        peer_package_relayer.send_and_ping(msg_ancpkginfo([int(wtxid, 16) for wtxid in package_wtxids]))
        self.wait_until(lambda: "ancpkginfo" in node.getpeerinfo()[0]["bytesrecv_per_msg"])

    @cleanup
    def test_orphan_handling_prefer_outbound(self):
        self.log.info("Test that the node uses all announcers as potential candidates for orphan handling")
        node = self.nodes[0]
        package_hex, package_txns, package_wtxids = self.create_package()
        orphan_tx = package_txns[-1]
        orphan_wtxid = package_wtxids[-1]
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))

        peer_inbound = node.add_p2p_connection(PackageRelayer())
        peer_outbound = node.add_outbound_p2p_connection(PackageRelayer(), p2p_idx=1)

        peer_inbound.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(NONPREF_PEER_TX_DELAY + 1)
        peer_inbound.wait_for_getdata([int(orphan_wtxid, 16)])
        # Both send invs for the orphan, so the node an expect both to know its ancestors.
        peer_outbound.send_and_ping(msg_inv([orphan_inv]))
        peer_inbound.send_and_ping(msg_tx(orphan_tx))
        self.fastforward(NONPREF_PEER_TX_DELAY)

        self.log.info("Test that the node prefers requesting ancpkginfo from outbound peers")
        # The outbound peer should be preferred for getting ancpkginfo
        peer_outbound.wait_for_getancpkginfo(int(orphan_wtxid, 16))
        # There should be no request to the inbound peer
        ancpkginfo_request = peer_outbound.getdata_received.pop()
        assert ancpkginfo_request not in peer_inbound.getdata_received

        self.log.info("Test that, if the preferred peer doesn't respond, the node sends another request")
        self.fastforward(ORPHAN_ANCESTOR_GETDATA_INTERVAL)
        peer_inbound.sync_with_ping()
        peer_inbound.wait_for_getancpkginfo(int(orphan_wtxid, 16))

    @cleanup
    def test_orphan_handling_prefer_ancpkginfo(self):
        node = self.nodes[0]
        package_hex, package_txns, package_wtxids = self.create_package()
        orphan_tx = package_txns[-1]
        orphan_wtxid = package_wtxids[-1]
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))

        peer_nonpackage = node.add_p2p_connection(PackageRelayer(send_sendpackages=False))
        assert not node.getpeerinfo()[0]["relaytxpackages"]
        peer_package_relay = node.add_p2p_connection(PackageRelayer())

        peer_nonpackage.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(NONPREF_PEER_TX_DELAY + 1)
        peer_nonpackage.wait_for_getdata([int(orphan_wtxid, 16)])
        # Both send invs for the orphan, so the node an expect both to know its ancestors.
        peer_package_relay.send_and_ping(msg_inv([orphan_inv]))
        peer_nonpackage.send_and_ping(msg_tx(orphan_tx))

        # tx is an orphan. Node should first try to resolve it by requesting ancpkginfo from package relay peer.
        nonpackage_prev_getdata = len(peer_nonpackage.getdata_received)
        self.fastforward(NONPREF_PEER_TX_DELAY)
        peer_nonpackage.sync_with_ping()
        peer_package_relay.sync_with_ping()
        self.log.info("Test that the node prefers resolving orphans using package relay peers")
        peer_package_relay.wait_for_getancpkginfo(int(orphan_wtxid, 16))
        # The non-package relay peer should not have received any request.
        assert_equal(nonpackage_prev_getdata, len(peer_nonpackage.getdata_received))

        self.log.info("Test that, if the package relay peer doesn't respond, node falls back to parent txids")
        self.fastforward(ORPHAN_ANCESTOR_GETDATA_INTERVAL)
        peer_nonpackage.wait_for_getdata_txids([int(tx.rehash(), 16) for tx in package_txns[:-1]])

    @cleanup
    def test_orphan_announcer_memory(self):
        self.log.info("Test that the node remembers who announced orphan transactions")
        node = self.nodes[0]
        package_hex, package_txns, package_wtxids = self.create_package()
        orphan_tx = package_txns[-1]
        orphan_wtxid = package_wtxids[-1]
        orphan_inv = CInv(t=MSG_WTX, h=int(orphan_wtxid, 16))

        # Original announcer of orphan
        peer_package_relay1 = node.add_outbound_p2p_connection(PackageRelayer(), p2p_idx=2)
        # Sends an inv for the orphan before the node requests orphan tx data.
        # Preferred for orphan handling over peer3 because it's an outbound connection.
        peer_package_relay2 = node.add_p2p_connection(PackageRelayer())
        # Sends an inv for the orphan while the node is requesting ancpkginfo
        peer_package_relay3 = node.add_p2p_connection(PackageRelayer())

        peer_package_relay1.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(NONPREF_PEER_TX_DELAY + 1)
        peer_package_relay1.wait_for_getdata([int(orphan_wtxid, 16)])

        # Both send invs for the orphan, so the node an expect both to know its ancestors.
        peer_package_relay2.send_and_ping(msg_inv([orphan_inv]))
        peer_package_relay1.send_and_ping(msg_tx(orphan_tx))

        peer2_prev_getdata = len(peer_package_relay2.getdata_received)
        peer3_prev_getdata = len(peer_package_relay3.getdata_received)
        self.fastforward(NONPREF_PEER_TX_DELAY)
        peer_package_relay1.wait_for_getancpkginfo(int(orphan_wtxid, 16))
        peer_package_relay3.send_and_ping(msg_inv([orphan_inv]))
        # Peers 2 and 3 should not have received any getdata
        # Not for tx data of the orphan, not for ancpkginfo, and not for parent txids
        assert_equal(peer2_prev_getdata, len(peer_package_relay2.getdata_received))
        assert_equal(peer3_prev_getdata, len(peer_package_relay3.getdata_received))

        self.log.info("Test that the node requests ancpkginfo from a different peer upon receiving notfound")
        orphan_ancpkginfo_notfound = msg_notfound(vec=[CInv(MSG_ANCPKGINFO, int(orphan_wtxid, 16))])
        peer_package_relay1.send_and_ping(orphan_ancpkginfo_notfound)
        self.fastforward(1)
        # Node should try again from peer2
        peer_package_relay2.wait_for_getancpkginfo(int(orphan_wtxid, 16))

        self.log.info("Test that the node requests ancpkginfo from a different peer if peer disconnects")
        # Peer 2 disconnected before responding
        peer_package_relay2.peer_disconnect()
        self.fastforward(1)
        peer_package_relay3.sync_with_ping()
        peer_package_relay3.wait_for_getancpkginfo(int(orphan_wtxid, 16))

    @cleanup
    def test_ancpkginfo_received(self):
        node = self.nodes[0]
        parent1 = self.wallet.create_self_transfer()
        parent2 = self.wallet.create_self_transfer()
        child = self.wallet.create_self_transfer_multi(
            utxos_to_spend=[parent1['new_utxo'], parent2["new_utxo"]],
            num_outputs=1,
            fee_per_output=int(DEFAULT_FEE * COIN)
        )
        package_txns = [parent1["tx"], parent2["tx"], child["tx"]]
        package_wtxids = [tx.getwtxid() for tx in package_txns]
        ancpkginfo_message = msg_ancpkginfo([int(wtxid, 16) for wtxid in package_wtxids])

        self.log.info("Test that unsolicited ancpkginfo results in disconnection")
        peer1 = node.add_p2p_connection(PackageRelayer())
        peer1.send_message(ancpkginfo_message)
        peer1.wait_for_disconnect()

        self.log.info("Test that peer uses ancpkginfo to request orphan's ancestors")
        orphan_inv = CInv(t=MSG_WTX, h=int(package_wtxids[-1], 16))
        peer2 = node.add_p2p_connection(PackageRelayer())
        peer2.send_and_ping(msg_inv([orphan_inv]))
        self.fastforward(NONPREF_PEER_TX_DELAY + 1)
        peer2.wait_for_getdata([int(package_wtxids[-1], 16)])
        peer2.send_and_ping(msg_tx(package_txns[-1]))
        self.fastforward(NONPREF_PEER_TX_DELAY + 1)
        peer2.wait_for_getancpkginfo(int(package_wtxids[-1], 16))
        peer2.send_and_ping(ancpkginfo_message)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 160)

        self.test_sendpackages()
        self.test_ancpkginfo_requests()
        self.test_orphan_get_ancpkginfo()
        self.test_orphan_handling_prefer_outbound()
        self.test_orphan_handling_prefer_ancpkginfo()
        self.test_orphan_announcer_memory()
        self.test_ancpkginfo_received()


if __name__ == '__main__':
    PackageRelayTest().main()
