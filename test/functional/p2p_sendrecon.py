#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test SENDRECON message
"""

from test_framework.messages import (
    msg_sendrecon,
    msg_verack,
    msg_version,
    msg_wtxidrelay,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    P2P_SUBVERSION,
    P2P_VERSION,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class SendReconSender(P2PInterface):
    def __init__(self, wtxidrelay=True):
        super().__init__()
        self.sendrecon_msg_received = None
        self.wtxidrelay = wtxidrelay

    def on_version(self, message):
        # Don't send verack here, send it manually instead.
        if self.wtxidrelay:
            self.send_message(msg_wtxidrelay())

    def on_sendrecon(self, message):
        self.sendrecon_msg_received = message

def create_sendrecon_msg():
    sendrecon_msg = msg_sendrecon()
    sendrecon_msg.initiator = True
    sendrecon_msg.responder = False
    sendrecon_msg.version = 1
    sendrecon_msg.salt = 2
    return sendrecon_msg

class SendReconTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-txrecon']]

    def run_test(self):
        # Checks for the node *sending* SENDRECON
        self.log.info('SENDRECON sent to an inbound')
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=True, wait_for_verack=False)
        peer.wait_until(lambda: peer.sendrecon_msg_received)
        assert not peer.sendrecon_msg_received.initiator
        assert peer.sendrecon_msg_received.responder
        assert_equal(peer.sendrecon_msg_received.version, 1)

        self.log.info('SENDRECON on pre-WTXID version should not be sent')
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=False, wait_for_verack=False)
        pre_wtxid_version_msg = msg_version()
        pre_wtxid_version_msg.nVersion = 70015
        pre_wtxid_version_msg.strSubVer = P2P_SUBVERSION
        pre_wtxid_version_msg.nServices = P2P_SERVICES
        pre_wtxid_version_msg.relay = 1
        peer.send_message(pre_wtxid_version_msg)
        peer.wait_for_verack()
        assert not peer.sendrecon_msg_received

        self.log.info('SENDRECON for fRelay=false should not be sent')
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=False, wait_for_verack=False)
        no_txrelay_version_msg = msg_version()
        no_txrelay_version_msg.nVersion = P2P_VERSION
        no_txrelay_version_msg.strSubVer = P2P_SUBVERSION
        no_txrelay_version_msg.nServices = P2P_SERVICES
        no_txrelay_version_msg.relay = 0
        peer.send_message(no_txrelay_version_msg)
        peer.wait_for_verack()
        assert not peer.sendrecon_msg_received

        # Checks for the node *receiving* SENDRECON
        self.log.info('valid SENDRECON')
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=True, wait_for_verack=False)
        peer.send_message(create_sendrecon_msg())
        self.log.info('second SENDRECON triggers a disconnect')
        peer.send_message(create_sendrecon_msg())
        peer.wait_for_disconnect()

        self.log.info('SENDRECON with initiator=responder=0 triggers a disconnect')
        sendrecon_no_role = create_sendrecon_msg()
        sendrecon_no_role.initiator = False
        sendrecon_no_role.responder = False
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=True, wait_for_verack=False)
        peer.send_message(sendrecon_no_role)
        peer.wait_for_disconnect()

        self.log.info('SENDRECON with initiator=0 and responder=1 from inbound triggers a disconnect')
        sendrecon_wrong_role = create_sendrecon_msg()
        sendrecon_wrong_role.initiator = False
        sendrecon_wrong_role.responder = True
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=True, wait_for_verack=False)
        peer.send_message(sendrecon_wrong_role)
        peer.wait_for_disconnect()

        self.log.info('SENDRECON with version=0 triggers a disconnect')
        sendrecon_low_version = create_sendrecon_msg()
        sendrecon_low_version.version = 0
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=True, wait_for_verack=False)
        peer.send_message(sendrecon_low_version)
        peer.wait_for_disconnect()

        self.log.info('SENDRECON after VERACK triggers a disconnect')
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=True, wait_for_verack=False)
        peer.send_message(msg_verack())
        peer.send_message(create_sendrecon_msg())
        peer.wait_for_disconnect()

        self.log.info('SENDRECON without WTXIDRELAY is ignored (recon state is erased after VERACK)')
        with self.nodes[0].assert_debug_log(['Forget reconciliation state of peer=8']):
            peer = self.nodes[0].add_p2p_connection(SendReconSender(wtxidrelay=False), send_version=True, wait_for_verack=False)
            peer.send_message(create_sendrecon_msg())
            peer.send_message(msg_verack())

        self.log.info('SENDRECON from a block-relay-only peer triggers a disconnect')
        peer = self.nodes[0].add_outbound_p2p_connection(
            SendReconSender(), wait_for_verack=False, p2p_idx=0, connection_type="block-relay-only")
        peer.send_message(create_sendrecon_msg())
        peer.wait_for_disconnect()

        # Outbound
        self.log.info('SENDRECON sent to an outbound')
        peer = self.nodes[0].add_outbound_p2p_connection(
            SendReconSender(), wait_for_verack=False, p2p_idx=1, connection_type="outbound-full-relay")
        peer.wait_until(lambda: peer.sendrecon_msg_received)
        assert peer.sendrecon_msg_received.initiator
        assert not peer.sendrecon_msg_received.responder
        assert_equal(peer.sendrecon_msg_received.version, 1)

        self.log.info('SENDRECON should not be sent if block-relay-only')
        peer = self.nodes[0].add_outbound_p2p_connection(
            SendReconSender(), wait_for_verack=False, p2p_idx=2, connection_type="block-relay-only")
        peer.wait_for_verack()
        assert not peer.sendrecon_msg_received

        self.log.info('SENDRECON with initiator=1 and responder=0 from outbound triggers a disconnect')
        sendrecon_wrong_role = create_sendrecon_msg()
        sendrecon_wrong_role.initiator = True
        sendrecon_wrong_role.responder = False
        peer = self.nodes[0].add_outbound_p2p_connection(
            SendReconSender(), wait_for_verack=False, p2p_idx=3, connection_type="outbound-full-relay")
        peer.send_message(sendrecon_wrong_role)
        peer.wait_for_disconnect()

class SendReconBlocksOnlyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-txrecon -blocksonly']]

    def run_test(self):
        self.log.info('SENDRECON not sent if blocksonly')
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=True, wait_for_verack=False)
        peer.sync_with_ping()
        assert not peer.sendrecon_msg_received

class SendReconNoTxReconFlagTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.log.info('SENDRECON not sent if -txrecon flag is not set')
        peer = self.nodes[0].add_p2p_connection(SendReconSender(), send_version=True, wait_for_verack=False)
        peer.sync_with_ping()
        assert not peer.sendrecon_msg_received


if __name__ == '__main__':
    SendReconTest().main()
    SendReconBlocksOnlyTest().main()
    SendReconNoTxReconFlagTest().main()
