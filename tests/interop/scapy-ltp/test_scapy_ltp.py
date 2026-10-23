#!/usr/bin/env python3
"""LTP and LTP/UDP Testbed using Scapy.

Conforms to:
- RFC 5326: Licklider Transmission Protocol (LTP)
- RFC 7122: Using Advanced Encryption Standard (AES) / LTP over UDP
- RFC 9171: Bundle Protocol Version 7 (BPv7)
"""

import os
import random
import sys
import unittest

from ltp_harness import (
    ScapyLtpPeer,
    extract_bpv7_payload,
    make_bpv7_bundle,
)
from scapy.compat import raw
from scapy.contrib.ltp import LTP, LTPReceptionClaim

LOCAL_PORT = int(os.environ.get("SCAPY_LTP_PORT", "21116"))
REMOTE_PORT = int(os.environ.get("HARDY_LTP_PORT", "21115"))
LOCAL_ENGINE = int(os.environ.get("SCAPY_ENGINE_ID", "2"))
REMOTE_ENGINE = int(os.environ.get("HARDY_ENGINE_ID", "1"))


class TestScapyLtp(unittest.TestCase):
    """Test suite for Hardy LTP against Scapy."""

    @classmethod
    def setUpClass(cls):
        cls.peer = ScapyLtpPeer(
            local_port=LOCAL_PORT,
            remote_port=REMOTE_PORT,
            local_engine_id=LOCAL_ENGINE,
            remote_engine_id=REMOTE_ENGINE,
            timeout=2.0,
        )

    @classmethod
    def tearDownClass(cls):
        cls.peer.close()

    def setUp(self):
        # Flush any stray datagrams from previous tests
        while True:
            seg = self.peer.recv_segment(timeout=0.05)
            if seg is None:
                break

    def test_01_red_data_single_segment_happy_path(self):
        """Test 1: Red data single segment with CP + RS + RA handshake (RFC 5326 §6.2, §6.7, §6.8)."""
        session_no = 101
        payload = b"Hello Red Data via Scapy"
        seg = self.peer.make_red_data(
            session_no=session_no,
            payload=payload,
            offset=0,
            client_service=1,
            is_checkpoint=True,
            is_eorp=True,
            is_eob=True,
            checkpoint_serial=1,
            report_serial=0,
        )
        self.peer.send_segment(seg)

        # Expect RS (flags 8)
        rs = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(rs, "Hardy should respond with a Report Segment")
        self.assertEqual(rs.flags, 8, "Expected Report Segment (flag 0x8)")
        self.assertEqual(rs.SessionOriginator, LOCAL_ENGINE)
        self.assertEqual(rs.SessionNumber, session_no)
        self.assertEqual(rs.ReportCheckpointSerialNo, 1)
        self.assertEqual(rs.ReportLowerBound, 0)
        self.assertEqual(rs.ReportUpperBound, len(payload))
        self.assertEqual(rs.ReportReceptionClaimCount, 1)
        self.assertEqual(len(rs.ReportReceptionClaims), 1)
        self.assertEqual(rs.ReportReceptionClaims[0].ReceptionClaimOffset, 0)
        self.assertEqual(rs.ReportReceptionClaims[0].ReceptionClaimLength, len(payload))

        # Acknowledge RS with RA (flags 9)
        ra = self.peer.make_report_ack(session_no=session_no, report_serial=rs.ReportSerialNo)
        self.peer.send_segment(ra)

        # Verify no unexpected retransmissions
        spurious = self.peer.recv_segment(timeout=0.3)
        self.assertIsNone(spurious, "Session should complete cleanly with no trailing segments")

    def test_02_red_data_multi_segment_reassembly(self):
        """Test 2: Multi-segment Red data reassembly and single RS (RFC 5326 §6.2, §6.7)."""
        session_no = 102
        part1 = b"AAAAABBBBBCCCCC"  # 15 bytes
        part2 = b"DDDDDEEEEEFFFFFGGGGG"  # 20 bytes
        total_len = len(part1) + len(part2)

        # Segment 1: Red data, not checkpoint, not EOB (flags 0)
        seg1 = self.peer.make_red_data(
            session_no=session_no,
            payload=part1,
            offset=0,
            client_service=1,
            is_checkpoint=False,
            is_eorp=False,
            is_eob=False,
        )
        self.peer.send_segment(seg1)

        # Hardy should NOT send RS for non-checkpoint
        no_rs = self.peer.recv_segment(timeout=0.2)
        self.assertIsNone(no_rs, "No RS expected before checkpoint")

        # Segment 2: Red data, checkpoint, EORP, EOB (flags 3)
        seg2 = self.peer.make_red_data(
            session_no=session_no,
            payload=part2,
            offset=len(part1),
            client_service=1,
            is_checkpoint=True,
            is_eorp=True,
            is_eob=True,
            checkpoint_serial=1,
        )
        self.peer.send_segment(seg2)

        # Hardy should respond with RS claiming both segments [0..total_len]
        rs = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(rs, "Hardy should respond with RS after checkpoint")
        self.assertEqual(rs.flags, 8)
        self.assertEqual(rs.ReportLowerBound, 0)
        self.assertEqual(rs.ReportUpperBound, total_len)
        self.assertEqual(rs.ReportReceptionClaimCount, 1)
        self.assertEqual(rs.ReportReceptionClaims[0].ReceptionClaimOffset, 0)
        self.assertEqual(rs.ReportReceptionClaims[0].ReceptionClaimLength, total_len)

        # Send RA
        ra = self.peer.make_report_ack(session_no=session_no, report_serial=rs.ReportSerialNo)
        self.peer.send_segment(ra)

    def test_03_green_data_transfer(self):
        """Test 3: Green data (unreliable) transfer produces no RS (RFC 5326 §6.3)."""
        session_no = 103
        payload = b"Unreliable Green Data from Scapy"
        seg = self.peer.make_green_data(
            session_no=session_no,
            payload=payload,
            offset=0,
            client_service=1,
            is_eob=True,
        )
        self.peer.send_segment(seg)

        # Expect silence (no RS sent for green data)
        resp = self.peer.recv_segment(timeout=0.3)
        self.assertIsNone(resp, "Green data must never trigger a Report Segment (RFC 5326 §6.3)")

    def test_04_unreachable_client_service(self):
        """Test 4: Unreachable/unknown Client Service ID triggers CR(UNREACH) (RFC 5326 §6.2, §8.2)."""
        session_no = 104
        payload = b"Invalid Client Service Data"
        seg = self.peer.make_red_data(
            session_no=session_no,
            payload=payload,
            offset=0,
            client_service=99,  # Disallowed service (only service 1 is allowed)
            is_checkpoint=True,
            is_eorp=True,
            is_eob=True,
        )
        self.peer.send_segment(seg)

        # Expect Cancel Segment from receiver (CR, flags 14) with reason 1 (UNREACH)
        cr = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(cr, "Hardy must emit CR for unreachable client service")
        self.assertEqual(cr.flags, 14, "Expected Cancel Segment from Receiver (CR, flag 0xE)")
        self.assertEqual(cr.SessionOriginator, LOCAL_ENGINE)
        self.assertEqual(cr.SessionNumber, session_no)
        self.assertEqual(cr.CancelFromReceiverReason, 1, "Expected reason UNREACH (1)")

        # Send CAR (flags 15)
        car = self.peer.make_cancel_ack_to_receiver(session_no=session_no)
        self.peer.send_segment(car)

    def test_05_rfc7122_zero_keepalive_discard(self):
        """Test 5: 4-octet zero keep-alives are silently discarded (RFC 7122 §3.4)."""
        keep_alive = b"\x00\x00\x00\x00"
        self.peer.send_raw(keep_alive)

        # Ensure no error or response is sent
        resp = self.peer.recv_segment(timeout=0.2)
        self.assertIsNone(resp, "Zero keep-alive must be silently discarded")

        # Verify Hardy is healthy with a regular Red session
        session_no = 105
        seg = self.peer.make_red_data(
            session_no=session_no,
            payload=b"HealthCheck",
            is_checkpoint=True,
        )
        self.peer.send_segment(seg)
        rs = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(rs, "Hardy should remain healthy after keep-alives")
        self.peer.send_segment(self.peer.make_report_ack(session_no=session_no, report_serial=rs.ReportSerialNo))

    def test_06_rfc7122_trailing_bytes_discard(self):
        """Test 6: Datagrams with trailing bytes are rejected (RFC 7122 §3.3)."""
        session_no = 106
        seg = self.peer.make_red_data(
            session_no=session_no,
            payload=b"GoodPayload",
            is_checkpoint=True,
        )
        # Append 10 bytes of trailing garbage
        corrupted = raw(seg) + b"TRAILJUNK!"
        self.peer.send_raw(corrupted)

        # Hardy must drop trailing-byte segments
        resp = self.peer.recv_segment(timeout=0.3)
        self.assertIsNone(resp, "Datagram with trailing bytes must be rejected (RFC 7122 §3.3)")

    def test_07_redundant_checkpoint_idempotence(self):
        """Test 7: Redundant checkpoint retransmission preserves RS serial (RFC 5326 §6.8 (b))."""
        session_no = 107
        payload = b"RedundantCheckpointPayload"
        seg = self.peer.make_red_data(
            session_no=session_no,
            payload=payload,
            is_checkpoint=True,
            checkpoint_serial=1,
        )
        # Send checkpoint #1
        self.peer.send_segment(seg)
        rs1 = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(rs1)
        serial1 = rs1.ReportSerialNo

        # Retransmit checkpoint #1 WITHOUT sending RA
        self.peer.send_segment(seg)
        rs2 = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(rs2, "Hardy must reply to redundant checkpoint")
        self.assertEqual(rs2.ReportSerialNo, serial1, "RS serial number must be preserved")

        # Clean up with RA
        self.peer.send_segment(self.peer.make_report_ack(session_no=session_no, report_serial=serial1))

    def test_08_client_service_cancel_from_sender(self):
        """Test 8: Sender cancellation CS(USR_CNCLD) produces CAS (RFC 5326 §6.10, §6.13)."""
        session_no = 108
        # Send initial data segment without EOB
        seg = self.peer.make_red_data(
            session_no=session_no,
            payload=b"InitialIncompleteData",
            is_checkpoint=False,
            is_eorp=False,
            is_eob=False,
        )
        self.peer.send_segment(seg)

        # Send CS (flags 12) with reason USR_CNCLD (0)
        cs = self.peer.make_cancel_from_sender(session_no=session_no, reason=0)
        self.peer.send_segment(cs)

        # Hardy must respond with CAS (flags 13)
        cas = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(cas, "Hardy must reply with CAS")
        self.assertEqual(cas.flags, 13, "Expected Cancel-Acknowledgment Segment to Sender (CAS, flag 0xD)")
        self.assertEqual(cas.SessionOriginator, LOCAL_ENGINE)
        self.assertEqual(cas.SessionNumber, session_no)

    def test_09_fuzzing_and_malformed_packets_resilience(self):
        """Test 9: Injection of truncated, invalid, and mutated packets does not crash engine."""
        mutated_packets = [
            b"",  # Empty datagram
            b"\x00",  # 1 byte
            b"\x01\x02",  # 2 bytes
            b"\x50\x01\x02\x03",  # Invalid flag 5 (undefined)
            b"\xa0\x01\x02\x03",  # Invalid flag 10 (undefined)
            b"\xb0\x01\x02\x03",  # Invalid flag 11 (undefined)
            b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",  # Overlong/malformed SDNV
            bytes([random.randint(0, 255) for _ in range(64)]),  # Random noise
            bytes([random.randint(0, 255) for _ in range(256)]),  # Larger random noise
        ]

        for idx, packet in enumerate(mutated_packets):
            self.peer.send_raw(packet)

        # Drain any possible error segments
        while self.peer.recv_segment(timeout=0.05) is not None:
            pass

        # Verify engine remains responsive and processes valid Red data
        session_no = 109
        valid_seg = self.peer.make_red_data(
            session_no=session_no,
            payload=b"ResilienceCheckAfterFuzzing",
            is_checkpoint=True,
        )
        self.peer.send_segment(valid_seg)
        rs = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(rs, "Hardy should remain fully functional after malformed packets injection")
        self.peer.send_segment(self.peer.make_report_ack(session_no=session_no, report_serial=rs.ReportSerialNo))

    def test_10_bidirectional_bp_echo_over_ltp(self):
        """Test 10: Bidirectional BPv7 echo exchange between Scapy and Hardy built-in echo service."""
        session_no = 110
        echo_message = b"PING_FROM_SCAPY_TO_HARDY"
        bundle_bytes = make_bpv7_bundle(
            src_node=LOCAL_ENGINE,
            src_service=7,
            dest_node=REMOTE_ENGINE,
            dest_service=7,
            payload=echo_message,
        )

        # 1. Scapy sends bundle to Hardy in Red data session
        seg = self.peer.make_red_data(
            session_no=session_no,
            payload=bundle_bytes,
            offset=0,
            client_service=1,  # Client service 1 is Bundle Protocol
            is_checkpoint=True,
            is_eorp=True,
            is_eob=True,
            checkpoint_serial=1,
        )
        self.peer.send_segment(seg)

        # 2. Hardy sends RS to Scapy
        rs = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(rs, "Hardy must acknowledge ingress bundle")
        self.assertEqual(rs.flags, 8)
        self.peer.send_segment(self.peer.make_report_ack(session_no=session_no, report_serial=rs.ReportSerialNo))

        # 3. Hardy's BPA delivers bundle to echo service (7), echoes it to ipn:2.7,
        #    and transmits it back to Scapy (Engine 2) over LTP!
        echoed_data_seg = self.peer.recv_segment(timeout=3.0)
        self.assertIsNotNone(echoed_data_seg, "Hardy must transmit echoed bundle back to Scapy over LTP")
        self.assertEqual(echoed_data_seg.SessionOriginator, REMOTE_ENGINE)
        self.assertIn(echoed_data_seg.flags, [1, 2, 3], "Expected Red data checkpoint from Hardy")

        # 4. Scapy acknowledges Hardy's echoed LTP session
        hardy_session_no = echoed_data_seg.SessionNumber
        hardy_cp_serial = echoed_data_seg.CheckpointSerialNo
        echoed_payload = echoed_data_seg.LTP_Payload[0].load

        rs_to_hardy = LTP(
            version=0,
            flags=8,
            SessionOriginator=REMOTE_ENGINE,
            SessionNumber=hardy_session_no,
            HeaderExtensionCount=0,
            TrailerExtensionCount=0,
            ReportSerialNo=1,
            ReportCheckpointSerialNo=hardy_cp_serial,
            ReportUpperBound=len(echoed_payload),
            ReportLowerBound=0,
            ReportReceptionClaimCount=1,
            ReportReceptionClaims=[
                LTPReceptionClaim(ReceptionClaimOffset=0, ReceptionClaimLength=len(echoed_payload))
            ],
        )
        self.peer.send_segment(rs_to_hardy)

        # 5. Hardy sends RA to Scapy
        ra = self.peer.recv_segment(timeout=2.0)
        self.assertIsNotNone(ra, "Hardy should send RA acknowledging Scapy's RS")
        self.assertEqual(ra.flags, 9, "Expected RA (flag 0x9)")

        # 6. Verify echoed bundle payload
        extracted = extract_bpv7_payload(echoed_payload)
        self.assertEqual(extracted, echo_message, f"Echoed payload mismatch: {extracted} vs {echo_message}")


if __name__ == "__main__":
    unittest.main()
