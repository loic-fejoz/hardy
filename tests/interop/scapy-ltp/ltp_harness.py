"""LTP test harness using Scapy.

Provides utilities to construct, manipulate, inject, and receive
Licklider Transmission Protocol (RFC 5326) and LTP/UDP (RFC 7122) segments.
"""

import socket
import sys
from typing import Optional, Tuple

import cbor2
from scapy.compat import raw
from scapy.contrib.ltp import LTP, LTPReceptionClaim


def make_bpv7_bundle(
    src_node: int = 2,
    src_service: int = 7,
    dest_node: int = 1,
    dest_service: int = 7,
    payload: bytes = b"PING",
) -> bytes:
    """Create an RFC 9171 BPv7 bundle containing a payload block."""
    import time

    dest_eid = [2, [dest_node, dest_service]]
    src_eid = [2, [src_node, src_service]]
    report_eid = [2, [src_node, src_service]]

    # DTN epoch is 2000-01-01T00:00:00Z (timestamp 946684800)
    dtn_now_ms = int((time.time() - 946684800.0) * 1000)

    primary_block = [
        7,          # version
        0,          # bundle control flags
        0,          # CRC type: none
        dest_eid,
        src_eid,
        report_eid,
        [dtn_now_ms, 1],  # creation timestamp: [milliseconds since DTN epoch, sequence]
        3600000,    # lifetime in ms
    ]

    payload_block = [
        1,          # block type code: Payload block
        1,          # block number: 1
        0,          # block processing control flags
        0,          # CRC type: none
        payload,
    ]

    # RFC 9171 §4.1: The bundle must be encoded as a CBOR indefinite-length array
    # starting with 0x9f and terminating with a 0xff break code.
    return b"\x9f" + cbor2.dumps(primary_block) + cbor2.dumps(payload_block) + b"\xff"


def extract_bpv7_payload(bundle_bytes: bytes) -> Optional[bytes]:
    """Extract payload bytes from an RFC 9171 CBOR bundle."""
    try:
        decoded = cbor2.loads(bundle_bytes)
        if isinstance(decoded, list) and len(decoded) >= 2:
            # Look for block type 1 (Payload Block)
            for block in decoded[1:]:
                if isinstance(block, list) and len(block) >= 5 and block[0] == 1:
                    return block[4]
    except Exception:
        return None
    return None



class ScapyLtpPeer:
    """A Scapy-based LTP UDP peer."""

    def __init__(
        self,
        local_port: int,
        remote_port: int,
        local_engine_id: int = 2,
        remote_engine_id: int = 1,
        host: str = "127.0.0.1",
        timeout: float = 2.0,
    ):
        self.local_port = local_port
        self.remote_port = remote_port
        self.local_engine_id = local_engine_id
        self.remote_engine_id = remote_engine_id
        self.host = host
        self.timeout = timeout

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.local_port))
        self.sock.settimeout(self.timeout)

    def close(self):
        """Close the underlying UDP socket."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_raw(self, data: bytes):
        """Send raw bytes over the UDP socket."""
        self.sock.sendto(data, (self.host, self.remote_port))

    def send_segment(self, segment: LTP):
        """Serialize a Scapy LTP segment and send it over UDP."""
        data = raw(segment)
        self.send_raw(data)

    def recv_raw(self, timeout: Optional[float] = None) -> Tuple[bytes, Tuple[str, int]]:
        """Receive raw bytes from the UDP socket."""
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(65535)
            return data, addr
        finally:
            self.sock.settimeout(self.timeout)

    def recv_segment(self, timeout: Optional[float] = None) -> Optional[LTP]:
        """Receive a datagram and parse it as a Scapy LTP segment."""
        try:
            data, _ = self.recv_raw(timeout=timeout)
            return LTP(data)
        except socket.timeout:
            return None

    def make_red_data(
        self,
        session_no: int,
        payload: bytes,
        offset: int = 0,
        client_service: int = 1,
        is_checkpoint: bool = True,
        is_eorp: bool = True,
        is_eob: bool = True,
        checkpoint_serial: int = 1,
        report_serial: int = 0,
        originator: Optional[int] = None,
    ) -> LTP:
        """Create a Red data segment (flags 0x0..0x3)."""
        if originator is None:
            originator = self.local_engine_id

        flags = 0
        if is_checkpoint and not is_eorp and not is_eob:
            flags = 1
        elif is_checkpoint and is_eorp and not is_eob:
            flags = 2
        elif is_checkpoint and is_eorp and is_eob:
            flags = 3

        kwargs = {
            "version": 0,
            "flags": flags,
            "SessionOriginator": originator,
            "SessionNumber": session_no,
            "HeaderExtensionCount": 0,
            "TrailerExtensionCount": 0,
            "DATA_ClientServiceID": client_service,
            "DATA_PayloadOffset": offset,
            "LTP_Payload": payload,
        }
        if is_checkpoint:
            kwargs["CheckpointSerialNo"] = checkpoint_serial
            kwargs["ReportSerialNo"] = report_serial

        return LTP(**kwargs)

    def make_green_data(
        self,
        session_no: int,
        payload: bytes,
        offset: int = 0,
        client_service: int = 1,
        is_eob: bool = True,
        originator: Optional[int] = None,
    ) -> LTP:
        """Create a Green data segment (flags 0x4 or 0x7)."""
        if originator is None:
            originator = self.local_engine_id

        flags = 7 if is_eob else 4
        return LTP(
            version=0,
            flags=flags,
            SessionOriginator=originator,
            SessionNumber=session_no,
            HeaderExtensionCount=0,
            TrailerExtensionCount=0,
            DATA_ClientServiceID=client_service,
            DATA_PayloadOffset=offset,
            LTP_Payload=payload,
        )

    def make_report_ack(
        self,
        session_no: int,
        report_serial: int,
        originator: Optional[int] = None,
    ) -> LTP:
        """Create a Report Acknowledgment (RA) segment (flag 0x9)."""
        if originator is None:
            originator = self.local_engine_id

        return LTP(
            version=0,
            flags=9,
            SessionOriginator=originator,
            SessionNumber=session_no,
            HeaderExtensionCount=0,
            TrailerExtensionCount=0,
            RA_ReportSerialNo=report_serial,
        )

    def make_cancel_from_sender(
        self,
        session_no: int,
        reason: int,
        originator: Optional[int] = None,
    ) -> LTP:
        """Create a Cancel Segment from Sender (CS) (flag 0xC)."""
        if originator is None:
            originator = self.local_engine_id

        return LTP(
            version=0,
            flags=12,
            SessionOriginator=originator,
            SessionNumber=session_no,
            HeaderExtensionCount=0,
            TrailerExtensionCount=0,
            CancelFromSenderReason=reason,
        )

    def make_cancel_ack_to_receiver(
        self,
        session_no: int,
        originator: Optional[int] = None,
    ) -> LTP:
        """Create a Cancel Acknowledgment Segment to Receiver (CAR) (flag 0xF)."""
        if originator is None:
            originator = self.local_engine_id

        return LTP(
            version=0,
            flags=15,
            SessionOriginator=originator,
            SessionNumber=session_no,
            HeaderExtensionCount=0,
            TrailerExtensionCount=0,
        )
