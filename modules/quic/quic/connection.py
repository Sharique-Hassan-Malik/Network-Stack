"""
QUICConnection — the central object managing one QUIC connection.

Handshake (simplified, no TLS)
-------------------------------
  Client                              Server
    ──INITIAL(CRYPTO handshake)──►
                                 ◄──INITIAL(CRYPTO handshake + token)──
    ──HANDSHAKE(CRYPTO finished)──►
                                 ◄──HANDSHAKE(CRYPTO finished)──
    ──1-RTT(HANDSHAKE_DONE ACK)──►
                                 ◄──1-RTT(HANDSHAKE_DONE)──
           [ data flows ]

Because TLS 1.3 is out of scope, the "CRYPTO frames" carry a trivial
handshake message (the connection ID and role) so the state machine works
without a real cryptographic library.

The "encryption" for 1-RTT packets is a single-byte XOR with the first
byte of the destination connection ID — purely to show where the AEAD layer
would sit.
"""

from __future__ import annotations

import os
import random
import socket
import threading
import time
from dataclasses import dataclass
from enum import IntEnum, auto
from typing import Optional, Tuple

from .frames import (
    AckFrame, AckRange, CryptoFrame, HandshakeDoneFrame,
    StreamFrame, MaxDataFrame, MaxStreamDataFrame, MaxStreamsFrame,
    ConnectionCloseFrame, PingFrame,
    decode_frames, encode_frame,
)
from .packet import LongHeader, ShortHeader, PacketType, QUIC_VERSION
from .recovery import RecoveryManager
from .stream import StreamManager, SendStream, RecvStream
from .types import new_connection_id, encode_varint, decode_varint


_HANDSHAKE_TIMEOUT = 5.0
_IO_POLL           = 0.05
_MAX_DATAGRAM      = 1452
_MAX_PAYLOAD       = 1200


class ConnState(IntEnum):
    IDLE         = auto()
    INITIAL      = auto()
    HANDSHAKE    = auto()
    ESTABLISHED  = auto()
    CLOSING      = auto()
    CLOSED       = auto()


class QUICConnection:
    """
    One QUIC connection (client or server role).

    Client usage::

        conn = QUICConnection(is_server=False)
        conn.connect(("127.0.0.1", 4433))
        stream = conn.open_stream()
        stream.write(b"hello")
        stream.close()
        data = conn.recv_stream(0).read(4096)
        conn.close()

    Server usage::

        srv = QUICConnection(is_server=True)
        srv.bind(("0.0.0.0", 4433))
        conn = srv.accept()
        # use conn identically to client side
    """

    def __init__(self, is_server: bool = False) -> None:
        self._is_server = is_server
        self._state     = ConnState.IDLE

        self._local_cid  = new_connection_id()
        self._remote_cid = b""

        self._sock: Optional[socket.socket] = None
        self._peer: Optional[Tuple[str, int]] = None

        self._recovery = RecoveryManager()
        self._streams  = StreamManager(is_server=is_server)

        # Per-space packet numbers (allocate through recovery)
        self._spaces = self._recovery.spaces

        # Pending ACKs: space → set of received PNs
        self._pending_ack: dict[str, set[int]] = {
            "initial": set(), "handshake": set(), "app": set()
        }
        self._acked_pns: dict[str, set[int]] = {
            "initial": set(), "handshake": set(), "app": set()
        }

        self._handshake_done  = threading.Event()
        self._running         = False
        self._io_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Crypto handshake state
        self._crypto_send_offset: dict[str, int] = {"initial": 0, "handshake": 0}
        self._crypto_recv:        dict[str, bytearray] = {
            "initial": bytearray(), "handshake": bytearray()
        }

    # ── public API ─────────────────────────────────────────────────────────────

    def bind(self, addr: Tuple[str, int]) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(addr)
        self._state = ConnState.IDLE

    def connect(self, addr: Tuple[str, int]) -> None:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind(("0.0.0.0", 0))
        self._peer  = addr
        self._state = ConnState.INITIAL
        self._remote_cid = new_connection_id()

        self._send_initial_crypto()
        self._start_io()

        if not self._handshake_done.wait(timeout=_HANDSHAKE_TIMEOUT):
            self._state = ConnState.CLOSED
            raise ConnectionRefusedError(f"Handshake timeout connecting to {addr}")

    def accept(self) -> "QUICConnection":
        """Block until a client completes the handshake. Returns a new connection."""
        if self._sock is None:
            raise OSError("bind() must be called before accept()")
        self._state = ConnState.IDLE

        # Wait for an Initial packet
        self._sock.settimeout(None)
        while True:
            try:
                raw, addr = self._sock.recvfrom(65536)
            except OSError:
                raise
            if raw and (raw[0] & 0x80):   # long header
                break

        child = QUICConnection(is_server=True)
        child._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        child._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        child._sock.bind(("0.0.0.0", 0))
        child._peer = addr
        child._state = ConnState.INITIAL

        # Process the client's Initial
        child._dispatch_packet(raw, "initial")

        child._start_io()
        if not child._handshake_done.wait(timeout=_HANDSHAKE_TIMEOUT):
            child._state = ConnState.CLOSED
            raise ConnectionResetError("Handshake not completed")

        return child

    def open_stream(self) -> SendStream:
        if self._state != ConnState.ESTABLISHED:
            raise BrokenPipeError("Not connected")
        return self._streams.open_bidi_stream()

    def recv_stream(self, stream_id: int) -> RecvStream:
        return self._streams.get_or_create_recv(stream_id)

    def close(self) -> None:
        if self._state == ConnState.ESTABLISHED:
            self._send_app_frames([ConnectionCloseFrame(error_code=0, frame_type=0)])
        self._state   = ConnState.CLOSED
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    # ── handshake internals ────────────────────────────────────────────────────

    def _send_initial_crypto(self) -> None:
        msg = b"QUIC_HELLO:" + self._local_cid
        cf  = CryptoFrame(offset=self._crypto_send_offset["initial"], data=msg)
        self._crypto_send_offset["initial"] += len(msg)
        pn  = self._spaces["initial"].allocate_pn()
        payload = encode_frame(cf) + self._build_ack("initial")
        raw = self._build_long_packet(PacketType.INITIAL, pn, payload)
        self._sock.sendto(raw, self._peer)
        self._spaces["initial"].on_packet_sent(pn, len(raw), True, [cf])

    def _send_handshake_crypto(self) -> None:
        msg = b"QUIC_FINISHED:" + self._local_cid
        cf  = CryptoFrame(offset=self._crypto_send_offset["handshake"], data=msg)
        self._crypto_send_offset["handshake"] += len(msg)
        pn  = self._spaces["handshake"].allocate_pn()
        payload = encode_frame(cf) + self._build_ack("handshake")
        raw = self._build_long_packet(PacketType.HANDSHAKE, pn, payload)
        self._sock.sendto(raw, self._peer)
        self._spaces["handshake"].on_packet_sent(pn, len(raw), True, [cf])

    def _send_handshake_done(self) -> None:
        pn = self._spaces["app"].allocate_pn()
        payload = encode_frame(HandshakeDoneFrame()) + self._build_ack("app")
        raw = self._build_short_packet(pn, payload)
        self._sock.sendto(raw, self._peer)
        self._spaces["app"].on_packet_sent(pn, len(raw), True, [HandshakeDoneFrame()])

    # ── packet building ────────────────────────────────────────────────────────

    def _build_long_packet(self, ptype: PacketType, pn: int, payload: bytes) -> bytes:
        hdr = LongHeader(
            ptype=ptype, dcid=self._remote_cid, scid=self._local_cid, pn=pn,
        )
        return hdr.to_bytes(payload)

    def _build_short_packet(self, pn: int, payload: bytes) -> bytes:
        key  = (self._remote_cid[0] if self._remote_cid else 0)
        enc  = bytes(b ^ key for b in payload)
        hdr  = ShortHeader(dcid=self._remote_cid, pn=pn)
        return hdr.to_bytes(enc)

    def _build_ack(self, space: str) -> bytes:
        pending = sorted(self._pending_ack[space], reverse=True)
        if not pending:
            return b""
        largest = pending[0]
        first   = 0
        i = 0
        while i + 1 < len(pending) and pending[i] - pending[i + 1] == 1:
            first += 1
            i     += 1
        af = AckFrame(largest_acked=largest, ack_delay=0, first_ack_range=first)
        self._acked_pns[space].update(self._pending_ack[space])
        self._pending_ack[space].clear()
        return encode_frame(af)

    # ── I/O loop ───────────────────────────────────────────────────────────────

    def _start_io(self) -> None:
        self._running = True
        self._sock.settimeout(_IO_POLL)
        self._io_thread = threading.Thread(target=self._io_loop, daemon=True, name="quic-io")
        self._io_thread.start()

    def _io_loop(self) -> None:
        while self._running:
            # Retransmit check
            for space in ("initial", "handshake", "app"):
                if self._recovery.pto_expired(space):
                    self._recovery.on_pto_fired()
                    self._retransmit_space(space)

            # Push pending stream data (only when established)
            if self._state == ConnState.ESTABLISHED:
                self._flush_streams()

            try:
                raw, addr = self._sock.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break

            if not raw:
                continue
            if raw[0] & 0x80:
                ptype = (raw[0] >> 4) & 0x03
                space = ["initial", None, "handshake"][ptype] if ptype in (0, 2) else "initial"
                self._dispatch_packet(raw, space)
            else:
                self._dispatch_packet(raw, "app")

    def _dispatch_packet(self, raw: bytes, space: str) -> None:
        try:
            if space in ("initial", "handshake"):
                hdr, payload, _ = LongHeader.from_bytes(raw)
                if not self._remote_cid:
                    self._remote_cid = hdr.scid
                pn = hdr.pn
            else:
                dcid_len = len(self._local_cid)
                hdr, enc_payload, _ = ShortHeader.from_bytes(raw, dcid_len)
                key     = (self._local_cid[0] if self._local_cid else 0)
                payload = bytes(b ^ key for b in enc_payload)
                pn      = hdr.pn

            self._pending_ack[space].add(pn)
            frames = decode_frames(payload)
            for frame in frames:
                self._handle_frame(frame, space)

        except Exception:
            pass

    def _handle_frame(self, frame, space: str) -> None:
        if isinstance(frame, CryptoFrame):
            self._crypto_recv[space if space != "app" else "handshake"].extend(frame.data)
            self._advance_handshake(space)

        elif isinstance(frame, AckFrame):
            acked_ranges = self._expand_ack_frame(frame)
            self._recovery.on_ack_received(
                space, frame.largest_acked, frame.ack_delay / 1000, acked_ranges
            )

        elif isinstance(frame, StreamFrame):
            self._streams.on_stream_data_received(frame)

        elif isinstance(frame, MaxDataFrame):
            self._streams.update_connection_limit(frame.maximum)

        elif isinstance(frame, MaxStreamDataFrame):
            self._streams.update_stream_limit(frame.stream_id, frame.maximum)

        elif isinstance(frame, HandshakeDoneFrame):
            if not self._is_server:
                self._state = ConnState.ESTABLISHED
                self._handshake_done.set()

        elif isinstance(frame, ConnectionCloseFrame):
            self._state   = ConnState.CLOSED
            self._running = False

    def _advance_handshake(self, space: str) -> None:
        if space == "initial":
            data = bytes(self._crypto_recv["initial"])
            if b"QUIC_HELLO:" in data:
                if self._is_server:
                    # Send our own Initial + Handshake
                    self._remote_cid = data.split(b"QUIC_HELLO:")[1][:8]
                    self._send_initial_crypto()
                    self._state = ConnState.HANDSHAKE
                    self._send_handshake_crypto()
                else:
                    self._state = ConnState.HANDSHAKE
                    self._send_handshake_crypto()

        elif space == "handshake":
            data = bytes(self._crypto_recv["handshake"])
            if b"QUIC_FINISHED:" in data:
                if self._is_server:
                    self._state = ConnState.ESTABLISHED
                    self._send_handshake_done()
                    self._handshake_done.set()
                else:
                    self._state = ConnState.ESTABLISHED
                    self._handshake_done.set()

    # ── data sending ──────────────────────────────────────────────────────────

    def _flush_streams(self) -> None:
        frames = self._streams.pending_send_frames(
            conn_budget=self._recovery.cwnd - self._recovery.bytes_in_flight
        )
        frames += self._streams.flow_control_frames()
        if frames:
            self._send_app_frames(frames)

    def _send_app_frames(self, frames: list) -> None:
        payload = b""
        for f in frames:
            payload += encode_frame(f)
        if not payload:
            return
        pn  = self._spaces["app"].allocate_pn()
        raw = self._build_short_packet(pn, payload)
        try:
            self._sock.sendto(raw, self._peer)
            self._recovery.bytes_in_flight += len(raw)
            self._spaces["app"].on_packet_sent(pn, len(raw), True, frames)
        except OSError:
            pass

    def _retransmit_space(self, space: str) -> None:
        ns = self._recovery.spaces[space]
        for pkt in list(ns.sent.values()):
            if not pkt.acked and not pkt.lost:
                pass   # probe: re-send a PING
        pn = ns.allocate_pn()
        if space == "app":
            payload = encode_frame(PingFrame()) + self._build_ack(space)
            raw     = self._build_short_packet(pn, payload)
        else:
            ptype   = PacketType.INITIAL if space == "initial" else PacketType.HANDSHAKE
            payload = encode_frame(PingFrame()) + self._build_ack(space)
            raw     = self._build_long_packet(ptype, pn, payload)
        try:
            self._sock.sendto(raw, self._peer)
            ns.on_packet_sent(pn, len(raw), True, [PingFrame()])
        except OSError:
            pass

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _expand_ack_frame(frame: AckFrame) -> list[tuple[int, int]]:
        ranges = []
        end   = frame.largest_acked
        start = end - frame.first_ack_range
        ranges.append((start, end))
        prev_start = start
        for r in frame.ranges:
            end   = prev_start - r.gap - 2
            start = end - r.ack
            ranges.append((start, end))
            prev_start = start
        return ranges

    def __repr__(self) -> str:
        return (
            f"QUICConnection(role={'server' if self._is_server else 'client'}, "
            f"state={self._state.name}, cid={self._local_cid.hex()[:8]})"
        )
