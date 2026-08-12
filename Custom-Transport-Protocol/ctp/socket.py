"""
CTPSocket — the public API for the Custom Transport Protocol.

Usage mirrors Python's built-in socket interface::

    # Receiver
    srv = CTPSocket()
    srv.bind(("0.0.0.0", 9000))
    conn, addr = srv.accept()
    data = conn.recv(1 << 20)
    conn.close()

    # Sender
    cli = CTPSocket(congestion="bbr")
    cli.connect(("127.0.0.1", 9000))
    cli.send(payload)
    cli.close()

Design
------
* Handshake (connect / accept) is synchronous; the calling thread blocks
  until the three-way exchange completes or times out.
* After ESTABLISHED a background thread drives the receive loop.  A second
  thread fires retransmission timeouts.
* The UDP socket is connect()ed to the peer after the handshake so that
  recv() only delivers packets from that peer.
"""

import random
import socket
import threading
import time
from enum import IntEnum, auto
from typing import Optional, Tuple, Union

from .buffer import RecvBuffer, SendWindow
from .congestion import BBR, CUBIC
from .packet import (
    F_ACK, F_DATA, F_FIN, F_RST, F_SYN,
    MAX_SEGMENT_DATA, Packet,
)
from .rtt import RTTEstimator

_HANDSHAKE_TIMEOUT = 5.0
_HANDSHAKE_RETRIES = 5
_IO_POLL           = 0.05    # seconds; recv timeout in background loop
_RETX_POLL         = 0.01    # seconds; retransmit check interval
_TIME_WAIT         = 2.0     # seconds; quiet period before final close
_MONOTONIC_EPOCH   = time.monotonic()


def _ts() -> int:
    """Microseconds since module import, packed into uint64."""
    return int((time.monotonic() - _MONOTONIC_EPOCH) * 1_000_000) & 0xFFFF_FFFF_FFFF_FFFF


class State(IntEnum):
    CLOSED        = auto()
    LISTEN        = auto()
    SYN_SENT      = auto()
    SYN_RECEIVED  = auto()
    ESTABLISHED   = auto()
    FIN_WAIT_1    = auto()
    FIN_WAIT_2    = auto()
    CLOSE_WAIT    = auto()
    LAST_ACK      = auto()
    TIME_WAIT     = auto()


class CTPSocket:
    """
    Reliable transport over UDP with pluggable congestion control.

    Parameters
    ----------
    congestion : "bbr" or "cubic"
        Congestion control algorithm.
    mss : int
        Maximum segment payload in bytes.
    """

    def __init__(
        self,
        congestion: str = "bbr",
        mss: int = MAX_SEGMENT_DATA,
    ) -> None:
        self.mss      = mss
        self._cc_name = congestion.lower()

        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self._state: State                             = State.CLOSED
        self._peer:  Optional[Tuple[str, int]]         = None
        self._local: Optional[Tuple[str, int]]         = None
        self._isn:   int                               = random.randint(0, 2 ** 32 - 1)

        self._send_win: Optional[SendWindow]           = None
        self._recv_buf: Optional[RecvBuffer]           = None
        self._cc:       Optional[Union[BBR, CUBIC]]    = None
        self._rtt:      Optional[RTTEstimator]         = None

        self._established = threading.Event()
        self._close_done  = threading.Event()

        self._running     = False
        self._io_thread:  Optional[threading.Thread]  = None
        self._rtx_thread: Optional[threading.Thread]  = None

        # Lock for state variable only; per-object locks live in SendWindow/RecvBuffer
        self._state_lock = threading.Lock()

    # ── connection setup ───────────────────────────────────────────────────────

    def bind(self, addr: Tuple[str, int]) -> None:
        self._udp.bind(addr)
        self._local = self._udp.getsockname()
        self._state = State.LISTEN

    def connect(self, addr: Tuple[str, int]) -> None:
        """
        Active open.  Performs the three-way handshake and raises
        ConnectionRefusedError if no response is received.
        """
        if self._local is None:
            self._udp.bind(("0.0.0.0", 0))
            self._local = self._udp.getsockname()

        self._peer  = addr
        self._state = State.SYN_SENT
        self._init_tc(self._isn, 0, placeholder_recv=True)

        syn = Packet(seq=self._isn, flags=F_SYN, timestamp=_ts())
        self._udp.settimeout(_HANDSHAKE_TIMEOUT)

        for _ in range(_HANDSHAKE_RETRIES):
            self._udp.sendto(syn.to_bytes(), addr)
            try:
                raw, src = self._udp.recvfrom(65536)
            except socket.timeout:
                continue
            if src != addr:
                continue
            try:
                pkt = Packet.from_bytes(raw)
            except ValueError:
                continue
            if pkt.has(F_SYN) and pkt.has(F_ACK):
                sample = (_ts() - pkt.timestamp) / 1_000_000
                if 0 < sample < 10:
                    self._rtt.update(sample)
                self._recv_buf = RecvBuffer(isn=pkt.seq + 1)
                ack = Packet(
                    seq=pkt.ack, ack=pkt.seq + 1,
                    flags=F_ACK, timestamp=_ts(),
                )
                self._udp.sendto(ack.to_bytes(), addr)
                self._udp.connect(addr)
                self._state = State.ESTABLISHED
                self._start_background()
                return

        self._state = State.CLOSED
        raise ConnectionRefusedError(f"No response from {addr}")

    def accept(self) -> Tuple["CTPSocket", Tuple[str, int]]:
        """
        Passive open.  Blocks until a client completes the handshake.
        The same socket transitions to ESTABLISHED and is returned.
        """
        if self._state != State.LISTEN:
            raise OSError("bind() must be called before accept()")

        self._udp.settimeout(None)   # wait indefinitely for first SYN

        # Wait for a valid SYN
        while True:
            try:
                raw, addr = self._udp.recvfrom(65536)
            except OSError:
                raise
            try:
                pkt = Packet.from_bytes(raw)
            except ValueError:
                continue
            if pkt.has(F_SYN) and not pkt.has(F_ACK):
                break

        self._peer = addr
        self._init_tc(self._isn, pkt.seq, placeholder_recv=False)
        self._state = State.SYN_RECEIVED

        synack = Packet(
            seq=self._isn, ack=pkt.seq + 1,
            flags=F_SYN | F_ACK, timestamp=_ts(),
        )
        self._udp.settimeout(_HANDSHAKE_TIMEOUT)

        for _ in range(_HANDSHAKE_RETRIES):
            self._udp.sendto(synack.to_bytes(), addr)
            try:
                raw2, addr2 = self._udp.recvfrom(65536)
            except socket.timeout:
                continue
            if addr2 != addr:
                continue
            try:
                pkt2 = Packet.from_bytes(raw2)
            except ValueError:
                continue
            if pkt2.has(F_ACK) and not pkt2.has(F_SYN):
                self._udp.connect(addr)
                self._state = State.ESTABLISHED
                self._start_background()
                return self, addr

        self._state = State.CLOSED
        raise ConnectionResetError("Handshake not completed")

    # ── data transfer ──────────────────────────────────────────────────────────

    def send(self, data: bytes) -> int:
        """
        Send data.  Segments are paced according to the congestion control
        algorithm and queued in the send window.  Returns len(data).
        """
        if self._state != State.ESTABLISHED:
            raise BrokenPipeError("Not connected")

        offset = 0
        while offset < len(data):
            chunk_size = min(self.mss, len(data) - offset)

            # Congestion window check: block until there is room
            while self._send_win.inflight_bytes() + chunk_size > self._cc.cwnd:
                time.sleep(0.001)
                if self._state != State.ESTABLISHED:
                    raise BrokenPipeError("Connection lost during send")

            chunk = data[offset: offset + chunk_size]
            seq   = self._send_win.push(chunk)
            pkt   = Packet(
                seq=seq,
                ack=self._recv_buf.next_expected,
                flags=F_DATA | F_ACK,
                window=65535,
                data=chunk,
                timestamp=_ts(),
            )
            try:
                self._udp.send(pkt.to_bytes())
            except OSError:
                raise BrokenPipeError("Send failed")

            # Pacing: spread packets at the BBR pacing rate
            pr = self._cc.pacing_rate
            if pr != float("inf") and pr > 0:
                time.sleep(chunk_size / pr)

            offset += chunk_size

        return len(data)

    def recv(self, bufsize: int, timeout: float = 60.0) -> bytes:
        """Block until up to bufsize bytes arrive or the connection closes."""
        if self._state not in (State.ESTABLISHED, State.CLOSE_WAIT):
            raise BrokenPipeError("Not connected")
        return self._recv_buf.read(bufsize, timeout=timeout)

    def close(self) -> None:
        """Orderly close: drain the send window then exchange FIN."""
        if self._state != State.ESTABLISHED:
            self._teardown()
            return

        # Flush: wait until all sent data is acknowledged
        deadline = time.monotonic() + 30
        while self._send_win.inflight_bytes() > 0:
            if time.monotonic() > deadline:
                break
            time.sleep(0.005)

        self._state = State.FIN_WAIT_1
        fin_seq = self._send_win.next_seq
        fin = Packet(
            seq=fin_seq,
            ack=self._recv_buf.next_expected,
            flags=F_FIN | F_ACK,
            timestamp=_ts(),
        )

        for _ in range(_HANDSHAKE_RETRIES):
            try:
                self._udp.send(fin.to_bytes())
            except OSError:
                break
            if self._close_done.wait(timeout=_HANDSHAKE_TIMEOUT):
                break

        time.sleep(_TIME_WAIT)
        self._teardown()

    # ── private helpers ────────────────────────────────────────────────────────

    def _init_tc(self, isn_local: int, isn_remote: int, placeholder_recv: bool) -> None:
        """Initialise per-connection transport objects."""
        self._send_win = SendWindow(isn=isn_local)
        self._recv_buf = RecvBuffer(isn=isn_remote + 1) if not placeholder_recv else None
        self._rtt      = RTTEstimator()
        self._cc       = BBR(self.mss) if self._cc_name == "bbr" else CUBIC(self.mss)

    def _start_background(self) -> None:
        self._running = True
        self._udp.settimeout(_IO_POLL)
        self._io_thread  = threading.Thread(target=self._io_loop,  daemon=True, name="ctp-io")
        self._rtx_thread = threading.Thread(target=self._rtx_loop, daemon=True, name="ctp-rtx")
        self._io_thread.start()
        self._rtx_thread.start()

    def _teardown(self) -> None:
        self._running = False
        self._state   = State.CLOSED
        if self._recv_buf:
            self._recv_buf.close()
        try:
            self._udp.close()
        except OSError:
            pass

    def _ack_now(self) -> None:
        if self._recv_buf and self._send_win:
            pkt = Packet(
                seq=self._send_win.next_seq,
                ack=self._recv_buf.next_expected,
                flags=F_ACK,
                timestamp=_ts(),
            )
            try:
                self._udp.send(pkt.to_bytes())
            except OSError:
                pass

    # ── background threads ─────────────────────────────────────────────────────

    def _io_loop(self) -> None:
        while self._running:
            try:
                raw = self._udp.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                pkt = Packet.from_bytes(raw)
            except ValueError:
                continue
            self._dispatch(pkt)

    def _dispatch(self, pkt: Packet) -> None:
        state = self._state

        if state == State.ESTABLISHED:
            if pkt.has(F_RST):
                self._teardown()
                return
            if pkt.has(F_DATA):
                if self._recv_buf:
                    self._recv_buf.receive(pkt.seq, pkt.data)
                self._ack_now()
            if pkt.has(F_ACK):
                self._process_ack(pkt)
            if pkt.has(F_FIN):
                self._process_fin(pkt)

        elif state in (State.FIN_WAIT_1, State.FIN_WAIT_2):
            if pkt.has(F_ACK):
                self._process_ack(pkt)
                with self._state_lock:
                    if self._state == State.FIN_WAIT_1:
                        self._state = State.FIN_WAIT_2
            if pkt.has(F_FIN):
                self._process_fin(pkt)

        elif state == State.LAST_ACK:
            if pkt.has(F_ACK):
                self._close_done.set()

    def _process_ack(self, pkt: Packet) -> None:
        if not (self._send_win and self._cc and self._rtt):
            return
        newly, is_dup = self._send_win.ack(pkt.ack, rtt_cb=self._rtt.update)
        if not is_dup and newly > 0:
            rtt = (_ts() - pkt.timestamp) / 1_000_000
            if 0 < rtt < 10:
                self._cc.on_ack(newly, rtt)
            self._rtt.reset_backoff()
        elif self._send_win.dup_ack_count >= 3:
            self._fast_retransmit()

    def _process_fin(self, pkt: Packet) -> None:
        # Echo acknowledgement of the FIN
        ack = Packet(
            seq=self._send_win.next_seq if self._send_win else 0,
            ack=pkt.seq + 1,
            flags=F_ACK,
            timestamp=_ts(),
        )
        try:
            self._udp.send(ack.to_bytes())
        except OSError:
            pass

        state = self._state
        if state == State.ESTABLISHED:
            # Simultaneous or passive close: send our own FIN
            with self._state_lock:
                self._state = State.CLOSE_WAIT
            fin = Packet(
                seq=self._send_win.next_seq if self._send_win else 0,
                ack=pkt.seq + 1,
                flags=F_FIN | F_ACK,
                timestamp=_ts(),
            )
            try:
                self._udp.send(fin.to_bytes())
            except OSError:
                pass
            with self._state_lock:
                self._state = State.LAST_ACK
            if self._recv_buf:
                self._recv_buf.close()

        elif state == State.FIN_WAIT_2:
            self._close_done.set()

    def _fast_retransmit(self) -> None:
        segs = self._send_win.timed_out(0)   # everything in-flight
        if segs:
            oldest = min(segs, key=lambda s: s.seq)
            self._retransmit(oldest.seq)

    def _rtx_loop(self) -> None:
        while self._running:
            time.sleep(_RETX_POLL)
            if self._state != State.ESTABLISHED:
                continue
            if not (self._send_win and self._rtt):
                continue
            for seg in self._send_win.timed_out(self._rtt.rto):
                self._retransmit(seg.seq)
                self._rtt.backoff()
                if self._cc:
                    self._cc.on_loss()

    def _retransmit(self, seq: int) -> None:
        seg = self._send_win.get(seq)
        if seg is None:
            return
        self._send_win.mark_retransmit(seq)
        pkt = Packet(
            seq=seq,
            ack=self._recv_buf.next_expected if self._recv_buf else 0,
            flags=F_DATA | F_ACK,
            window=65535,
            data=seg.data,
            timestamp=_ts(),
        )
        try:
            self._udp.send(pkt.to_bytes())
        except OSError:
            pass

    # ── repr ──────────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"CTPSocket(state={self._state.name}, "
            f"cc={self._cc_name}, local={self._local}, peer={self._peer})"
        )
