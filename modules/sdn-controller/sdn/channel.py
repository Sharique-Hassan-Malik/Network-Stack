"""
OpenFlow channel: one persistent TCP connection per switch.

Each connected switch runs in its own thread.  Incoming messages are
dispatched to a registered handler via a callback dict keyed on OFPType.
The controller hands back a SwitchConnection object per switch so the
application layer can send messages without touching the socket directly.

Message framing: every OpenFlow message starts with an 8-byte header
containing the total length.  The reader buffers bytes until a complete
message is available.
"""

from __future__ import annotations

import logging
import socket
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from .openflow import (
    OFP_VERSION, OFPType,
    unpack_header, HEADER_SIZE,
    hello, echo_reply, features_request,
)

log = logging.getLogger(__name__)


@dataclass
class SwitchConnection:
    """
    Represents one live switch connection.

    Attributes
    ----------
    dpid : int
        Datapath ID (set after FEATURES_REPLY is received).
    address : tuple
        (ip, port) of the connecting switch.
    """
    address:  tuple
    dpid:     int   = 0
    _sock:    socket.socket = field(repr=False, default=None)
    _lock:    threading.Lock = field(repr=False, default_factory=threading.Lock)

    def send(self, msg: bytes) -> None:
        with self._lock:
            try:
                self._sock.sendall(msg)
            except OSError as e:
                log.warning("send to %s failed: %s", self.address, e)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def __repr__(self) -> str:
        dpid_str = f"0x{self.dpid:016x}" if self.dpid else "unknown"
        return f"SwitchConnection(dpid={dpid_str}, addr={self.address})"


MessageHandler = Callable[[SwitchConnection, bytes], None]


class OpenFlowServer:
    """
    Listens for incoming switch connections and drives the message loop.

    Parameters
    ----------
    host : str
    port : int
    handlers : dict[OFPType, MessageHandler]
        Callbacks invoked when a message of the given type is received.
    on_connect : callable, optional
        Called with SwitchConnection after the initial handshake completes.
    on_disconnect : callable, optional
        Called with SwitchConnection when the TCP connection drops.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 6653,
        handlers: Optional[dict] = None,
        on_connect:    Optional[Callable[[SwitchConnection], None]] = None,
        on_disconnect: Optional[Callable[[SwitchConnection], None]] = None,
    ) -> None:
        self._host           = host
        self._port           = port
        self._handlers:  dict[int, MessageHandler] = handlers or {}
        self._on_connect     = on_connect
        self._on_disconnect  = on_disconnect
        self._connections:   dict[int, SwitchConnection] = {}
        self._conn_lock      = threading.Lock()
        self._running        = False
        self._server_sock:   Optional[socket.socket] = None
        self._xid            = 1

    # ── public interface ──────────────────────────────────────────────────────

    def start(self) -> None:
        self._running      = True
        self._server_sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self._host, self._port))
        self._server_sock.listen(64)
        self._server_sock.settimeout(1.0)
        log.info("OpenFlow controller listening on %s:%d", self._host, self._port)
        t = threading.Thread(target=self._accept_loop, daemon=True, name="of-accept")
        t.start()

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            self._server_sock.close()
        with self._conn_lock:
            for conn in list(self._connections.values()):
                conn.close()

    def register(self, msg_type: int, handler: MessageHandler) -> None:
        self._handlers[msg_type] = handler

    def connections(self) -> list[SwitchConnection]:
        with self._conn_lock:
            return list(self._connections.values())

    def next_xid(self) -> int:
        xid = self._xid
        self._xid = (self._xid + 1) & 0xFFFFFFFF
        return xid

    # ── accept loop ───────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        while self._running:
            try:
                sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn = SwitchConnection(address=addr, _sock=sock)
            log.info("New connection from %s", addr)
            t = threading.Thread(
                target=self._handle_connection,
                args=(conn,),
                daemon=True,
                name=f"of-conn-{addr}",
            )
            t.start()

    # ── per-switch message loop ───────────────────────────────────────────────

    def _handle_connection(self, conn: SwitchConnection) -> None:
        # Handshake: send Hello then Features Request
        conn.send(hello(self.next_xid()))
        conn.send(features_request(self.next_xid()))

        buf = b""
        conn._sock.settimeout(30.0)

        try:
            while self._running:
                try:
                    chunk = conn._sock.recv(4096)
                except socket.timeout:
                    # Send echo to keep alive
                    conn.send(b"")
                    continue
                if not chunk:
                    break
                buf += chunk
                buf = self._drain_messages(conn, buf)
        except OSError:
            pass
        finally:
            with self._conn_lock:
                self._connections.pop(conn.dpid, None)
            if self._on_disconnect:
                self._on_disconnect(conn)
            conn.close()
            log.info("Disconnected: %s", conn)

    def _drain_messages(self, conn: SwitchConnection, buf: bytes) -> bytes:
        while len(buf) >= HEADER_SIZE:
            version, msg_type, length, xid = unpack_header(buf[:HEADER_SIZE])
            if len(buf) < length:
                break
            msg  = buf[:length]
            buf  = buf[length:]
            self._dispatch(conn, msg_type, msg, xid)
        return buf

    def _dispatch(self, conn: SwitchConnection, msg_type: int, msg: bytes, xid: int) -> None:
        # Built-in handling before user callbacks
        if msg_type == OFPType.HELLO:
            pass   # handshake already initiated

        elif msg_type == OFPType.ECHO_REQUEST:
            conn.send(echo_reply(xid, msg[HEADER_SIZE:]))
            return

        elif msg_type == OFPType.FEATURES_REPLY:
            from .openflow import FeaturesReply
            feat = FeaturesReply.from_bytes(msg)
            conn.dpid = feat.datapath_id
            with self._conn_lock:
                self._connections[conn.dpid] = conn
            log.info("Switch connected: dpid=0x%016x", conn.dpid)
            if self._on_connect:
                self._on_connect(conn)

        handler = self._handlers.get(msg_type)
        if handler:
            try:
                handler(conn, msg)
            except Exception:
                log.exception("Handler error for type %d on %s", msg_type, conn)
