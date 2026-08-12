"""
OpenFlow 1.3 message structures (RFC-like spec: ONF-TS-011).

Only the subset needed for this controller is implemented:
  Hello, Features Request/Reply, Echo Request/Reply,
  Packet-In, Packet-Out, Flow-Mod, Port-Status, Stats/Multipart Request/Reply.

All fields are big-endian (network order) per the OpenFlow spec.

Wire layout reference: openflow-spec-v1.3.5.pdf
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum


# ── version / type constants ──────────────────────────────────────────────────

OFP_VERSION = 0x04   # OpenFlow 1.3

class OFPType(IntEnum):
    HELLO               = 0
    ERROR               = 1
    ECHO_REQUEST        = 2
    ECHO_REPLY          = 3
    FEATURES_REQUEST    = 5
    FEATURES_REPLY      = 6
    GET_CONFIG_REQUEST  = 7
    GET_CONFIG_REPLY    = 8
    SET_CONFIG          = 9
    PACKET_IN           = 10
    FLOW_REMOVED        = 11
    PORT_STATUS         = 12
    PACKET_OUT          = 13
    FLOW_MOD            = 14
    GROUP_MOD           = 15
    PORT_MOD            = 16
    TABLE_MOD           = 17
    MULTIPART_REQUEST   = 18
    MULTIPART_REPLY     = 19
    BARRIER_REQUEST     = 20
    BARRIER_REPLY       = 21


class OFPFlowModCommand(IntEnum):
    ADD     = 0
    MODIFY  = 1
    DELETE  = 3


class OFPActionType(IntEnum):
    OUTPUT      = 0
    COPY_TTL_OUT= 11
    COPY_TTL_IN = 12
    SET_MPLS_TTL= 15
    DEC_MPLS_TTL= 16
    PUSH_VLAN   = 17
    POP_VLAN    = 18
    SET_FIELD   = 25
    PUSH_PBB    = 26
    POP_PBB     = 27
    EXPERIMENTER= 0xFFFF


class OFPPortNo(IntEnum):
    MAX        = 0xFFFFFF00
    IN_PORT    = 0xFFFFFFF8
    TABLE      = 0xFFFFFFF9
    NORMAL     = 0xFFFFFFFA
    FLOOD      = 0xFFFFFFFB
    ALL        = 0xFFFFFFFC
    CONTROLLER = 0xFFFFFFFD
    LOCAL      = 0xFFFFFFFE
    ANY        = 0xFFFFFFFF


class OFPPacketInReason(IntEnum):
    NO_MATCH    = 0
    ACTION      = 1
    INVALID_TTL = 2


class OFPPortReason(IntEnum):
    ADD    = 0
    DELETE = 1
    MODIFY = 2


class OFPMultipartType(IntEnum):
    DESC        = 0
    FLOW        = 1
    AGGREGATE   = 2
    TABLE       = 3
    PORT_STATS  = 4
    PORT_DESC   = 13


# ── header ────────────────────────────────────────────────────────────────────

HEADER_SIZE = 8

def pack_header(msg_type: int, length: int, xid: int) -> bytes:
    return struct.pack("!BBHI", OFP_VERSION, msg_type, length, xid)

def unpack_header(buf: bytes) -> tuple[int, int, int, int]:
    """Returns (version, type, length, xid)."""
    return struct.unpack_from("!BBHI", buf)


# ── Hello ─────────────────────────────────────────────────────────────────────

def hello(xid: int = 0) -> bytes:
    return pack_header(OFPType.HELLO, HEADER_SIZE, xid)


# ── Echo ──────────────────────────────────────────────────────────────────────

def echo_request(xid: int, data: bytes = b"") -> bytes:
    return pack_header(OFPType.ECHO_REQUEST, HEADER_SIZE + len(data), xid) + data

def echo_reply(xid: int, data: bytes = b"") -> bytes:
    return pack_header(OFPType.ECHO_REPLY, HEADER_SIZE + len(data), xid) + data


# ── Features ──────────────────────────────────────────────────────────────────

def features_request(xid: int) -> bytes:
    return pack_header(OFPType.FEATURES_REQUEST, HEADER_SIZE, xid)

@dataclass
class FeaturesReply:
    datapath_id: int
    n_buffers:   int
    n_tables:    int
    aux_id:      int
    capabilities:int
    xid:         int

    @classmethod
    def from_bytes(cls, buf: bytes) -> "FeaturesReply":
        _, _, _, xid = unpack_header(buf[:HEADER_SIZE])
        dpid, n_buf, n_tab, aux, cap, _ = struct.unpack_from("!QIBBHI", buf, HEADER_SIZE)
        return cls(datapath_id=dpid, n_buffers=n_buf, n_tables=n_tab,
                   aux_id=aux, capabilities=cap, xid=xid)


# ── Packet-In ─────────────────────────────────────────────────────────────────

@dataclass
class PacketIn:
    buffer_id:  int
    total_len:  int
    reason:     int
    table_id:   int
    cookie:     int
    in_port:    int
    data:       bytes
    xid:        int

    @classmethod
    def from_bytes(cls, buf: bytes) -> "PacketIn":
        _, _, _, xid = unpack_header(buf[:HEADER_SIZE])
        off  = HEADER_SIZE
        buf_id, tot_len, reason, table_id = struct.unpack_from("!IHBB", buf, off)
        off += 8
        cookie = struct.unpack_from("!Q", buf, off)[0]; off += 8
        # Match structure: parse just enough to find in_port
        # OXM match: type(2) + length(2) + oxm_fields...
        match_type = struct.unpack_from("!H", buf, off)[0]; off += 2
        match_len  = struct.unpack_from("!H", buf, off)[0]; off += 2
        in_port    = 0
        # Walk OXM TLVs to find IN_PORT (oxm_field = 0)
        m_end = (HEADER_SIZE + 8 + 8 + 4 + match_len - 4)
        pos   = HEADER_SIZE + 8 + 8 + 4
        while pos + 4 <= m_end and pos + 4 <= len(buf):
            oxm_class = struct.unpack_from("!H", buf, pos)[0]
            oxm_field = (buf[pos + 2] >> 1) & 0x7F
            oxm_len   = buf[pos + 3]
            if oxm_class == 0x8000 and oxm_field == 0 and oxm_len == 4:
                in_port = struct.unpack_from("!I", buf, pos + 4)[0]
            pos += 4 + oxm_len

        # Align to 8 bytes then skip 2-byte pad
        match_end = HEADER_SIZE + 8 + 8 + align8(match_len)
        data_off  = match_end + 2
        data = buf[data_off:] if data_off < len(buf) else b""

        return cls(buffer_id=buf_id, total_len=tot_len, reason=reason,
                   table_id=table_id, cookie=cookie, in_port=in_port,
                   data=data, xid=xid)


def align8(n: int) -> int:
    return (n + 7) & ~7


# ── Packet-Out ────────────────────────────────────────────────────────────────

def packet_out(
    xid: int,
    buffer_id: int,
    in_port: int,
    actions: bytes,
    data: bytes = b"",
) -> bytes:
    actions_len = len(actions)
    body = struct.pack("!IIH2x", buffer_id, in_port, actions_len)
    total = HEADER_SIZE + len(body) + actions_len + len(data)
    return pack_header(OFPType.PACKET_OUT, total, xid) + body + actions + data


# ── Actions ───────────────────────────────────────────────────────────────────

def action_output(port: int, max_len: int = 0xFFFF) -> bytes:
    """OFPAT_OUTPUT — forward to port."""
    return struct.pack("!HHIH", OFPActionType.OUTPUT, 16, port, max_len) + b"\x00" * 6


def action_set_field_vlan_vid(vlan_id: int) -> bytes:
    """OFPAT_SET_FIELD — set VLAN VID."""
    # OXM TLV for VLAN_VID: class=0x8000 field=6 hasmask=0 len=2
    oxm = struct.pack("!HBB", 0x8000, (6 << 1), 2) + struct.pack("!H", vlan_id | 0x1000)
    pad = b"\x00" * (align8(4 + len(oxm)) - 4 - len(oxm))
    length = 4 + len(oxm) + len(pad)
    return struct.pack("!HH", OFPActionType.SET_FIELD, length) + oxm + pad


# ── Flow-Mod ──────────────────────────────────────────────────────────────────

def _build_oxm_match(fields: dict) -> bytes:
    """
    Build an OXM match structure from a dict of field_name → value.

    Supported field names: in_port, eth_dst, eth_src, eth_type,
                           ipv4_src, ipv4_dst, ip_proto, tcp_dst, udp_dst.
    """
    OXM_FIELD = {
        "in_port":  (0x8000, 0,  4),
        "eth_dst":  (0x8000, 3,  6),
        "eth_src":  (0x8000, 4,  6),
        "eth_type": (0x8000, 5,  2),
        "ipv4_src": (0x8000, 11, 4),
        "ipv4_dst": (0x8000, 12, 4),
        "ip_proto": (0x8000, 10, 1),
        "tcp_dst":  (0x8000, 22, 2),
        "udp_dst":  (0x8000, 23, 2),
    }
    import socket as _s
    oxm = b""
    for name, value in fields.items():
        cls_, fid, flen = OXM_FIELD[name]
        header = struct.pack("!HBB", cls_, fid << 1, flen)
        if isinstance(value, str) and ":" in value:
            raw = bytes(int(x, 16) for x in value.split(":"))
        elif isinstance(value, str) and "." in value:
            raw = _s.inet_aton(value)
        else:
            raw = int(value).to_bytes(flen, "big")
        oxm += header + raw

    match_len = 4 + len(oxm)
    pad       = b"\x00" * (align8(match_len) - match_len)
    return struct.pack("!HH", 1, match_len) + oxm + pad   # type=OXM_MT_OXM=1


def flow_mod(
    xid:       int,
    command:   int,
    priority:  int,
    match:     bytes,
    actions:   bytes,
    table_id:  int  = 0,
    idle_timeout: int = 0,
    hard_timeout: int = 0,
    buffer_id: int  = 0xFFFFFFFF,
    out_port:  int  = OFPPortNo.ANY,
    flags:     int  = 0,
    cookie:    int  = 0,
) -> bytes:
    instructions = b""
    if actions:
        # OFPIT_APPLY_ACTIONS = 4
        inst_len = 8 + len(actions)
        instructions = struct.pack("!HH4x", 4, inst_len) + actions

    body = struct.pack(
        "!QQBBHHHIIIH2x",
        cookie, 0,
        table_id, command,
        idle_timeout, hard_timeout,
        priority, buffer_id,
        out_port, int(OFPPortNo.ANY),
        flags,
    )
    total = HEADER_SIZE + len(body) + len(match) + len(instructions)
    return (
        pack_header(OFPType.FLOW_MOD, total, xid)
        + body
        + match
        + instructions
    )


# ── Port-Status ───────────────────────────────────────────────────────────────

@dataclass
class PortStatus:
    reason:    int
    port_no:   int
    hw_addr:   bytes
    name:      str
    config:    int
    state:     int
    xid:       int

    PORT_LIVE  = 0
    PORT_LINK_DOWN = 1 << 0
    PORT_BLOCKED   = 1 << 1

    @classmethod
    def from_bytes(cls, buf: bytes) -> "PortStatus":
        _, _, _, xid = unpack_header(buf[:HEADER_SIZE])
        reason = struct.unpack_from("!B", buf, HEADER_SIZE)[0]
        off    = HEADER_SIZE + 8   # reason + 7 pad
        port_no, _, hw_addr, _, name_raw, config, state = struct.unpack_from(
            "!I4s6s2s16sII", buf, off
        )
        return cls(
            reason=reason, port_no=port_no, hw_addr=hw_addr,
            name=name_raw.rstrip(b"\x00").decode("ascii", errors="replace"),
            config=config, state=state, xid=xid,
        )


# ── Multipart (Stats) ─────────────────────────────────────────────────────────

def multipart_request(xid: int, mtype: int, body: bytes = b"", flags: int = 0) -> bytes:
    total = HEADER_SIZE + 4 + len(body)
    return pack_header(OFPType.MULTIPART_REQUEST, total, xid) + struct.pack("!HH", mtype, flags) + body

@dataclass
class PortStats:
    port_no:    int
    rx_packets: int
    tx_packets: int
    rx_bytes:   int
    tx_bytes:   int
    rx_dropped: int
    tx_dropped: int
    rx_errors:  int
    tx_errors:  int

    @classmethod
    def parse_reply(cls, buf: bytes) -> list["PortStats"]:
        """Parse a MULTIPART_REPLY body containing port stats entries."""
        stats: list[PortStats] = []
        off = HEADER_SIZE + 4   # skip header + multipart type/flags
        while off + 112 <= len(buf):
            fields = struct.unpack_from("!I4x" + "Q" * 13, buf, off)
            stats.append(cls(
                port_no    = fields[0],
                rx_packets = fields[1],
                tx_packets = fields[2],
                rx_bytes   = fields[3],
                tx_bytes   = fields[4],
                rx_dropped = fields[5],
                tx_dropped = fields[6],
                rx_errors  = fields[7],
                tx_errors  = fields[8],
            ))
            off += 112
        return stats


# ── Barrier ───────────────────────────────────────────────────────────────────

def barrier_request(xid: int) -> bytes:
    return pack_header(OFPType.BARRIER_REQUEST, HEADER_SIZE, xid)
