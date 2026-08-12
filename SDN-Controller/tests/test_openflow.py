import struct
import pytest

from sdn.openflow import (
    OFP_VERSION, OFPType, OFPPortNo, OFPFlowModCommand,
    HEADER_SIZE, pack_header, unpack_header,
    hello, echo_request, echo_reply, features_request,
    action_output, flow_mod, packet_out, barrier_request,
    _build_oxm_match, align8,
    FeaturesReply, PortStats,
    multipart_request, OFPMultipartType,
)


class TestHeader:
    def test_pack_unpack_roundtrip(self):
        raw = pack_header(OFPType.HELLO, 8, 42)
        ver, typ, length, xid = unpack_header(raw)
        assert ver    == OFP_VERSION
        assert typ    == OFPType.HELLO
        assert length == 8
        assert xid    == 42

    def test_correct_size(self):
        raw = pack_header(OFPType.PACKET_IN, 64, 1)
        assert len(raw) == HEADER_SIZE

    def test_version_is_1_3(self):
        raw = hello(0)
        assert raw[0] == 0x04


class TestHelloEcho:
    def test_hello_length(self):
        h = hello(0)
        assert len(h) == HEADER_SIZE
        _, _, length, _ = unpack_header(h)
        assert length == HEADER_SIZE

    def test_echo_request_type(self):
        er = echo_request(5, b"ping")
        _, typ, _, xid = unpack_header(er)
        assert typ == OFPType.ECHO_REQUEST
        assert xid == 5
        assert er[HEADER_SIZE:] == b"ping"

    def test_echo_reply_type(self):
        reply = echo_reply(5, b"pong")
        _, typ, _, _ = unpack_header(reply)
        assert typ == OFPType.ECHO_REPLY
        assert reply[HEADER_SIZE:] == b"pong"

    def test_echo_length_field(self):
        er = echo_request(1, b"ABCD")
        _, _, length, _ = unpack_header(er)
        assert length == HEADER_SIZE + 4


class TestActionOutput:
    def test_output_to_port(self):
        act = action_output(3)
        assert len(act) == 16
        action_type = struct.unpack_from("!H", act, 0)[0]
        assert action_type == 0   # OFPAT_OUTPUT

    def test_output_port_value(self):
        act = action_output(7)
        port = struct.unpack_from("!I", act, 4)[0]
        assert port == 7

    def test_output_to_controller(self):
        act = action_output(OFPPortNo.CONTROLLER)
        port = struct.unpack_from("!I", act, 4)[0]
        assert port == int(OFPPortNo.CONTROLLER)

    def test_flood(self):
        act = action_output(OFPPortNo.FLOOD)
        port = struct.unpack_from("!I", act, 4)[0]
        assert port == int(OFPPortNo.FLOOD)


class TestOXMMatch:
    def test_empty_match(self):
        m = _build_oxm_match({})
        assert len(m) >= 4   # at least type + length

    def test_match_type_oxm(self):
        m = _build_oxm_match({})
        match_type = struct.unpack_from("!H", m, 0)[0]
        assert match_type == 1   # OXM_MT_OXM

    def test_in_port_field(self):
        m = _build_oxm_match({"in_port": 2})
        assert len(m) > 4

    def test_eth_type_field(self):
        m = _build_oxm_match({"eth_type": 0x0800})
        assert len(m) > 4

    def test_align8_values(self):
        assert align8(0)  == 0
        assert align8(1)  == 8
        assert align8(8)  == 8
        assert align8(9)  == 16
        assert align8(16) == 16

    def test_multiple_fields(self):
        m = _build_oxm_match({"in_port": 1, "eth_type": 0x0800})
        # Should be longer than a single-field match
        single = _build_oxm_match({"in_port": 1})
        assert len(m) >= len(single)


class TestFlowMod:
    def test_flow_mod_type(self):
        match   = _build_oxm_match({})
        actions = action_output(1)
        fm = flow_mod(xid=1, command=OFPFlowModCommand.ADD,
                      priority=10, match=match, actions=actions)
        _, typ, _, xid = unpack_header(fm[:HEADER_SIZE])
        assert typ == OFPType.FLOW_MOD
        assert xid == 1

    def test_flow_mod_length_consistent(self):
        match   = _build_oxm_match({"eth_dst": "aa:bb:cc:dd:ee:ff"})
        actions = action_output(2)
        fm = flow_mod(xid=2, command=OFPFlowModCommand.ADD,
                      priority=5, match=match, actions=actions)
        _, _, length, _ = unpack_header(fm[:HEADER_SIZE])
        assert length == len(fm)

    def test_delete_command(self):
        match = _build_oxm_match({})
        fm    = flow_mod(xid=3, command=OFPFlowModCommand.DELETE,
                         priority=0, match=match, actions=b"")
        assert len(fm) >= HEADER_SIZE


class TestPacketOut:
    def test_type(self):
        po = packet_out(xid=1, buffer_id=0xFFFFFFFF, in_port=1,
                        actions=action_output(2), data=b"frame")
        _, typ, _, _ = unpack_header(po)
        assert typ == OFPType.PACKET_OUT

    def test_length_field(self):
        actions = action_output(3)
        po = packet_out(xid=1, buffer_id=0xFFFFFFFF, in_port=1,
                        actions=actions, data=b"eth frame here")
        _, _, length, _ = unpack_header(po)
        assert length == len(po)

    def test_no_data_when_buffered(self):
        actions = action_output(3)
        po = packet_out(xid=1, buffer_id=42, in_port=1, actions=actions)
        _, _, length, _ = unpack_header(po)
        assert length == len(po)


class TestMultipart:
    def test_port_stats_request(self):
        req = multipart_request(1, OFPMultipartType.PORT_STATS)
        _, typ, _, _ = unpack_header(req)
        assert typ == OFPType.MULTIPART_REQUEST

    def test_barrier(self):
        br = barrier_request(99)
        _, typ, _, xid = unpack_header(br)
        assert typ == OFPType.BARRIER_REQUEST
        assert xid == 99
