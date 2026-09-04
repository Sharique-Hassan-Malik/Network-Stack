"""Wire format: the pure half, tested without a network.

Everything here runs on bytes. The hostile-input cases matter most — a resolver
parses packets from servers it has never met, several of which are not friendly.
"""

from __future__ import annotations

import struct

import pytest

from dnskit import wire


# ---- names ----------------------------------------------------------------

def test_a_name_round_trips():
    encoded = wire.encode_name("www.example.com")
    name, end = wire.decode_name(encoded, 0)
    assert name == "www.example.com."
    assert end == len(encoded)


def test_the_root_is_a_single_zero_byte():
    assert wire.encode_name(".") == b"\x00"
    assert wire.decode_name(b"\x00", 0) == (".", 1)


def test_names_compare_case_insensitively_but_keep_their_case_on_the_wire():
    # RFC 4343. The wire form must preserve case — that is what makes 0x20
    # encoding possible — while comparison ignores it.
    assert wire.normalise("WwW.Example.COM") == "www.example.com."
    assert b"WwW" in wire.encode_name("WwW.example.com")


def test_an_over_long_label_is_refused():
    with pytest.raises(wire.WireError):
        wire.encode_name("a" * 64 + ".com")


def test_an_over_long_name_is_refused():
    with pytest.raises(wire.WireError):
        wire.encode_name(".".join(["abcdefghij"] * 30))


# ---- compression, and the ways it is abused -------------------------------

def test_a_compression_pointer_is_followed():
    # "example.com" at offset 12, then a pointer back to it.
    message = bytearray(b"\x00" * 12)
    message += wire.encode_name("example.com")
    pointer_at = len(message)
    message += struct.pack("!H", 0xC000 | 12)

    name, end = wire.decode_name(bytes(message), pointer_at)
    assert name == "example.com."
    # The cursor advances past the two pointer bytes, not past the target.
    assert end == pointer_at + 2


def test_a_pointer_to_itself_is_refused_rather_than_looping():
    # Four bytes that hang a naive parser forever.
    message = b"\x00" * 12 + struct.pack("!H", 0xC000 | 12)
    with pytest.raises(wire.WireError, match="backwards|loop"):
        wire.decode_name(message, 12)


def test_a_forward_pointer_is_refused():
    # Pointing forwards is how the same loop is written without pointing at
    # yourself: two pointers that reference each other.
    message = bytearray(b"\x00" * 12)
    message += struct.pack("!H", 0xC000 | 16)   # at 12, points to 16
    message += struct.pack("!H", 0xC000 | 12)   # at 14 (unused)
    message += struct.pack("!H", 0xC000 | 12)   # at 16, points back to 12
    with pytest.raises(wire.WireError):
        wire.decode_name(bytes(message), 12)


def test_a_pointer_chain_cannot_describe_an_unbounded_name():
    """Legal backward pointers, arbitrarily long result.

    Every pointer here points strictly backwards, so the loop check alone does
    not stop it. The length cap is what does.
    """
    # A chain of labels each ending in a pointer to the previous one.
    message = bytearray(b"\x00" * 12)
    prev = None
    for _ in range(80):
        here = len(message)
        message.append(9)
        message += b"aaaaaaaaa"
        if prev is None:
            message.append(0)
        else:
            message += struct.pack("!H", 0xC000 | prev)
        prev = here
    with pytest.raises(wire.WireError, match="maximum length"):
        wire.decode_name(bytes(message), prev)


def test_a_reserved_label_type_is_refused():
    message = b"\x00" * 12 + bytes([0x80])
    with pytest.raises(wire.WireError, match="reserved"):
        wire.decode_name(message, 12)


def test_a_truncated_name_is_refused():
    message = b"\x00" * 12 + bytes([5]) + b"ab"      # says 5, gives 2
    with pytest.raises(wire.WireError):
        wire.decode_name(message, 12)


# ---- messages -------------------------------------------------------------

def test_a_query_encodes_to_the_expected_shape():
    query = wire.encode_query("example.com", wire.TYPE_A, 0x1234)
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", query, 0)
    assert ident == 0x1234
    assert (qd, an, ns, ar) == (1, 0, 0, 0)
    assert flags & 0x0100 == 0, "recursion must be off by default: this is an iterative resolver"


def test_a_query_round_trips_through_the_decoder():
    query = wire.encode_query("www.example.com", wire.TYPE_AAAA, 0xBEEF)
    msg = wire.decode_message(query)
    assert msg.ident == 0xBEEF
    assert not msg.response
    assert len(msg.questions) == 1
    assert msg.questions[0].name == "www.example.com."
    assert msg.questions[0].qtype == wire.TYPE_AAAA


def _build_response(records: list[tuple[str, int, int, bytes]], *, rcode: int = 0):
    """A response carrying `records` as answers, with no compression."""
    body = bytearray()
    body += wire.encode_name("example.com") + struct.pack("!HH", wire.TYPE_A, 1)
    for name, rtype, ttl, rdata in records:
        body += wire.encode_name(name)
        body += struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
        body += rdata
    header = struct.pack("!HHHHHH", 0x4242, 0x8180 | rcode, 1, len(records), 0, 0)
    return bytes(header) + bytes(body)


def test_an_a_record_is_parsed_to_dotted_quad():
    msg = wire.decode_message(_build_response(
        [("example.com", wire.TYPE_A, 300, bytes([93, 184, 216, 34]))]))
    assert msg.response
    assert msg.answers[0].parsed == "93.184.216.34"
    assert msg.answers[0].ttl == 300


def test_an_aaaa_record_is_parsed_to_a_v6_string():
    rdata = bytes.fromhex("20010db8000000000000000000000001")
    msg = wire.decode_message(_build_response(
        [("example.com", wire.TYPE_AAAA, 60, rdata)]))
    assert msg.answers[0].parsed == "2001:0db8:0000:0000:0000:0000:0000:0001"


def test_a_message_shorter_than_a_header_is_refused():
    with pytest.raises(wire.WireError):
        wire.decode_message(b"\x00\x01\x02")


def test_rdata_running_past_the_end_is_refused():
    body = wire.encode_name("example.com") + struct.pack("!HH", wire.TYPE_A, 1)
    body += wire.encode_name("example.com")
    body += struct.pack("!HHIH", wire.TYPE_A, 1, 300, 400)   # claims 400 bytes
    body += b"\x01\x02"
    header = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    with pytest.raises(wire.WireError, match="past the end"):
        wire.decode_message(header + body)


def test_ttl_is_read_as_unsigned():
    """A TTL above 2^31 must not come back negative.

    Signed parsing turns a long TTL into a value that is always in the past,
    so every such record is treated as immediately stale — a cache that never
    caches exactly the records the zone wanted cached longest.
    """
    msg = wire.decode_message(_build_response(
        [("example.com", wire.TYPE_A, 0xF000_0000, bytes([1, 2, 3, 4]))]))
    assert msg.answers[0].ttl == 0xF000_0000
    assert msg.answers[0].ttl > 0
