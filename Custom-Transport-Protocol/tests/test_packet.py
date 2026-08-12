import pytest
import zlib

from ctp.packet import (
    Packet, HEADER_SIZE, MAX_SEGMENT_DATA, SEQ_SPACE,
    F_SYN, F_ACK, F_FIN, F_DATA,
)


class TestPacketRoundTrip:
    def test_empty_payload(self):
        pkt = Packet(seq=100, ack=200, flags=F_ACK)
        raw = pkt.to_bytes()
        got = Packet.from_bytes(raw)
        assert got.seq    == pkt.seq
        assert got.ack    == pkt.ack
        assert got.flags  == pkt.flags
        assert got.data   == b""

    def test_with_payload(self):
        payload = b"hello, transport layer"
        pkt = Packet(seq=0, ack=0, flags=F_DATA | F_ACK, data=payload)
        raw = pkt.to_bytes()
        got = Packet.from_bytes(raw)
        assert got.data == payload

    def test_max_size_payload(self):
        payload = bytes(range(256)) * (MAX_SEGMENT_DATA // 256)
        pkt = Packet(seq=1, ack=2, flags=F_DATA, data=payload[:MAX_SEGMENT_DATA])
        got = Packet.from_bytes(pkt.to_bytes())
        assert got.data == payload[:MAX_SEGMENT_DATA]

    def test_flag_combinations(self):
        for flags in (F_SYN, F_SYN | F_ACK, F_FIN | F_ACK, F_DATA | F_ACK):
            pkt = Packet(flags=flags)
            got = Packet.from_bytes(pkt.to_bytes())
            assert got.flags == flags

    def test_seq_wraparound(self):
        pkt = Packet(seq=2**32 - 1, ack=0)
        got = Packet.from_bytes(pkt.to_bytes())
        assert got.seq == 2**32 - 1

    def test_timestamp_preserved(self):
        pkt = Packet(timestamp=123456789)
        got = Packet.from_bytes(pkt.to_bytes())
        assert got.timestamp == 123456789


class TestPacketChecksum:
    def test_corrupt_payload_rejected(self):
        pkt = Packet(seq=1, flags=F_DATA, data=b"secret")
        raw = bytearray(pkt.to_bytes())
        raw[-1] ^= 0xFF   # flip a byte in the payload
        with pytest.raises(ValueError, match="Checksum"):
            Packet.from_bytes(bytes(raw))

    def test_corrupt_header_rejected(self):
        pkt = Packet(seq=42, ack=7, flags=F_ACK)
        raw = bytearray(pkt.to_bytes())
        raw[0] ^= 0x01   # flip a bit in seq field
        with pytest.raises(ValueError):
            Packet.from_bytes(bytes(raw))

    def test_clean_packet_accepted(self):
        pkt = Packet(seq=999, ack=888, flags=F_SYN | F_ACK, data=b"ok")
        Packet.from_bytes(pkt.to_bytes())   # must not raise


class TestPacketSizeContract:
    def test_header_size(self):
        import struct
        assert HEADER_SIZE == struct.calcsize("!IIBBHHIQ")

    def test_overhead_per_segment(self):
        payload = b"A" * MAX_SEGMENT_DATA
        pkt = Packet(flags=F_DATA, data=payload)
        overhead = len(pkt.to_bytes()) - len(payload)
        assert overhead == HEADER_SIZE

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="Too short"):
            Packet.from_bytes(b"\x00" * (HEADER_SIZE - 1))


class TestHasFlag:
    def test_has_returns_true(self):
        pkt = Packet(flags=F_SYN | F_ACK)
        assert pkt.has(F_SYN)
        assert pkt.has(F_ACK)

    def test_has_returns_false(self):
        pkt = Packet(flags=F_SYN)
        assert not pkt.has(F_ACK)
        assert not pkt.has(F_FIN)
