import pytest

from quic.packet import LongHeader, ShortHeader, PacketType, QUIC_VERSION
from quic.stream import SendStream, RecvStream, StreamManager, StreamState
from quic.frames import StreamFrame


# ── long header ───────────────────────────────────────────────────────────────

class TestLongHeader:
    def test_initial_round_trip(self):
        hdr = LongHeader(
            ptype=PacketType.INITIAL,
            dcid=b"\x01" * 8,
            scid=b"\x02" * 8,
            pn=42,
        )
        payload = b"test payload"
        raw = hdr.to_bytes(payload)
        got, got_payload, _ = LongHeader.from_bytes(raw)

        assert got.ptype   == PacketType.INITIAL
        assert got.dcid    == b"\x01" * 8
        assert got.scid    == b"\x02" * 8
        assert got.pn      == 42
        assert got_payload == payload

    def test_handshake_round_trip(self):
        hdr = LongHeader(ptype=PacketType.HANDSHAKE, dcid=b"\xab" * 4, scid=b"\xcd" * 4, pn=1)
        raw = hdr.to_bytes(b"handshake data")
        got, payload, _ = LongHeader.from_bytes(raw)
        assert got.ptype == PacketType.HANDSHAKE
        assert payload == b"handshake data"

    def test_long_header_marker(self):
        hdr = LongHeader(ptype=PacketType.INITIAL, pn=0)
        raw = hdr.to_bytes(b"")
        assert raw[0] & 0x80   # long header bit set

    def test_version_field(self):
        hdr = LongHeader(ptype=PacketType.INITIAL, pn=0)
        raw = hdr.to_bytes(b"")
        import struct
        version = struct.unpack_from("!I", raw, 1)[0]
        assert version == QUIC_VERSION

    def test_token_in_initial(self):
        hdr = LongHeader(ptype=PacketType.INITIAL, dcid=b"\x01", scid=b"\x02",
                         token=b"mytoken", pn=0)
        raw = hdr.to_bytes(b"payload")
        got, pl, _ = LongHeader.from_bytes(raw)
        assert got.token == b"mytoken"
        assert pl == b"payload"

    def test_pn_lengths(self):
        for pn_len in (1, 2, 3, 4):
            hdr = LongHeader(ptype=PacketType.INITIAL, pn=2**((pn_len * 8) - 1), pn_len=pn_len)
            raw = hdr.to_bytes(b"x")
            got, _, _ = LongHeader.from_bytes(raw)
            assert got.pn_len == pn_len

    def test_empty_payload(self):
        hdr = LongHeader(ptype=PacketType.INITIAL, dcid=b"\x01", scid=b"\x02", pn=0)
        raw = hdr.to_bytes(b"")
        _, payload, _ = LongHeader.from_bytes(raw)
        assert payload == b""

    def test_rejects_short_header(self):
        hdr = ShortHeader(dcid=b"\x01" * 8, pn=1)
        raw = hdr.to_bytes(b"data")
        with pytest.raises(ValueError, match="Not a long header"):
            LongHeader.from_bytes(raw)


# ── short header ──────────────────────────────────────────────────────────────

class TestShortHeader:
    def test_round_trip(self):
        hdr = ShortHeader(dcid=b"\xaa" * 8, pn=99)
        raw = hdr.to_bytes(b"app data")
        got, payload, _ = ShortHeader.from_bytes(raw, dcid_len=8)
        assert got.dcid == b"\xaa" * 8
        assert got.pn   == 99
        assert payload  == b"app data"

    def test_short_header_bit(self):
        hdr = ShortHeader(dcid=b"\x00" * 8, pn=0)
        raw = hdr.to_bytes(b"")
        assert not (raw[0] & 0x80)   # bit 7 = 0 for short header
        assert raw[0] & 0x40         # bit 6 = 1 (fixed bit)

    def test_spin_bit_set(self):
        hdr = ShortHeader(dcid=b"\x00" * 8, pn=0, spin=True)
        raw = hdr.to_bytes(b"")
        got, _, _ = ShortHeader.from_bytes(raw, dcid_len=8)
        assert got.spin is True

    def test_spin_bit_clear(self):
        hdr = ShortHeader(dcid=b"\x00" * 8, pn=0, spin=False)
        raw = hdr.to_bytes(b"")
        got, _, _ = ShortHeader.from_bytes(raw, dcid_len=8)
        assert got.spin is False


# ── SendStream ────────────────────────────────────────────────────────────────

class TestSendStream:
    def test_write_and_dequeue(self):
        s = SendStream(stream_id=0, limit=4096)
        s.write(b"hello")
        frames = s.pending_frames()
        assert len(frames) == 1
        assert frames[0].data == b"hello"
        assert frames[0].stream_id == 0

    def test_flow_control_blocks(self):
        s = SendStream(stream_id=0, limit=10)
        s.write(b"A" * 20)
        frames = s.pending_frames(max_payload=20)
        total = sum(len(f.data) for f in frames)
        assert total == 10   # limited to stream limit

    def test_fin_sent_on_close(self):
        s = SendStream(stream_id=0, limit=4096)
        s.write(b"last")
        s.close()
        frames = s.pending_frames()
        assert frames[-1].fin is True

    def test_offset_increments(self):
        s = SendStream(stream_id=0, limit=4096)
        s.write(b"AAA")
        s.pending_frames()
        s.write(b"BBB")
        frames = s.pending_frames()
        assert frames[0].offset == 3

    def test_limit_update_unblocks(self):
        s = SendStream(stream_id=0, limit=4)
        s.write(b"ABCDEFGH")
        frames = s.pending_frames()
        assert sum(len(f.data) for f in frames) == 4
        s.update_limit(8)
        frames2 = s.pending_frames()
        assert sum(len(f.data) for f in frames2) == 4

    def test_is_blocked(self):
        s = SendStream(stream_id=0, limit=2)
        s.write(b"ABC")
        s.pending_frames()
        assert s.is_blocked()


# ── RecvStream ────────────────────────────────────────────────────────────────

class TestRecvStream:
    def test_in_order_delivery(self):
        rs = RecvStream(stream_id=0)
        rs.receive(0, b"hello", fin=False)
        data = rs.read(5)
        assert data == b"hello"

    def test_out_of_order_held_then_delivered(self):
        rs = RecvStream(stream_id=0)
        rs.receive(5, b" world", fin=False)
        rs.receive(0, b"hello", fin=False)
        data = rs.read(11)
        assert data == b"hello world"

    def test_fin_detection(self):
        rs = RecvStream(stream_id=0)
        rs.receive(0, b"done", fin=True)
        rs.read(4)
        assert rs.is_fin_read()

    def test_duplicate_ignored(self):
        rs = RecvStream(stream_id=0)
        rs.receive(0, b"abc", fin=False)
        rs.receive(0, b"abc", fin=False)
        data = rs.read(10)
        assert data == b"abc"

    def test_partial_read(self):
        rs = RecvStream(stream_id=0)
        rs.receive(0, b"hello world", fin=False)
        assert rs.read(5) == b"hello"
        assert rs.read(6) == b" world"


# ── StreamManager ─────────────────────────────────────────────────────────────

class TestStreamManager:
    def test_client_bidi_ids(self):
        sm = StreamManager(is_server=False)
        s1 = sm.open_bidi_stream()
        s2 = sm.open_bidi_stream()
        assert s1.stream_id % 4 == 0
        assert s2.stream_id == s1.stream_id + 4

    def test_server_bidi_ids(self):
        sm = StreamManager(is_server=True)
        s = sm.open_bidi_stream()
        assert s.stream_id % 4 == 1

    def test_on_stream_data_received(self):
        sm  = StreamManager()
        frm = StreamFrame(stream_id=4, offset=0, data=b"payload", fin=False)
        sm.on_stream_data_received(frm)
        rs = sm.get_or_create_recv(4)
        assert rs.read(7) == b"payload"

    def test_flow_control_frames_generated(self):
        sm = StreamManager(initial_max_data=1000, initial_max_stream_data=200)
        sm._conn_send_offset = 800   # nearly at limit
        frames = sm.flow_control_frames()
        types = [type(f).__name__ for f in frames]
        assert "MaxDataFrame" in types
