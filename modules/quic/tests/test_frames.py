import struct
import pytest

from quic.types import encode_varint, decode_varint, varint_len
from quic.frames import (
    AckFrame, AckRange, CryptoFrame, StreamFrame,
    MaxDataFrame, MaxStreamDataFrame, MaxStreamsFrame,
    DataBlockedFrame, StreamDataBlockedFrame,
    ConnectionCloseFrame, HandshakeDoneFrame,
    PaddingFrame, PingFrame,
    encode_frame, decode_frames,
)


# ── varint ────────────────────────────────────────────────────────────────────

class TestVarint:
    @pytest.mark.parametrize("value, expected_len", [
        (0,         1),
        (63,        1),
        (64,        2),
        (16383,     2),
        (16384,     4),
        (1073741823, 4),
        (1073741824, 8),
        (4611686018427387903, 8),
    ])
    def test_round_trip(self, value, expected_len):
        enc = encode_varint(value)
        assert len(enc) == expected_len
        dec, off = decode_varint(enc)
        assert dec == value
        assert off == expected_len

    def test_boundary_0(self):
        enc = encode_varint(0)
        assert enc == b"\x00"
        assert decode_varint(enc) == (0, 1)

    def test_boundary_63(self):
        enc = encode_varint(63)
        assert enc == b"\x3f"

    def test_boundary_64(self):
        enc = encode_varint(64)
        val, off = decode_varint(enc)
        assert val == 64 and off == 2

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            encode_varint(-1)

    def test_overflow_raises(self):
        with pytest.raises(ValueError):
            encode_varint(2**62)

    def test_varint_len_values(self):
        assert varint_len(0)           == 1
        assert varint_len(63)          == 1
        assert varint_len(64)          == 2
        assert varint_len(16383)       == 2
        assert varint_len(16384)       == 4
        assert varint_len(1073741823)  == 4
        assert varint_len(1073741824)  == 8

    def test_decode_with_offset(self):
        buf = b"\x00" + encode_varint(1000) + b"\xff"
        val, off = decode_varint(buf, 1)
        assert val == 1000
        assert off == 3   # 1 start + 2 bytes for 1000

    def test_short_buffer_raises(self):
        with pytest.raises(ValueError):
            decode_varint(b"")
        with pytest.raises(ValueError):
            decode_varint(b"\x40")   # 2-byte varint with only 1 byte


# ── frame round-trips ─────────────────────────────────────────────────────────

class TestFrameRoundTrip:
    def _rt(self, frame):
        """Encode then decode and check the first frame matches."""
        enc    = encode_frame(frame)
        frames = decode_frames(enc)
        assert frames, f"No frames decoded from {enc.hex()}"
        return frames[0]

    def test_padding(self):
        f = self._rt(PaddingFrame(length=5))
        assert isinstance(f, PaddingFrame)
        assert f.length >= 1

    def test_ping(self):
        f = self._rt(PingFrame())
        assert isinstance(f, PingFrame)

    def test_ack_simple(self):
        frame = AckFrame(largest_acked=10, ack_delay=5, first_ack_range=3)
        f = self._rt(frame)
        assert isinstance(f, AckFrame)
        assert f.largest_acked == 10
        assert f.ack_delay == 5
        assert f.first_ack_range == 3

    def test_ack_with_ranges(self):
        frame = AckFrame(
            largest_acked=20, ack_delay=0, first_ack_range=2,
            ranges=[AckRange(gap=1, ack=3), AckRange(gap=2, ack=1)],
        )
        f = self._rt(frame)
        assert len(f.ranges) == 2
        assert f.ranges[0].gap == 1
        assert f.ranges[0].ack == 3

    def test_crypto(self):
        frame = CryptoFrame(offset=0, data=b"TLS handshake data")
        f = self._rt(frame)
        assert isinstance(f, CryptoFrame)
        assert f.offset == 0
        assert f.data == b"TLS handshake data"

    def test_crypto_nonzero_offset(self):
        frame = CryptoFrame(offset=512, data=b"\xab" * 32)
        f = self._rt(frame)
        assert f.offset == 512
        assert f.data == b"\xab" * 32

    def test_stream_basic(self):
        frame = StreamFrame(stream_id=4, offset=0, data=b"hello world")
        f = self._rt(frame)
        assert isinstance(f, StreamFrame)
        assert f.stream_id == 4
        assert f.data == b"hello world"
        assert not f.fin

    def test_stream_with_offset_and_fin(self):
        frame = StreamFrame(stream_id=0, offset=1024, data=b"last chunk", fin=True)
        f = self._rt(frame)
        assert f.offset == 1024
        assert f.fin is True
        assert f.data == b"last chunk"

    def test_stream_empty_fin(self):
        frame = StreamFrame(stream_id=8, offset=100, data=b"", fin=True)
        f = self._rt(frame)
        assert f.fin is True

    def test_max_data(self):
        f = self._rt(MaxDataFrame(maximum=1 << 20))
        assert isinstance(f, MaxDataFrame)
        assert f.maximum == 1 << 20

    def test_max_stream_data(self):
        f = self._rt(MaxStreamDataFrame(stream_id=12, maximum=65536))
        assert isinstance(f, MaxStreamDataFrame)
        assert f.stream_id == 12
        assert f.maximum == 65536

    def test_max_streams_bidi(self):
        f = self._rt(MaxStreamsFrame(maximum=100, bidirectional=True))
        assert isinstance(f, MaxStreamsFrame)
        assert f.maximum == 100
        assert f.bidirectional is True

    def test_max_streams_uni(self):
        f = self._rt(MaxStreamsFrame(maximum=50, bidirectional=False))
        assert f.bidirectional is False

    def test_data_blocked(self):
        f = self._rt(DataBlockedFrame(limit=2048))
        assert isinstance(f, DataBlockedFrame)
        assert f.limit == 2048

    def test_stream_data_blocked(self):
        f = self._rt(StreamDataBlockedFrame(stream_id=4, limit=512))
        assert isinstance(f, StreamDataBlockedFrame)
        assert f.stream_id == 4

    def test_connection_close(self):
        f = self._rt(ConnectionCloseFrame(error_code=0x1a, frame_type=8, reason=b"overflow"))
        assert isinstance(f, ConnectionCloseFrame)
        assert f.error_code == 0x1a
        assert f.reason == b"overflow"

    def test_handshake_done(self):
        f = self._rt(HandshakeDoneFrame())
        assert isinstance(f, HandshakeDoneFrame)

    def test_multiple_frames_in_payload(self):
        payload = (
            encode_frame(PingFrame())
            + encode_frame(MaxDataFrame(maximum=4096))
            + encode_frame(StreamFrame(stream_id=0, offset=0, data=b"abc"))
        )
        frames = decode_frames(payload)
        assert len(frames) == 3
        assert isinstance(frames[0], PingFrame)
        assert isinstance(frames[1], MaxDataFrame)
        assert isinstance(frames[2], StreamFrame)
        assert frames[2].data == b"abc"
