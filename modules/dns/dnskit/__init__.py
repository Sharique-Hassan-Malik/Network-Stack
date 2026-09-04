"""dnskit — an iterative DNS resolver, from the root down.

    from dnskit import Resolver
    Resolver().address("example.com")

`wire` is pure and has the whole message format; `cache` is pure and has TTL
handling; `resolve` is the thin layer that owns the socket and the clock.
"""

from .cache import Cache
from .resolve import Answer, ResolveError, Resolver, ROOT_SERVERS
from .wire import (
    Message, Question, Record, WireError,
    TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX, TYPE_NS, TYPE_SOA, TYPE_TXT,
    decode_message, encode_query, normalise,
)

__all__ = [
    "Resolver", "Answer", "ResolveError", "Cache", "ROOT_SERVERS",
    "Message", "Question", "Record", "WireError",
    "decode_message", "encode_query", "normalise",
    "TYPE_A", "TYPE_AAAA", "TYPE_CNAME", "TYPE_MX", "TYPE_NS", "TYPE_SOA", "TYPE_TXT",
]
__version__ = "1.0.0"
