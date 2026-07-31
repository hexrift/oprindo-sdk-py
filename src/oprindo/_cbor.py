"""Minimal CBOR *span* walker — it never decodes values, it only measures
where each item starts and ends.

That is deliberate. The one job here is to permute entries of the claim's
``created_assertions`` array while keeping the claim byte-for-byte otherwise
identical, so the JUMBF box it lives in does not change size. Decoding and
re-encoding could not promise that: any encoder disagreement with c2pa-rs
(integer width, map key order, string form) would silently resize the claim and
corrupt the manifest store. Moving raw byte slices cannot.

Definite-length items only, which is what c2pa-rs emits; anything else raises
rather than guessing.
"""

from __future__ import annotations

from typing import NamedTuple

MAJOR_UINT = 0
MAJOR_NINT = 1
MAJOR_BSTR = 2
MAJOR_TSTR = 3
MAJOR_ARRAY = 4
MAJOR_MAP = 5
MAJOR_TAG = 6
MAJOR_SIMPLE = 7


class CborError(ValueError):
    """Malformed or unsupported CBOR encountered while walking spans."""


class Head(NamedTuple):
    major: int
    """Major type (0-7)."""
    arg: int
    """Argument: length for strings/arrays/maps, value for integers."""
    body: int
    """Offset of the first byte after the head."""


class Span(NamedTuple):
    start: int
    end: int


def read_head(buf: bytes, offset: int) -> Head:
    """Read an item's head at ``offset``."""
    if offset >= len(buf):
        raise CborError("read past end")
    initial = buf[offset]
    major = initial >> 5
    ai = initial & 0x1F
    if ai < 24:
        return Head(major, ai, offset + 1)
    if ai == 24:
        if offset + 2 > len(buf):
            raise CborError("truncated head")
        return Head(major, buf[offset + 1], offset + 2)
    if ai == 25:
        if offset + 3 > len(buf):
            raise CborError("truncated head")
        return Head(major, int.from_bytes(buf[offset + 1 : offset + 3], "big"), offset + 3)
    if ai == 26:
        if offset + 5 > len(buf):
            raise CborError("truncated head")
        return Head(major, int.from_bytes(buf[offset + 1 : offset + 5], "big"), offset + 5)
    if ai == 27:
        if offset + 9 > len(buf):
            raise CborError("truncated head")
        return Head(major, int.from_bytes(buf[offset + 1 : offset + 9], "big"), offset + 9)
    # 28-30 reserved, 31 indefinite length.
    raise CborError(f"unsupported additional info {ai}")


def item_end(buf: bytes, offset: int) -> int:
    """Offset one past the end of the complete item starting at ``offset``."""
    major, arg, body = read_head(buf, offset)
    if major in (MAJOR_UINT, MAJOR_NINT):
        return body
    if major in (MAJOR_BSTR, MAJOR_TSTR):
        end = body + arg
        if end > len(buf):
            raise CborError("string past end")
        return end
    if major == MAJOR_ARRAY:
        at = body
        for _ in range(arg):
            at = item_end(buf, at)
        return at
    if major == MAJOR_MAP:
        at = body
        for _ in range(arg):
            at = item_end(buf, at)  # key
            at = item_end(buf, at)  # value
        return at
    if major == MAJOR_TAG:
        return item_end(buf, body)
    if major == MAJOR_SIMPLE:
        ai = buf[offset] & 0x1F
        if ai <= 27:
            return body
        raise CborError(f"unsupported simple value {ai}")
    raise CborError(f"unknown major type {major}")


def read_text_string(buf: bytes, offset: int) -> str | None:
    """A text string read at ``offset``, or None if the item there is not one."""
    major, arg, body = read_head(buf, offset)
    if major != MAJOR_TSTR:
        return None
    return buf[body : body + arg].decode("utf-8", errors="replace")


def map_value_spans(buf: bytes, offset: int) -> dict[str, Span]:
    """Byte spans of a map's values, keyed by their text-string keys.

    Non-text keys are skipped — the claim uses text keys throughout.
    """
    major, arg, body = read_head(buf, offset)
    if major != MAJOR_MAP:
        raise CborError("expected a map")
    spans: dict[str, Span] = {}
    at = body
    for _ in range(arg):
        key = read_text_string(buf, at)
        at = item_end(buf, at)
        value_end = item_end(buf, at)
        if key is not None:
            spans[key] = Span(at, value_end)
        at = value_end
    return spans


class ArraySpans(NamedTuple):
    first: int
    """Offset of the first element (i.e. one past the array head)."""
    end: int
    """Offset one past the last element."""
    elements: list[Span]


def array_element_spans(buf: bytes, offset: int) -> ArraySpans:
    """Byte spans of each element of the array at ``offset``."""
    major, arg, body = read_head(buf, offset)
    if major != MAJOR_ARRAY:
        raise CborError("expected an array")
    elements: list[Span] = []
    at = body
    for _ in range(arg):
        end = item_end(buf, at)
        elements.append(Span(at, end))
        at = end
    return ArraySpans(body, at, elements)


def cose_payload_span(to_be_signed: bytes) -> Span:
    """Span of the payload inside a COSE ``Sig_structure``.

    The structure is ``["Signature1", protected, external_aad, payload]``, so
    the payload is the fourth element — and for a C2PA signature it is the
    claim itself. Locating it lets the claim be permuted inside the bytes that
    are about to be signed, so the signature covers the permuted claim rather
    than having to be re-made afterwards.
    """
    array = array_element_spans(to_be_signed, 0)
    if len(array.elements) != 4:
        raise CborError(f"expected a 4-element Sig_structure, got {len(array.elements)}")
    payload = array.elements[3]
    major, _, body = read_head(to_be_signed, payload.start)
    if major != MAJOR_BSTR:
        raise CborError("Sig_structure payload is not a byte string")
    return Span(body, payload.end)
