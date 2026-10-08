"""Reading and rewriting the JUMBF manifest store *in place* inside a signed
asset, without changing any byte count.

Needed because the claim has to be permuted after c2pa-rs has laid the store
out. Every rewrite here is length-preserving, so JUMBF box lengths, JPEG
segment lengths and the hard binding all stay valid — the hard binding covers
the asset *excluding* the manifest store, so editing the store cannot
invalidate it.

Note the store is NOT contiguous in a JPEG: it is split across APP11 segments,
each repeating an 8-byte LBox/TBox header, so the rewrite works on the
reassembled logical store rather than on raw asset bytes.
"""

from __future__ import annotations

import zlib
from typing import NamedTuple

JPEG_SOI = 0xD8
JPEG_SOS = 0xDA
JPEG_APP11 = 0xEB
#: APP11 header: Le(2) CI(2) En(2) Z(4) — the fragment payload follows.
APP11_HEADER = 8
#: Every APP11 fragment repeats LBox(4) + TBox(4); only the first is store.
JUMBF_BOX_HEADER = 8

PNG_SIGNATURE = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
PNG_C2PA_CHUNK = b"caBX"


class StoreFragment(NamedTuple):
    start: int
    end: int


class ManifestStoreError(ValueError):
    """The manifest store could not be read or rewritten safely."""


def manifest_store_fragments(asset: bytes, mime_type: str) -> list[StoreFragment]:
    """Where the manifest store lives inside the asset, in store order.

    Empty when the asset carries no store.
    """
    if mime_type == "image/jpeg":
        return _jpeg_fragments(asset)
    if mime_type == "image/png":
        return _png_fragments(asset)
    raise ManifestStoreError(f"unsupported media type {mime_type}")


def _u16(buf: bytes, at: int) -> int:
    return int.from_bytes(buf[at : at + 2], "big")


def _u32(buf: bytes, at: int) -> int:
    return int.from_bytes(buf[at : at + 4], "big")


def _jpeg_fragments(asset: bytes) -> list[StoreFragment]:
    fragments: list[StoreFragment] = []
    at = 2  # skip SOI
    while at + 4 <= len(asset):
        if asset[at] != 0xFF:
            break
        marker = asset[at + 1]
        # Standalone markers carry no length.
        if marker == JPEG_SOI or 0xD0 <= marker <= 0xD9:
            at += 2
            continue
        if marker == JPEG_SOS:
            break  # entropy-coded data follows; no more segments
        length = _u16(asset, at + 2)
        if length < 2 or at + 2 + length > len(asset):
            break
        if marker == JPEG_APP11 and asset[at + 4 : at + 6] == b"JP":
            # Packet sequence number Z is 1-based; continuation fragments repeat
            # the JUMBF box header, which is carriage rather than store content.
            sequence = _u32(asset, at + 8)
            skip = APP11_HEADER + (0 if sequence == 1 else JUMBF_BOX_HEADER)
            fragments.append(StoreFragment(at + 4 + skip, at + 2 + length))
        at += 2 + length
    return fragments


def _png_fragments(asset: bytes) -> list[StoreFragment]:
    if asset[:8] != PNG_SIGNATURE:
        return []
    fragments: list[StoreFragment] = []
    at = 8
    while at + 12 <= len(asset):
        length = _u32(asset, at)
        chunk_type = asset[at + 4 : at + 8]
        data_start = at + 8
        if data_start + length + 4 > len(asset):
            break
        if chunk_type == PNG_C2PA_CHUNK:
            fragments.append(StoreFragment(data_start, data_start + length))
        if chunk_type == b"IEND":
            break
        at = data_start + length + 4  # + CRC
    return fragments


def read_manifest_store(asset: bytes, fragments: list[StoreFragment]) -> bytes:
    """The logical manifest store: every fragment concatenated, in order."""
    return b"".join(asset[f.start : f.end] for f in fragments)


def write_manifest_store(
    asset: bytes,
    fragments: list[StoreFragment],
    store: bytes,
    mime_type: str,
) -> bytes:
    """Write ``store`` back over the fragments it came from, returning the new
    asset. PNG chunk CRCs are recomputed; JPEG segments need no checksum.

    Raises:
        ManifestStoreError: if ``store`` is not exactly the size of the
            fragments it must fill.
    """
    capacity = sum(f.end - f.start for f in fragments)
    if len(store) != capacity:
        raise ManifestStoreError(
            f"store is {len(store)}B but its fragments hold {capacity}B"
        )
    out = bytearray(asset)
    cursor = 0
    for fragment in fragments:
        size = fragment.end - fragment.start
        out[fragment.start : fragment.end] = store[cursor : cursor + size]
        cursor += size
    if mime_type == "image/png":
        _repair_png_crcs(out, fragments)
    return bytes(out)


def _repair_png_crcs(asset: bytearray, fragments: list[StoreFragment]) -> None:
    """Recompute the CRC of every PNG chunk a fragment sits in."""
    for fragment in fragments:
        # The chunk's type field is the 4 bytes immediately before its data.
        type_start = fragment.start - 4
        crc = zlib.crc32(bytes(asset[type_start : fragment.end])) & 0xFFFFFFFF
        asset[fragment.end : fragment.end + 4] = crc.to_bytes(4, "big")


def replace_in_store(store: bytes, find: bytes, replace: bytes) -> bytes:
    """Replace one exact byte sequence in the store with another of the same
    length. The needle must occur exactly once: the caller relies on hitting the
    claim box and nothing else.
    """
    if len(find) != len(replace):
        raise ManifestStoreError(
            f"replacement is {len(replace)}B, needle is {len(find)}B"
        )
    at = store.find(find)
    if at == -1:
        raise ManifestStoreError("sequence to replace not found in store")
    if store.find(find, at + 1) != -1:
        raise ManifestStoreError("sequence to replace is ambiguous (occurs more than once)")
    return store[:at] + replace + store[at + len(find) :]


def signature_placeholder_span(store: bytes, marker: bytes) -> StoreFragment:
    """Locate the one CBOR signature box containing our random raw signature.

    Walk actual JUMBF box boundaries, including ingredient stores, rather than
    interpreting a byte pattern inside certificate or assertion data as a box.
    """
    matches: list[StoreFragment] = []

    def walk(start: int, end: int) -> None:
        at = start
        while at < end:
            if at + 8 > end:
                raise ManifestStoreError("truncated JUMBF box")
            size = _u32(store, at)
            header = 8
            if size == 1:
                if at + 16 > end:
                    raise ManifestStoreError("truncated extended JUMBF box")
                size = int.from_bytes(store[at + 8 : at + 16], "big")
                header = 16
            elif size == 0:
                size = end - at
            stop = at + size
            if size < header or stop > end:
                raise ManifestStoreError("invalid JUMBF box length")
            kind = store[at + 4 : at + 8]
            payload = at + header
            if kind == b"jumb":
                walk(payload, stop)
            elif kind == b"cbor" and marker in store[payload:stop]:
                matches.append(StoreFragment(payload, stop))
            at = stop

    if not marker or store.count(marker) != 1:
        raise ManifestStoreError("signature placeholder is missing or ambiguous")
    walk(0, len(store))
    if len(matches) != 1:
        raise ManifestStoreError("signature placeholder is not in one CBOR box")
    return matches[0]
