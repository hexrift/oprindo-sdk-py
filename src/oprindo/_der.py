"""Pure-python DER helpers: ECDSA DER signature -> raw r||s (COSE ES256)."""

from __future__ import annotations


def _read_tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the TLV at off."""
    if off + 2 > len(buf):
        raise ValueError("der: truncated")
    tag = buf[off]
    length = buf[off + 1]
    len_bytes = 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or off + 2 + n > len(buf):
            raise ValueError("der: bad length")
        length = int.from_bytes(buf[off + 2 : off + 2 + n], "big")
        len_bytes = 1 + n
    start = off + 1 + len_bytes
    end = start + length
    if end > len(buf):
        raise ValueError("der: truncated content")
    return tag, start, end


def ecdsa_der_to_raw(der: bytes, size: int = 32) -> bytes:
    """ECDSA DER (SEQUENCE of two INTEGERs) -> raw r||s, each `size` bytes."""
    tag, start, end = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("der: not a sequence")
    rtag, rstart, rend = _read_tlv(der, start)
    if rtag != 0x02:
        raise ValueError("der: r not integer")
    stag, sstart, send_ = _read_tlv(der, rend)
    if stag != 0x02:
        raise ValueError("der: s not integer")

    r = der[rstart:rend].lstrip(b"\x00") or b"\x00"
    s = der[sstart:send_].lstrip(b"\x00") or b"\x00"
    if len(r) > size or len(s) > size:
        raise ValueError("der: integer too large")
    return r.rjust(size, b"\x00") + s.rjust(size, b"\x00")
