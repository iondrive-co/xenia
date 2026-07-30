from __future__ import annotations

import struct
import zlib

SIZE = 32

GREEN = (0x4C, 0xAF, 0x50, 0xFF)
INK = (0x26, 0x2B, 0x30, 0xFF)


def _role(x: int, y: int) -> str | None:
    left, right, top, bottom = 7, 25, 3, 29
    fold = 7

    if not (left <= x < right and top <= y < bottom):
        return None

    if x >= right - fold and y < top + fold:
        cut = (x - (right - fold)) - (y - top)
        if cut > 1:
            return None
        if cut >= -1:
            return "edge"

    if x < left + 2 or x >= right - 2 or y < top + 2 or y >= bottom - 2:
        return "edge"

    for row, (start, end) in enumerate(((11, 18), (11, 22), (11, 22), (11, 19))):
        line_y = top + 7 + row * 5
        if line_y <= y < line_y + 2 and start <= x < end:
            return "line"

    return "body"


def _colour(role: str) -> tuple[int, int, int, int]:
    if role == "edge":
        return GREEN
    if role == "line":
        return INK
    return (GREEN[0], GREEN[1], GREEN[2], 0x2E)


def _pixels() -> list[list[tuple[int, int, int, int]]]:
    return [
        [_colour(role) if (role := _role(x, y)) else (0, 0, 0, 0)
         for x in range(SIZE)]
        for y in range(SIZE)
    ]


def render() -> bytes:
    raw = bytearray()
    for row in _pixels():
        raw.append(0)
        for r, g, b, a in row:
            raw += bytes((r, g, b, a))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def argb_for_dbus() -> tuple[int, int, bytes]:
    out = bytearray()
    for row in _pixels():
        for r, g, b, a in row:
            out += bytes((a, r, g, b))
    return SIZE, SIZE, bytes(out)
