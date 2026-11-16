#!/usr/bin/env python3
"""Generate the PWA icons with nothing but the standard library.

    python3 tools/make-icons.py

Draws a dark tile with an orange prompt chevron and an underscore, so the home
screen icon reads as a terminal. Writes icon-192.png, icon-512.png and
apple-touch-icon.png next to the repo root.
"""
import math
import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BG = (15, 17, 21)
FG = (232, 234, 237)
ACCENT = (255, 138, 61)


def segment_distance(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    length = dx * dx + dy * dy
    t = 0.0 if length == 0 else max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length))
    cx, cy = ax + t * dx, ay + t * dy
    return math.hypot(px - cx, py - cy)


def draw(size):
    pixels = [[BG for _ in range(size)] for _ in range(size)]
    width = size * 0.055
    strokes = [
        ((0.30, 0.30), (0.50, 0.50), ACCENT),
        ((0.50, 0.50), (0.30, 0.70), ACCENT),
        ((0.56, 0.70), (0.74, 0.70), FG),
    ]
    for y in range(size):
        for x in range(size):
            px, py = (x + 0.5) / size, (y + 0.5) / size
            for (a, b, color) in strokes:
                if segment_distance(px, py, a[0], a[1], b[0], b[1]) <= width:
                    pixels[y][x] = color
                    break
    return pixels


def write_png(path, size):
    pixels = draw(size)
    raw = bytearray()
    for row in pixels:
        raw.append(0)
        for r, g, b in row:
            raw.extend((r, g, b))

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)
    print(f"{os.path.basename(path)}  {size}x{size}  {len(png)} bytes")


if __name__ == "__main__":
    write_png(os.path.join(ROOT, "icon-192.png"), 192)
    write_png(os.path.join(ROOT, "icon-512.png"), 512)
    write_png(os.path.join(ROOT, "apple-touch-icon.png"), 180)
