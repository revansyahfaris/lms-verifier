#!/usr/bin/env python3
"""Data uji SHA-256 untuk RTL A (sha256_round, sha256_core, sha256_compress).

Jalankan dari root repo:   python3 python/gen_sha256_vectors.py

Keluaran (format mengikuti docs/kontrak.md bagian 5: huruf kecil, tanpa 0x,
big-endian, baris sejajar antar file):
  tv/sha256/blocks.hex     128 hex per baris   satu blok 64 byte
  tv/sha256/state_in.hex    64 hex per baris   H0..H7 sebelum kompresi
  tv/sha256/state_out.hex   64 hex per baris   H0..H7 sesudah kompresi (feed-forward sudah termasuk)
  tv/sha256/round_in.hex    80 hex per baris   A..H, W, K (10 kata 32 bit)
  tv/sha256/round_out.hex   64 hex per baris   A..H baru setelah satu ronde

Jawaban dihitung dengan kompresi SHA-256 murni Python, lalu dicek terhadap hashlib.
Seed tetap, jadi hasilnya selalu sama di komputer mana pun. Jangan edit file .hex tangan.
"""
import hashlib
import os
import random
import struct

M = 0xFFFFFFFF
IV = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)
NIST56 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M


def round_fn(s, w, k):
    """Satu ronde SHA-256 (FIPS 180-4 bagian 6.2.2). s = [A..H]."""
    a, b, c, d, e, f, g, h = s
    s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
    ch = (e & f) ^ (~e & g)
    t1 = (h + s1 + ch + k + w) & M
    s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    t2 = (s0 + maj) & M
    return [(t1 + t2) & M, a, b, c, (d + t1) & M, e, f, g]


def schedule(block):
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M)
    return w


def compress(state, block):
    w = schedule(block)
    s = list(state)
    for t in range(64):
        s = round_fn(s, w[t], K[t])
    return [(x + y) & M for x, y in zip(state, s)]


def pad(msg):
    """Padding FIPS 180-4 bagian 5.1.1 -> daftar blok 64 byte."""
    m = msg + b"\x80"
    m += b"\x00" * ((56 - len(m)) % 64)
    m += struct.pack(">Q", len(msg) * 8)
    return [m[i:i + 64] for i in range(0, len(m), 64)]


def hx(words):
    return "".join(f"{x:08x}" for x in words)


def main():
    rng = random.Random(0x5A256)
    blocks, st_in, st_out = [], [], []

    # Pesan nyata; blok berantai (state_in blok 2 = state_out blok 1).
    for msg in (b"abc", b"", NIST56, b"a" * 55, b"a" * 56, b"a" * 64):
        st = list(IV)
        for blk in pad(msg):
            out = compress(st, blk)
            blocks.append(blk.hex())
            st_in.append(hx(st))
            st_out.append(hx(out))
            st = out
        assert struct.pack(">8I", *st) == hashlib.sha256(msg).digest(), msg

    # Blok dan state acak (seed tetap): menguji kompresi untuk state sembarang.
    for _ in range(16):
        st = [rng.getrandbits(32) for _ in range(8)]
        blk = bytes(rng.getrandbits(8) for _ in range(64))
        blocks.append(blk.hex())
        st_in.append(hx(st))
        st_out.append(hx(compress(st, blk)))

    # Vektor satu ronde untuk sha256_round.
    r_in, r_out = [], []
    for _ in range(16):
        s = [rng.getrandbits(32) for _ in range(8)]
        w, k = rng.getrandbits(32), rng.getrandbits(32)
        r_in.append(hx(s + [w, k]))
        r_out.append(hx(round_fn(s, w, k)))

    os.makedirs(os.path.join("tv", "sha256"), exist_ok=True)
    for name, lines in (("blocks", blocks), ("state_in", st_in), ("state_out", st_out),
                        ("round_in", r_in), ("round_out", r_out)):
        with open(os.path.join("tv", "sha256", name + ".hex"), "w") as fh:
            fh.write("\n".join(lines) + "\n")
    print(f"tv/sha256: {len(blocks)} vektor kompresi, {len(r_in)} vektor ronde")


if __name__ == "__main__":
    main()
