"""Pembuat image firmware (pemilik: Verifikasi, kontrak bagian 7).

Image = header 16 byte + payload program PicoRV32. Header mengikuti
tata letak kontrak bagian 1:

| Offset | Panjang | Isi                                          |
| 0      | 4       | Magic 0x50465731 ("PFW1")                     |
| 4      | 4       | Versi firmware (u32 big-endian)               |
| 8      | 4       | Panjang payload (u32 BE) = IMG_LEN - 16       |
| 12     | 4       | Cadangan, harus 0                             |
| 16     | sisanya | Payload: program PicoRV32                     |

Pesan yang ditandatangani = seluruh image termasuk header, sehingga
nomor versi ikut terlindungi tanda tangan.
"""

import struct

MAGIC = 0x50465731            # "PFW1"
HDR_BYTES = 16
MAX_IMG = 16384               # 16 KB termasuk header


def make_image(payload, version):
    """Rangkai image firmware: header 16 byte + payload.

    Payload di-pad 0x00 sampai kelipatan 4 supaya rapi di IMG_RAM.
    Mengembalikan bytes image lengkap (header + payload).
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload harus bytes")
    if not (0 <= version <= 0xFFFFFFFF):
        raise ValueError("version harus 0..0xFFFFFFFF")

    payload = bytes(payload)
    pad = (-len(payload)) % 4
    payload = payload + b"\x00" * pad

    img = struct.pack(">IIII", MAGIC, version, len(payload), 0) + payload
    if not (HDR_BYTES <= len(img) <= MAX_IMG):
        raise ValueError(f"panjang image {len(img)} di luar 16..{MAX_IMG}")
    return img


def parse_header(img):
    """Baca header image. Mengembalikan dict magic/version/payload_len/reserved."""
    if len(img) < HDR_BYTES:
        raise ValueError("image lebih pendek dari header 16 byte")
    magic, version, payload_len, reserved = struct.unpack(">IIII", img[:HDR_BYTES])
    return {
        "magic": magic,
        "version": version,
        "payload_len": payload_len,
        "reserved": reserved,
    }


def header_valid(img):
    """Cek header sesuai aturan kontrak (untuk expect / data uji rusak)."""
    try:
        h = parse_header(img)
    except ValueError:
        return False
    if h["magic"] != MAGIC:
        return False
    if h["reserved"] != 0:
        return False
    if h["payload_len"] != len(img) - HDR_BYTES:
        return False
    return True


# Payload demo sederhana (placeholder program PicoRV32). Isi sebenarnya
# akan diganti firmware sw/pico/ milik RTL B; yang penting di sini hanya
# image-nya valid secara format dan bisa ditandatangani.
DEFAULT_PAYLOAD = bytes(
    [0x13, 0x01, 0x00, 0x00]      # nop-ish (addi x2, x0, 0) placeholder
    + [0x00] * 60
)


def make_demo_image(version=1, payload=None):
    """Image demo siap tanda tangan untuk data uji valid_*."""
    return make_image(payload if payload is not None else DEFAULT_PAYLOAD, version)


if __name__ == "__main__":
    img = make_demo_image(version=2)
    print(f"image demo: {len(img)} byte")
    print("header:", parse_header(img))
    print("valid:", header_valid(img))
