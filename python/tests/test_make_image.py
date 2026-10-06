"""Uji pembuat image firmware sesuai tata letak kontrak bagian 1."""

from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import make_image as mi


def test_header_layout():
    img = mi.make_image(b"ABCD", version=2)
    assert len(img) == 16 + 4
    assert img[0:4] == b"PFW1"
    assert int.from_bytes(img[4:8], "big") == 2          # versi
    assert int.from_bytes(img[8:12], "big") == 4         # payload_len
    assert img[12:16] == b"\x00\x00\x00\x00"             # cadangan
    assert img[16:] == b"ABCD"


def test_payload_padded_to_word():
    img = mi.make_image(b"ABC", version=1)               # 3 byte -> pad 1
    assert len(img) == 16 + 4
    assert int.from_bytes(img[8:12], "big") == 4
    assert img[16:19] == b"ABC"
    assert img[19] == 0


def test_parse_and_valid():
    img = mi.make_demo_image(version=5)
    h = mi.parse_header(img)
    assert h["magic"] == mi.MAGIC
    assert h["version"] == 5
    assert h["payload_len"] == len(img) - 16
    assert h["reserved"] == 0
    assert mi.header_valid(img)


def test_reject_wrong_magic():
    img = bytearray(mi.make_demo_image())
    img[0] ^= 1
    assert not mi.header_valid(bytes(img))


def test_reject_bad_payload_len():
    img = bytearray(mi.make_demo_image())
    img[11] ^= 1                                          # ubah payload_len
    assert not mi.header_valid(bytes(img))


def test_reject_too_short():
    assert not mi.header_valid(b"PFW1")


def test_reject_oversize():
    with pytest.raises(ValueError):
        mi.make_image(b"\x00" * (mi.MAX_IMG - 16 + 4), version=1)
