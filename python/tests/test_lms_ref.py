"""Uji model referensi lms_ref terhadap vektor resmi RFC 8554 Appendix F
dan terhadap dirinya sendiri (sign/verify kunci demo)."""

from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import lms_ref

APPENDIX_F = Path(__file__).resolve().parents[1] / "rfc8554_appendix_f.txt"


@pytest.fixture(scope="module")
def rfc():
    return lms_ref.parse_rfc_appendix_f(APPENDIX_F)


def split_hss(sig_bytes, nspk):
    """Pisah tanda tangan HSS multi-level jadi (daftar_sig, daftar_pub_sementara)."""
    offset = 4
    sigs, pubs = [], []
    for _ in range(nspk):
        s, offset = lms_ref.parse_lms_sig(sig_bytes, offset)
        p, offset = lms_ref.parse_lms_pubkey(sig_bytes, offset)
        sigs.append(s)
        pubs.append(p)
    s, offset = lms_ref.parse_lms_sig(sig_bytes, offset)
    sigs.append(s)
    return sigs, pubs


# ---------------------------------------------------------------------------
# 1. Parser Appendix F: ukuran byte harus persis sesuai RFC/kontrak
# ---------------------------------------------------------------------------

def test_parse_byte_counts(rfc):
    tc1, tc2 = rfc["tc1"], rfc["tc2"]
    assert len(tc1["pubkey"]) == 60        # 4 levels + 24 LMS pubkey + 32 K
    assert len(tc1["message"]) == 162
    assert len(tc1["signature"]) == 2644   # Nspk=1: 4 + 1292 + 56 + 1292
    assert len(tc2["pubkey"]) == 60
    assert len(tc2["message"]) == 131
    # TC2: sig[0] H10+W4 = 4+4+32+67*32+4+10*32 = 2508; pub1 56; sig1 1292
    assert len(tc2["signature"]) == 4 + 2508 + 56 + 1292
    assert len(tc2["privkey"]["top"]["seed"]) == 32
    assert len(tc2["privkey"]["second"]["seed"]) == 32


# ---------------------------------------------------------------------------
# 2. Keygen seed-tetap harus menghasilkan K yang sama dengan RFC (TC2)
# ---------------------------------------------------------------------------

def test_keygen_matches_rfc_tc2_toplevel(rfc):
    priv = rfc["tc2"]["privkey"]["top"]
    key = lms_ref.LmsPrivateKey(
        priv["seed"], priv["i"],
        lms=lms_ref.LMS_SHA256_M32_H10, ots=lms_ref.LMOTS_SHA256_N32_W4,
    )
    pub_from_rfc, _ = lms_ref.parse_lms_pubkey(rfc["tc2"]["pubkey"], 4)
    assert key.root == pub_from_rfc["K"]
    assert key.public_key_bytes() == rfc["tc2"]["pubkey"][4:60]


def test_keygen_matches_rfc_tc2_second_level(rfc):
    priv = rfc["tc2"]["privkey"]["second"]
    key = lms_ref.LmsPrivateKey(
        priv["seed"], priv["i"],
        lms=lms_ref.LMS_SHA256_M32_H5, ots=lms_ref.LMOTS_SHA256_N32_W8,
    )
    # Kunci publik level 2 tertanam di dalam tanda tangan TC2 setelah sig[0]
    _, offset = lms_ref.parse_lms_sig(rfc["tc2"]["signature"], 4)
    pub1, _ = lms_ref.parse_lms_pubkey(rfc["tc2"]["signature"], offset)
    assert key.public_key_bytes() == lms_ref.serialize_lms_pubkey(pub1)


# ---------------------------------------------------------------------------
# 3. Verifikasi vektor resmi (HSS penuh dan per-level, sesuai kasus rfc_*)
# ---------------------------------------------------------------------------

def test_rfc_tc1_full_hss_valid(rfc):
    hasil = lms_ref.hss_verify(
        rfc["tc1"]["pubkey"], rfc["tc1"]["message"], rfc["tc1"]["signature"]
    )
    assert hasil["valid"]


def test_rfc_tc1_level0_lms_valid(rfc):
    """Kasus rfc_tc1_l0: level 0 menandatangani kunci publik level 1."""
    tc1 = rfc["tc1"]
    top_pub, _ = lms_ref.parse_lms_pubkey(tc1["pubkey"], 4)
    sigs, pubs = split_hss(tc1["signature"], 1)
    assert sigs[0]["q"] == 5
    signed_data = lms_ref.serialize_lms_pubkey(pubs[0])
    valid, _ = lms_ref.lms_verify(top_pub, signed_data, sigs[0])
    assert valid


def test_rfc_tc1_level1_lms_valid(rfc):
    """Kasus rfc_tc1_l1: level 1 menandatangani pesan asli."""
    tc1 = rfc["tc1"]
    sigs, pubs = split_hss(tc1["signature"], 1)
    assert sigs[1]["q"] == 10
    valid, _ = lms_ref.lms_verify(pubs[0], tc1["message"], sigs[1])
    assert valid


def test_rfc_tc2_full_hss_valid(rfc):
    hasil = lms_ref.hss_verify(
        rfc["tc2"]["pubkey"], rfc["tc2"]["message"], rfc["tc2"]["signature"]
    )
    assert hasil["valid"]


def test_rfc_tc2_level1_lms_valid(rfc):
    """Kasus rfc_tc2_l1 (H5 + W8, parameter sama dengan desain tim)."""
    tc2 = rfc["tc2"]
    sigs, pubs = split_hss(tc2["signature"], 1)
    assert sigs[1]["q"] == 4
    assert sigs[1]["lms"] == lms_ref.LMS_SHA256_M32_H5
    assert sigs[1]["lmots"]["ots"] == lms_ref.LMOTS_SHA256_N32_W8
    valid, _ = lms_ref.lms_verify(pubs[0], tc2["message"], sigs[1])
    assert valid


# ---------------------------------------------------------------------------
# 4. Serangan bit-flip harus ditolak
# ---------------------------------------------------------------------------

def test_tc1_corrupted_signature_rejected(rfc):
    sig = bytearray(rfc["tc1"]["signature"])
    sig[100] ^= 1
    hasil = lms_ref.hss_verify(rfc["tc1"]["pubkey"], rfc["tc1"]["message"], bytes(sig))
    assert not hasil["valid"]


def test_tc1_corrupted_message_rejected(rfc):
    msg = bytearray(rfc["tc1"]["message"])
    msg[10] ^= 1
    hasil = lms_ref.hss_verify(
        rfc["tc1"]["pubkey"], bytes(msg), rfc["tc1"]["signature"]
    )
    assert not hasil["valid"]


def test_hss_l1_rejects_nspk_nonzero(rfc):
    # Format tim wajib Nspk = 0; tanda tangan RFC (Nspk = 1) harus ditolak
    pub, _ = lms_ref.parse_lms_pubkey(rfc["tc1"]["pubkey"], 4)
    valid, info = lms_ref.hss_l1_verify(
        lms_ref.serialize_lms_pubkey(pub),
        rfc["tc1"]["message"],
        rfc["tc1"]["signature"],
    )
    assert not valid
    assert info["error"] == "Nspk != 0"


# ---------------------------------------------------------------------------
# 5. Sign/verify kunci demo tim (HSS L=1, format 1296 byte)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def demo():
    return lms_ref.demo_key()


def test_demo_sign_verify_roundtrip(demo):
    msg = b"firmware demo tim"
    pub = demo.public_key_bytes()
    for q in (0, 31):  # daun pertama dan terakhir (arah kiri/kanan Merkle)
        sig, _ = lms_ref.hss_l1_sign(demo, msg, q)
        assert len(sig) == 1296
        valid, _ = lms_ref.hss_l1_verify(pub, msg, sig)
        assert valid, f"verifikasi gagal untuk q={q}"


def test_demo_sig_tampered_rejected(demo):
    msg = b"firmware demo tim"
    pub = demo.public_key_bytes()
    sig, _ = lms_ref.hss_l1_sign(demo, msg, 0)
    sig_rusak = bytearray(sig)
    sig_rusak[100] ^= 1
    valid, _ = lms_ref.hss_l1_verify(pub, msg, bytes(sig_rusak))
    assert not valid


def test_demo_key_reproducible():
    k1 = lms_ref.demo_key()
    k2 = lms_ref.demo_key()
    assert k1.public_key_bytes() == k2.public_key_bytes()


# ---------------------------------------------------------------------------
# 6. Ekspor nilai perantara lengkap untuk berkas tv/
# ---------------------------------------------------------------------------

def test_intermediates_complete(demo):
    msg = b"firmware demo tim"
    pub = demo.public_key_bytes()
    sig, _ = lms_ref.hss_l1_sign(demo, msg, 7)
    sig_parsed, _ = lms_ref.parse_lms_sig(sig, 4)
    iv = lms_ref.compute_intermediates(pub, msg, sig_parsed)
    assert iv["valid"]
    assert len(iv["coef"]) == 34
    assert all(0 <= a <= 255 for a in iv["coef"])
    assert len(iv["y"]) == 34
    assert len(iv["z"]) == 34
    assert len(iv["merkle"]) == 6      # hash daun + 5 level
    assert iv["Tc"] == iv["T1"]
    assert len(iv["Kc"]) == 32
