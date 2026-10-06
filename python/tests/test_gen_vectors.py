"""Uji generator data uji: struktur folder dan isi tv/ sesuai kontrak bagian 5."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import lms_ref

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN = REPO_ROOT / "python" / "gen_vectors.py"


@pytest.fixture(scope="module")
def tv(tmp_path_factory):
    out = tmp_path_factory.mktemp("tv")
    subprocess.run([sys.executable, str(GEN), str(out)], check=True,
                   capture_output=True, text=True)
    return out


def test_sha256_blocks_aligned(tv):
    blocks = (tv / "sha256" / "blocks.hex").read_text().split()
    sin = (tv / "sha256" / "state_in.hex").read_text().split()
    sout = (tv / "sha256" / "state_out.hex").read_text().split()
    assert len(blocks) == len(sin) == len(sout) == 5
    assert all(len(b) == 128 for b in blocks)          # 512 bit = 128 hex
    assert all(len(h) == 64 for h in sout)             # 256 bit = 64 hex


def test_sha256_block1_is_abc(tv):
    import hashlib
    blocks = (tv / "sha256" / "blocks.hex").read_text().split()
    sout = (tv / "sha256" / "state_out.hex").read_text().split()
    assert hashlib.sha256(bytes.fromhex(blocks[0])).hexdigest() == sout[0]


def test_case_structure(tv):
    always = {"pubkey.bin", "sig.bin", "img.bin", "sig.words.hex",
              "img.words.hex", "rom_I.hex", "rom_T1.hex", "expect.txt"}
    inter = {"Q.hex", "coef.hex", "y.hex", "z.hex", "Kc.hex", "merkle.hex",
             "Tc.hex"}
    # Kasus dengan type tidak dikenal sengaja tidak punya berkas perantara
    no_inter = {"bad_ots_type", "bad_lms_type"}
    for case in ("valid_q0", "valid_q31", "valid_v2", "valid_len_odd",
                 "bad_img_bit", "bad_sig_C", "bad_sig_y17", "bad_sig_path3",
                 "wrong_key", "bad_sig_len", "bad_nspk", "bad_ots_type",
                 "bad_lms_type", "bad_q_range", "bad_magic", "rollback",
                 "rfc_tc1_l1", "rfc_tc1_l0", "rfc_tc2_l1"):
        d = tv / case
        assert d.is_dir(), f"folder {case} hilang"
        have = {p.name for p in d.iterdir()}
        missing = always - have
        assert not missing, f"{case} kurang berkas: {missing}"
        if case not in no_inter:
            assert not (inter - have), f"{case} kurang perantara: {inter - have}"


def test_valid_q0_self_consistent(tv):
    d = tv / "valid_q0"
    pub = (d / "pubkey.bin").read_bytes()
    sig = (d / "sig.bin").read_bytes()
    img = (d / "img.bin").read_bytes()
    assert len(sig) == 1296
    assert len(pub) == 56
    # Nilai perantara di berkas harus cocok dengan model
    pub_p, _ = lms_ref.parse_lms_pubkey(pub)
    sig_p, _ = lms_ref.parse_lms_sig(sig, 4)
    iv = lms_ref.compute_intermediates(pub, img, sig_p)
    assert (d / "Q.hex").read_text().split()[0] == iv["Q"].hex()
    assert (d / "Kc.hex").read_text().split()[0] == iv["Kc"].hex()
    assert (d / "Tc.hex").read_text().split()[0] == iv["Tc"].hex()
    assert (d / "rom_T1.hex").read_text().split()[0] == pub_p["K"].hex()
    assert (d / "expect.txt").read_text().split()[0] == "result=PASS"


def test_ram_words_little_endian(tv):
    # byte pertama sig.bin harus muncul di 2 hex terakhir word pertama
    d = tv / "valid_q0"
    sig = (d / "sig.bin").read_bytes()
    words = (d / "sig.words.hex").read_text().split()
    assert words[0] == sig[3:4].hex() + sig[2:3].hex() + sig[1:2].hex() + sig[0:1].hex()


def test_coef_and_merkle_counts(tv):
    d = tv / "valid_q0"
    assert len((d / "coef.hex").read_text().split()) == 34
    assert len((d / "y.hex").read_text().split()) == 34
    assert len((d / "z.hex").read_text().split()) == 34
    assert len((d / "merkle.hex").read_text().split()) == 6   # H+1


def test_bad_cases_fail_codes(tv):
    expect_err = {
        "bad_img_bit": 0x08, "bad_sig_C": 0x08, "bad_sig_y17": 0x08,
        "bad_sig_path3": 0x08, "wrong_key": 0x08,
        "bad_sig_len": 0x01, "bad_nspk": 0x02, "bad_ots_type": 0x03,
        "bad_lms_type": 0x04, "bad_q_range": 0x05, "bad_magic": 0x07,
        "rollback": 0x09,
    }
    for case, err in expect_err.items():
        txt = (tv / case / "expect.txt").read_text().splitlines()
        assert txt[0] == "result=FAIL", case
        assert txt[1] == f"err=0x{err:02x}", case


def test_random_cases_all_fail(tv):
    flips = sorted(tv.glob("random_flip_*"))
    assert len(flips) == 200
    for d in flips:
        assert (d / "expect.txt").read_text().splitlines()[0] == "result=FAIL"


def test_rfc_cases_are_valid_signatures(tv):
    for case in ("rfc_tc1_l1", "rfc_tc1_l0", "rfc_tc2_l1"):
        d = tv / case
        pub = (d / "pubkey.bin").read_bytes()
        sig = (d / "sig.bin").read_bytes()
        img = (d / "img.bin").read_bytes()
        valid, _ = lms_ref.hss_l1_verify(pub, img, sig)
        assert valid, f"{case} tidak valid menurut model"
