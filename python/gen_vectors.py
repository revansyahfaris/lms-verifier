"""Generator seluruh folder data uji tv/ (pemilik: Verifikasi, kontrak bagian 5).

Semua data uji dihasilkan dari kunci demo seed-tetap (lms_ref.DEMO_SEED) dan
vektor resmi RFC 8554 Appendix F, sehingga berkas yang dihasilkan selalu
identik di komputer siapa pun. Jangan edit berkas di tv/ secara manual.

Format berkas (kontrak bagian 5):
- Nilai 256 bit  : 64 hex huruf kecil per baris (big-endian, seperti bytes.hex())
- Nilai 512 bit  : 128 hex per baris
- Nilai kecil    : lebar tetap sesuai bit (2 hex untuk 8 bit)
- Isi RAM        : 8 hex per word 32 bit, LITTLE-ENDIAN seperti dilihat RAM
                   (byte 01 02 03 04 -> baris "04030201"), untuk $readmemh.

Pemakaian:
    python3 gen_vectors.py [outdir]      # default: tv/
"""

import hashlib
import os
import random
import shutil
import struct
import sys
from pathlib import Path

import lms_ref
import make_image as mi

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "tv"
APPENDIX_F = REPO_ROOT / "python" / "rfc8554_appendix_f.txt"

N = 32          # byte per hash
P = 34          # jumlah rantai (W=8)
H = 5           # tinggi pohon
SIG_LEN = 1296  # tanda tangan HSS L=1 penuh
N_RANDOM = 200  # jumlah kasus bit-flip acak
RANDOM_SEED = 0xC0FFEE

# Blok rantai Winternitz (kontrak bagian 3.3): I||q||i||j||tmp||0x80||len
# panjangnya tetap 55 byte data + padding = 64 byte, state_in = IV SHA-256.
SHA256_IV = bytes.fromhex(
    "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"
)


# ---------------------------------------------------------------------------
# Penulis berkas kecil
# ---------------------------------------------------------------------------

def write_hex_lines(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for v in values:
            f.write(v + "\n")


def to_ram_words(data):
    """Ubah bytes jadi daftar word 32-bit little-endian seperti dilihat RAM.

    bytes[0:4] -> word dengan bytes[0] di bit rendah: hex "04030201".
    Ini meniru hasil memcpy HPS, sesuai kontrak bagian 2 dan 5.
    """
    assert len(data) % 4 == 0, "isi RAM harus kelipatan 4 byte"
    words = []
    for off in range(0, len(data), 4):
        w = struct.unpack("<I", data[off:off + 4])[0]
        words.append(f"{w:08x}")
    return words


def write_ram_words(path, data):
    write_hex_lines(path, to_ram_words(data))


def write_expect(path, result, err, version):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(f"result={result}\n")
        f.write(f"err=0x{err:02x}\n")
        f.write(f"version={version}\n")


def shared_img(out, img_bytes):
    """Simpan image dan img.words.hex sekali di tv/img/<hash16>.* .

    Banyak kasus memakai image yang sama (mis. 200 random_flip); menyimpan
    tiap-tiap salinan akan menggandakan ukuran repo tanpa manfaat.
    Mengembalikan nama dasar <hash16> (tanpa ekstensi).
    """
    base = hashlib.sha256(img_bytes).hexdigest()[:16]
    img_dir = out / "img"
    img_dir.mkdir(parents=True, exist_ok=True)
    bin_target = img_dir / (base + ".bin")
    if not bin_target.exists():
        bin_target.write_bytes(img_bytes)
        img_padded = img_bytes + b"\x00" * ((-len(img_bytes)) % 4)
        write_ram_words(img_dir / (base + ".words.hex"), img_padded)
    return base


# ---------------------------------------------------------------------------
# Format HSS L=1 tim (Nspk=0)
# ---------------------------------------------------------------------------

def lms_to_hss_l1(lms_sig_bytes):
    """Tambahkan 4 byte Nspk=0 di depan tanda tangan LMS (kontrak bagian 5)."""
    return b"\x00\x00\x00\x00" + lms_sig_bytes


def parse_hss_l1(sig_bytes):
    """Baca HSS L=1 tim: pastikan Nspk=0 lalu parse tanda tangan LMS."""
    return lms_ref.parse_lms_sig(sig_bytes, 4)


# ---------------------------------------------------------------------------
# Penulis satu kasus uji lengkap (tv/<nama>/)
# ---------------------------------------------------------------------------

def write_case(out, name, pub_bytes, sig_bytes, img_bytes, expect, raw_mode=False):
    """Tulis semua berkas untuk satu kasus uji sesuai struktur kontrak.

    pub_bytes   : kunci publik LMS (56 byte) yang dipakai ROM.
    sig_bytes   : tanda tangan HSS L=1 lengkap (1296 byte).
    img_bytes   : isi IMG_RAM (image firmware, atau pesan mentah jika raw_mode).
    expect      : dict {result, err, version}.
    raw_mode    : True untuk kasus RFC (pesan tanpa header, RAW_MSG_MODE=1).
    """
    case_dir = out / name
    case_dir.mkdir(parents=True, exist_ok=True)

    # Berkas mentah. Image (dan img.words.hex) disimpan sekali di tv/img/
    # lalu di-symlink supaya repo tidak menggandakan image yang sama.
    (case_dir / "pubkey.bin").write_bytes(pub_bytes)
    (case_dir / "sig.bin").write_bytes(sig_bytes)
    img_base = shared_img(out, img_bytes)
    for link_name, target_name in (
            ("img.bin", img_base + ".bin"),
            ("img.words.hex", img_base + ".words.hex")):
        link = case_dir / link_name
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(os.path.join("..", "img", target_name))

    # sig.words.hex ditulis per kasus (tiap tanda tangan memang berbeda).
    sig_padded = sig_bytes + b"\x00" * ((-len(sig_bytes)) % 4)
    write_ram_words(case_dir / "sig.words.hex", sig_padded)

    # Kunci publik ke dalam ROM
    pub, _ = lms_ref.parse_lms_pubkey(pub_bytes)
    write_hex_lines(case_dir / "rom_I.hex", [pub["I"].hex()])
    write_hex_lines(case_dir / "rom_T1.hex", [pub["K"].hex()])

    # Nilai perantara dari model. Hanya ditulis kalau tanda tangan bisa
    # di-parse secara struktur; untuk kasus dengan type tidak dikenal
    # (bad_ots_type/bad_lms_type) perantara tidak bermakna sehingga dilewati.
    try:
        sig, _ = parse_hss_l1(sig_bytes)
        iv = lms_ref.compute_intermediates(pub, img_bytes, sig)
    except (KeyError, IndexError):
        iv = None

    if iv is not None:
        write_hex_lines(case_dir / "Q.hex", [iv["Q"].hex()])
        write_hex_lines(case_dir / "coef.hex", [f"{a:02x}" for a in iv["coef"]])
        write_hex_lines(case_dir / "y.hex", [v.hex() for v in iv["y"]])
        write_hex_lines(case_dir / "z.hex", [v.hex() for v in iv["z"]])
        write_hex_lines(case_dir / "Kc.hex", [iv["Kc"].hex()])
        write_hex_lines(case_dir / "merkle.hex", [v.hex() for v in iv["merkle"]])
        write_hex_lines(case_dir / "Tc.hex", [iv["Tc"].hex()])

    write_expect(case_dir / "expect.txt", expect["result"], expect["err"],
                 expect["version"])


# ---------------------------------------------------------------------------
# Blok SHA-256 (tv/sha256/) untuk sha256_compress dan lmots_chain
# ---------------------------------------------------------------------------

def chain_block(I, q, i, j, tmp):
    """Satu blok SHA-256 rantai Winternitz sesuai kontrak bagian 3.3."""
    data = I + struct.pack(">I", q) + struct.pack(">H", i) + bytes([j]) + tmp
    assert len(data) == 55
    return data + b"\x80" + struct.pack(">Q", 440)


def gen_sha256_blocks(out, demo):
    """Berkas tv/sha256/: blocks.hex, state_in.hex, state_out.hex (sejajar)."""
    import hashlib
    blocks, state_out = [], []

    # 1. Blok "abc" ter-padding
    blocks.append(
        b"abc" + b"\x80" + b"\x00" * 52 + struct.pack(">Q", 24)
    )
    # 2. Blok pesan kosong
    blocks.append(b"\x80" + b"\x00" * 55 + struct.pack(">Q", 0))
    # 3-5. Tiga blok pertama rantai ke-0 data uji (dari kunci demo, q=0)
    I, q, i = demo.I, 0, 0
    x0 = lms_ref.lmots_chain_element(I, demo.seed, q, i, demo.ots)
    tmp = x0
    for j in range(3):
        blocks.append(chain_block(I, q, i, j, tmp))
        tmp = lms_ref.H(I + struct.pack(">I", q) + struct.pack(">H", i)
                        + bytes([j]) + tmp)

    for b in blocks:
        assert len(b) == 64
        state_out.append(hashlib.sha256(b).hexdigest())

    sha_dir = out / "sha256"
    write_hex_lines(sha_dir / "blocks.hex", [b.hex() for b in blocks])
    write_hex_lines(sha_dir / "state_in.hex", [SHA256_IV.hex()] * len(blocks))
    write_hex_lines(sha_dir / "state_out.hex", state_out)
    return len(blocks)


# ---------------------------------------------------------------------------
# Kasus valid_* (kunci demo, image dengan header)
# ---------------------------------------------------------------------------

def gen_valid_cases(out, demo, pub_bytes):
    # Image untuk tiap kasus valid
    img_q = mi.make_demo_image(version=1)
    img_v2 = mi.make_image(mi.DEFAULT_PAYLOAD, version=2)
    img_odd = mi.make_image(bytes(range(33)), version=1)   # payload 33 -> 36 byte

    cases = []

    for q, ver in ((0, 1), (31, 1)):
        sig, _ = lms_ref.hss_l1_sign(demo, img_q, q)
        cases.append((f"valid_q{q}", pub_bytes, sig, img_q,
                      {"result": "PASS", "err": 0x00, "version": ver}))

    sig, _ = lms_ref.hss_l1_sign(demo, img_v2, 0)
    cases.append(("valid_v2", pub_bytes, sig, img_v2,
                  {"result": "PASS", "err": 0x00, "version": 2}))

    sig, _ = lms_ref.hss_l1_sign(demo, img_odd, 0)
    cases.append(("valid_len_odd", pub_bytes, sig, img_odd,
                  {"result": "PASS", "err": 0x00, "version": 1}))

    for name, pub, sig, img, expect in cases:
        write_case(out, name, pub, sig, img, expect)
    return [c[0] for c in cases], img_q, img_v2


# ---------------------------------------------------------------------------
# Kasus rusak
# ---------------------------------------------------------------------------

def flip(data, byte_off, bit=0):
    b = bytearray(data)
    b[byte_off] ^= (1 << bit)
    return bytes(b)


def gen_bad_cases(out, demo, pub_bytes, base_img, img_v2):
    base_sig, _ = lms_ref.hss_l1_sign(demo, base_img, 0)
    sig_v2, _ = lms_ref.hss_l1_sign(demo, img_v2, 0)
    cases = []

    def add(name, sig, img, expect):
        cases.append((name, pub_bytes, sig, img, expect))

    # Kesalahan kriptografi -> SIG_INVALID (0x08)
    add("bad_img_bit", base_sig, flip(base_img, 30),
        {"result": "FAIL", "err": 0x08, "version": 1})
    add("bad_sig_C", flip(base_sig, 12), base_img,
        {"result": "FAIL", "err": 0x08, "version": 1})
    add("bad_sig_y17", flip(base_sig, 44 + 32 * 17), base_img,
        {"result": "FAIL", "err": 0x08, "version": 1})
    add("bad_sig_path3", flip(base_sig, 1136 + 32 * 3), base_img,
        {"result": "FAIL", "err": 0x08, "version": 1})

    # Kunci lain -> SIG_INVALID (0x08)
    other = lms_ref.LmsPrivateKey(bytes(range(32, 64)), b"OTHER-KEY-DEMO01")
    sig_other, _ = lms_ref.hss_l1_sign(other, base_img, 0)
    add("wrong_key", sig_other, base_img,
        {"result": "FAIL", "err": 0x08, "version": 1})

    # Kesalahan format (kode error 0x01..0x07)
    add("bad_sig_len", base_sig[:1295], base_img,
        {"result": "FAIL", "err": 0x01, "version": 1})
    add("bad_nspk", flip(base_sig, 3, 0), base_img,          # Nspk = 1
        {"result": "FAIL", "err": 0x02, "version": 1})
    add("bad_ots_type", flip(base_sig, 11, 1), base_img,     # ots type 4->6
        {"result": "FAIL", "err": 0x03, "version": 1})
    add("bad_lms_type", flip(base_sig, 1135, 1), base_img,   # lms type 5->7
        {"result": "FAIL", "err": 0x04, "version": 1})
    q32 = bytearray(base_sig)
    q32[7] = 32                                              # q = 32
    add("bad_q_range", bytes(q32), base_img,
        {"result": "FAIL", "err": 0x05, "version": 1})
    add("bad_magic", base_sig, flip(base_img, 0),            # magic rusak
        {"result": "FAIL", "err": 0x07, "version": 1})

    # Rollback: image versi 1 ditandatangani sah, tetapi MIN_VERSION sudah 2
    # (dicapai dengan COMMIT pada image versi 2 lebih dulu).
    add("rollback", base_sig, base_img,
        {"result": "FAIL", "err": 0x09, "version": 1})

    for name, pub, sig, img, expect in cases:
        write_case(out, name, pub, sig, img, expect)

    # Catatan pendamping rollback: sig versi 2 yang sah (untuk COMMIT lebih dulu)
    (out / "rollback").mkdir(parents=True, exist_ok=True)
    (out / "rollback" / "sig_v2.bin").write_bytes(sig_v2)
    write_ram_words(out / "rollback" / "sig_v2.words.hex", sig_v2)
    return [c[0] for c in cases]


# ---------------------------------------------------------------------------
# Kasus acak: 200 bit-flip -> semuanya FAIL
# ---------------------------------------------------------------------------

def gen_random_cases(out, demo, pub_bytes, base_img):
    """200+ kasus bit acak -> semuanya FAIL SIG_INVALID.

    Bit dibalik di dalam TANDA TANGAN (bukan image), supaya:
    1. Kegagalan murni dari jalur kriptografi (SIG_INVALID 0x08), bukan dari
       cek format header image.
    2. Semua kasus memakai image yang sama, sehingga tidak menggandakan
       berkas image (repo tetap kecil).
    """
    rng = random.Random(RANDOM_SEED)
    sig, _ = lms_ref.hss_l1_sign(demo, base_img, 0)
    names = []
    for k in range(N_RANDOM):
        off = rng.randrange(len(sig))
        sig2 = flip(sig, off, rng.randrange(8))
        name = f"random_flip_{k:03d}"
        write_case(out, name, pub_bytes, sig2, base_img,
                   {"result": "FAIL", "err": 0x08, "version": 1})
        names.append(name)
    return names


# ---------------------------------------------------------------------------
# Kasus RFC resmi (RAW_MSG_MODE=1, pesan tanpa header)
# ---------------------------------------------------------------------------

def split_hss(sig_bytes, nspk):
    offset = 4
    sigs, pubs = [], []
    for _ in range(nspk):
        s, offset = lms_ref.parse_lms_sig(sig_bytes, offset)
        p, offset = lms_ref.parse_lms_pubkey(sig_bytes, offset)
        sigs.append(s)
        pubs.append(p)
    s, offset = lms_ref.parse_lms_sig(sig_bytes, offset)
    sigs.append(s)
    return sigs, pubs, offset


def serialize_lms_sig(sig):
    return (
        struct.pack(">I", sig["q"])
        + struct.pack(">I", sig["lmots"]["ots"].typecode)
        + sig["lmots"]["C"]
        + b"".join(sig["lmots"]["y"])
        + struct.pack(">I", sig["lms"].typecode)
        + b"".join(sig["path"])
    )


def gen_rfc_cases(out):
    rfc = lms_ref.parse_rfc_appendix_f(APPENDIX_F)
    names = []

    def add(name, pub, sig_parsed, msg):
        sig = lms_to_hss_l1(serialize_lms_sig(sig_parsed))
        assert len(sig) == SIG_LEN, f"{name}: sig {len(sig)} != {SIG_LEN}"
        write_case(out, name, pub, sig, msg,
                   {"result": "PASS", "err": 0x00, "version": 0}, raw_mode=True)
        names.append(name)

    # TC1 level 1: menandatangani pesan asli (q=10)
    tc1 = rfc["tc1"]
    sigs1, pubs1, _ = split_hss(tc1["signature"], 1)
    add("rfc_tc1_l1", lms_ref.serialize_lms_pubkey(pubs1[0]), sigs1[1],
        tc1["message"])

    # TC1 level 0: menandatangani kunci publik level 1 (q=5)
    top_pub1, _ = lms_ref.parse_lms_pubkey(tc1["pubkey"], 4)
    add("rfc_tc1_l0", lms_ref.serialize_lms_pubkey(top_pub1), sigs1[0],
        lms_ref.serialize_lms_pubkey(pubs1[0]))

    # TC2 level 1: menandatangani pesan asli (q=4, parameter sama dgn desain)
    tc2 = rfc["tc2"]
    sigs2, pubs2, _ = split_hss(tc2["signature"], 1)
    add("rfc_tc2_l1", lms_ref.serialize_lms_pubkey(pubs2[0]), sigs2[1],
        tc2["message"])

    return names


# ---------------------------------------------------------------------------
# Utama
# ---------------------------------------------------------------------------

def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT

    # Bersihkan hanya subfolder yang kita kelola (jangan sentuh README/core_mock)
    for sub in ("sha256",):
        d = out / sub
        if d.exists():
            shutil.rmtree(d)
    for d in out.iterdir() if out.exists() else []:
        if d.is_dir() and (d.name.startswith(("valid_", "bad_", "wrong_key",
                                               "rollback", "random_flip_",
                                               "rfc_"))):
            shutil.rmtree(d)

    out.mkdir(parents=True, exist_ok=True)

    demo = lms_ref.demo_key()
    pub_bytes = demo.public_key_bytes()

    n_blocks = gen_sha256_blocks(out, demo)
    valid_names, base_img, img_v2 = gen_valid_cases(out, demo, pub_bytes)
    bad_names = gen_bad_cases(out, demo, pub_bytes, base_img, img_v2)
    rand_names = gen_random_cases(out, demo, pub_bytes, base_img)
    rfc_names = gen_rfc_cases(out)

    total = (len(valid_names) + len(bad_names) + len(rand_names) + len(rfc_names))
    print(f"tv/sha256            : {n_blocks} blok")
    print(f"valid_*              : {len(valid_names)} kasus")
    print(f"bad_* / wrong_key / rollback : {len(bad_names)} kasus")
    print(f"random_flip_*        : {len(rand_names)} kasus")
    print(f"rfc_*                : {len(rfc_names)} kasus")
    print(f"TOTAL                : {total} kasus -> {out}")


if __name__ == "__main__":
    main()
