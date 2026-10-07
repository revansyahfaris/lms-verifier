"""Model referensi LMS/HSS (pemilik: Verifikasi, kontrak bagian 7).

Implementasi murni Python di atas hashlib mengikuti RFC 8554:
keygen dengan seed tetap (Appendix A), sign, verify, dan ekspor nilai
perantara (Q, koefisien, z, Kc, langkah Merkle, Tc) untuk data uji tv/.

Konfigurasi tim (kontrak bagian 1):
  utama   : LMS_SHA256_M32_H5 (type 5) + LMOTS_SHA256_N32_W8 (type 4)
  kedua   : LMOTS_SHA256_N32_W4 (type 3) untuk benchmark trade-off
Format pembungkus: HSS dengan L = 1 (Nspk = 0, overhead 4 byte).
Model ini juga bisa memverifikasi HSS dua level dari RFC 8554 Appendix F
karena vektor uji resmi (rfc_tc1_*, rfc_tc2_*) berbentuk dua level.
"""

import hashlib
import re
from dataclasses import dataclass

# Pemisah domain (RFC 8554 bagian 4.4, 4.6, 5.4)
D_PBLC = 0x8080
D_MESG = 0x8181
D_LEAF = 0x8282
D_INTR = 0x8383


def u8str(x):
    return x.to_bytes(1, "big")


def u16str(x):
    return x.to_bytes(2, "big")


def u32str(x):
    return x.to_bytes(4, "big")


def H(data):
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Parameter resmi RFC 8554 (typecode -> parameter)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LmotsParams:
    typecode: int
    name: str
    n: int   # byte per nilai hash
    w: int   # parameter Winternitz
    p: int   # jumlah rantai
    ls: int  # pergeseran checksum


@dataclass(frozen=True)
class LmsParams:
    typecode: int
    name: str
    n: int
    h: int   # tinggi pohon Merkle


LMOTS_SHA256_N32_W4 = LmotsParams(3, "LMOTS_SHA256_N32_W4", 32, 4, 67, 4)
LMOTS_SHA256_N32_W8 = LmotsParams(4, "LMOTS_SHA256_N32_W8", 32, 8, 34, 0)
LMS_SHA256_M32_H5 = LmsParams(5, "LM_SHA256_M32_H5", 32, 5)
LMS_SHA256_M32_H10 = LmsParams(6, "LM_SHA256_M32_H10", 32, 10)

LMOTS_BY_TYPE = {p.typecode: p for p in (LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8)}
LMS_BY_TYPE = {p.typecode: p for p in (LMS_SHA256_M32_H5, LMS_SHA256_M32_H10)}

# Kunci demo tim (kontrak bagian 5 dan 7): seed tetap supaya berkas tv/
# selalu identik di komputer siapa pun. Kunci ini BUKAN rahasia.
DEMO_SEED = bytes(range(32))          # 000102...1f
DEMO_I = b"LMS-VERIFIER-DEM"          # tepat 16 byte


# ---------------------------------------------------------------------------
# Koefisien dan checksum LM-OTS (RFC 8554 bagian 4.4)
# ---------------------------------------------------------------------------

def coef(S, i, w):
    """Digit ke-i (w bit) dari string byte S."""
    return (S[(i * w) // 8] >> (8 - w * ((i % (8 // w)) + 1))) & ((1 << w) - 1)


def cksm(Q, ots):
    """Checksum atas Q: u16str(sum((2^w - 1) - a_i) << ls)."""
    u = (8 * ots.n) // ots.w
    total = sum(((1 << ots.w) - 1) - coef(Q, i, ots.w) for i in range(u))
    return u16str(total << ots.ls)


def message_digits(Q, ots):
    """Koefisien a_0..a_{p-1} yang dihitung dari Q || Cksm(Q)."""
    S = Q + cksm(Q, ots)
    return [coef(S, i, ots.w) for i in range(ots.p)]


# ---------------------------------------------------------------------------
# Rantai Winternitz (RFC 8554 bagian 4.5)
# ---------------------------------------------------------------------------

def winternitz_chain(I, q, i, start_value, j_from, j_to, ots, collect=False):
    """Hash berantai: tmp = H(I || u32(q) || u16(i) || u8(j) || tmp)
    untuk j dari j_from sampai j_to (inklusif). Jika j_from > j_to,
    tidak ada hash dan hasilnya start_value (rantai kosong).
    Mengembalikan (nilai_akhir, semua_langkah_atau_None).
    """
    tmp = start_value
    steps = [tmp] if collect else None
    for j in range(j_from, j_to + 1):
        tmp = H(I + u32str(q) + u16str(i) + u8str(j) + tmp)
        if collect:
            steps.append(tmp)
    return tmp, steps


def lmots_chain_element(I, seed, q, i, ots):
    """Elemen kunci privat x_q[i] = H(I || u32(q) || u16(i) || u8(0xff) || SEED)
    (prosedur pseudorandom, RFC 8554 Appendix A)."""
    return H(I + u32str(q) + u16str(i) + u8str(0xFF) + seed)


def lmots_pubkey_k(I, seed, q, ots):
    """Kunci publik LM-OTS K_q = H(I || u32(q) || u16(D_PBLC) || z_0..z_{p-1}),
    dengan z_i = rantai penuh dari x_i (j = 0 .. 2^w - 2)."""
    z = []
    for i in range(ots.p):
        x_i = lmots_chain_element(I, seed, q, i, ots)
        z_i, _ = winternitz_chain(I, q, i, x_i, 0, (1 << ots.w) - 2, ots)
        z.append(z_i)
    return H(I + u32str(q) + u16str(D_PBLC) + b"".join(z))


# ---------------------------------------------------------------------------
# Keygen LMS: pohon Merkle di atas kunci publik LM-OTS (RFC 8554 bagian 5.3)
# ---------------------------------------------------------------------------

def build_tree(I, seed, lms, ots):
    """Bangun pohon Merkle penuh. tree[1] = akar T[1]."""
    n_leaves = 1 << lms.h
    tree = [b""] * (2 * n_leaves)
    for q in range(n_leaves):
        k_q = lmots_pubkey_k(I, seed, q, ots)
        r = n_leaves + q
        tree[r] = H(I + u32str(r) + u16str(D_LEAF) + k_q)
    for r in range(n_leaves - 1, 0, -1):
        tree[r] = H(I + u32str(r) + u16str(D_INTR) + tree[2 * r] + tree[2 * r + 1])
    return tree


class LmsPrivateKey:
    """Kunci privat demo: SEED + I + pohon Merkle (dipakai untuk auth path)."""

    def __init__(self, seed, I, lms=None, ots=None):
        self.seed = seed
        self.I = I
        self.lms = lms or LMS_SHA256_M32_H5
        self.ots = ots or LMOTS_SHA256_N32_W8
        self.tree = build_tree(I, seed, self.lms, self.ots)

    @property
    def root(self):
        return self.tree[1]

    def public_key_bytes(self):
        """Serialisasi: u32(lms_type) || u32(ots_type) || I || T[1]."""
        return (
            u32str(self.lms.typecode)
            + u32str(self.ots.typecode)
            + self.I
            + self.root
        )

    def auth_path(self, q):
        """Jalur otentikasi daun q: saudara tiap level dari bawah ke atas."""
        node = (1 << self.lms.h) + q
        path = []
        for _ in range(self.lms.h):
            path.append(self.tree[node ^ 1])
            node //= 2
        return path


def demo_key():
    """Kunci demo tim dari seed tetap (reprodusibel di semua komputer)."""
    return LmsPrivateKey(DEMO_SEED, DEMO_I)


# ---------------------------------------------------------------------------
# Sign (RFC 8554 bagian 4.5, 5.4) dengan pembungkus HSS L=1
# ---------------------------------------------------------------------------

def derive_c(seed, q, n):
    """C deterministik dari SEED dan q supaya data uji reprodusibel.

    CATATAN: di pemakaian nyata C harus acak (RFC 8554 bagian 4.6).
    Deterministik hanya untuk demo/pengujian sesuai kontrak bagian 5.
    """
    return H(seed + b"C" + u32str(q))[:n]


def lms_sign(key, message, q, C=None):
    """Tanda tangani message dengan daun q. Mengembalikan (lms_sig, detail).

    lms_sig = u32(q) || u32(ots_type) || C || y[0..p-1] || u32(lms_type) || path
    detail berisi semua nilai perantara untuk data uji.
    """
    ots, lms, I = key.ots, key.lms, key.I
    if C is None:
        C = derive_c(key.seed, q, ots.n)

    Q = H(I + u32str(q) + u16str(D_MESG) + C + message)
    digits = message_digits(Q, ots)

    y = []
    for i in range(ots.p):
        x_i = lmots_chain_element(I, key.seed, q, i, ots)
        y_i, _ = winternitz_chain(I, q, i, x_i, 0, digits[i] - 1, ots)
        y.append(y_i)

    path = key.auth_path(q)

    lms_sig = (
        u32str(q)
        + u32str(ots.typecode)
        + C
        + b"".join(y)
        + u32str(lms.typecode)
        + b"".join(path)
    )

    detail = {"Q": Q, "digits": digits, "y": y, "C": C, "path": path, "q": q}
    return lms_sig, detail


def hss_l1_sign(key, message, q, C=None):
    """Pembungkus HSS L=1: u32(Nspk=0) || lms_sig. Total 1296 byte (H5+W8)."""
    lms_sig, detail = lms_sign(key, message, q, C)
    return u32str(0) + lms_sig, detail


# ---------------------------------------------------------------------------
# Parsing struktur (dipakai verify dan gen_vectors)
# ---------------------------------------------------------------------------

def parse_lms_pubkey(data, offset=0):
    """Baca kunci publik LMS: type LMS || type LM-OTS || I || K."""
    lms_type = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    ots_type = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    lms = LMS_BY_TYPE[lms_type]
    ots = LMOTS_BY_TYPE[ots_type]
    I = data[offset:offset + 16]
    offset += 16
    K = data[offset:offset + lms.n]
    offset += lms.n
    return {"lms": lms, "ots": ots, "I": I, "K": K}, offset


def serialize_lms_pubkey(pub):
    """Kebalikan parse_lms_pubkey (untuk pesan bertingkat HSS)."""
    return (
        u32str(pub["lms"].typecode)
        + u32str(pub["ots"].typecode)
        + pub["I"]
        + pub["K"]
    )


def parse_lmots_sig(data, offset=0):
    """Baca tanda tangan LM-OTS: type || C || y[0..p-1]."""
    ots_type = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    ots = LMOTS_BY_TYPE[ots_type]
    C = data[offset:offset + ots.n]
    offset += ots.n
    y = []
    for _ in range(ots.p):
        y.append(data[offset:offset + ots.n])
        offset += ots.n
    return {"ots": ots, "C": C, "y": y}, offset


def parse_lms_sig(data, offset=0):
    """Baca tanda tangan LMS: q || sig LM-OTS || type LMS || path[0..h-1]."""
    q = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    lmots, offset = parse_lmots_sig(data, offset)
    lms_type = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    lms = LMS_BY_TYPE[lms_type]
    path = []
    for _ in range(lms.h):
        path.append(data[offset:offset + lms.n])
        offset += lms.n
    return {"q": q, "lmots": lmots, "lms": lms, "path": path}, offset


# ---------------------------------------------------------------------------
# Verify (RFC 8554 bagian 4.6, 5.4.2, 6.4)
# ---------------------------------------------------------------------------

def lmots_candidate_key(I, q, message, lmots_sig):
    """Kunci kandidat Kc dari tanda tangan LM-OTS + semua nilai perantara."""
    ots = lmots_sig["ots"]
    C, y = lmots_sig["C"], lmots_sig["y"]

    Q = H(I + u32str(q) + u16str(D_MESG) + C + message)
    digits = message_digits(Q, ots)

    z, chains = [], []
    for i in range(ots.p):
        z_i, steps = winternitz_chain(
            I, q, i, y[i], digits[i], (1 << ots.w) - 2, ots, collect=True
        )
        z.append(z_i)
        chains.append(steps)

    Kc = H(I + u32str(q) + u16str(D_PBLC) + b"".join(z))
    return {"Q": Q, "digits": digits, "z": z, "chains": chains, "Kc": Kc}


def merkle_climb(I, q, Kc, path, lms):
    """Naik pohon Merkle sampai kandidat akar Tc (Algorithm 6a)."""
    node_num = (1 << lms.h) + q
    tmp = H(I + u32str(node_num) + u16str(D_LEAF) + Kc)
    steps = [tmp]
    for i in range(lms.h):
        if node_num % 2 == 1:
            tmp = H(I + u32str(node_num // 2) + u16str(D_INTR) + path[i] + tmp)
        else:
            tmp = H(I + u32str(node_num // 2) + u16str(D_INTR) + tmp + path[i])
        node_num //= 2
        steps.append(tmp)
    return {"root": tmp, "steps": steps}


def lms_verify(pub, message, sig):
    """Verifikasi satu level LMS. pub/sig boleh dict hasil parse atau bytes."""
    if isinstance(pub, (bytes, bytearray)):
        pub, _ = parse_lms_pubkey(bytes(pub))
    if isinstance(sig, (bytes, bytearray)):
        sig, _ = parse_lms_sig(bytes(sig))

    cand = lmots_candidate_key(pub["I"], sig["q"], message, sig["lmots"])
    merkle = merkle_climb(pub["I"], sig["q"], cand["Kc"], sig["path"], pub["lms"])
    valid = merkle["root"] == pub["K"]
    return valid, {"lmots": cand, "merkle": merkle, "q": sig["q"]}


def hss_l1_verify(pub_bytes, message, sig_bytes):
    """Verifikasi format tim: HSS L=1 (Nspk wajib 0)."""
    nspk = int.from_bytes(sig_bytes[0:4], "big")
    if nspk != 0:
        return False, {"error": "Nspk != 0"}
    pub, _ = parse_lms_pubkey(pub_bytes)
    sig, _ = parse_lms_sig(sig_bytes, 4)
    return lms_verify(pub, message, sig)


def hss_verify(pub_bytes, message, sig_bytes):
    """Verifikasi HSS umum (multi-level), dipakai untuk vektor RFC Appendix F."""
    levels = int.from_bytes(pub_bytes[0:4], "big")
    top_pub, _ = parse_lms_pubkey(pub_bytes, 4)

    nspk = int.from_bytes(sig_bytes[0:4], "big")
    if nspk != levels - 1:
        return {"valid": False, "error": "Nspk tidak cocok dengan levels"}

    offset = 4
    sig_list, pub_list = [], [top_pub]
    for _ in range(nspk):
        s, offset = parse_lms_sig(sig_bytes, offset)
        p, offset = parse_lms_pubkey(sig_bytes, offset)
        sig_list.append(s)
        pub_list.append(p)
    final_sig, offset = parse_lms_sig(sig_bytes, offset)
    sig_list.append(final_sig)

    details = []
    for i in range(levels):
        if i < levels - 1:
            signed_data = serialize_lms_pubkey(pub_list[i + 1])
        else:
            signed_data = message
        valid, detail = lms_verify(pub_list[i], signed_data, sig_list[i])
        details.append({"level": i, "valid": valid, **detail})
        if not valid:
            return {"valid": False, "levels": details}
    return {"valid": True, "levels": details}


# ---------------------------------------------------------------------------
# Ekspor nilai perantara (untuk gen_vectors.py menulis berkas tv/)
# ---------------------------------------------------------------------------

def compute_intermediates(pub, message, sig):
    """Semua nilai perantara satu verifikasi LMS untuk berkas tv/<kasus>/.

    Mengembalikan dict: Q, coef, y (dari sig), z, Kc, merkle (daun + tiap
    level), Tc, I, T1 (root kunci publik), valid.
    """
    if isinstance(pub, (bytes, bytearray)):
        pub, _ = parse_lms_pubkey(bytes(pub))
    if isinstance(sig, (bytes, bytearray)):
        sig, _ = parse_lms_sig(bytes(sig))

    cand = lmots_candidate_key(pub["I"], sig["q"], message, sig["lmots"])
    merkle = merkle_climb(pub["I"], sig["q"], cand["Kc"], sig["path"], pub["lms"])
    return {
        "I": pub["I"],
        "T1": pub["K"],
        "q": sig["q"],
        "C": sig["lmots"]["C"],
        "Q": cand["Q"],
        "coef": cand["digits"],
        "y": sig["lmots"]["y"],
        "z": cand["z"],
        "chains": cand["chains"],
        "Kc": cand["Kc"],
        "merkle": merkle["steps"],
        "Tc": merkle["root"],
        "valid": merkle["root"] == pub["K"],
    }


# ---------------------------------------------------------------------------
# Parser RFC 8554 Appendix F (sumber vektor uji resmi, kontrak bagian 5)
# ---------------------------------------------------------------------------

def _hex_fields(section_lines):
    """Gabungkan semua field hex dalam satu bagian (lanjutan baris ikut).

    Pemisah antar-field adalah spasi ganda (sesuai format Appendix F),
    sehingga footer halaman seperti "April 2019" tidak ikut terbaca.
    """
    parts = []
    for line in section_lines:
        line = line.split("|")[0].split("#")[0].rstrip()
        if not line.strip():
            continue
        fields = re.split(r"\s{2,}", line.strip())
        candidate = fields[-1].strip()
        if candidate and re.fullmatch(r"[0-9a-fA-F]+", candidate) \
                and len(candidate) % 2 == 0:
            parts.append(candidate.lower())
    return "".join(parts)


def _split_sections(lines, markers):
    """Potong teks menjadi bagian-bagian berdasarkan daftar penanda."""
    sections = {}
    current, buf = None, []
    for line in lines:
        matched = None
        for key, marker in markers:
            if marker in line:
                matched = key
                break
        if matched is not None:
            if current is not None:
                sections[current] = buf
            current, buf = matched, []
            continue
        if current is not None:
            buf.append(line)
    if current is not None:
        sections[current] = buf
    return sections


def parse_rfc_appendix_f(path):
    """Baca python/rfc8554_appendix_f.txt menjadi dict siap pakai.

    Hasil: {"tc1": {pubkey, message, signature},
            "tc2": {privkey: {top: {seed, i}, second: {seed, i}},
                    pubkey, message, signature}}
    Semua nilai berupa bytes.
    """
    with open(path) as f:
        lines = f.read().splitlines()

    markers = [
        ("tc1_pub", "Test Case 1 Public Key"),
        ("tc1_msg", "Test Case 1 Message"),
        ("tc1_sig", "Test Case 1 Signature"),
        ("tc2_priv", "Test Case 2 Private Key"),
        ("tc2_pub", "Test Case 2 Public Key"),
        ("tc2_msg", "Test Case 2 Message"),
        ("tc2_sig", "Test Case 2 Signature"),
    ]
    sec = _split_sections(lines, markers)

    out = {
        "tc1": {
            "pubkey": bytes.fromhex(_hex_fields(sec["tc1_pub"])),
            "message": bytes.fromhex(_hex_fields(sec["tc1_msg"])),
            "signature": bytes.fromhex(_hex_fields(sec["tc1_sig"])),
        },
        "tc2": {
            "pubkey": bytes.fromhex(_hex_fields(sec["tc2_pub"])),
            "message": bytes.fromhex(_hex_fields(sec["tc2_msg"])),
            "signature": bytes.fromhex(_hex_fields(sec["tc2_sig"])),
        },
    }

    # Kunci privat TC2: dua sub-bagian (top level / second level)
    priv = {"top": {}, "second": {}}
    current = None
    for line in sec["tc2_priv"]:
        clean = line.split("#")[0]
        if "Top level" in clean:
            current = priv["top"]
        elif "Second level" in clean:
            current = priv["second"]
        elif current is not None and clean.strip().startswith("SEED"):
            current["seed"] = clean.split()[-1]
        elif current is not None and clean.strip().startswith("I "):
            current["i"] = clean.split()[-1]
        elif current is not None and "seed" in current and "seed_cont" not in current \
                and clean.strip() and not clean.strip().startswith(("SEED", "I", "-")):
            # Baris lanjutan SEED (32 hex kedua)
            frag = clean.split()[-1]
            if all(c in "0123456789abcdefABCDEF" for c in frag):
                current["seed"] += frag
                current["seed_cont"] = True
    out["tc2"]["privkey"] = {
        k: {"seed": bytes.fromhex(v["seed"]), "i": bytes.fromhex(v["i"])}
        for k, v in priv.items()
    }
    return out
