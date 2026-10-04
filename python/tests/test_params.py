"""Cek bahwa konstanta di rtl/common/lms_params.vh konsisten dengan rumus RFC 8554."""
import math
import re
from pathlib import Path

VH = Path(__file__).resolve().parents[2] / "rtl" / "common" / "lms_params.vh"


def read_defines():
    text = VH.read_text()
    return {k: int(v) for k, v in re.findall(r"`define\s+(\w+)\s+(\d+)", text)}


def lmots_p(n, w):
    # RFC 8554 Appendix B
    u = math.ceil(8 * n / w)
    v = math.ceil((math.floor(math.log2((2**w - 1) * u)) + 1) / w)
    return u + v


def test_p_matches_rfc():
    d = read_defines()
    assert d["LMS_P"] == lmots_p(d["LMS_N"], d["LMS_W"])


def test_signature_size():
    d = read_defines()
    n, p, h = d["LMS_N"], d["LMS_P"], d["LMS_H"]
    lmots_sig = 4 + n + p * n          # type + C + y[p]
    lms_sig = 4 + lmots_sig + 4 + h * n  # q + lmots_sig + type + path
    hss_sig = 4 + lms_sig              # Nspk (L=1)
    assert hss_sig == d["SIG_BYTES"]
