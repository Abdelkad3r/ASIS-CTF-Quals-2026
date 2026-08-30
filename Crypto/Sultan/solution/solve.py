#!/usr/bin/env python3
"""
Sultan -- ASIS CTF Quals 2026 (Crypto).

The scheme derives its whole symmetric key from a small module-LWE secret and then
leaks that secret through "committee session" hints.

Per downloaded secret.enc:
  * a fresh secret s in R_q = Z_q[X]/(X^n+1)  (q=8380417, n=64) with coeffs in [-3,3];
  * k = SHAKE256("SULTAN/key" || s);  keystream = SHAKE256("SULTAN/stream" || k || nonce);
    e = secret_string XOR keystream;  d = BLAKE2s tag.
  * m=70 sessions, each publishing seed, v = u + c*s (u a fresh uniform mask,
    c = _b(seed)), and hint = floor(<A_seed, u> / b) with A_seed = _r(seed), b=65000.

Since u = v - c*s:
    <A,u> = <A,v> - <A, c*s>  (mod q)
so with M_j*s := <A_j, c_j*s> (linear in s) and T_j := (<A_j,v_j> - hint_j*b) mod q:
    T_j = M_j*s + r_j   (mod q),   s in [-3,3]^n,   r_j in [0, b).
That is small-secret LWE (70 samples, 64 unknowns, error < 65000 << q).  A
Bai-Galbraith primal (Kannan) embedding + BKZ recovers s; then k decrypts the flag.

Recovering s from one file is enough (the session's secret_string is constant).

Requires: fpylll, and the challenge's crypto_engine.py (stdlib-only) on sys.path.
Usage:
    python3 solve.py <secret.enc>     # recover & print the secret string
    python3 solve.py --selftest       # generate a local file and recover it
"""
from __future__ import annotations
import hashlib
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "challenge"))
import crypto_engine as CE  # noqa: E402
from fpylll import IntegerMatrix, LLL, BKZ  # noqa: E402

q, n, ell, m, t, b = CE.q, CE.n, CE.ell, CE.m, CE.t, CE.b
HEADER = CE.HEADER


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def parse(blob: bytes) -> dict:
    raw = zlib.decompress(blob)
    hsz = struct.calcsize(HEADER)
    (_magic, _ver, _q, _n, _ell, _m, _t, _b, _sb, _cs, _thr, slen) = struct.unpack(HEADER, raw[:hsz])
    off = hsz
    nonce = raw[off:off + 24]; off += 24
    e = raw[off:off + slen]; off += slen
    d = raw[off:off + 32]; off += 32
    recs = []
    reclen = 32 + 32 + 4 + 4 * _ell * _n
    for _ in range(_m):
        r = raw[off:off + reclen]; off += reclen
        x, y = r[0:32], r[32:64]
        hint = struct.unpack("<I", r[64:68])[0]
        vcoef = struct.unpack("<" + "I" * (_ell * _n), r[68:68 + 4 * _ell * _n])
        v = [list(vcoef[j * _n:(j + 1) * _n]) for j in range(_ell)]
        recs.append((x, y, hint, v))
    return dict(slen=slen, nonce=nonce, e=e, d=d, recs=recs)


# --------------------------------------------------------------------------- #
# build the LWE system  T_j = M_j . s + r_j (mod q),  r_j in [0,b)
# --------------------------------------------------------------------------- #
def _c_times_ek(c, k):
    """(c * e_k)[i] in R_q = Z_q[X]/(X^n+1):  c[i-k] for i>=k else -c[i-k+n]."""
    out = [0] * n
    for i in range(n):
        kk = i - k
        out[i] = c[kk] if kk >= 0 else -c[kk + n]
    return out


def build_MT(recs):
    M, T = [], []
    for (x, y, hint, v) in recs:
        seed = x + y
        c = CE._b(seed)
        A = CE._r(seed)[0]            # ell == 1 -> single row of n coefficients
        v0 = v[0]
        a = sum(A[i] * v0[i] for i in range(n)) % q         # <A, v>
        row = [sum(A[i] * _c_times_ek(c, kk)[i] for i in range(n)) % q for kk in range(n)]
        M.append(row)
        T.append((a - hint * b) % q)
    return M, T


# --------------------------------------------------------------------------- #
# solve small-secret LWE via Bai-Galbraith primal embedding + progressive BKZ
# --------------------------------------------------------------------------- #
def solve_lwe(M, T):
    mm = len(M)
    Ws = max(1, (b // 2) // CE.secret_bound)     # balance secret scale vs error slack
    d = n + mm + 1
    B = IntegerMatrix(d, d)
    for i in range(n):
        B[i, i] = Ws
        for j in range(mm):
            B[i, n + j] = M[j][i] % q
    for j in range(mm):
        B[n + j, n + j] = q
    for j in range(mm):
        B[d - 1, n + j] = (T[j] - b // 2) % q
    B[d - 1, d - 1] = 1

    def check(s):
        if any(abs(si) > CE.secret_bound for si in s):
            return False
        return all(0 <= (T[j] - sum(M[j][i] * s[i] for i in range(n))) % q < b for j in range(mm))

    def extract():
        for r in range(d):
            if B[r, d - 1] == 0:
                continue
            cand = [int(round(B[r, i] / Ws)) for i in range(n)]
            for s in (cand, [-x for x in cand]):
                if check(s):
                    return s
        return None

    LLL.reduction(B)
    s = extract()
    if s:
        return s
    for bs in (20, 30, 40, 50, 60):
        BKZ.reduction(B, BKZ.Param(block_size=bs, max_loops=8, flags=BKZ.AUTO_ABORT | BKZ.GH_BND))
        s = extract()
        if s:
            return s
    return None


# --------------------------------------------------------------------------- #
# full recovery: s -> k -> keystream -> plaintext (tag verified)
# --------------------------------------------------------------------------- #
def recover_secret(blob: bytes):
    P = parse(blob)
    M, T = build_MT(P["recs"])
    s = solve_lwe(M, T)
    if s is None:
        return None
    w = CE._secret_bytes([s])
    k = hashlib.shake_256(b"SULTAN/key" + w).digest(32)
    p = hashlib.shake_256(b"SULTAN/stream" + k + P["nonce"]).digest(P["slen"])
    msg = bytes(u ^ v for u, v in zip(P["e"], p))
    tag = hashlib.blake2s(b"SULTAN/tag" + P["nonce"] + P["e"], key=k, digest_size=32).digest()
    return msg, tag == P["d"]


def _selftest():
    import secrets as _s
    import string
    sec = "".join(_s.choice(string.ascii_letters + string.digits) for _ in range(_s.randbelow(5) + 28))
    blob = CE.encrypt_sultan(sec.encode())
    res = recover_secret(blob)
    ok = bool(res) and res[0].decode() == sec and res[1]
    print(f"[selftest] secret={sec!r}")
    print(f"[selftest] recovered={res[0].decode() if res else None!r} tag_ok={res[1] if res else None} MATCH={ok}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        _selftest()
    if len(sys.argv) < 2:
        sys.exit("usage: solve.py <secret.enc> | --selftest")
    res = recover_secret(open(sys.argv[1], "rb").read())
    if not res:
        sys.exit("[-] recovery failed")
    print(f"[+] tag_ok={res[1]}")
    print(f"[+] secret_string: {res[0].decode()}")
