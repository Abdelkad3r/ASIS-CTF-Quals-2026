#!/usr/bin/env python3
"""Linchan -- ASIS CTF Quals 2026 (crypto).

The challenge publishes 112 "boxes". Each box is a basis of an m-dimensional
subspace of M_32(F_2) (m in {16, 17, 18}), handed over in a random basis and
transposed with probability 1/2. Five secret invertible matrices S are hidden as
conjugate pairs of boxes -- span(D) = S * span(C) * S^-1 -- and the ChaCha20
key is SHAKE-256 over the five S. The other 102 boxes are decoys.

The break is that real subspaces are seeded by `_h()`, which returns a product
of a 32x25 and a 25x32 matrix and therefore has rank exactly 25, while decoy
subspaces are uniform. A uniform 32x32 matrix over F_2 has rank <= 25 with
probability about 2^-47, so across every element of every decoy subspace the
expected number of low-rank matrices is ~1e-7. Rank is a property of the
subspace, not of the basis, so the scrambling in `_o()` does not hide it.

Pipeline:

  1. minrank.c enumerates all 2^m elements of each subspace and reports the
     rank <= 26 ones. This finds the 10 real boxes and, inside each, the two
     planted matrices.
  2. Real boxes are paired using rank(H^k), a similarity invariant that also
     survives transposition.
  3. Because the planted matrices are canonically identifiable inside their own
     subspace, the correspondence H -> G = S H S^-1 is known, which turns the
     recovery of S into the linear system X*H_i == G_i*X -- 2048 equations over
     the 1024 bits of X, with a one-dimensional solution space.
  4. `_f` canonicalises S over {S, S^-1, S^T, S^-T}, so the transposition
     ambiguity costs nothing: a transposed box simply yields S^-T.

Usage:  python3 solve.py            (needs a C compiler for step 1)
"""
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from collections import defaultdict
from itertools import combinations
from pathlib import Path

N = 32
HERE = Path(__file__).resolve().parent
CHALLENGE = HERE.parent / "challenge" / "output.txt"
AAD = b"linchan/v2"


# --------------------------------------------------------------- GF(2) matrices
# A matrix is a list of 32 ints; bit k of row i is the entry (i, k).

def mul(A, B):
    R = []
    for x in A:
        y = 0
        while x:
            b = x & -x
            y ^= B[b.bit_length() - 1]
            x ^= b
        R.append(y)
    return R


def transpose(A):
    R = [0] * N
    for i, x in enumerate(A):
        while x:
            b = x & -x
            R[b.bit_length() - 1] |= 1 << i
            x ^= b
    return R


def inverse(A):
    R = [x | (1 << (N + i)) for i, x in enumerate(A)]
    for i in range(N):
        j = next((j for j in range(i, N) if (R[j] >> i) & 1), None)
        if j is None:
            return None
        R[i], R[j] = R[j], R[i]
        for k in range(N):
            if k != i and ((R[k] >> i) & 1):
                R[k] ^= R[i]
    return [x >> N for x in R]


def rank(A):
    pivot = {}
    for x in A:
        while x:
            i = x.bit_length() - 1
            if i in pivot:
                x ^= pivot[i]
            else:
                pivot[i] = x
                break
    return len(pivot)


def combine(mask, basis):
    """XOR the basis elements selected by `mask`."""
    M = [0] * N
    while mask:
        b = mask & -mask
        M = [x ^ y for x, y in zip(M, basis[b.bit_length() - 1])]
        mask ^= b
    return M


def pack(A):
    return b"".join(x.to_bytes(4, "little") for x in A)


def canon(S):
    """`_f`: the challenge's canonical form, min over {S, S^-1, S^T, S^-T}."""
    T = inverse(S)
    return min(pack(S), pack(T), pack(transpose(S)), pack(transpose(T)))


def fingerprint(H):
    """Similarity invariant; also invariant under transposition."""
    out, P = [], list(H)
    for _ in range(12):
        out.append(rank(P))
        P = mul(P, H)
    return tuple(out)


# ------------------------------------------------------ simultaneous intertwiners
def intertwiners(pairs, max_dim=14):
    """Basis of { X : X*H == G*X for every (H, G) in pairs }.

    Unknown X has 1024 bits, indexed as bit (i*32 + k) for entry (i, k). Entry
    (i, j) of X*H - G*X gives one equation:

        sum_k H[k][j] * X[i][k]  xor  sum_k G[i][k] * X[k][j]  ==  0
    """
    piv = {}
    for H, G in pairs:
        HT = transpose(H)
        for i in range(N):
            gi, base = G[i], i * N
            for j in range(N):
                mask = HT[j] << base
                g = gi
                while g:
                    b = g & -g
                    mask ^= 1 << ((b.bit_length() - 1) * N + j)
                    g ^= b
                while mask:
                    h = mask.bit_length() - 1
                    if h in piv:
                        mask ^= piv[h]
                    else:
                        piv[h] = mask
                        break
                if len(piv) == N * N:
                    return []                       # only X = 0 solves it
    for h in list(piv):                             # reduce to RREF
        for k in list(piv):
            if k != h and (piv[k] >> h) & 1:
                piv[k] ^= piv[h]
    free = [c for c in range(N * N) if c not in piv]
    if len(free) > max_dim:
        return []
    basis = []
    for f in free:
        v = 1 << f
        for h, row in piv.items():
            if (row >> f) & 1:
                v |= 1 << h
        basis.append([(v >> (i * N)) & 0xffffffff for i in range(N)])
    return basis


def find_invertible(basis):
    for mask in range(1, 1 << len(basis)):
        M = combine(mask, basis)
        if rank(M) == N:
            return M
    return None


# ------------------------------------------------------ ChaCha20-Poly1305, RFC 8439
def _rotl(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _chacha_block(key, counter, nonce):
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state += list(struct.unpack("<8I", key)) + [counter]
    state += list(struct.unpack("<3I", nonce))
    x = list(state)

    def quarter(a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = _rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = _rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = _rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = _rotl(x[b] ^ x[c], 7)

    for _ in range(10):
        quarter(0, 4, 8, 12); quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14); quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15); quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13); quarter(3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xffffffff for a, b in zip(x, state)])


def _poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    p, acc = (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        acc = ((acc + int.from_bytes(msg[i:i + 16] + b"\x01", "little")) * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def aead_decrypt(key, nonce, data, aad):
    body, tag = data[:-16], data[-16:]
    out = bytearray()
    for i in range(0, len(body), 64):
        ks = _chacha_block(key, 1 + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(body[i:i + 64], ks))
    mac = (aad + b"\0" * (-len(aad) % 16) + body + b"\0" * (-len(body) % 16)
           + struct.pack("<QQ", len(aad), len(body)))
    ok = _poly1305(_chacha_block(key, 0, nonce)[:32], mac) == tag
    return bytes(out), ok


# ------------------------------------------------------------------- the pipeline
def load_boxes(path=CHALLENGE):
    blob = json.loads(zlib.decompress(base64.b85decode(Path(path).read_bytes())))
    boxes = []
    for b in blob["boxes"]:
        raw = base64.b85decode(b["x"])
        boxes.append((b["m"], [
            [int.from_bytes(raw[o + 4 * k: o + 4 * k + 4], "little") for k in range(N)]
            for o in range(0, len(raw), 128)]))
    return blob, boxes


def minrank_scan(boxes, threshold=26):
    """Compile and run minrank.c; return {box index: [planted matrices]}."""
    if shutil.which("cc") is None:
        sys.exit("need a C compiler (cc) to run the MinRank scan")
    with tempfile.TemporaryDirectory() as td:
        binpath = os.path.join(td, "boxes.bin")
        with open(binpath, "wb") as fh:
            fh.write(struct.pack("<I", len(boxes)))
            for m, mats in boxes:
                fh.write(struct.pack("<I", m))
                for M in mats:
                    fh.write(pack(M))
        exe = os.path.join(td, "minrank")
        subprocess.run(["cc", "-O3", "-o", exe, str(HERE / "minrank.c")], check=True)
        out = subprocess.run([exe, binpath, str(threshold)],
                             capture_output=True, text=True, check=True).stdout

    hits = defaultdict(list)
    for line in out.splitlines():
        bi, mask, r = (int(t) for t in line.split())
        M = combine(mask, boxes[bi][1])
        assert rank(M) == r
        hits[bi].append(M)
    return dict(hits)


def recover_secrets(boxes, hits):
    """Pair the real boxes and solve for each conjugating matrix."""
    groups = defaultdict(list)
    for bi in sorted(hits):
        groups[boxes[bi][0]].append(bi)
    print("[+] real boxes by dimension:",
          {m: v for m, v in sorted(groups.items())})

    fps = {bi: [fingerprint(H) for H in hits[bi]] for bi in hits}
    found = {}
    for m, members in sorted(groups.items()):
        for a, b in combinations(members, 2):
            if sorted(fps[a]) != sorted(fps[b]):
                continue                            # not a similar pair
            for flip in (False, True):
                Hs = [transpose(h) for h in hits[a]] if flip else hits[a]
                for order in ((0, 1), (1, 0)):
                    Gs = [hits[b][order[0]], hits[b][order[1]]]
                    basis = intertwiners(list(zip(Hs, Gs)))
                    S = find_invertible(basis) if basis else None
                    if S is None:
                        continue
                    assert all(mul(S, H) == mul(G, S) for H, G in zip(Hs, Gs))
                    found[(a, b)] = S
                    print(f"[+] m={m}: box {a:>3} ~ box {b:>3}   "
                          f"solution space dim {len(basis)}, "
                          f"transposed={flip}, order={order}")
                    break
                if (a, b) in found:
                    break
    return found


def main():
    blob, boxes = load_boxes()
    print(f"[+] {len(boxes)} boxes, "
          f"{sum((1 << m) - 1 for m, _ in boxes):,} subspace elements to scan")

    hits = minrank_scan(boxes)
    print(f"[+] MinRank: {sum(len(v) for v in hits.values())} matrices of rank <= 26 "
          f"in {len(hits)} boxes")

    found = recover_secrets(boxes, hits)
    if len(found) != 5:
        sys.exit(f"expected 5 conjugate pairs, recovered {len(found)}")

    key = hashlib.shake_256(
        b"linchan-v2/key\0" + b"".join(sorted(canon(S) for S in found.values()))
    ).digest(32)
    print("[+] key:", key.hex())

    ct = base64.b85decode(blob["ct"])
    flag, ok = aead_decrypt(key, ct[:12], ct[12:], AAD)
    print("[+] Poly1305 tag valid:", ok)
    print("[+] flag:", flag.decode())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
