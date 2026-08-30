#!/usr/bin/env python3
"""Less is more -- ASIS CTF Quals 2026 (crypto).

The device signs with a code-equivalence scheme over GF(827). Each of its seven
secret keys is a monomial map (a column permutation p and a diagonal scaling d)
applied to a public Cauchy code g; the public key is RREF(g[:,p] . diag(1/d)).
The flag is sealed under SHAKE-256("o" + pack_key(the 7 real keys)), so recovering
all seven (p, d) pairs is the whole challenge.

Each signature is an MPC-in-the-head cut-and-choose over a 345-leaf Merkle tree.
A per-leaf response reveals the set { i : p_x[i] in v } for a *secret* half-set
v = take(leaf, 'n', N, K) hidden inside the leaf seed -- normally zero-knowledge.

The break ("less is more"): with 72% probability the signer overwrites f[target]
with the *previous* round's state (target = (37*serial + 11) mod T). When that
makes f[target] = 0 while the challenge b[target] != 0, the leaf is *covered* --
its seed is shipped in the cover path -- yet it still carries a response. For
those "hit" records the secret v becomes known, so the response set S gives a hard
constraint:  p_x[i] in v  <=>  i in S.

  1. Recover serial from the message, recompute target and the challenge b.
  2. Invert token(cmt, u), descend the Merkle tree to leaf[target] (labels match,
     confirming the descent). Now v = take(leaf[target], 'n', N, K) is known.
  3. Vote every position: over all hits of class x, tally the allowed side. The
     true p_x[i] is allowed in every honest hit; the 14% garbage-fault records are
     outvoted. This pins each of the seven permutations exactly.
  4. With p_x known, solve d_x from M = RREF(g[:,p_x] . diag(1/d)) column by column
     (up to the global scale that pack_key's /d[0] normalisation removes), and
     match each permutation to its public key by pivot set.
  5. pack_key, derive the SHAKE-256 pad, unseal the flag.

Runtime: ~2-3 minutes (step 4 uses numpy for GF(827) linear algebra).

Usage:  python3 solve.py [path/to/flag.enc]
"""
import hashlib
import json
import pickle
import struct
import sys
import zlib
from collections import Counter
from pathlib import Path

import numpy as np

P, N, K, T, W = 827, 548, 274, 345, 75
REAL, SLOTS, DECOY = 7, 17, 15
HERE = Path(__file__).resolve().parent
DEFAULT = HERE.parent / "challenge" / "flag.enc"


# --------------------------------------------------------- deterministic helpers
def inv(x):
    return pow(x, P - 2, P)


def stream(seed, tag, n):
    return hashlib.shake_256(tag + seed).digest(8 * n)


def take(seed, tag, n, k):
    b, a = stream(seed, tag, k), list(range(n))
    for i in range(k):
        j = i + int.from_bytes(b[8 * i:8 * i + 8], "big") % (n - i)
        a[i], a[j] = a[j], a[i]
    return a[:k]


def chal(cmt, salt, msg):
    b = hashlib.shake_256(b"c" + cmt + salt + msg).digest(8 * (2 * T + 2))
    a = list(range(T))
    for i in range(T - 1, 0, -1):
        j = int.from_bytes(b[8 * (T - 1 - i):8 * (T - i)], "big") % (i + 1)
        a[i], a[j] = a[j], a[i]
    out = [0] * T
    for i in a[:W]:
        out[i] = int.from_bytes(b[8 * (T + i):8 * (T + i + 1)], "big") % REAL + 1
    return out


def label(cmt, seed):
    return hashlib.sha256(b"t" + cmt + seed).digest()[:8]


def pack_key(key):
    out = bytearray()
    for p, d in key:
        u = inv(d[0])
        for x in p:
            out.extend(x.to_bytes(2, "little"))
        for x in d:
            out.extend((x * u % P).to_bytes(2, "little"))
    return bytes(out)


DEPTH = 0
_z = 1
while _z < T:
    _z <<= 1
    DEPTH += 1
BASE0 = 1 << DEPTH                      # 512


def node_leaf_range(u):
    """Leaf-index range [lo, hi) covered by internal tree node u."""
    level = u.bit_length() - 1
    span = 1 << (DEPTH - level)
    lo = (u - (1 << level)) * span
    return lo, lo + span


def leaf_from_node(u, seed, leaf_node):
    """Descend the Merkle tree from internal node u (value seed) to leaf_node."""
    bits, x = [], leaf_node
    while x > u:
        bits.append(x & 1)             # 0 -> left child (2u), 1 -> right (2u+1)
        x >>= 1
    if x != u:
        return None
    for bit in reversed(bits):
        seed = hashlib.sha256((b"r" if bit else b"l") + seed).digest()
    return seed


# ------------------------------------------------------------------ step 1-3
def recover_permutations(records):
    votes = [None] + [np.zeros((N, N), dtype=np.int32) for _ in range(REAL)]
    nhits = Counter()
    for r in records:
        cmt, salt, msg = r["cmt"], r["salt"], r["msg"]
        serial = int(msg[1:])
        target = (37 * serial + 11) % T
        b = chal(cmt, salt, msg)
        if b[target] == 0:
            continue
        mask = int.from_bytes(hashlib.sha256(b"m" + cmt).digest()[:2], "big") & 1023
        leaf_seed = None
        for tok, seed in r["path"]:
            u = tok ^ mask
            if 1 <= u < BASE0:
                lo, hi = node_leaf_range(u)
                if lo <= target < hi:
                    leaf_seed = leaf_from_node(u, seed, BASE0 + target)
                    break
            elif u == BASE0 + target:
                leaf_seed = seed
        if leaf_seed is None:
            continue
        lab = label(cmt, leaf_seed)
        labs = {bytes(x[0]): bytes(x[1]) for x in r["rsp"]}
        if lab not in labs:            # would flag a wrong tree descent; never happens
            continue
        x = b[target]
        v = take(leaf_seed, b"n", N, K)
        vmask = np.zeros(N, dtype=bool)
        vmask[v] = True
        Sint = int.from_bytes(labs[lab], "little")
        S = np.array([(Sint >> i) & 1 for i in range(N)], dtype=bool)
        # position i: p_x[i] in v  iff  i in S
        Vx = votes[x]
        Vx[S] += vmask                 # broadcast: allowed = v for i in S
        Vx[~S] += ~vmask               # allowed = complement of v otherwise
        nhits[x] += 1

    perms = {}
    for x in range(1, REAL + 1):
        p = votes[x].argmax(axis=1)
        margin = int(np.min(np.sort(votes[x], axis=1)[:, -1] - np.sort(votes[x], axis=1)[:, -2]))
        assert sorted(p.tolist()) == list(range(N)), f"class {x}: not a permutation"
        perms[x] = p.tolist()
        print(f"[+] class {x}: {nhits[x]} hits, permutation recovered (min vote margin {margin})")
    return perms


# ------------------------------------------------------------------ step 4
INV = np.array([0] + [pow(x, P - 2, P) for x in range(1, P)], dtype=np.int64)


def rref(a):
    a = a.copy() % P
    h, w, r, piv = a.shape[0], a.shape[1], 0, []
    for c in range(w):
        nz = np.nonzero(a[r:, c])[0]
        if len(nz) == 0:
            continue
        z = r + nz[0]
        a[[r, z]] = a[[z, r]]
        a[r] = (a[r] * INV[a[r, c]]) % P
        for i in range(h):
            if i != r and a[i, c]:
                a[i] = (a[i] - a[i, c] * a[r]) % P
        piv.append(c)
        r += 1
        if r == h:
            break
    return a, piv


def matinv(a):
    n = a.shape[0]
    m = np.concatenate([a % P, np.eye(n, dtype=np.int64)], axis=1)
    for c in range(n):
        nz = np.nonzero(m[c:, c])[0]
        if len(nz) == 0:
            return None
        z = c + nz[0]
        m[[c, z]] = m[[z, c]]
        m[c] = (m[c] * INV[m[c, c]]) % P
        for i in range(n):
            if i != c and m[i, c]:
                m[i] = (m[i] - m[i, c] * m[c]) % P
    return m[:, n:]


def recover_diagonals(g, pubs, perms):
    def public_of(p, d):
        dinv = INV[np.array(d) % P]
        return rref((g[:, p] * dinv[None, :]) % P)[0]

    keys = {}
    for x in range(1, REAL + 1):
        p = np.array(perms[x])
        Gp = g[:, p] % P
        _, gpiv = rref(Gp)
        found = None
        for idx, M in enumerate(pubs):
            _, mpiv = rref(M)
            if mpiv != gpiv:
                continue
            piv = np.array(gpiv)
            Ginv = matinv(Gp[:, piv])
            if Ginv is None:
                continue
            W_ = (Ginv @ Gp) % P            # (Ginv.Gp).diag(1/d) == M  up to d[piv] scaling
            d = np.full(N, -1, dtype=np.int64)
            m0 = M[0] != 0
            d[m0] = (W_[0, m0] * INV[M[0, m0]]) % P
            dpiv = np.full(K, -1, dtype=np.int64)
            ok = True
            for t in range(K):
                jj = np.nonzero((d >= 0) & (M[t] != 0) & (W_[t] != 0))[0]
                if len(jj) == 0:
                    ok = False
                    break
                j = jj[0]
                dpiv[t] = (d[j] * M[t, j] % P * INV[W_[t, j]]) % P
            if not ok:
                continue
            for j in range(N):
                if d[j] >= 0:
                    continue
                tt = np.nonzero((M[:, j] != 0) & (W_[:, j] != 0))[0]
                if len(tt) == 0:
                    ok = False
                    break
                t = tt[0]
                d[j] = (dpiv[t] * W_[t, j] % P * INV[M[t, j]]) % P
            if not ok:
                continue
            if np.array_equal(public_of(p, d), M):
                found = (idx, [int(v) for v in d])
                break
        assert found, f"class {x}: no matching public key"
        print(f"[+] class {x}: matched public key #{found[0]}, diagonal recovered and verified")
        keys[x] = found[1]
    return keys


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    raw = path.read_bytes()
    assert raw[:8] == b"ASIS117\x04", "bad magic"
    ln = struct.unpack(">I", raw[8:12])[0]
    data = pickle.loads(zlib.decompress(raw[12:12 + ln]))
    g = np.array(data["pub"]["g"], dtype=np.int64)
    pubs = [np.array(M, dtype=np.int64) for M in data["pub"]["pub"]]
    records = data["records"]
    sealed = data["sealed"]
    print(f"[+] {len(records)} records, {len(pubs)} public keys, {len(sealed)}-byte flag")

    perms = recover_permutations(records)
    diags = recover_diagonals(g, pubs, perms)

    key = [(perms[x], diags[x]) for x in range(1, REAL + 1)]
    pad = hashlib.shake_256(b"o" + pack_key(key)).digest(len(sealed))
    flag = bytes(a ^ b for a, b in zip(sealed, pad))
    print("[+] flag:", flag.decode())


if __name__ == "__main__":
    main()
