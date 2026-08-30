#!/usr/bin/env python3
"""Mario -- ASIS CTF Quals 2026 (crypto).

The public key is a UOV instance over GF(16): 72 quadratic forms in 96
variables, all vanishing on a secret 24-dimensional "oil" subspace O. The AES
key is HKDF over the row-reduced basis of O, so recovering O *as a subspace* is
the whole challenge -- the monomial scramble applied at the end is only a change
of coordinates, and the published forms already vanish on the scrambled oil
space, so the attack runs entirely in public coordinates.

Attacking UOV directly at these parameters is the intended problem. The leaked
`reports` make it unnecessary. Each report is

    r_i = o_i + lambda_i * g        o_i in O, lambda_i != 0

with a single g shared by all 64 of them, so every report lies in the
25-dimensional space W = O + <g>, and 64 samples span it. That turns "find a
24-dimensional subspace of GF(16)^96" into "find a hyperplane of a 25-dimensional
space", which is linear algebra:

  * Restricted to W, a quadratic form vanishing on the hyperplane O = ker(l)
    factors as Q = l * L for some linear form L.
  * Its polar form B(u,v) = Q(u+v)+Q(u)+Q(v) is then l(u)L(v) + l(v)L(u), i.e.
    the matrix l.L^T + L.l^T -- alternating, of rank exactly 2.
  * Its 23-dimensional kernel is ker(l) and ker(L), so it lies inside O. Two
    such kernels already span O.

Usage:  python3 solve.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gf import MUL, kernel, row_reduce, vec_add, vec_scale
from aesgcm import gcm_decrypt, hkdf_sha256, selftest

CHALLENGE = Path(__file__).resolve().parent.parent / "challenge" / "output.txt"


def polar_matrix(hex_poly, n):
    """Matrix of the polar form B(u,v) = P(u+v) + P(u) + P(v).

    P is stored upper-triangular and packed one hex digit per coefficient. In
    characteristic 2 the square terms cancel out of the polar form, so only the
    off-diagonal coefficients survive, symmetrised.
    """
    S = [[0] * n for _ in range(n)]
    t = 0
    for i in range(n):
        for j in range(i, n):
            c = int(hex_poly[t], 16)
            t += 1
            if c and i != j:
                S[i][j] = c
                S[j][i] = c
    return S


def restrict(S, basis, n):
    """basis . S . basis^T -- the polar form expressed in basis coordinates."""
    k = len(basis)
    rows = []
    for a in range(k):
        row = [0] * n
        for i, coeff in enumerate(basis[a]):
            if coeff:
                scale, Si = MUL[coeff], S[i]
                row = [x ^ scale[y] for x, y in zip(row, Si)]
        rows.append(row)
    M = []
    for a in range(k):
        Ra, out = rows[a], [0] * k
        for b in range(k):
            acc = 0
            for x, y in zip(Ra, basis[b]):
                if x and y:
                    acc ^= MUL[x][y]
            out[b] = acc
        M.append(out)
    return M


def eval_quad(hex_poly, x, n):
    out, t = 0, 0
    for i in range(n):
        xi = x[i]
        for j in range(i, n):
            c = int(hex_poly[t], 16)
            t += 1
            if c and xi and x[j]:
                out ^= MUL[c][MUL[xi][x[j]]]
    return out


def main():
    selftest()
    print("[+] AES-256-GCM / HKDF self-test passed (FIPS-197 + NIST vectors)")

    data = json.loads(CHALLENGE.read_text())
    n, m, d, s = data["p"]
    polys, reports = data["A"], data["B"]
    print(f"[+] GF(16) UOV: n={n} variables, m={m} equations, "
          f"oil dim d={d}, {s} reports")

    # 1. All reports live in W = O + <g>: one shared direction, so dim d + 1.
    W = row_reduce(reports)
    print(f"[+] span(reports) has dim {len(W)}  (expected {d} + 1)")
    assert len(W) == d + 1
    k = len(W)

    # 2. Each polar form restricted to W has rank 2 and its kernel lies in O.
    oil_coords = []
    for idx, hp in enumerate(polys):
        M = restrict(polar_matrix(hp, n), W, n)
        rank = len(row_reduce(M))
        if rank == 0:
            continue
        assert rank == 2, f"poly {idx}: polar rank {rank}, expected 2"
        oil_coords = row_reduce(oil_coords + kernel(M, k))
        print(f"[+] poly {idx}: polar rank 2, kernel dim {k - rank}, "
              f"oil span now {len(oil_coords)}")
        if len(oil_coords) == d:
            break
    assert len(oil_coords) == d

    # 3. Lift back to GF(16)^n.
    oil = []
    for c in oil_coords:
        v = [0] * n
        for coeff, w in zip(c, W):
            if coeff:
                v = vec_add(v, vec_scale(w, coeff))
        oil.append(v)

    bad = sum(1 for hp in polys for v in oil if eval_quad(hp, v, n))
    print(f"[+] verified: {len(polys)} polys x {len(oil)} basis vectors, "
          f"{bad} nonzero")
    assert bad == 0

    # 4. row_reduce is a canonical RREF, so any basis of O reproduces the
    #    generator's key material exactly.
    material = bytes(x for row in row_reduce(oil) for x in row)
    salt, nonce, ct = (bytes.fromhex(h) for h in data["C"])
    key = hkdf_sha256(material, 32, salt, b"MARIO")
    print("[+] key:", key.hex())

    flag, ok = gcm_decrypt(key, nonce, ct, b"MARIO")
    print("[+] GCM tag valid:", ok)
    print("[+] flag:", flag.decode())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
