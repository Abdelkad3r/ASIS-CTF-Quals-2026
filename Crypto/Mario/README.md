# Mario

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Crypto |
| **Difficulty** | Medium |
| **Files** | [`challenge/mario.py`](challenge/mario.py), [`challenge/output.txt`](challenge/output.txt) |
| **Solver** | [`solution/solve.py`](solution/solve.py) |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/d211cf2f-b74b-4e78-b3ab-5348db3707ce) |
| **Flag** | `ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}` |

> Something is wrong beneath the Mushroom Kingdom Mario. Find the flag!

---

## TL;DR

The public key is a textbook **UOV** (Unbalanced Oil and Vinegar) instance over GF(16):
72 quadratic forms in 96 variables, all vanishing on a secret 24-dimensional *oil*
subspace `O`. The AES key is derived from `O`, so recovering that subspace is the whole
challenge, and doing it from the public key alone is the intended hard problem.

The generator also publishes 64 "reports", each of the form `o + λ·g` — and **`g` is the
same vector in all 64 of them**. Every report therefore lies in the 25-dimensional space
`W = O ⊕ ⟨g⟩`, and 64 samples span it exactly. Finding a 24-dimensional subspace of
GF(16)⁹⁶ collapses into finding a hyperplane of a 25-dimensional space, which is pure
linear algebra. Runtime: 1.2 seconds.

```
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```

## 1. What the generator builds

Everything happens over GF(16) with modulus `x⁴+x+1`, and the parameters are

```python
n, m, d, s = 96, 72, 24, 64      # variables, equations, oil dimension, reports
v = n - d                        # 72 vinegar variables
```

**The oil space.** `oil_embed` maps `x ∈ GF(16)²⁴` to `(K·x, x) ∈ GF(16)⁹⁶` for a secret
72×24 matrix `K`. Its image is the 24-dimensional subspace

```
O = { (K·x, x) : x ∈ GF(16)^24 }
```

**The public map.** `build_public_map` fills each quadratic form with random coefficients
everywhere except the oil-oil block, then patches that block so the form vanishes on `O`.
The patch is a characteristic-2 trick worth spelling out. For a quadratic form with no
linear part, `P(a+b) = P(a) + P(b) + B(a,b)` where `B` is the polar form. First:

```python
poly[v + i][v + i] = eval_quad(poly, basis[i])
```

Since `basis[i][v+i] = 1`, adding coefficient `c` at position `(v+i, v+i)` shifts
`P(basis[i])` by exactly `c`. Choosing `c = P(basis[i])` gives `P(basis[i]) + P(basis[i]) = 0`
in characteristic 2. Then:

```python
poly[v + i][v + j] = eval_quad(poly, basis[i] + basis[j]) ^ ... ^ ...
```

kills each `P(basisᵢ + basisⱼ)` the same way, which forces `B(basisᵢ, basisⱼ) = 0`.
With `P` zero on every basis vector *and* every pairwise sum, `P` vanishes on the whole
span — `P(Σ cᵢbᵢ) = Σ cᵢ² P(bᵢ) + Σ cᵢcⱼ B(bᵢ,bⱼ) = 0`.

**The scramble.** `monomial_scramble` picks a permutation and per-coordinate nonzero
scalars; `transform_poly` applies the matching change of variables so that
`P'(T(x)) = P(x)`. This is a linear change of coordinates and nothing more: the published
forms vanish on the transformed oil space `T(O)` exactly as the originals vanished on `O`.
**The whole attack runs in public coordinates and never undoes it.**

**The key.**

```python
material = bytes(x for row in row_reduce(oil_basis) for x in row)
key = HKDF(material, 32, salt, SHA256, context=b"MARIO")
```

`row_reduce` is a full Gauss-Jordan reduction, so its output is the canonical RREF of the
subspace. Any basis of `T(O)` reproduces the same bytes — we need the subspace, not the
generator's particular basis.

## 2. What is published

| Field | Contents |
|---|---|
| `F` | `[16, "x^4+x+1"]` — the field |
| `p` | `[96, 72, 24, 64]` |
| `A` | 72 quadratic forms, packed upper-triangular, 4656 hex digits each (`96·97/2`) |
| `B` | 64 reports, each a vector in GF(16)⁹⁶ |
| `C` | salt (32 B), nonce (12 B), ciphertext+tag (76 B → a 60-byte flag) |

## 3. The intended problem

Recovering the oil subspace of a UOV public key is the classic key-recovery problem.
At `n=96, m=72, d=24` over GF(16) that is not something you do by hand, and the flag text
(`grOe8n3r`, `8aSi5`) points at an algebraic Gröbner-basis route. The reports make it
unnecessary.

## 4. The leak

```python
while True:
    g = r(n)
    if any(eval_quad(poly, g) for poly in polys):
        break                      # one g, chosen once

reports = []
for _ in range(s):
    oil_vec = oil_embed(k_mat, r(d))
    mask = secrets.randbelow(15) + 1
    reports.append(vec_add(oil_vec, vec_scale(g, mask)))
```

Each report is `rᵢ = oᵢ + λᵢ·g` with `oᵢ ∈ O` and `λᵢ ≠ 0`. The masks vary, but they only
rescale **the same direction** `g`, which is drawn once outside the loop. So every report
lies in

```
W = O ⊕ ⟨g⟩          dim W = 24 + 1 = 25
```

(`g ∉ O` because it was chosen so some form is nonzero at it, and every form vanishes on
`O`.) Twenty-five independent reports suffice to span `W`; the generator hands over 64.

```console
[+] span(reports) has dim 25  (expected 24 + 1)
```

## 5. Inside W, the forms factor

`O` is a hyperplane of `W`, so write `O = ker(l)` for a linear form `l` on `W`, unique up
to scalar. Choose coordinates on `W` in which `l` is the last coordinate, `O = {c₂₅ = 0}`.
A quadratic form `Q` restricted to `W` vanishes on `O`, so every monomial that does not
involve `c₂₅` must have zero coefficient, leaving

```
Q(c) = c₂₅ · ( Σ_{i<25} q_{i,25} cᵢ  +  q_{25,25} c₂₅ )  =  l(c) · L(c)
```

for some linear form `L`. **Every one of the 72 forms, restricted to `W`, is a product of
two linear forms, and they all share the factor `l`.**

## 6. The polar form gives it away

The polar form of `Q = l·L` is

```
B(u,v) = Q(u+v) + Q(u) + Q(v) = l(u)L(v) + l(v)L(u)
```

whose matrix is `l·Lᵀ + L·lᵀ` — symmetric with zero diagonal (alternating), and of **rank
exactly 2** whenever `L` is not a multiple of `l`. Its kernel is

```
ker(B) = ker(l) ∩ ker(L) ⊆ ker(l) = O          dim 23
```

So each restricted polar form hands over a 23-dimensional slice of the 24-dimensional
secret. Two different forms give two different slices, and inside a 24-dimensional space
two distinct 23-dimensional subspaces already span it:

```console
[+] poly 0: polar rank 2, kernel dim 23, oil span now 23
[+] poly 1: polar rank 2, kernel dim 23, oil span now 24
```

Computationally this is one matrix triple product per form. With `W` as a 25×96 matrix and
`S` the 96×96 symmetrised coefficient matrix, the restricted polar form is `W·S·Wᵀ`, a
25×25 matrix — and in characteristic 2 the diagonal coefficients drop out of `S` entirely.

## 7. Verification

Lift the 24 recovered coordinate vectors back through the basis of `W` and evaluate every
public form on every basis vector:

```console
[+] verified: 72 polys x 24 basis vectors, 0 nonzero
```

1728 evaluations, all zero. That is the oil space.

## 8. Key derivation and decryption

`row_reduce` the recovered basis, flatten to 2304 bytes, and run the generator's own KDF.
No crypto library is installed in this environment — `Crypto`, `Cryptodome` and
`cryptography` are all absent — so [`solution/aesgcm.py`](solution/aesgcm.py) implements
AES-256-GCM and HKDF-SHA256 from the standard library. It is checked against the FIPS-197
AES-256 known-answer test and two NIST GCM vectors before being used:

```console
[+] AES-256-GCM / HKDF self-test passed (FIPS-197 + NIST vectors)
[+] key: c22b0c9d68704da8a95c8cc4753ad5c85f579e8958d5215ce1d45802d4a9449b
[+] GCM tag valid: True
[+] flag: ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```

The GCM tag validating is the proof: it confirms the recovered subspace is exactly the
generator's, not merely a subspace that happens to satisfy the equations.

## 9. Flag

```
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```

## 10. What would have fixed it

The bug is one line out of place. `g` is drawn **before** the report loop and reused; draw
it inside instead and each report becomes `oᵢ + λᵢ·gᵢ` with an independent random
direction. Those vectors span the whole of GF(16)⁹⁶ within a hundred samples and reveal
nothing about `O` — there is no common 25-dimensional envelope to intersect.

Two supporting observations:

* **The monomial scramble contributes nothing here.** It is a change of coordinates, and
  the attack is coordinate-free: it only ever asks which subspace the reports span and
  where the forms vanish. Obfuscation that commutes with the attack is not a defence.
* **The masks are a decoy.** Random nonzero `λᵢ` look like they randomise each report, but
  scaling a fixed vector stays inside `⟨g⟩`. Randomness that does not increase the
  dimension of what you publish does not hide anything.

## 11. Takeaways

* **Count dimensions before doing algebra.** The published data was 64 vectors in a
  96-dimensional space; the only question worth asking first was how many dimensions they
  actually span. The answer, 25, made the rest routine.
* **A quadratic form vanishing on a hyperplane factors.** `Q = l·L` is a small fact with a
  large consequence: the polar form drops to rank 2 and its kernel is a near-complete slice
  of the secret. Whenever a form is known to vanish on a codimension-1 subspace, take the
  polar form.
* **Auxiliary data is part of the attack surface.** The public key was sound; the extra
  "reports" were what leaked. A scheme is only as strong as everything shipped alongside
  it.
* **Verify with the AEAD tag.** Recovering the right subspace produces a valid GCM tag,
  which is a proof rather than a plausibility argument.

## Reproducing

```console
$ python3 solution/solve.py
```

Python 3, standard library only — no third-party packages and no compiler needed.
