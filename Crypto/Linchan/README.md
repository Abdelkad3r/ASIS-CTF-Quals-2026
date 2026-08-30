# Linchan

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Crypto |
| **Difficulty** | Hard |
| **Files** | [`challenge/linchan.py`](challenge/linchan.py), [`challenge/output.txt`](challenge/output.txt) |
| **Solver** | [`solution/solve.py`](solution/solve.py), [`solution/minrank.c`](solution/minrank.c) |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/17a393fa-8a38-4b5c-91c7-88a17aaaf4c7) |
| **Flag** | `ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}` |

The challenge ships a generator script and its output, with no description.

---

## TL;DR

The scheme hides five secret matrices `S` as **conjugate pairs of matrix subspaces** over
GF(2), buried among 102 decoys, and derives a ChaCha20 key from them. Recovering `S` from a
conjugate pair of subspaces is bilinear and genuinely awkward — but the generator plants
two **rank-25** matrices in every real subspace, and a uniform 32×32 matrix over GF(2) has
rank ≤ 25 with probability ≈ 2⁻⁴⁷.

Rank is a property of a subspace, not of the basis you are handed, so the random
re-basing does nothing to hide it. Enumerating all 2^m elements of each subspace (m ≤ 18)
finds the real boxes instantly, pairs them, and reduces the recovery of `S` to a linear
system. Total runtime: 17 seconds.

```
ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```

## 1. Reading through the obfuscation

`linchan.py` uses single-letter names throughout. All of it is linear algebra over
GF(2), with a 32×32 matrix represented as 32 integers — bit `k` of row `i` is the entry
`(i, k)`, so `_m(A, B)` is the ordinary row-convention product.

| Name | Meaning |
|---|---|
| `_r(A)` | rank of a set of vectors (Gaussian elimination with a pivot table) |
| `_v(A)` | flatten a 32×32 matrix into a single 1024-bit integer |
| `_a`, `_m`, `_t`, `_i` | matrix add, multiply, transpose, inverse |
| `_g()` | uniform **invertible** 32×32 matrix |
| `_h()` | 32×25 times 25×32 &rarr; a 32×32 matrix of **rank exactly 25** |
| `_c(x, B)` | the linear combination of `B` selected by the bitmask `x` |
| `_u(m)` | uniform invertible m×m matrix |
| `_b(m, q)` | basis of an m-dimensional subspace of M₃₂(GF(2)); if `q`, the first two elements are `_h()` outputs |
| `_o(B)` | re-express `B` in a random basis, then transpose every element with probability ½ |
| `_f(S)` | canonical form: `min` over the packed bytes of `{S, S⁻¹, Sᵀ, S⁻ᵀ}` |
| `_k(K)` | SHAKE-256 over the **sorted** canonical forms of the secrets |

## 2. The scheme

```python
_l = ((16, 2), (17, 2), (18, 1))     # (dimension, number of real pairs)
_d = 34                              # decoys per dimension

for m, c in _l:
    for _ in range(c):
        C, S = _b(m, True), _g()
        T = _i(S)
        D = [_m(_m(S, A), T) for A in C]      # D = S C S^-1
        B += [(m, _o(C)), (m, _o(D))]
        K.append(S)
    for _ in range(_d):
        B.append((m, _o(_b(m))))              # decoy
shuffle(B)
```

So the output is **112 boxes**, each an m-dimensional subspace of the 1024-dimensional
space of 32×32 matrices, presented in a random basis and transposed half the time:

| m | real boxes | decoys | total |
|---|---|---|---|
| 16 | 4 (2 pairs) | 34 | 38 |
| 17 | 4 (2 pairs) | 34 | 38 |
| 18 | 2 (1 pair) | 34 | 36 |

Ten boxes form five conjugate pairs `span(D) = S · span(C) · S⁻¹`. The flag is encrypted
under `ChaCha20Poly1305(_k(K))` with associated data `b"linchan/v2"`, where `K` is the list
of the five secret `S`.

Note what `_k` needs: only the **set** of the five canonical forms. `_f` quotients out
`{S, S⁻¹, Sᵀ, S⁻ᵀ}` and the forms are sorted, so recovering any representative of each
class, in any order, is enough.

## 3. What the intended problem looks like

You are given two subspaces and told that one is a conjugate of the other, but not which
box pairs with which, not the basis correspondence, and not whether either has been
transposed. Solving `X · span(C) · X⁻¹ = span(D)` directly is bilinear: you would have to
find both `X` and the m×m change of basis relating the two spanning sets at the same time.

The decoys make it worse — with 38 boxes at one dimension there are 703 candidate
pairings, so any per-pair test has to be cheap.

## 4. The flaw: `_h()` is visible from the outside

Real subspaces are seeded with two matrices from `_h()`, which factors through rank 25 by
construction. Decoy subspaces are uniform. Here is the rank distribution of a uniform
32×32 matrix over GF(2):

| rank | probability |
|---|---|
| 32 | 0.2888 |
| 31 | 0.5776 |
| 30 | 0.1284 |
| 29 | 5.24 × 10⁻³ |
| 28 | 4.66 × 10⁻⁵ |
| 27 | 9.69 × 10⁻⁸ |
| 26 | 4.88 × 10⁻¹¹ |
| 25 | 6.06 × 10⁻¹⁵ |

`P(rank ≤ 25) ≈ 6.1 × 10⁻¹⁵ ≈ 2⁻⁴⁷·²`. A decoy subspace of dimension 18 contains 2¹⁸
elements, so its expected number of rank-≤25 matrices is **1.6 × 10⁻⁹**. Across all 102
decoys the expected count is about 10⁻⁷.

Two things make this fatal rather than merely interesting:

* **Rank is a property of the subspace, not the basis.** `_o()` re-expresses the basis
  through a random invertible change of basis, which leaves the set of subspace elements
  identical. The planted matrices are still in there.
* **Rank is invariant under both conjugation and transposition.** `rank(S H S⁻¹) = rank(H)`
  and `rank(Hᵀ) = rank(H)`, so the marker survives into the partner box and survives
  `_o()`'s coin flip.

Finding a low-rank element of a matrix subspace is the **MinRank** problem, which is hard
in general — but only when the subspace dimension is large. Here m ≤ 18.

## 5. MinRank by exhaustion

Every element of every subspace can simply be enumerated:

```
38 × (2¹⁶ − 1) + 38 × (2¹⁷ − 1) + 36 × (2¹⁸ − 1) = 16,908,176 matrices
```

[`solution/minrank.c`](solution/minrank.c) walks each subspace in Gray-code order, so
moving to the next element costs one XOR of 32 words, and ranks each one with a 32-step
elimination. Threshold 26 keeps the false-positive probability negligible while catching
anything planted.

```console
[+] 112 boxes, 16,908,176 subspace elements to scan
[+] MinRank: 20 matrices of rank <= 26 in 10 boxes
[+] real boxes by dimension: {16: [49, 60, 82, 86], 17: [1, 47, 92, 106], 18: [32, 44]}
```

Fourteen seconds, and the result is exactly as predicted: **20 hits, all of rank exactly
25, exactly two per box, in exactly 10 boxes**, splitting 4 / 4 / 2 across the three
dimensions — precisely the shape of `_l`. No false positives, no ambiguity about which
boxes are real.

## 6. Pairing the real boxes

Ten real boxes still have to be matched into five pairs. Conjugate matrices are similar,
so any similarity invariant works, provided it also survives transposition. The rank
sequence of the powers does both:

```python
fingerprint(H) = tuple(rank(H**k) for k in range(1, 13))
```

`rank((S H S⁻¹)ᵏ) = rank(Hᵏ)` and `rank((Hᵏ)ᵀ) = rank(Hᵏ)`, so a real pair has matching
fingerprint multisets and everything else does not. This costs twelve 32×32 multiplications
per matrix and reduces the candidate pairings to the correct ones immediately.

## 7. Recovering S is then linear

This is where the planted matrices pay off a second time. They are not just a marker —
they are **canonically identifiable inside their own subspace**, being the only elements of
rank 25. That removes the unknown change of basis entirely: if box A contains `H₁, H₂` and
box B contains `G₁, G₂`, then up to swapping the two, `Gᵢ = S Hᵢ S⁻¹`.

The unknown is now only `S`, and the relation is linear in it:

```
X · H₁ = G₁ · X
X · H₂ = G₂ · X
```

Writing entry `(i, j)` of each equation over the 1024 bits of `X` gives

```
sum_k H[k][j] · X[i][k]   xor   sum_k G[i][k] · X[k][j]   =   0
```

which is 2 × 1024 = **2048 equations in 1024 unknowns** over GF(2) — one Gaussian
elimination.

The solution space is `S · Centralizer(H₁, H₂)`. Two random rank-25 matrices generate the
whole matrix algebra M₃₂(GF(2)) with overwhelming probability, whose centralizer is just
`{0, I}`, so the space should be one-dimensional and its single nonzero element should be
`S` itself. That is exactly what happens for all five pairs:

```console
[+] m=16: box  49 ~ box  60   solution space dim 1, transposed=False, order=(0, 1)
[+] m=16: box  82 ~ box  86   solution space dim 1, transposed=True,  order=(0, 1)
[+] m=17: box   1 ~ box  92   solution space dim 1, transposed=False, order=(0, 1)
[+] m=17: box  47 ~ box 106   solution space dim 1, transposed=False, order=(0, 1)
[+] m=18: box  32 ~ box  44   solution space dim 1, transposed=True,  order=(0, 1)
```

## 8. The transposition ambiguity costs nothing

`_o()` transposes each box independently, so there are four combinations to worry about.
There are not, for two reasons.

First, only **one** side ever needs to be flipped. Write the true relation as
`Gᵢ = S Hᵢ S⁻¹` and let `Y = Sᵀ X`:

| box A holds | box B holds | flip A? | system reduces to | recovered X |
|---|---|---|---|---|
| `Hᵢ` | `Gᵢ` | no | `X Hᵢ = Gᵢ X` | `S` |
| `Hᵢᵀ` | `Gᵢ` | yes | `X Hᵢ = Gᵢ X` | `S` |
| `Hᵢ` | `Gᵢᵀ` | yes | `Y Hᵢᵀ = Hᵢᵀ Y` &rArr; `Y = I` | `S⁻ᵀ` |
| `Hᵢᵀ` | `Gᵢᵀ` | no | `Y Hᵢᵀ = Hᵢᵀ Y` &rArr; `Y = I` | `S⁻ᵀ` |

Transposing *both* boxes is absorbed by the `S ↔ S⁻ᵀ` symmetry, so a single boolean covers
all four cases.

Second, it does not matter which of the two you land on: `_f` takes the minimum over
`{S, S⁻¹, Sᵀ, S⁻ᵀ}`, and `S⁻ᵀ` generates the same four-element set. The key is unchanged.

## 9. Key derivation and decryption

```python
key = shake_256(b"linchan-v2/key\0" + b"".join(sorted(_f(S) for S in K))).digest(32)
```

then ChaCha20-Poly1305 with the leading 12 bytes of the ciphertext as the nonce and
`b"linchan/v2"` as associated data. `cryptography` was not installed on the solving
machine, so [`solution/solve.py`](solution/solve.py) carries a small RFC 8439
implementation instead — about 40 lines for both the stream cipher and the MAC.

The Poly1305 tag verifying is the point worth stressing: it is not a plausibility check on
the plaintext but a cryptographic confirmation that all five recovered matrices are
correct.

```console
[+] key: c79d930f6691caace9686711a0d8b9e9590a16831b935f14fb5beb6a5c56b638
[+] Poly1305 tag valid: True
[+] flag: ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```

## 10. Flag

```
ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```

## 11. Why the planted matrices had to go

The rank-25 seeds are not a slip that can simply be deleted — they are load-bearing. Take
them out and every subspace is uniform, the boxes become indistinguishable, and matching a
conjugate pair means solving the bilinear subspace-conjugacy problem across 703 candidate
pairs per dimension. The author needed a canonical hook so that the puzzle had a solution
at all.

The mistake is *which* hook. A rank anomaly at density 2⁻⁴⁷ is visible to anyone who can
enumerate the subspace, and m ≤ 18 makes that a fourteen-second scan. Worse, the same hook
that separates real boxes from decoys also fixes the correspondence `Hᵢ → Gᵢ`, which is the
one piece of information that turns the bilinear problem into a linear one. One marker
solved all three subproblems at once.

A hook that only becomes visible *after* the pairing is known — or subspace dimensions large
enough to put MinRank out of reach — would have left the intended difficulty intact.

## 12. Takeaways

* **Ask what survives the obfuscation.** `_o()` looks like it hides the subspace, but a
  change of basis preserves every element of it. Before attacking a scheme, list the
  quantities that are invariant under whatever scrambling it applies — here rank, and rank
  under conjugation and transposition — and check whether the construction disturbs any of
  them.
* **A distinguisher and a key-recovery are often the same observation.** The low-rank
  elements identified the real boxes, paired them, and pinned the basis correspondence.
  When a marker has to be canonical enough to find, it is usually canonical enough to
  exploit.
* **MinRank is only hard when the space is big.** Its hardness is asymptotic in the
  dimension of the span. At m ≤ 18 the entire subspace fits in a Gray-code loop, and the
  security argument evaporates.
* **Verify with the tag, not the plaintext.** An AEAD gives a free proof of correctness.
  If the tag validates, the recovered key is right — no eyeballing of ASCII required.

## Reproducing

```console
$ python3 solution/solve.py
```

One command: it parses `challenge/output.txt`, compiles and runs the MinRank scan, pairs
the boxes, solves for the five matrices and decrypts. Needs Python 3 and a C compiler; no
third-party Python packages.
