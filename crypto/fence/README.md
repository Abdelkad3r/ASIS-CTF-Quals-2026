# Fence

## Challenge Information

| Field | Value |
| --- | --- |
| Event | ASIS CTF Quals 2026 |
| Category | Cryptography |
| Challenge | Fence |
| Description | Five locks, one dense true fence, and a flag that thinks it is safe. Find the gap! |
| Solver | [`solve.py`](solve.py) |
| Original handout | [`artifacts/Fence_7e750d85599a53701faa9ec6b58323c4b4a9d977.txz`](artifacts/Fence_7e750d85599a53701faa9ec6b58323c4b4a9d977.txz) |
| Flag | `ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}` |

## Executive Summary

The challenge publishes five independent NTRU-like public keys. For every lock,
two balanced ternary polynomials `a` and `b` are generated and the public key is

```text
h = b * a^(-1) mod (q, x^n + 1).
```

Rearranging gives the public modular relation

```text
a * h = b mod (q, x^n + 1).
```

This relation places the secret pair `(a, b)` in a standard 256-dimensional
NTRU lattice. Both polynomials contain only 80 nonzero coefficients, all equal
to `+1` or `-1`, so the squared norm of the hidden vector is only

```text
|| (a, b) ||^2 = 80 + 80 = 160.
```

That vector is exceptionally short compared with ordinary vectors in a lattice
whose determinant is `q^128`, where `q` is approximately `2^28`. LLL prepares
the basis and BKZ-30 recovers a norm-160 ternary vector in the secret's
negacyclic rotation orbit.

The key derivation function intentionally canonicalizes that entire orbit.
Consequently, recovering any rotated or negated representative is sufficient.
The included HMAC tag provides an exact test for each candidate. After
decrypting all five authenticated shares, XORing them together yields the flag.

## Included Files

| File | Purpose | SHA-256 |
| --- | --- | --- |
| [`artifacts/Fence_7e750d85599a53701faa9ec6b58323c4b4a9d977.txz`](artifacts/Fence_7e750d85599a53701faa9ec6b58323c4b4a9d977.txz) | Untouched challenge handout | `2a4658f47a63ccd2179801bfdddca6d8fb53fed7bfbb8495c8636a2dfc14ede1` |
| [`artifacts/fence.py`](artifacts/fence.py) | Encryption and key-generation source | `e527b2aff1c3c11f3362c3aeb00feef8be923059f5b27a3bb02c45e6f1093f99` |
| [`artifacts/flag.enc`](artifacts/flag.enc) | Five public keys and ciphertext records | `c775e0401a025aa202daf2173dc57ceddace9bf984d11e783e1fd3c24f66a039` |
| [`solve.py`](solve.py) | End-to-end lattice solver | `ff8a0b9030b4ec4552a437e2abcbf1284965f8637a1ba510b14834f5a06a2e77` |

## 1. Inspecting the Handout

The archive contains only the encryption source and its output:

```console
$ tar -tJvf Fence_7e750d85599a53701faa9ec6b58323c4b4a9d977.txz
drwxr-xr-x  Fence/
-rw-r--r--  Fence/fence.py
-rw-r--r--  Fence/flag.enc
```

The important public parameters are:

```python
n = 128
q = 268435361
w = 80
r = 5
```

The computation takes place in the quotient ring

```text
R_q = Z_q[x] / (x^128 + 1).
```

The `pm()` function implements negacyclic multiplication in this ring. Terms
whose degrees reach 128 wrap around with a minus sign because
`x^128 = -1`.

## 2. Understanding the Private Polynomials

The generator `gn()` shuffles all 128 coefficient positions and selects 80:

```python
for j in i[:w // 2]:
    a[j] = 1
for j in i[w // 2:w]:
    a[j] = -1
```

Every private polynomial therefore has exactly:

- 40 coefficients equal to `+1`;
- 40 coefficients equal to `-1`;
- 48 coefficients equal to `0`.

Its squared Euclidean norm is 80. The concatenated secret pair `(a, b)` has
squared norm 160 and norm `sqrt(160)`, approximately 12.65.

The public key is computed as:

```python
h = pm(b, iv(a))
```

Therefore:

```text
h = b/a             in R_q
a*h = b             in R_q
a*h - b = q*k       over the integers, for some vector k.
```

The last equation is exactly what is needed to construct an NTRU lattice.

## 3. Constructing the NTRU Lattice

Let `H` be the `128 x 128` integer matrix representing multiplication by the
public polynomial `h` in the negacyclic ring. Row `i` of `H` is the coefficient
vector of `x^i * h mod (x^128 + 1)`, which is precisely `sh(h, i)` in the
challenge's notation.

Use the following row basis:

```text
    [ I   H ]
B = [       ]
    [ 0  qI ]
```

For arbitrary row vectors `u` and `k`, a lattice vector has the form

```text
(u, u*H + q*k).
```

Set `u = a`. Since `a*H = b mod q`, there is an integer vector `k` for which

```text
(a, a*H + q*k) = (a, b).
```

Thus the hidden key pair is a vector in this lattice.

The determinant is `q^128`. In dimension 256, the determinant scale per
dimension is

```text
det(B)^(1/256) = sqrt(q),
```

which is about 16384. The private vector's norm of about 12.65 is separated by
a very large gap from the ordinary lattice scale. This is the gap referenced
by the challenge description.

The solver builds the basis with:

```python
for i in range(n):
    rows.append([int(i == j) for j in range(n)] + shift(h, i))
for i in range(n):
    rows.append([0] * n + [q * int(i == j) for j in range(n)])
```

## 4. Lattice Reduction

Plain LLL substantially reduces the basis but does not consistently expose the
norm-160 vector as a basis row. A modest BKZ pass is enough because the target
is so unusually short.

The reproducible reduction pipeline is:

```console
fplll -a lll -d 0.99 -m fast -f double lock.matrix > lock.lll
fplll -a bkz -b 30 -bkzautoabort lock.lll > lock.bkz
```

The BKZ output contains ternary vectors with:

```text
length       = 256
coefficients in {-1, 0, 1}
squared norm = 160
```

There can be many such rows because negacyclic shifts of a valid secret are
also lattice vectors of the same norm.

## 5. Why a Rotated Secret Is Enough

The `sh()` function implements multiplication by powers of `x`, including the
sign changes produced by `x^128 = -1`. The key derivation function computes:

```python
u = min(tuple(sh(a, i) + sh(b, i)) for i in range(2 * n))
```

It considers all 256 negacyclic rotations, including the sign-equivalent half
of the orbit, and chooses the lexicographically smallest representation.

Suppose BKZ returns

```text
(a', b') = (sh(a, j), sh(b, j))
```

for some `j`. The set of all rotations of `(a', b')` is the same as the set of
all rotations of `(a, b)`. Both produce the same minimum `u`, and therefore the
same symmetric key. Recovering the generator's exact orientation is not
necessary.

This also explains why a recovered shifted polynomial may no longer contain
exactly 40 positive and 40 negative coefficients: coefficients that cross the
degree-128 boundary change sign. The total number of nonzero coefficients and
the norm remain unchanged.

## 6. Authenticating Candidate Vectors

Not every short vector has to be trusted. Each ciphertext includes a 16-byte
HMAC tag:

```python
t = HMAC-SHA256(k, d || associated_data || salt || ciphertext)[:16]
```

The associated data is serialized exactly as:

```python
json.dumps(
    {"N": n, "Q": q, "H": h},
    sort_keys=True,
    separators=(",", ":"),
).encode()
```

For every norm-160 ternary row, the solver:

1. Splits it into candidate polynomials `(a, b)`.
2. Applies the challenge's rotation canonicalization.
3. Derives the SHA3-256 key.
4. Recomputes the HMAC tag.
5. Accepts the candidate only when `hmac.compare_digest()` succeeds.

The tag turns candidate selection into an exact check. No visual or statistical
guess about decrypted plaintext is required.

## 7. Decrypting the Five Shares

After authentication, a lock's stream is:

```python
stream = SHAKE256(d || key || salt, output_length=len(ciphertext))
message = ciphertext XOR stream
```

The five messages are not five copies of the flag. The generator creates four
random strings `m_0` through `m_3`, accumulates their XOR, and sets

```text
m_4 = m_0 XOR m_1 XOR m_2 XOR m_3 XOR flag.
```

Consequently:

```text
m_0 XOR m_1 XOR m_2 XOR m_3 XOR m_4 = flag.
```

This is why the first four correctly decrypted messages still look random.
Their authenticity comes from the HMAC, and readability appears only after the
final XOR.

## 8. Running the Solver

### Requirements

- Python 3.9 or newer;
- `fplll` available in `PATH`.

No third-party Python packages are required.

From this challenge directory:

```console
$ python3 solve.py artifacts/flag.enc
[*] reducing lock 1/5
[+] lock 1: authenticated share recovered
[*] reducing lock 2/5
[+] lock 2: authenticated share recovered
[*] reducing lock 3/5
[+] lock 3: authenticated share recovered
[*] reducing lock 4/5
[+] lock 4: authenticated share recovered
[*] reducing lock 5/5
[+] lock 5: authenticated share recovered
[+] plaintext: b'ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}'
[+] flag: ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}
```

Runtime is hardware-dependent and is dominated by five 256-dimensional lattice
reductions. To retain the generated matrices for inspection, use:

```console
$ python3 solve.py artifacts/flag.enc --workdir fence-matrices
```

## 9. Complete Attack Flow

The complete solution can be summarized as follows:

1. Parse `flag.enc` and read the five public polynomials and ciphertexts.
2. For each public polynomial `h`, construct the 256-dimensional NTRU basis.
3. Run LLL, then BKZ-30 with automatic abort.
4. Filter reduced rows for ternary vectors with squared norm 160.
5. Derive a candidate key using the challenge's rotation canonicalization.
6. Validate the candidate against the ciphertext's truncated HMAC.
7. Decrypt the authenticated ciphertext with SHAKE256.
8. XOR the five recovered plaintext shares.
9. Decode the result as the flag.

## 10. Root Cause and Remediation

The symmetric encryption, SHA3, SHAKE, and HMAC components are not broken. The
failure occurs before those primitives are used: the public NTRU relation leaks
an exceptionally short secret vector recoverable with practical lattice
reduction.

The issue is amplified by several design decisions:

- low dimension (`n = 128`);
- a very large modulus relative to the secret norm;
- secrets restricted to exactly 80 ternary coefficients;
- direct publication of `b/a` without an encryption-noise mechanism;
- an authentication tag that provides a perfect offline candidate oracle.

A secure design should use a well-studied, standardized lattice construction
with reviewed parameters and security estimates. Increasing one parameter in
this custom design is not a reliable fix. In particular, cryptographic secrets
should not be protected by an ad hoc NTRU ratio and then used directly as
symmetric key material.

## Flag

```text
ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}
```
