# Sultan

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Crypto |
| **Difficulty** | Medium–Hard |
| **Service** | `http://91.107.152.21:17131` |
| **Files** | [`challenge/crypto_engine.py`](challenge/crypto_engine.py), [`challenge/app.py`](challenge/app.py) |
| **Flag** | `ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}` |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/987f9426-4fe0-47aa-9990-fe519c7ab697) |

> An encrypted archive from the sultan's laboratory has resurfaced. It is said to contain a message
> meant for the court alone.

---

## TL;DR

Each downloaded `secret.enc` derives its **entire** symmetric key from a small module-LWE secret
`s` (one polynomial in `Z_q[X]/(X⁶⁴+1)`, `q = 8380417`, coefficients in `[-3,3]`), and then leaks
`s` through 70 "committee session" records. Each record publishes `v = u + c·s` (`u` a fresh mask)
and, fatally, `hint = ⌊⟨A, u⟩ / b⌋` with `b = 65000`. Substituting `u = v − c·s` turns every hint
into a linear constraint on `s`:

```
T_j ≡ M_j·s + r_j   (mod q),     s ∈ [-3,3]⁶⁴,   r_j ∈ [0, b)
```

— textbook **small-secret LWE** (70 samples, 64 unknowns, error `< 65000 ≪ q`). A Bai–Galbraith
primal (Kannan) embedding + **BKZ-30** recovers `s` in seconds; then
`k = SHAKE256("SULTAN/key" ‖ s)` decrypts the flag. One file suffices — the session's
`secret_string` is constant — and submitting it to `/api/verify` returns the flag.

---

## 1. The web wrapper

`app.py` mints a per-session `secret_string` (28–32 random alphanumerics, constant for 20 minutes)
and lets us download `encrypt_sultan(secret_string)` as `secret.enc` up to 500 times, or submit a
`guess` to `/api/verify` for the flag. So the whole task is: **recover the session's secret string
from one `secret.enc`**, then verify it on the same cookie.

## 2. The cipher — key is a function of a tiny lattice secret

[`crypto_engine.py`](challenge/crypto_engine.py), `encrypt_sultan`:

```python
q, n, ell, m, t, b = 8380417, 64, 1, 70, 16, 65000
secret_bound = 3

s = [_g(-secret_bound, secret_bound) for _ in range(ell)]   # fresh; coeffs in [-3,3]
w = _secret_bytes(s)
k = shake_256(b"SULTAN/key" + w).digest(32)                 # <-- key is JUST f(s)
nonce = token_bytes(24)
p = shake_256(b"SULTAN/stream" + k + nonce).digest(len(secret_data))
e = bytes(u ^ v for u, v in zip(secret_data, p))            # ciphertext of the secret string
d = blake2s(b"SULTAN/tag" + nonce + e, key=k).digest()      # MAC
```

`_p` is negacyclic polynomial multiplication in `R_q = Z_q[X]/(X⁶⁴+1)`; `_a` is coefficient-wise
addition. Recovering `s` yields `k`, hence the keystream `p`, hence `secret_string = e ⊕ p`. The
BLAKE2s tag `d` lets us confirm a candidate `s` offline.

## 3. The leak — committee sessions expose `s`

For each of `m = 70` sessions:

```python
x = token_bytes(32)
y = bytes(sorted(random.sample(range(63), 32)))             # committee subset
seed = x + y
u = [_g(0, q-1) for _ in range(ell)]                        # fresh uniform mask
c = _b(seed)                                                # sparse ±1 challenge (t=16 nonzeros)
v = [_a(up, _p(c, sp)) for up, sp in zip(u, s)]            # v = u + c*s
R.append(x + y + struct.pack("<I", _i(_r(seed), u) // b) + _z(v))
```

`_r(seed)` is a public pseudorandom vector `A`, and `_i(A, u) = ⟨A, u⟩ mod q`. Each record therefore
publishes, all derivable from the public `seed`:

- `c = _b(seed)` and `A = _r(seed)`,
- the full `v = u + c·s`,
- `hint = ⌊⟨A, u⟩ / b⌋`  (with `⟨A,u⟩` reduced to `[0, q)` before the division).

`v` alone is uniform (masked by `u`) — useless. The hint is the whole game. Because
`u = v − c·s`:

```
⟨A, u⟩ ≡ ⟨A, v⟩ − ⟨A, c·s⟩   (mod q)
```

Both `⟨A, v⟩` and the map `s ↦ ⟨A, c·s⟩` are known. Writing the linear form
`M_j·s := ⟨A_j, c_j·s⟩` and the constant `a_j := ⟨A_j, v_j⟩`, the hint says
`⟨A_j,u_j⟩ = a_j − M_j·s ∈ [hint_j·b, hint_j·b + b)`, i.e.

```
M_j·s + r_j ≡ a_j − hint_j·b   (mod q),     r_j ∈ [0, b).
```

Set `T_j = (a_j − hint_j·b) mod q`. **That is an LWE sample** with a tiny secret and error
bounded by `b`.

### Making the linear form explicit

`⟨A, c·s⟩` is linear in the 64 coefficients of `s`. Column `k` is `M_{j,k} = ⟨A_j, c_j·e_k⟩`, where
in `R_q`:

```
(c · e_k)[i] = c[i-k]        if i ≥ k
             = -c[i-k+n]     otherwise      (negacyclic wrap, X^n = -1)
```

## 4. Why it's easy — and the lattice that solves it

70 samples constrain 64 unknowns; each hint carries `log₂(q/b) ≈ 7` bits, so ≈490 bits pin a secret
with only ≈180 bits of entropy — wildly over-determined; `s` is unique. The work is a lattice reduction.

**Bai–Galbraith primal embedding.** Build the `(n + m + 1)`-dimensional basis (secret coordinates
scaled by `Ws ≈ b/6` so the tiny secret and the `[0,b)` error contribute comparable length; error
centered at `b/2`, Kannan embedding coefficient `1`):

```
rows i<n :   [ Ws·e_i | M[:,i] | 0 ]
rows n+j :   [   0     | q·e_j  | 0 ]
last row :   [   0     | (T_j − b/2) | 1 ]
```

The unique short vector encodes `(−s, r − b/2, 1)`. Here the target norm ≈ 2.4·10⁵ vs a Gaussian
heuristic ≈ 9·10⁵ — a uSVP gap of ≈ 3.7 in dimension 135. Plain LLL falls short (it only reaches
≈ 4·10⁶, ~14×GH), so we run **progressive BKZ**; **BKZ-30 recovers `s` in ~2 s**.

## 5. Execution

```console
$ python3 solution/solve.py --selftest
[selftest] secret='iaCQb8DV3xowy475AeB462UY1fxYKVk'
[selftest] recovered='iaCQb8DV3xowy475AeB462UY1fxYKVk' tag_ok=True MATCH=True

$ python3 solution/pwn.py
[*] downloaded secret.enc: 19608 bytes  (session uw1hEaOnIAmtR0wJ...)
[*] recovered secret (30 chars, tag_ok=True) in 5.5s: 'fLyoSLn8rMz1UnXrEwQknVO0v0SZS6'

[+] FLAG: ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}
```

```
ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}
```

The whole chain was validated offline against locally-generated files (every recovery
BLAKE2s-tag-verified) before running it live.

## 6. Solution files

| File | Purpose |
|---|---|
| [`solution/solve.py`](solution/solve.py) | Parse `secret.enc`, build the LWE system, recover `s` (BKZ), derive the key, decrypt. `--selftest` self-checks against a locally generated file. |
| [`solution/pwn.py`](solution/pwn.py) | Remote end-to-end: download → recover → `/api/verify` → flag. |

Requires `fpylll`; `crypto_engine.py` is standard-library only.

## 7. Lessons

- **Don't leak high bits of a mask that also carries the secret.** Publishing `⌊⟨A,u⟩/b⌋` alongside
  `v = u + c·s` converts every "committee hint" into a linear equation on `s` with `b`-bounded error.
- **Toy parameters are toy security.** `n = 64`, `ℓ = 1`, secret width 3 — this module-LWE is far
  below any real Dilithium-style level and collapses under BKZ-30 in seconds.
- **Small-secret LWE with many hints is essentially free.** 70 samples for 64 unknowns with ~7 bits
  each leaves an enormous gap; the flag (`corrupt quorum reuse`) names the design flaw.
- **A key that is a pure function of a recoverable value is only as strong as that value.**
  `k = SHAKE(s)` means one lattice solve unlocks the entire authenticated cipher.
