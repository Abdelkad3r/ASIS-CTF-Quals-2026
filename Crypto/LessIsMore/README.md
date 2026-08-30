# Less is more

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Crypto |
| **Difficulty** | Hard |
| **Files** | [`challenge/challenge.py`](challenge/challenge.py), `challenge/flag.enc` (75 MB capture, not committed) |
| **Solver** | [`solution/solve.py`](solution/solve.py) |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/9decc08f-ed92-4cc5-9568-ebfc2f6d6b6e) |
| **Flag** | `ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}` |

> We captured traffic from a prototype signing device. The implementation is small, but some
> records in the capture do not match a normal run. **Note the less is more.**
>
> The device sealed its backup vault with a key derived from its secret matrices. Recover the
> vault key, open the vault, and take the flag.

---

## TL;DR

The device is a **code-equivalence signature** over GF(827). Each of its seven secret keys is
a *monomial map* — a column permutation `p` and a diagonal scaling `d` — applied to a public
Cauchy code `g`; the public key is `RREF(g[:,p]·diag(1/d))`. The flag is sealed under
`SHAKE-256("o" + pack_key(the 7 real keys))`, so recovering all seven `(p, d)` pairs is the
whole game.

Each signature is a zero-knowledge cut-and-choose whose responses reveal `{i : p_x[i] ∈ v}`
for a **secret** half-set `v` hidden inside a Merkle leaf. The bug — *less is more* — is an
occasional **iteration skip**: with 72 % probability the signer overwrites one challenge
indicator `f[target]` with the *previous* round's state. When that turns a challenged leaf's
indicator to 0, the leaf's seed is shipped in the clear **and** it still carries a response.
Now `v` is known, and the response becomes a hard constraint on the permutation. Voting over
the "hit" records across ~6000 signatures pins all seven permutations; a linear solve then
recovers the diagonals from the public keys.

```
ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```

## 1. The scheme

Parameters: `P=827, N=548, K=274, T=345, W=75`, with `REAL=7` real keys hidden among
`SLOTS=17` public slots (`10` decoys).

**The code.** `base()` builds a `K×N` Cauchy matrix `g[i][j] = 1/((i − (K+j)) mod P)` and
reduces it to RREF. This is public.

**A secret key** is `(p, d)` where `p` is a permutation of the `N` columns and `d` is a vector
of `N` nonzero scalars. Its **public key** is

```python
public(g, (p, d)) = RREF([[ g[i][p[j]] · inv(d[j]) for j in range(N)] for i in range(K)])
```

i.e. permute the columns of `g` by `p`, scale column `j` by `1/d[j]`, and row-reduce. The
box publishes the 17 public keys (7 real + 10 decoy), shuffled, so you do not even know which
are real.

**The seal.** `pack_key` serialises each real key as its permutation followed by its diagonal
**normalised by `d[0]`** (`d[j]·inv(d[0])`), and

```python
pad    = SHAKE-256("o" + pack_key(box.key))
sealed = flag XOR pad
```

So the target is exactly the seven `(p, d)` pairs, with each `d` only needed up to a global
scalar.

## 2. One signature

`box.one(msg, serial)` is an MPC-in-the-head cut-and-choose over a Merkle tree of `T=345`
leaves:

* A per-message `root` seeds a binary tree; `leaf[i]` is the `i`-th leaf seed.
* `cmt` commits to all leaves, and `b = chal(cmt, salt, msg)` is a length-`T` challenge with
  exactly `W=75` nonzero entries, each a **class label** in `1..7`.
* `f = [int(b[i] != 0)]` is the "reveal indicator". `cover()` ships the seeds of every maximal
  subtree whose leaves are all `f=0` (so the verifier can recompute those leaves), while
  `f=1` leaves stay hidden.
* For every challenged leaf `i` (`b[i]=x`), the response is

  ```python
  v = take(leaf[i], 'n', N, K)                       # a secret K-subset of columns
  rsp += [ label(cmt, leaf[i]), bits({ p_x⁻¹[j] : j ∈ v }) ]
  ```

  `bits(·)` is an `N`-bit set mask. So the response reveals the **set**
  `S = { i : p_x[i] ∈ v }` — but `v` is derived from the *hidden* leaf seed, so honestly it is
  zero-knowledge: you learn a `K`-subset with no idea which columns `v` contained.

Decoys and a 14 % "fault" (one response per record replaced by a random mask) add noise.

## 3. The bug: an iteration skip

```python
target = (37 * serial + 11) % T
if int.from_bytes(sha256(b'v' + root)[:2], 'big') % 100 < 72:
    f[target] = self.state[target]      # <-- overwrite with LAST round's indicator
self.state = f
hit = [i for i in range(T) if b[i] and not f[i]]
```

72 % of the time the signer replaces `f[target]` with the **previous** signature's indicator
at that position instead of recomputing it. When the previous value was `0` while this round's
challenge has `b[target] ≠ 0`, we get a **hit**: a leaf that is genuinely challenged (so it
has a response) but is marked `f=0` (so its seed is *revealed* by the cover). The two are never
supposed to coincide.

The consequence is exactly the diagram below: the revealed seed lets us recompute `v`, and the
response then leaks the permutation.

## 4. Detecting hits from the capture

`_hit` is stripped before saving, but every hit is reconstructible:

1. `serial = int(msg[1:])`, so `target = (37·serial + 11) mod T`.
2. Recompute `b = chal(cmt, salt, msg)` (needs only `cmt, salt, msg` — all public). Skip
   records where `b[target] = 0`.
3. Recover `leaf[target]`. The cover path stores `[token(cmt, u), seed]` with
   `token(cmt, u) = u XOR (sha256('m'+cmt)[:2] & 1023)`, so invert it to get the node `u`. If
   an internal node `u` covers `target`, **descend the tree** from `u`'s seed to
   `leaf[target]`.
4. Confirm by matching `label(cmt, leaf[target])` against the record's responses.

Across the 5963 records this finds **830 hits, every one label-matched** (proving the descent),
**105–128 per class** — comfortably above the ~90 the generator loops until.

## 5. Recovering the permutations

For a hit of class `x` we now know both `v = take(leaf[target], 'n', N, K)` and the response
set `S`. The response was `{ i : p_x[i] ∈ v }`, and since `|v| = |S| = K = N/2` with `p_x` a
bijection, it says precisely

```
p_x[i] ∈ v   ⇔   i ∈ S           (and p_x[i] ∈ vᶜ for i ∉ S)
```

Each hit therefore restricts every position `i` to one side (`v` or `vᶜ`) of a random balanced
split. **Vote**: for each `(x, i)` tally how often each column is on the allowed side. The true
`p_x[i]` is allowed in every honest hit (~110 votes); any other column is allowed about half
the time (~55); the rare 14 % fault records are simply outvoted. `argmax` gives `p_x[i]`, and
every recovered `p_x` is a valid permutation (minimum vote margin 21).

## 6. Recovering the diagonals

With `p_x` fixed, the public key `M` for that key satisfies `M = RREF(g[:,p_x]·diag(1/d))`.
Column scaling does not change which columns are pivots, so:

* **Match** each `p_x` to its public key by comparing the pivot set of `RREF(g[:,p_x])` against
  the pivot set of each `M`. This uniquely identifies the real slot
  (classes 1–7 → public keys 0, 4, 14, 2, 6, 16, 12).
* **Solve `d`.** Let `piv` be the pivots and `Ginv = (g[:,p][:,piv])⁻¹`. Then
  `(Ginv·g[:,p])·diag(1/d)` has the same row space as `M`, giving
  `d[j]/d[piv[t]] = W[t,j]/M[t,j]` with `W = Ginv·g[:,p]`. Fixing the global scale, propagate to
  every `d[j]` column by column, and verify `public(g,(p,d)) == M` exactly.

The `/d[0]` normalisation in `pack_key` removes the global scalar, so the recovered diagonals
reproduce the sealed key bytes regardless of scale.

## 7. Opening the vault

Reassemble the seven keys in class order (`class x` ↔ `box.key[x-1]`), pack, derive the pad,
and XOR:

```console
$ python3 solution/solve.py
[+] 5963 records, 17 public keys, 54-byte flag
[+] class 1: 127 hits, permutation recovered (min vote margin 29)
 ...
[+] class 1: matched public key #0, diagonal recovered and verified
 ...
[+] flag: ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```

## 8. Flag

```
ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```

The name says it: *an iteration skip makes no innocent response.*

## 9. Takeaways

* **A cut-and-choose is only zero-knowledge if the two cases stay disjoint.** The whole scheme
  rests on "challenged ⟹ hidden" and "revealed ⟹ unchallenged". The iteration skip lets a
  single leaf be both revealed *and* challenged, and that one coincidence collapses the ZK
  property into a plaintext leak.
* **Reused state across signatures is the vulnerability, not the maths.** The Cauchy code and
  the monomial masking are sound; `f[target] = self.state[target]` — carrying one bit from the
  last run — is what leaks.
* **Set-membership leaks compose.** A single hit only tells you which *half* each column sits
  in. But balanced random halves intersect down to a point: ~110 of them per class pin the
  permutation with no cryptanalysis beyond counting.
* **Recover structure, then scale.** Once the permutation is known, the diagonal is a linear
  problem against the public key, and the key-derivation's own normalisation makes the leftover
  global scalar irrelevant.

## Reproducing

```console
$ # place the challenge capture at challenge/flag.enc (75 MB, not committed)
$ python3 solution/solve.py            # or: solution/solve.py path/to/flag.enc
```

Needs Python 3 and numpy (step 6 does GF(827) linear algebra; the pure-Python version was too
slow at 274×548). Everything else is the standard library.
