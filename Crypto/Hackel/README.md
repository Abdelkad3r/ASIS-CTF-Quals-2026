# Hackel

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Crypto |
| **Difficulty** | Baby |
| **Service** | `nc 65.109.208.91 3771` |
| **Files** | [`challenge/hackel.py`](challenge/hackel.py) |
| **Flag** | `ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}` |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/a15eb14f-a7f8-462b-bc5d-cb0c53094881) |

> Our lead cryptographer hackel proudly announced a "revolutionary post-quantum vault" guarded by
> intricate algebraic group presentations. With a search space boasting over 1.6 quadrillion states,
> they confidently declared: *"No supercomputer on Earth could brute-force our permutations before
> the heat death of the universe!"*

---

## TL;DR

The service dresses a trivial encoding in the language of combinatorial group theory. Two independent
breaks exist, and neither requires searching the advertised keyspace:

1. **The ciphertext is plaintext.** Flag bits are encoded as *words over the generator alphabet* and
   printed literally by menu option `[2]`. A bit is `1` exactly when its word contains the letter
   `b`. The flag decodes offline with a one-line classifier.
2. **The key check never involves the key.** Option `[4]` validates a submission only against the
   *published* presentation, never against the server's secret. The presentation collapses to
   `A^10 = B^11 = 1`, so a 10-cycle and an 11-cycle are accepted as an "equivalent key".

The advertised 1.6 quadrillion states is `(11!)^2 = 1,593,350,922,240,000` — the two independent
permutation assignments. It is never searched.

---

## 1. Reconnaissance

The archive holds a single file.

```console
$ tar xf Hackel_167b289c63c46836d376945105d757028321303a.txz
$ find . -type f
./Hackel/hackel.py
```

`hackel.py` is the full server. It imports a local `flag` module (not shipped), so the source is
complete apart from the flag itself. The menu exposes five actions:

```
[1] View Public Parameters & Relations
[2] View Training Samples & Encrypted Flag Words
[3] Homomorphic Word Concatenation Oracle
[4] Submit Recovered Equivalent Key (Unlock Flag)
[5] Interactive Speed Challenge (Unlock Flag)
```

Options `[4]` and `[5]` both print the flag. Option `[3]` is a red herring — it reads two words and
returns their concatenation as a string, computing nothing and leaking nothing:

```python
def oracle(self) -> None:
    w1 = parse_seq(self.get_line())
    w2 = parse_seq(self.get_line())
    self.out(f"[+] Homomorphic Product Word: {''.join(w1 + w2) or '1'}")
```

### Conventions

Permutations are 0-indexed tuples on `n = 11` points and compose **left to right**:

```python
def compose(a, b):
    return tuple(b[i] for i in a)      # result[i] = b[a[i]]  ->  "apply a, then b"
```

So the word `AB` means *A then B*, matching `eval_seq`, which folds `compose` over the token list.
`conj(x, c)` computes `c^-1 x c`.

## 2. How the vault is built

`init_state` builds two structurally identical alphabets — uppercase `A..E` and lowercase `a..e` —
from a random conjugator:

```python
l_rand = tuple(rng.sample(range(n), n))
a_l = conj(cyc_perm(n, [tuple(range(10))]), l_rand)          # a 10-cycle, conjugated
b_l = conj(cyc_perm(n, [tuple(rng.sample(range(n), n))]), l_rand)   # an 11-cycle, conjugated
c_l = compose(a_l, b_l)                                     # c = ab
d_l = compose(invert(a_l), compose(b_l, c_l))               # d = a^-1 b c
e_l = compose(c_l, d_l)                                     # e = cd
```

So `a` has order 10 (a 10-cycle fixing one point) and `b` has order 11 (an 11-cycle). `c`, `d`, `e`
are *derived*, not independent. The uppercase set is generated identically with its own conjugator.

### The bit encoding

This is the whole cryptosystem:

```python
flag_bits = "".join(f"{b:08b}" for b in flag_str.encode("utf-8"))
flag_words = [
    (t0,) * rng.randint(1, 9) if bit == "0" else (t0,) * rng.randint(0, 9) + (t1,)
    for bit in flag_bits
]
```

With `t0 = 'a'` and `t1 = 'b'`:

| plaintext bit | ciphertext word | exponent range |
|---|---|---|
| `0` | `a^k` | `k ∈ 1..9` |
| `1` | `a^k b` | `k ∈ 0..9` |

The intended hardness story is that `a^k` and `a^k b` are indistinguishable without the key. The
`a`-padding is the only randomness, and it is pure noise.

## 3. Break #1 — the ciphertext is never encrypted

`show_samples` prints the words **as strings**, not as evaluated permutations:

```python
self.out("    " + ", ".join("".join(w) or "1" for w in self.state.ciphertexts))
```

```console
[+] Encrypted Flag Words (496):
    aaa, ab, aaaaa, aaa, aaaaaaaa, a, aaa, aaaaaab, ...
```

The two branches differ by a single visible character, so:

> **bit = 1 ⟺ the word contains `b`**

The classifier is exact, with no edge cases: a `0` word is `a^k` with `k ≥ 1`, so it is never empty
and never contains `b`; a `1` word always ends in `b`. The literal `1` (identity) never appears.

496 words = 496 bits = 62 bytes, which is exactly the flag length.

```python
bits = "".join("1" if "b" in w else "0" for w in words)
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()
```

### The same break, one level deeper

Even if the server had evaluated the words into permutations before sending them, the scheme would
still fall. The bit is determined by the **coset of `⟨a⟩`**:

- `a^k ∈ ⟨a⟩` → bit `0`
- `a^k·b ∉ ⟨a⟩` → bit `1`, because `|b| = 11` does not divide `|⟨a⟩| = 10`

That membership test is preserved by *any* assignment satisfying the published relations — so it does
not even need the real key, only an equivalent one (Break #2). The server itself performs precisely
this test in `submit_key`:

```python
z_span = span_group(z_perms, limit=1000)      # = <a>, order 10
if not o_perms or o_perms[0] in z_span:       # a^k b must fall outside
    self.out("[-] Key consistency verification failed.")
```

The "semidirect product" framing adds no security: the secret conjugator is a change of basis, and
coset membership is basis-independent.

## 4. Break #2 — recovering an equivalent key

Option `[4]` is the intended path. Critically, **`submit_key` never references the server's secret
permutations.** It applies four gates only:

1. every symbol is a valid permutation of `range(11)`;
2. `is_symmetric_gen` holds for the upper and lower generator sets;
3. all upper, lower, and mixed relations hold;
4. the first one-sample lies outside the span of the zero-samples.

Any representation passing these is accepted — hence "Recovered **Equivalent** Key".

### 4.1 Collapsing the presentation

The published upper relations look formidable:

```
AAAAAAAAAA = 1      AB = C        CD = E        AC = AAB      CB = ABB
BBBBBBBBBBB = 1     AD = BC       ABD = E       DE = DCD      ED = CDD
```

Substituting the definitions `C = AB`, `D = A⁻¹BC = A⁻¹BAB`, `E = CD` turns eight of the ten into
tautologies:

| relation | check | result |
|---|---|---|
| `AB = C` | definition | trivial |
| `AD = BC` | `A·A⁻¹BAB = BAB` and `B·AB = BAB` | ✅ |
| `CD = E` | definition | trivial |
| `ABD = E` | `AB·D = C·D = E` | ✅ |
| `AC = AAB` | `A·(AB) = A·A·B` | ✅ |
| `DE = DCD` | `D·(CD) = D·C·D` | ✅ |
| `CB = ABB` | `(AB)·B = A·B·B` | ✅ |
| `ED = CDD` | `(CD)·D = C·D·D` | ✅ |

What actually remains is just:

```
⟨ A, B | A^10 = 1, B^11 = 1 ⟩
```

### 4.2 Collapsing the mixed relations

```
Aa = aA                 Ab = ab·a^9·A
Bb = bB                 Ba = ba·b^10·B
```

Setting **`lower := upper`** (`a = A`, `b = B`, …) satisfies all four, using the two surviving order
relations:

- `Aa = aA` → `A·A = A·A` ✅
- `Ab = ab a⁹ A` → RHS `= A·B·A⁹·A = A·B·A¹⁰ = A·B` ✅ (since `A¹⁰ = 1`)
- `Bb = bB` → `B·B = B·B` ✅
- `Ba = ba b¹⁰ B` → RHS `= B·A·B¹⁰·B = B·A·B¹¹ = B·A` ✅ (since `B¹¹ = 1`)

The "semidirect" structure evaporates: the diagonal embedding is a valid solution.

### 4.3 Satisfying the structural gates

`is_symmetric_gen` is misleadingly named — it does **not** verify the group is `S₁₁`. It checks only
that the generators act transitively on the 11 points, and that at least one is odd:

```python
has_odd = any(sign_p(g) == -1 for g in gens)
```

Both fall out of the obvious choice:

- **`B` = the 11-cycle `(0 1 2 … 10)`** — order 11, transitive on its own.
- **`A` = the 10-cycle `(0 1 … 9)`** fixing point 10 — order 10, and odd, since a `k`-cycle has sign
  `(-1)^(k-1)` and `(-1)^9 = -1`.

Then `C = AB`, `D = A⁻¹BC`, `E = CD`, and the lowercase set is a copy. Gate 4 is free: `a^k·b ∈ ⟨a⟩`
would force `b ∈ ⟨a⟩`, impossible since `11 ∤ 10`.

### 4.4 The solution is not unique

Because the gates test only the published presentation, many inequivalent groups pass. Our choice
above happens to generate the **whole of `S₁₁`** (order 39,916,800, confirmed by Schreier–Sims), but
the Frobenius group `AGL(1,11) = 11:10` of order **110** passes every gate just as well:

```python
A = tuple((i * 2) % 11 for i in range(11))   # x -> 2x,  a 10-cycle fixing 0 (2 is a primitive root)
B = tuple((i + 1) % 11 for i in range(11))   # x -> x+1, an 11-cycle
```

A group 362,880× smaller than `S₁₁` is accepted, which is the clearest statement of how little the
verifier constrains. This is why the challenge says "equivalent key", not "the key": the secret
conjugators are never pinned down at all.

### 4.5 The payload

```json
{"A":[1,2,3,4,5,6,7,8,9,0,10],"B":[1,2,3,4,5,6,7,8,9,10,0],
 "C":[2,3,4,5,6,7,8,9,10,1,0],"D":[0,3,4,5,6,7,8,9,10,1,2],"E":[4,5,6,7,8,9,10,1,2,3,0],
 "a":[1,2,3,4,5,6,7,8,9,0,10],"b":[1,2,3,4,5,6,7,8,9,10,0],
 "c":[2,3,4,5,6,7,8,9,10,1,0],"d":[0,3,4,5,6,7,8,9,10,1,2],"e":[4,5,6,7,8,9,10,1,2,3,0]}
```

[`solution/verify_key.py`](solution/verify_key.py) imports the server's own checkers and confirms
every gate offline before we ever touch the network:

```console
$ python3 solution/verify_key.py
  [PASS] A^10 == 1
  [PASS] B^11 == 1
  [PASS] upper relations
  [PASS] lower relations
  [PASS] mixed relations
  [PASS] is_symmetric_gen(upper)
  [PASS] is_symmetric_gen(lower)
  [PASS] one-word outside <a>

  |<a>| = 10 (expected 10, the order of the 10-cycle)

ALL CHECKS PASS: True
```

## 5. Break #3 — the speed challenge

Option `[5]` generates 16 fresh words with the *same* encoding and demands classification within
5 seconds — a human-speed barrier, not a cryptographic one. The same `"b" in word` test answers it
instantly.

```python
words = [l0 * rng.randint(1, 9) if b == "0" else l0 * rng.randint(0, 9) + l1 for b in bits]
```

## 6. Execution

```console
$ python3 solution/solve_key.py
[*] payload (291 bytes)
    {"A":[1,2,3,4,5,6,7,8,9,0,10],"B":[1,2,3,4,5,6,7,8,9,10,0], ... }
[+] KEY ACCEPTED! Verification successful.
[+] FLAG: ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}
```

```console
$ python3 solution/solve_leak.py
[*] lower alphabet ['a', 'b', 'c', 'd', 'e'] -> padding='a' marker='b'
[*] 496 words -> 496 bits -> 62 bytes
[*] sample: ['aaaaaaaaa', 'b', 'a', 'a', 'aaaaaaaa', 'aaaaa']
[+] FLAG (offline): ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}
[*] speed challenge -> 1111010111100000
[+] CHALLENGE PASSED!
[+] FLAG: ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}
```

```
ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}
```

## 7. Solution files

| File | Purpose | Network |
|---|---|---|
| [`solution/solve_leak.py`](solution/solve_leak.py) | Decodes the flag from option `[2]`; also passes option `[5]` | yes |
| [`solution/solve_key.py`](solution/solve_key.py) | Builds and submits the equivalent key to option `[4]` | yes |
| [`solution/verify_key.py`](solution/verify_key.py) | Proves the key against the server's own checkers | no |

## 8. Lessons

- **Encoding is not encryption.** The words were never evaluated into the permutation group; the
  group was decoration around a plaintext channel.
- **Never let a verifier accept anything but the secret.** `submit_key` validated a *public*
  presentation, converting key recovery into "solve the published equations" — the flag name says as
  much: `sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK`.
- **Redundant relations are not extra security.** Eight of the ten relations were consequences of the
  other two, so the presentation had a fraction of the constraint it appeared to.
- **Keyspace size is a ceiling, not a floor.** `(11!)² ≈ 1.6 × 10¹⁵` bounds brute force and says
  nothing about structure. The structure cost nothing to solve.
- **Naming can hide a weak check.** `is_symmetric_gen` sounds like "generates `S₁₁`", but it tests
  only transitivity plus one odd generator — conditions that are necessary for `S₁₁` and nowhere near
  sufficient. `AGL(1,11)`, of order 110, satisfies both.
