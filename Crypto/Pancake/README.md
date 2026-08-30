# Pancake Stack

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Crypto |
| **Difficulty** | Medium |
| **Files** | [`challenge/pancake.py`](challenge/pancake.py), [`challenge/challenge.json`](challenge/challenge.json) |
| **Flag** | `ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}` |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/5cf42c9d-0835-43e6-b754-7973d443df7b) |

> 🥞 "Chef Crypto served a batch of extra-fluffy key derivation layers, claiming they are
> mathematically unbreakable. But rumors say something went wrong during the baking process..."
> A state-of-the-art cipher suite is leaking keystreams under mysterious circumstances.

---

## TL;DR

The "fluffy KDF" boils down to **AES-GCM keystream reuse**, opened with two bugs:

1. **32-bit seed leak.** The AES-256 master key is `k1 = SHA256("K1-SEED" ‖ be32(seed))` with a
   random **32-bit** `seed`, and the challenge *publishes* `hint = SHA256("K1-SEED-HINT" ‖ be32(seed))`.
   Brute-forcing 2³² seeds recovers `seed` (`0x22c4d3ef`), hence `k1`.
2. **Truncated-collision KDF ⇒ identical keystreams.** The derived GCM `(key, iv)` depend only on
   `n1` and `j = upper96(AES_k1(n2 ‖ 0))` (the low 32 bits are dropped). Generation deliberately
   finds `alt ≠ n2` with `upper96(AES_k1(alt‖0)) = upper96(AES_k1(n2‖0))` and encrypts a known
   **all-zero** message under `(n1, alt)`, storing that ciphertext in the sealed ticket `z`. Because
   `j` collides, the flag `(n1, n2)` and the sample `(n1, alt)` share the exact same GCM key+IV — and
   GCM is CTR, so they share one **keystream**. The sample's plaintext is zeros, so its ciphertext
   *is* the keystream:

```
flag = flag_ciphertext  XOR  sample_ciphertext
```

We never need `k2`.

---

## 1. The construction

`challenge.json` publishes: `d=32` (dropped bits), `a` (the hint), `n = [n1, n2]`,
`h` (associated data), `m` (the 128-byte all-zero known plaintext), `y` (the flag AEAD blob), and
`z` (a "sealed ticket"). The relevant machinery in [`pancake.py`](challenge/pancake.py):

```python
BLOCK_SIZE_BITS = 128; DEFAULT_DROP = 32
NONCE_BITS = 96; NONCE_MASK = (1<<96)-1; DROP_MASK = (1<<32)-1
KNOWN_PLAINTEXT = bytes(128)                       # 128 zero bytes

def seed_to_k1(seed):   return sha256(b"K1-SEED"      + seed.to_bytes(4,"big")).digest()
def seed_to_hint(seed): return sha256(b"K1-SEED-HINT" + seed.to_bytes(4,"big")).hexdigest()

def format_block(x, sep=0): return (((x & NONCE_MASK)<<DROP) | (sep & DROP_MASK)).to_bytes(16,"big")
def extract_upper(x):       return int.from_bytes(x,"big") >> DROP        # top 96 bits

def diffuse_state(k, n1, n2):
    e = AES.new(k, AES.MODE_ECB)
    j  = extract_upper(e.encrypt(format_block(n2, 0)))
    w1 = n1 ^ j
    w2 = n1 ^ gf_double(j)
    r1 = extract_upper(e.encrypt(format_block(w1, 0x18)))
    r2 = extract_upper(e.encrypt(format_block(w2, 0x28)))
    return j, w1, w2, r1, r2

def derive_keys(k2, n1, state):                    # ek (GCM key), iv, ck (AD prefix)
    z = shake_256(b"KDF-STATE-v1" + k2 + n1 + j + w1 + w2 + r1 + r2).digest(80)
    return z[:16], z[16:28], z[28:44]
```

The flag blob is `y = AES-GCM(ek, iv).encrypt(flag)`, with `(ek, iv)` from
`derive_keys(k2, n1, diffuse_state(k1, n1, n2))`.

## 2. Bug #1 — the 32-bit seed is leaked by the hint

`k1` is a full AES-256 key, but it is generated from only a **32-bit** `seed`, and the public
`hint = SHA256("K1-SEED-HINT" ‖ be32(seed))` is a direct oracle for it. Two-line break: iterate
`seed ∈ [0, 2³²)`, hash, compare. A small threaded C program ([`solution/seedbrute.c`](solution/seedbrute.c))
finds it in seconds:

```
seed = 0x22c4d3ef      ->      k1 = SHA256("K1-SEED" ‖ 22c4d3ef)
```

## 3. Bug #2 — the truncated collision forces one keystream for two messages

`find_collision(k1, n2)` searches for `alt` such that, with `target = upper96(AES_k1(n2‖0))`:

```python
base_int = target << 32
for sep in range(1 << 32):
    x = AES_k1.decrypt((base_int | sep))           # 128-bit block
    if (x & DROP_MASK) == 0:                        # low 32 bits zero  => x = y<<32
        y = x >> 32
        if y != n2: return y                        # a *different* nonce with the same top-96 output
```

That is a collision in the **32-bit-truncated** AES permutation among inputs of the form `y‖0`.
Generation then produces:

```python
sample = encrypt_authenticated(k1, k2, n1, alt, ad, KNOWN_PLAINTEXT)   # (n1, alt), zeros
y      = encrypt_authenticated(k1, k2, n1, n2,  ad, flag)               # (n1, n2),  flag
z      = seal_sample(k1, n1, alt, {"n":[n1, alt], "x": sample})         # ticket holds the sample
```

Now trace `diffuse_state` for the two:

| quantity | flag `(n1, n2)` | sample `(n1, alt)` |
|---|---|---|
| `j` | `upper96(AES_k1(n2‖0))` | `upper96(AES_k1(alt‖0))` **= same** (that's what `alt` guarantees) |
| `w1 = n1 ^ j` | same | same |
| `w2 = n1 ^ gf_double(j)` | same | same |
| `r1, r2` | same (depend on `w1, w2`) | same |

The **entire diffused state is identical**, and `n1` is identical, so
`derive_keys(k2, n1, state)` returns the **same `(ek, iv, ck)`** for both — regardless of the secret
`k2`. AES-GCM is CTR mode, so identical `(key, nonce)` ⇒ **identical keystream**. The sample
encrypts zeros, hence `sample.ciphertext = keystream`, and:

```
flag = y.ciphertext  XOR  keystream[:len(flag)]
```

## 4. Getting the keystream — decrypting the sealed ticket

The sample ciphertext lives only inside `z`, which is itself AES-GCM:

```python
key   = sha256(b"SEALED-TICKET-KEY" + k1 + n1 + alt).digest()[:16]
nonce = sha256(b"SEALED-TICKET-IV"  + key).digest()[:12]
```

We know `k1` and `n1`; we recompute `alt` with the same 2³² scan
([`solution/collide.c`](solution/collide.c) — the challenge's own search, extended to print every
collision so we can try each and let the GCM tag select the right one). With `alt` in hand the ticket
decrypts (tag verifies), yielding `record["x"]["c"]` = the reused keystream.

For this instance:

```
alt = 0xa5720dc7719f529e8e9cb565      (record n = [n1, alt], confirming the reuse)
```

## 5. Execution

```console
$ python3 solution/solve.py
[*] brute-forcing 32-bit seed against hint ...
[+] seed = 0x22c4d3ef  ->  k1 recovered
[*] scanning 2^32 for truncated collision ...
[+] alt candidate(s): ['0xa5720dc7719f529e8e9cb565']
[+] ticket decrypted with alt = 0xa5720dc7719f529e8e9cb565

[+] FLAG: ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```

```
ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```

The break was validated end-to-end against a locally regenerated instance (dummy flag recovered
exactly) before running it on the real `challenge.json`.

## 6. Solution files

| File | Purpose |
|---|---|
| [`solution/solve.py`](solution/solve.py) | End-to-end: compiles the helpers, brutes the seed, recomputes the collision, decrypts the ticket, XORs out the flag (needs a C compiler + `pycryptodome`). |
| [`solution/seedbrute.c`](solution/seedbrute.c) | Threaded 2³² seed brute-force (CommonCrypto / OpenSSL). |
| [`solution/collide.c`](solution/collide.c) | Threaded 2³² truncated-collision scan (CommonCrypto / OpenSSL). |

## 7. Lessons

- **A 256-bit key seeded from 32 bits has 32 bits of security** — and publishing *any* deterministic
  function of the seed (the "hint") hands it over outright.
- **Truncating a PRP creates collisions by design.** Dropping 32 bits turns AES into a 96→96 map with
  frequent collisions; here a collision makes two distinct nonces derive the *same* GCM key+IV.
- **Nonce/keystream reuse is fatal for GCM (and any CTR mode).** One of the two colliding messages was
  a known all-zero plaintext, so its ciphertext is the raw keystream — XOR reveals the other.
- **A KDF that ignores its own fresh randomness isn't fresh.** `derive_keys` mixes in `k2`, but since
  every other input collided, the secret `k2` bought no protection at all.
