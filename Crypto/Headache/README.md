# Headache

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Crypto |
| **Difficulty** | Medium |
| **Service** | `nc 65.109.208.91 1337` |
| **Files** | [`challenge/server.py`](challenge/server.py) |
| **Flag** | `ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}` |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/b5e1e800-da8f-41d2-89da-11bb4f721cd6) |

> Headache is a haunted math blender. Crack its secret matrices, forge tags, get flag.

---

## TL;DR

The "Non-Linear Hamiltonian Authenticator" is a **softmax-attention PRF** wearing a physics
costume. Once the `einsum` is unwound, the tag of a sequence `X` (rows `X[i]`, tail
`x_tail = X[-1]`) is

```
T(X) = Σ_c  softmax_i( X[i] · (A[c] · x_tail) )  ·  ( X[i] · B[c] )
```

over `NUM_CHANNELS = 3` channels, with secret `A[c]` (4×4) and `B[c]` (length-4), all entries
`~ U(0.5, 2.0)`, **freshly regenerated every round**. Each of 7 rounds gives up to 1200
`eval` queries; then it hands us 6 random sequences and demands their tags to `1e-6`.

Because the oracle is **exact** (noise-free `float64`), any parameter set that reproduces the
tags on a few hundred generic sequences reproduces `T` *everywhere* — we need a *functional
twin*, not the true secret. We recover one per round by fitting the 60 parameters with
**Levenberg–Marquardt + an exact analytic Jacobian**, restarting from the known `U(0.5,2)`
prior until the residual collapses to `~1e-15`, then compute the challenge tags directly. Two
engineering tricks make it survive the network: **pipelining** the queries and running the LM
restarts **in parallel**.

---

## 1. Protocol

After a 20-bit SHA-256 proof of work, each of 7 rounds accepts:

- `eval <json_matrix>` — returns the float tag of a sequence `X` of shape `(L, 4)`, `1 ≤ L ≤ 20`
  (budget: 1200/round, with a 0.03 s server-side delay each).
- `challenge` — emits 6 random sequences of lengths `[3,5,7,9,13,17]` and immediately expects
  `verify <json_tags>`; if `max|pred − true| < 1e-6` the round passes.

Crucially, we **cannot** `eval` the challenge sequences (the command after `challenge` must be
`verify`), and every round regenerates the secret. So we must recover the map well enough to
evaluate it on arbitrary sequences.

## 2. Unwinding the "Hamiltonian"

The scary core is:

```python
microstate_energies = np.einsum('j,jk,ik->i', x_tail, coupling_tensors[c].T, X)
gauge_shift = np.max(microstate_energies)
boltzmann_weights = np.exp(microstate_energies - gauge_shift)
partition_fn = np.sum(boltzmann_weights)
observables = np.dot(X, observable_vectors[c])
ensemble_expectation = np.dot(boltzmann_weights, observables) / partition_fn
```

Expand the einsum (`A[c].T[j,k] = A[c][k,j]`):

```
energies[i] = Σ_{j,k} x_tail[j] · A[c][k,j] · X[i,k]
            = Σ_k X[i,k] · (Σ_j A[c][k,j] · x_tail[j])
            = X[i] · (A[c] @ x_tail)
```

The `gauge_shift = max` is just the standard numerically-stable softmax shift; it cancels in
the ratio. `boltzmann_weights / partition_fn` **is** `softmax(energies)`, and
`observables[i] = X[i] · B[c]`. So per channel the "ensemble expectation" is a
softmax-weighted average of linear observables, and the returned `total_energy` is:

```
T(X) = Σ_c  softmax_i( X[i] · (A[c] · x_tail) )  ·  ( X[i] · B[c] )
```

A three-headed **attention** layer: `A[c]` forms the query/key bilinear score against the last
token, `B[c]` is the value projection.

### What leaks trivially, and why it isn't enough

With `L = 1`, the softmax over a single element is `1` regardless of `A`, so
`T([v]) = Σ_c (v · B[c]) = v · (Σ_c B[c])`. Four such queries recover `S = Σ_c B[c]` — but the
challenge sequences (length ≥ 3) exercise the full nonlinear, per-channel behaviour, so we need
every `A[c]` and `B[c]` (or a functional equivalent).

## 3. Recovery as an exact nonlinear fit

We treat one round as system identification of a known functional form with **60 unknowns**
(`3·16` for `A`, `3·4` for `B`).

**Key observations that make it easy:**

1. **Noise-free ⇒ functional equivalence suffices.** The oracle returns exact `float64`. If a
   candidate `(A′, B′)` matches the tags on ~150 generic sequences (≫ 60 parameters, analytic
   model), it matches `T` everywhere. We never need the *true* secret — channel permutations and
   other internal symmetries are harmless because prediction only depends on `T`.
2. **`B` is linear given `A`.** The softmax weights `w_c = softmax(X·(A[c]·x_tail))` depend only
   on `A`, and `T = Σ_c (w_c · X) · B[c]`. So `B`'s Jacobian block is just `w_c · X` — trivial —
   and the fit is well conditioned.
3. **Analytic Jacobian.** With `o_c = X·B[c]`, `val_c = w_c · o_c`:
   - `∂T/∂B[c] = w_c · X`
   - `∂T/∂A[c] = outer( Xᵀ · (w_c ⊙ (o_c − val_c)), x_tail )`

   (the softmax derivative `∂w_m/∂e_n = w_m(δ_{mn} − w_n)` collapses neatly).

**The fit.** Levenberg–Marquardt over all 60 parameters with the analytic Jacobian, vectorised
across all queries (sequences padded to a common length with a `−∞` energy mask). The landscape
is cleanly **bimodal**: a restart either lands in the true basin (`rmse ~ 1e-15`) or an
obviously-wrong one (`rmse > 1e-3`), so success is unambiguous. We restart from the known
`U(0.5,2)` prior until `rmse < 1e-7`. Around 150 queries suffice; challenge predictions then
land at `~1e-15`, comfortably under the `1e-6` tolerance.

## 4. Making it survive the network

Two problems appear only against the live service:

- **Per-connection time limit (~120 s).** The first attempt died at round 4: 150–200 *synchronous*
  `eval` round-trips at ~0.18 s each is ~30 s/round, and three rounds exhausted the budget. Fix:
  **pipeline** — write all `eval` lines, flush, then read all responses. The query phase collapses
  to roughly the server-side delay (`150 × 0.03 ≈ 4.5 s`) plus one RTT.
- **Unlucky fits.** Some rounds need many restarts (one local round took 83 s). Fix: run the LM
  restarts **in parallel** across CPU cores (`multiprocessing`), stopping at the first
  `rmse < 1e-7`. Worst-case fit drops to ~10 s.

Everything else is routine: a brute-force loop for the 20-bit PoW, and JSON line framing.

## 5. Execution

```console
$ python3 solution/solve.py 65.109.208.91 1337
[*] solving PoW 20 bits
[*] PoW ok
[*] round 1: fit rmse=1.09e-15 (5.2s)
[*] round 1 -> ok: Round 1 authenticated! (max_err=8.88e-16)
[*] round 2: fit rmse=1.44e-15 (12.7s)
...
[*] round 7: fit rmse=1.35e-15 (10.9s)
[*] round 7 -> ok: All rounds authenticated! (max_err=2.22e-15)

[+] FLAG: ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}
```

All 7 rounds authenticated with per-round `max_err ≈ 1e-15`, ~9 orders of magnitude inside the
`1e-6` tolerance. Total wall time ≈ 70 s.

```
ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}
```

## 6. Solution files

| File | Purpose |
|---|---|
| [`solution/solve.py`](solution/solve.py) | End-to-end: PoW, pipelined `eval`, parallel LM fit (analytic Jacobian), forge & verify. Self-contained (`numpy` + `scipy`). Run `solve.py LOCAL` to drive a local `server.py` for testing. |
| [`challenge/server.py`](challenge/server.py) | The original oracle. |

Local validation: dropping a dummy `flag.py` beside `server.py` and running `solve.py LOCAL`
authenticates all 7 rounds end-to-end (PoW → fit → forge).

## 7. Lessons

- **Vocabulary is not security.** "Hamiltonian coupling tensors", "partition function",
  "gauge stabilization" — the whole thing is a 3-head softmax-attention layer. Always unwind the
  `einsum`.
- **A deterministic, noise-free oracle is a gift.** Exactness turns key recovery into curve
  fitting, and reduces the goal from "find the secret" to "find any functional twin", which
  sidesteps every internal symmetry.
- **Exploit linear substructure.** `B` linear given `A` cuts the hard nonlinearity in half and
  makes the Jacobian (and the fit) trivial to condition.
- **Interactive constraints are part of the crypto.** The real difficulty was budget management —
  pipelining and parallel restarts to fit seven independent 60-parameter systems inside one
  time-limited connection.
