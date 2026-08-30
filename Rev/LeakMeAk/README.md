# LeakMeAk

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Rev |
| **Difficulty** | Medium |
| **Service** | `nc 65.109.208.91 3117` |
| **Files** | [`challenge/leakmeak.elf`](challenge/leakmeak.elf) |
| **Solver** | [`solution/solve.py`](solution/solve.py) |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/faf2d0a7-dba4-4fa8-8fb8-2449692e2fca) |
| **Flag** | `ASIS{haaducrcplmekhylrozcxyxzuizs}` |

> In LeakMeAk, even the flag has trust issues.

---

## TL;DR

A stripped PIE flag-checker runs the 28 inner bytes of `ASIS{…}` through a bespoke,
non-injective hash and accepts only if a pile of conditions hold at once: an error
accumulator stays zero, seven cyclic equations on internal dwords, a poly-33 hash and its
remix, and two low-bit state checks. The hash is deliberately lossy — many inputs collide to
the same internal state ("trust issues") — but the extra state-machine constraints tighten it
back to a single printable answer.

z3 recovers the seven internal dwords uniquely; a Unicorn emulation of the check acts as an
oracle to invert each 4-byte group (`H = word·0x9e3779b9 XOR mix`, so
`word = (H ^ mix)·inv`); a tiny DFS over the few candidates per position keeps the one string
the checker actually grants.

```
ASIS{haaducrcplmekhylrozcxyxzuizs}
```

## 1. Recon

```console
$ file leakmeak.elf
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
$ strings leakmeak.elf | grep -Ei 'flag|access|asis|%127'
Enter Flag:
Access Denied!
ASIS{
Access Granted! Correct Flag.
%127s
ZZZZ<<<<
```

`main` reads `%127s` into a stack buffer, then verifies. Three cheap gates come first:

```asm
call strlen ; cmp rax, 0x22 ; jne DENIED     ; length must be 34
lea rsi,[ASIS{] ; mov edx,5 ; call strncmp   ; prefix "ASIS{"
cmp byte [rsp+0x81], 0x7d ; jne DENIED        ; suffix '}'
```

So the flag is `ASIS{` + **28 inner bytes** + `}`. Those 28 bytes are gathered onto the stack
and fed to the real check.

## 2. The internal hash

The core is one heavily obfuscated function. Working through it, the 28 bytes are consumed
**four at a time** as a big-endian word and folded into seven 32-bit dwords:

```
H[i] = (word_i * 0x9e3779b9) XOR mix_i          word_i = big-endian of bytes[4i..4i+3]
```

`0x9e3779b9` is the golden-ratio constant, and `mix_i` is produced by a per-byte **state
machine** — character-class counters, `> 'Y'` comparisons (`cmp r10b, 0x59`), and two small
stack arrays. Empirically `H = word·const ^ mix` holds exactly, and for a fixed prefix `mix_i`
depends only on the current four bytes (through low-bit masks and those comparisons), so it is
low-entropy.

## 3. The acceptance conditions

The function never early-exits; it accumulates an error mask in `ecx` and, at the end, checks
everything together:

* **`ecx == 0`** — the byte-processing state machine must never `or` an error bit
  (`0x1 / 0x2 / 0x4 / 0x10`) during the loop.
* **Seven cyclic equations** on the dwords, against two rodata tables
  (`tableA @0x204c`, `tableB @0x206c`):

  ```
  (ror(H[i % 7], 13) + H[i-1]) ^ tableB[i] == tableA[i]        for i = 1..7
  ```

* **A poly-33 hash** of the seven dwords equals `0xddaacf25`:
  `edx = 0; for h in H: edx = edx*33 ^ h`.
* **Its 64-round remix** equals `0x376a3d36` — deterministic in the poly result, hence a
  redundant check.
* **Two low-bit checks** on an internal state array `s30`: `s30[0] & 3 == 1` and
  `s30[1] & 3 == 2`.

Only when all of these pass does it print `Access Granted! Correct Flag.`

## 4. "Trust issues": the hash is not injective

`H[i] = word_i · const ^ mix_i` maps four bytes to a dword, but different `(word, mix)` pairs
collide to the same `H`. Given a target `H[i]`, each candidate value of `mix_i` yields one
`word_i = (H[i] ^ mix_i) · inv(const)`, so a single dword has several printable preimages —
this is the leak the title winks at. What restores uniqueness is the rest: the `ecx` state
machine and the `s30` checks couple the four-byte groups together, so only one full 28-byte
string satisfies *everything*.

## 5. Stage 1 — the internal dwords, with z3

The seven cyclic equations are seven constraints on seven 32-bit unknowns. Feeding them to z3
(with `C[i] = tableA[i] ^ tableB[i]`), plus the poly-33 target as a consistency check, gives a
**unique** solution:

```python
for i in 1..7:  ror(H[i % 7], 13) + H[i-1] == C[i]
edx = 0; for h in H: edx = edx*33 ^ h;  edx == 0xddaacf25
```

```
H = [0x0cf6a545, 0x89397a88, 0x54c2caf9, 0xab02cb0c,
     0xcda7368c, 0xb2fab02b, 0xf6c4d21a]
```

## 6. Stage 2 — a Unicorn oracle for the mix

Rather than fully reverse the tangled `mix` state machine by hand, [`solve.py`](solution/solve.py)
emulates the check function with **Unicorn**. Entering just past the length/prefix checks
(`0x115e`) with the flag written to the stack buffer, it hooks the dword store
(`mov [rsp+4*rbp+0x10], edx` at `0x13c2`) to read `(H_i, mix_i, ecx_i)` on every iteration, and
hooks the two `puts` sites (`0x147e` granted / `0x14bb` denied) for the verdict. The emulation is
cycle-accurate against the real binary (~0.16 ms per run) and confirms `H = word·const ^ mix`.

## 7. Stage 3 — invert and DFS

For each 4-byte group `i`, given the target `H[i]`:

* the oracle samples the small set of `mix_i` values reachable for the current prefix;
* each `mix` inverts to `word_i = (H[i] ^ mix) · inv(0x9e3779b9)`, and the printable ones whose
  emulated `H` matches with a clean `ecx` are the candidates.

A DFS over these (typically one or two per position) keeps only the completed string the
checker **grants**. The cross-position `ecx`/`s30` constraints eliminate every collision but
one:

```console
$ python3 solution/solve.py
[+] internal dwords H = ['0xcf6a545', '0x89397a88', ...]
[i=0]                           '' + 'haad'
[i=1]                       'haad' + 'ucrc'
 ...
[+] 1 string(s) accepted by the checker
[+] flag: ASIS{haaducrcplmekhylrozcxyxzuizs}
```

## 8. Flag

```
ASIS{haaducrcplmekhylrozcxyxzuizs}
```

Confirmed against the live service — `Access Granted! Correct Flag.`, and any single-byte
change gives `Access Denied!`. The flag reads as random rather than as leetspeak; that is a
property of the challenge (a lossy checker with exactly one printable fixed point), not a
missed decode — the exhaustive search finds this and only this.

## 9. Takeaways

* **A checker that accumulates errors and compares once has no timing oracle** — you cannot peel
  it character by character. The way in is to model the whole predicate, and z3 plus an
  emulator do that without hand-reversing every branch.
* **Emulate the parts that resist static reading.** The `mix` state machine is genuinely
  awkward; instead of transcribing it, Unicorn *is* the ground truth, and one hook on the dword
  store turns it into an exact oracle.
* **A lossy hash plus side constraints can still be unique.** Non-injectivity gives collisions
  per dword, but the state-machine and low-bit checks couple the groups; enumerating the small
  candidate tree and asking the checker for the verdict collapses it to one answer.
* **Trust the search, then trust the target.** The flag looks like noise, which invites
  second-guessing — but the enumeration is exhaustive and the live remote confirms it, so the
  odd-looking string is the intended one.

## Reproducing

```console
$ python3 solution/solve.py                 # or: solution/solve.py path/to/leakmeak.elf
```

Needs Python 3 with `z3-solver` and `unicorn`. No network access is required; the local ELF is
the oracle.
