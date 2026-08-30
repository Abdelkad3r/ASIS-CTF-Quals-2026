# ASIS Arch

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Rev |
| **Difficulty** | Medium |
| **Files** | [`challenge/qemu-asisarch`](challenge/qemu-asisarch), [`challenge/challenge.rom`](challenge/challenge.rom) |
| **Solver** | [`solution/solve.py`](solution/solve.py) |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/50975571-18fd-4559-b0ff-9d3d52c457f6) |
| **Flag** | `ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}` |

> We recovered a custom CPU emulator binary and a secure ROM image. The architecture does
> not appear in any public manual. Recover the ISA, reverse the verification logic, and
> find the correct flag from new ASIS Arch.
>
> ```
> chmod +x qemu-asisarch
> ./qemu-asisarch -M asisboard -kernel challenge.rom -nographic
> ```

---

## TL;DR

`qemu-asisarch` is not QEMU. It is a 2.5 KB custom VM with a 16-bit, 8-register
architecture whose instructions are **encrypted with a keystream derived from the address
they sit at** — the same four bytes decode differently at every PC, which defeats linear
disassembly and is the whole point of the challenge.

Recovering the ISA gives a 26-opcode machine. The ROM reads 44 bytes, folds them through
ten rounds of substitution and diffusion, and compares the result against constants baked
into the image. The transform is branch-free and every step is invertible, so the flag
falls out by running the transform backwards — no brute force, no SMT solver.

```
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```

## 1. Recon — the emulator is not QEMU

```console
$ file qemu-asisarch
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
$ ls -l qemu-asisarch challenge.rom
-rwxr-xr-x  14656 qemu-asisarch
-rw-r--r--  32171 challenge.rom
```

Real QEMU is measured in megabytes. Section sizes say what this actually is:

| Section | Size | What it is |
|---|---|---|
| `.text` | `0x9f5` (2549 B) | the entire CPU |
| `.rodata` | `0x260` | decode tables + strings |
| `.data.rel.ro` | `0x800` | **256 × 8** — an opcode dispatch table |

A 2 KB table of function pointers indexed by a byte is the shape of an interpreter
dispatch. The imports agree: no threading, no JIT, just `fopen`/`fread`/`getc`/`putc`.
Strings confirm the model — `illegal instruction`, `PC out of bounds`,
`guest cycle limit exceeded`, `ROM checksum mismatch`.

The binary is Linux/x86-64, so on any other host it runs under Docker:

```console
$ echo 'ASIS{aaaa}' | docker run --rm -i --platform linux/amd64 -v "$PWD":/w -w /w \
    debian:12-slim ./qemu-asisarch -M asisboard -kernel challenge.rom -nographic
=== ASISARCH Secure Enclave v2.0 ===
Enter flag:
[-] Access Denied. Invalid flag.
```

An interactive flag checker. Everything interesting is in the ROM.

## 2. The ROM container

The loader validates a 32-byte header before copying the body to guest address 0:

```
+0x00  "AARQ"            magic
+0x04  02                version, must be 2
+0x08  byte lo           entry PC, low  half (scrambled)
+0x09  byte hi           entry PC, high half (scrambled)
+0x0c  uint32            checksum over the body
+0x20  image             body, at most 0x10000 bytes
```

The checksum is a 16-bit rolling XOR, seeded with `0x31415926`:

```python
d = 0x31415926
for c in image:
    d = rol16(d & 0xffff, 3) ^ c ^ (d >> 16) ^ 0x9e37
```

The seed's high half only contributes on the first byte, after which the state is
16 bits wide. Worth reimplementing anyway — without it you cannot rebuild a patched ROM.

The entry PC is *not* stored directly. It is built by swapping the nibbles of each header
byte and rotating the assembled word:

```python
entry = rol16((rol8(hdr[9], 4) << 8) | rol8(hdr[8], 4), 5)   # = 0x0000 here
```

This same scramble decodes every instruction immediate — it is what the flag calls
*middle-endian nibbles*.

## 3. Machine state

The whole machine is one flat allocation, which makes the layout easy to read off the
offsets used in `.text`:

```
0x00000 .. 0x0ffff   RAM, 64 KiB
0x10000 .. 0x1000f   r0 .. r7, 16-bit each
0x10010              SP, initialised to 0xfff0
0x10012              PC
0x10018              cycle counter, aborts above 10_000_000
```

Registers are 16-bit, memory is byte-addressed and little-endian, and there are no flags —
conditional control flow tests a register directly.

## 4. The fetch stage — instructions are encrypted with their own address

This is the core of the challenge. Every instruction is four bytes, but before decoding,
the fetch stage derives a per-address keystream:

```python
raw = ((PC ^ 0x9e37) * 0x1039 + 0x79b9) & 0xffff
sel = (raw >> 14) & 3          # picks one of four byte permutations
k   = rol16(raw, 5)            # keystream word
```

`sel` indexes a 4 × 4 table in `.rodata` that permutes which of the four fetched bytes
plays which role:

```
sel 0: [0, 1, 2, 3]      sel 2: [3, 2, 1, 0]
sel 1: [2, 0, 3, 1]      sel 3: [1, 3, 0, 2]
```

The permuted bytes `b0..b3` are then unmasked with the keystream:

```python
op  = rol8((0x5d * PC ^ k ^ b2) & 0xff, (k >> 5) & 7) ^ 0x6d

x   = (7 * PC ^ (k >> 2) ^ b0) & 0xff
rd  = ((5 * (((5 * x) ^ 3) & 7)) ^ 3) & 7          # destination register

imm = rol16((rol8((b3 ^ (k >> 8)) & 0xff, 4) << 8)
            | rol8((b1 ^ k) & 0xff, 4), 5)          # 16-bit immediate
```

Three consequences, all deliberate:

* **The same bytes decode differently at different addresses.** A linear sweep from any
  offset produces plausible-looking but wrong instructions, and never resynchronises.
* **The ROM cannot be relocated.** Code is welded to the address it was assembled for.
* **Register numbers are permuted twice** by `x -> ((5x) ^ 3) & 7`, so the register field
  is not readable even after the keystream is removed.

The second register operand of ALU and memory instructions is not in the instruction byte
at all — it is packed into the low three bits of the immediate, through the same
permutation, with the remaining 13 bits used as an address displacement:

```python
rs   = ((5 * (imm & 7)) ^ 3) & 7
disp = imm >> 3
```

## 5. Recovering the opcode map without guessing

`.data.rel.ro` holds the 256-entry dispatch table, but in a PIE it is zero-filled on disk
and populated at load time by `R_X86_64_RELATIVE` relocations. Reading the relocation
table gives the mapping directly — 26 live opcodes, 230 null entries that trap as
*illegal instruction*. [`solution/isa.py`](solution/isa.py) does this, along with pulling
the S-box and permutation tables out of `.rodata`, so nothing about the ISA is hardcoded
except the names given to the 26 handler addresses:

```console
$ python3 solution/isa.py
26 live opcodes:
   16  0x10  nop        99  0x63  ldb       161  0xa1  call
   21  0x15  li        105  0x69  stb       167  0xa7  ret
   33  0x21  addi      113  0x71  ldw       179  0xb3  in
   ...
```

## 6. The instruction set

Reading the 26 handlers gives the architecture in full. Two are worth calling out.
Arithmetic is written with the carry-free identity `x + y == (x ^ y) + 2*(x & y)`, so `add`
compiles to that form and `sub` to `(a ^ ~b) + 2*(a & ~b) + 1` — neither looks like an
addition at a glance. And `sbox` is a substitution instruction with no equivalent on any
real CPU, which is the first hint that the ROM is doing block-cipher work.

| Op | Mnemonic | Semantics |
|---|---|---|
| `0x10` | `nop` | — |
| `0x15` | `li rd, imm` | `rd = imm` |
| `0x21` | `addi rd, imm` | `rd += imm` |
| `0x27` | `subi rd, imm` | `rd -= imm` |
| `0x32` | `xori rd, imm` | `rd ^= imm` |
| `0x38` | `andi rd, imm` | `rd &= imm` |
| `0x44` | `roli rd, imm` | `rd = rol16(rd, imm & 15)` |
| `0x4b` | `mov rd, rs` | `rd = rs` |
| `0x50` | `add rd, rs` | `rd += rs` |
| `0x56` | `sub rd, rs` | `rd -= rs` |
| `0x5c` | `xor rd, rs` | `rd ^= rs` |
| `0x63` | `ldb rd, [rs+disp]` | zero-extending byte load |
| `0x69` | `stb [rs+disp], rd` | byte store |
| `0x71` | `ldw rd, [rs+disp]` | 16-bit little-endian load |
| `0x77` | `stw [rs+disp], rd` | 16-bit little-endian store |
| `0x80` | `jmp imm` | `PC = imm` |
| `0x86` | `jz rd, imm` | jump if `rd == 0` |
| `0x8c` | `jnz rd, imm` | jump if `rd != 0` |
| `0x92` | `push rd` | `SP -= 2`, store word |
| `0x98` | `pop rd` | load word, `SP += 2` |
| `0xa1` | `call imm` | push `PC+4`, `PC = imm` |
| `0xa7` | `ret` | pop into `PC` |
| `0xb3` | `in rd` | `rd = getc(stdin)`, EOF reads as 0 |
| `0xb9` | `out rd` | `putc(rd & 0xff)` |
| `0xc2` | `sbox rd` | `rd = (S[rd >> 8] << 8) | S[rd & 0xff]` |
| `0xfe` | `halt` | stop |

## 7. Building an emulator, and proving it right

[`solution/asisarch.py`](solution/asisarch.py) reimplements the machine in ~200 lines. The
validation that matters is not "it produces output" but that it agrees with the original
on both paths, including the cycle count:

```console
$ echo 'ASIS{aaaaaaaa}' | python3 solution/asisarch.py
=== ASISARCH Secure Enclave v2.0 ===
Enter flag:
[-] Access Denied. Invalid flag.
[614 cycles]
```

Byte-identical to the reference binary. With a trustworthy decoder in hand, the ROM can be
disassembled.

## 8. Disassembling the ROM

Linear sweep is useless here, so [`solution/disasm.py`](solution/disasm.py) is a
recursive-descent disassembler: start at the header's entry PC, follow `jmp`/`jz`/`jnz`/
`call`, stop at `ret`/`halt`.

```console
$ python3 solution/disasm.py > rom.asm
; entry 0x0000, image 0x7d8b bytes
; 7960 instructions reached
```

7960 instructions covering essentially the whole image — nothing is hidden behind
computed jumps. The entry point reads clearly:

```
0000:  li r6, 0x7c60      ; banner
0004:  call 0x7c04        ; puts
0008:  li r6, 0x7c86      ; "Enter flag: "
000c:  call 0x7c04
0010:  li r6, 0xc000      ; input buffer
0014:  call 0x7c1c        ; readline -> length in r3
0018:  li r1, 0x002c
001c:  sub r1, r3
0020:  jnz r1, 0x7bf8     ; length != 44 -> reject
```

**The flag is exactly 44 bytes**, buffered at `0xc000` — 22 16-bit words.

## 9. The verification routine

Between the length check and the comparison sits one enormous basic block: `0x0024` to
`0x7873`, fully unrolled, with no branches at all. The instruction histogram is entirely
data movement and arithmetic — `li`, `xor`, `ldw`, `roli`, `mov`, `stw`, `add`, `sbox`.

Lifting it (section 10) shows exactly **660 stores to the buffer, in three repeating
shapes, 220 each — ten rounds of three passes over 22 words**:

| Pass | Operation |
|---|---|
| **Substitute** | `w[i] = S16(w[i]) ^ K[round][i]`, with 220 distinct constants |
| **Diffuse forward** | `w[i] = w[i] + w[i-1 mod 22] + 0x5a5a`, chained low to high |
| **Diffuse backward** | `w[i] ^= σ(w[i+1]) ^ rol(σ(w[i+2]), r)`, `σ(x) = x ^ rol(x,5) ^ rol(x,11)` |

The forward pass propagates changes upward through the buffer, the backward pass
propagates them downward, and the rotation amount `r` in the third pass increases each
round. After two rounds every output word depends on every input byte, so guessing the
flag piecewise is hopeless.

Then the comparison, `0x7874`–`0x7be7`, repeated 22 times:

```
li r6, 0xc022        ; a transformed word
ldw r3, [r6+0x0]
li r1, 0x7cdb        ; constant table
addi r1, 0x0058      ; ... at a shuffled offset
ldw r4, [r1+0x0]
addi r1, 0x0002
ldw r7, [r1+0x0]
xor r4, r7           ; expected = tbl[off] ^ tbl[off+2]
xor r3, r4
add r5, r3           ; accumulate the difference
...
jnz r5, 0x7bf8       ; any mismatch -> reject
```

The expected words are never stored in the clear: each is the XOR of two entries of a
176-byte table at `0x7cdb`, read at offsets that hop around the table. Differences are
accumulated into `r5` rather than compared individually, so there is no early exit to time
and no per-word oracle to attack.

## 10. Inverting the transform

The winning observation is that **the transform contains no branches**, so the sequence of
buffer updates is identical no matter what the input is. That makes it possible to lift it
once, symbolically, into a list of elementary steps.

[`solution/solve.py`](solution/solve.py) walks the block a single time, tracking a symbolic
expression per register instead of a value. Buffer loads produce the symbol `B[i]`, and
each `stw` emits a step and resets that symbol — so every step is expressed against the
*current* buffer contents rather than the original input:

```python
elif name == "ldw":
    sym[rd] = ("B", (a - BUF) // 2) if in_buffer(a) else ("C", word_at(a))
elif name == "stw":
    steps.append(((a - BUF) // 2, sym[rd]))
```

The result is 660 steps of the form `buf[i] <- f(buf[i], other words, constants)` with `f`
built only from `xor`, `add`, `rol` and `sbox`. Two properties make them trivially
invertible:

* every step mentions its own target **exactly once** (asserted by the solver), so the
  occurrence can be isolated by peeling operations from the outside in;
* the other words a step reads are not modified by that step, so when replaying backwards
  their post-values are also their pre-values.

Inverting is then mechanical — undo `xor` with `xor`, `add` with subtraction, `rol` with
`ror`, `sbox` with the inverse permutation:

```python
for i, e in reversed(steps):
    state[i] = invert(e, i, state[i], state)
```

Starting from the 22 expected words and running the steps backwards recovers the input
directly. No brute force, no SMT solver, and the search space never enters into it.

```console
$ python3 solution/solve.py
[+] lifted 660 elementary buffer updates
[+] expected words: 544c 15a0 eb44 09d6 b6ab 496e fd0a 3806 f1df 0913 ffd8 8549 debb 5400 261a 5185 a205 a0b8 be18 efff b9b9 e889
[+] flag: ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
[+] emulator says: ACCEPTED (8906 cycles)
```

## 11. Flag

Confirmed against the original binary, not just the reimplementation:

```console
$ echo 'ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}' | docker run --rm -i \
    --platform linux/amd64 -v "$PWD":/w -w /w debian:12-slim \
    ./qemu-asisarch -M asisboard -kernel challenge.rom -nographic
=== ASISARCH Secure Enclave v2.0 ===
Enter flag:
[+] Access Granted! Flag verified.
```

```
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```

The flag describes its own encoding: the middle-endian nibble scramble on every immediate
is exactly what makes the ROM undisassemblable until the fetch stage is understood.

## 12. Takeaways

* **Size is the first tell.** A 2.5 KB `.text` with a 2 KB pointer table in `.data.rel.ro`
  is an interpreter, and the dispatch table is the ISA. Do not start by reading the
  handlers — start by counting them.
* **Recover tables from relocations, not from a debugger.** In a PIE, a table of function
  pointers lives in `.rela.dyn`. Parsing it gives the opcode map statically, with no
  execution and no guessing about which entries are live.
* **Validate a reimplemented VM on cycle counts, not on output.** Matching text only proves
  the I/O path. Matching the cycle count on both the accepting and rejecting paths exercises
  every instruction the ROM uses.
* **Branch-free obfuscation defeats itself.** Unrolling the transform hides its structure
  from a reader, but it also removes every input-dependent decision — which is precisely
  what allows the operation sequence to be lifted once and inverted in closed form. A
  single data-dependent branch in that block would have forced a solver.

## Reproducing

```console
$ python3 solution/isa.py            # ISA tables straight out of the ELF
$ python3 solution/disasm.py > rom.asm
$ python3 solution/solve.py          # lifts, inverts, and self-verifies
$ echo 'ASIS{...}' | python3 solution/asisarch.py   # run the ROM
```

Python 3, standard library only. No dependency on the x86-64 binary at runtime beyond
[`solution/isa.py`](solution/isa.py) reading its tables.
