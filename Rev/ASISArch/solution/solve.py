#!/usr/bin/env python3
"""Recover the ASIS Arch flag by inverting the ROM's verification transform.

The ROM reads 44 bytes into a buffer at 0xc000, folds them through a long
straight-line sequence of 16-bit updates, then compares the result word by word
against values baked into the image.

The transform contains no branches, so the sequence of buffer updates is the
same whatever the input is. That makes it possible to lift it once, symbolically,
into a list of elementary steps

    buf[i] <- f(buf[i], other buffer words, constants)

where f is built only from xor / add / rotate / S-box. Each step mentions its
own target exactly once, so it inverts algebraically: peel the outer operation,
adjust the target value, repeat. Replaying the steps backwards from the expected
output yields the one input the ROM accepts.

Usage:  python3 solve.py
"""
import sys

from asisarch import CPU, M16, OPS, SBOX, decode, load_rom, rol16, rs_of

BUF, NWORDS = 0xc000, 22            # 44 bytes of flag
TRANSFORM_START = 0x0024            # first instruction after the length check
TRANSFORM_END = 0x7874              # 'li r5, 0' - start of the comparison
CHECK_END = 0x7be8                  # 'jnz r5, fail'

SBOX_INV = [0] * 256
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i


def ror16(v, n):
    n &= 15
    return ((v >> n) | (v << (16 - n))) & M16 if n else v & M16


# --------------------------------------------------------------- expressions
# ('C', k) constant   ('B', i) buffer word i   ('xor'|'add', a, b)
# ('rol', a, n)       ('sbox', a)

def ev(e, st):
    k = e[0]
    if k == "C":    return e[1]
    if k == "B":    return st[e[1]]
    if k == "xor":  return ev(e[1], st) ^ ev(e[2], st)
    if k == "add":  return (ev(e[1], st) + ev(e[2], st)) & M16
    if k == "rol":  return rol16(ev(e[1], st), e[2])
    if k == "sbox":
        v = ev(e[1], st)
        return (SBOX[v >> 8] << 8) | SBOX[v & 0xff]
    raise ValueError(k)


def uses(e, i):
    """How many times buffer word i appears in the expression."""
    if e[0] == "B":                   return int(e[1] == i)
    if e[0] in ("xor", "add"):        return uses(e[1], i) + uses(e[2], i)
    if e[0] in ("rol", "sbox"):       return uses(e[1], i)
    return 0


def invert(e, i, target, st):
    """Solve e == target for the single occurrence of buf[i]."""
    while e != ("B", i):
        k = e[0]
        if k in ("xor", "add"):
            a, b = e[1], e[2]
            if uses(a, i):
                known, e = ev(b, st), a
            else:
                known, e = ev(a, st), b
            target = target ^ known if k == "xor" else (target - known) & M16
        elif k == "rol":
            target, e = ror16(target, e[2]), e[1]
        elif k == "sbox":
            target = (SBOX_INV[target >> 8] << 8) | SBOX_INV[target & 0xff]
            e = e[1]
        else:
            raise ValueError(f"cannot invert node {k}")
    return target


# ------------------------------------------------------------- lifting passes
def lift(cpu):
    """Symbolically execute the transform into elementary buffer updates."""
    sym = [("C", 0)] * 8
    steps, previous = [], -1
    while cpu.pc < TRANSFORM_END:
        pc = cpu.pc
        if pc <= previous:
            raise RuntimeError(f"transform is not straight-line at {pc:#06x}")
        previous = pc
        op, rd, imm = decode(cpu.mem, pc)
        name = OPS[op]
        rs = rs_of(imm)
        before = list(cpu.r)
        cpu.cycles += 1
        cpu.step()

        if   name == "li":    sym[rd] = ("C", imm)
        elif name == "mov":   sym[rd] = sym[rs]
        elif name == "xor":   sym[rd] = ("xor", sym[rd], sym[rs])
        elif name == "add":   sym[rd] = ("add", sym[rd], sym[rs])
        elif name == "addi":  sym[rd] = ("add", sym[rd], ("C", imm))
        elif name == "roli":  sym[rd] = ("rol", sym[rd], (imm & 0x1f) % 16)
        elif name == "sbox":  sym[rd] = ("sbox", sym[rd])
        elif name == "ldw":
            a = ((imm >> 3) + before[rs]) & M16
            if BUF <= a < BUF + 2 * NWORDS:
                if a % 2:
                    raise RuntimeError(f"unaligned buffer load at {pc:#06x}")
                sym[rd] = ("B", (a - BUF) // 2)
            else:
                sym[rd] = ("C", cpu.mem[a] | (cpu.mem[a + 1] << 8))
        elif name == "stw":
            a = ((imm >> 3) + before[rs]) & M16
            if not (BUF <= a < BUF + 2 * NWORDS) or a % 2:
                raise RuntimeError(f"store outside the flag buffer at {pc:#06x}")
            steps.append(((a - BUF) // 2, sym[rd]))
        else:
            raise RuntimeError(f"unexpected {name} in transform at {pc:#06x}")
    return steps


def expected(cpu):
    """Replay the comparison region and record the target for each word."""
    out, slot = [None] * NWORDS, None
    while cpu.pc < CHECK_END:
        op, rd, imm = decode(cpu.mem, cpu.pc)
        name = OPS[op]
        before = list(cpu.r)
        cpu.cycles += 1
        cpu.step()
        if name == "ldw":
            a = ((imm >> 3) + before[rs_of(imm)]) & M16
            if BUF <= a < BUF + 2 * NWORDS:
                slot = (a - BUF) // 2
        if name == "xor" and rd == 4:       # r4 = table[off] ^ table[off+2]
            out[slot] = cpu.r[4]
    if any(v is None for v in out):
        raise RuntimeError("did not recover every expected word")
    return out


def main():
    cpu = CPU(load_rom(), b"A" * 44 + b"\n")
    while cpu.pc != TRANSFORM_START:        # banner, read, length check
        cpu.cycles += 1
        cpu.step()

    steps = lift(cpu)
    print(f"[+] lifted {len(steps)} elementary buffer updates")

    target = expected(cpu)
    print("[+] expected words:", " ".join(f"{w:04x}" for w in target))

    state = list(target)
    for i, e in reversed(steps):
        n = uses(e, i)
        if n != 1:
            raise SystemExit(f"word {i}: target appears {n} times, cannot isolate")
        state[i] = invert(e, i, state[i], state)

    flag = b"".join(w.to_bytes(2, "little") for w in state)
    print(f"[+] flag: {flag.decode('latin1')}")

    check = CPU(load_rom(), flag + b"\n")
    check.run()
    ok = b"Access Granted" in check.out
    print(f"[+] emulator says: {'ACCEPTED' if ok else 'REJECTED'}"
          f" ({check.cycles} cycles)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
