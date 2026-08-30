#!/usr/bin/env python3
"""LeakMeAk -- ASIS CTF Quals 2026 (rev).

The binary is a stripped PIE flag-checker. After length/prefix/suffix checks it
runs 28 inner bytes ("ASIS{" + 28 + "}") through a bespoke, obfuscated hash and
accepts only if every one of several conditions holds:

  * an error accumulator `ecx` stays 0 (a per-byte state machine must never trip);
  * 7 cyclic equations on internal dwords H[0..6]:
        (ror(H[i%7], 13) + H[i-1]) ^ tableB[i] == tableA[i];
  * a poly-33 hash of H == 0xddaacf25 and its 64-round remix == 0x376a3d36;
  * two low-bit checks on an internal `s30` state array.

The dwords come from  H[i] = (word_i * 0x9e3779b9) XOR mix_i  where word_i is the
i-th group of 4 flag bytes read big-endian and mix_i is produced by the state
machine (character-class counters, `> 'Y'` comparisons). The hash is
non-injective -- many strings collide to the same H -- which is the "trust
issues" the challenge jokes about; the extra state-machine constraints tighten it
back to a single printable answer.

The solve, in three stages:

  1. z3 solves the 7 cyclic equations (plus the poly-33 check) for H uniquely.
  2. A Unicorn emulation of the check function is used as an oracle: it reproduces
     the per-iteration (H_i, mix_i, ecx_i) exactly, so for each dword the four
     bytes invert as  word_i = (H_target[i] ^ mix_i) * inv(0x9e3779b9).  mix_i is
     low-entropy for a fixed prefix, so its value set is sampled and each
     printable candidate is verified against the oracle.
  3. A DFS over the (few) candidates per position keeps only the string the
     checker actually grants -- exactly one survives.

Usage:  python3 solve.py [path/to/leakmeak.elf]

Needs z3 and the Unicorn CPU emulator (`pip install z3-solver unicorn`).
"""
import os
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UcError
from unicorn.x86_const import (
    UC_X86_REG_RSP, UC_X86_REG_RBX, UC_X86_REG_FS_BASE, UC_X86_REG_EDX, UC_X86_REG_RSI,
    UC_X86_REG_ESI, UC_X86_REG_ECX, UC_X86_REG_RAX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
    UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
)
from z3 import BitVec, BitVecVal, RotateRight, Solver, Or, sat

HERE = Path(__file__).resolve().parent
DEFAULT_ELF = HERE.parent / "challenge" / "leakmeak.elf"
CONST = 0x9e3779b9
INV = pow(CONST, -1, 1 << 32)

# tableA @ .rodata 0x204c, tableB @ 0x206c (the cyclic-equation constants)
TABLE_A = [0x0, 0x449f4ab5, 0xbb5e7ac4, 0x91141f33,
           0x9caafb86, 0xd99258f7, 0x2abb0f38, 0x3ff226d0]
TABLE_B = [0x0, 0xa5a5a5a5, 0x5a5a5a5a, 0x3c3c3c3c,
           0xc3c3c3c3, 0x96969696, 0x69696969, 0x1f1f1f1f]
POLY_TARGET = 0xddaacf25


# --------------------------------------------------------------- stage 1: z3
def solve_internal_dwords():
    C = [(TABLE_A[i] ^ TABLE_B[i]) & 0xffffffff for i in range(8)]
    H = [BitVec(f"H{i}", 32) for i in range(7)]
    s = Solver()
    for rsi in range(1, 8):                       # (ror(H[rsi%7],13) + H[rsi-1]) == C[rsi]
        s.add(RotateRight(H[rsi % 7], 13) + H[rsi - 1] == C[rsi])
    edx = BitVecVal(0, 32)                         # poly-33 hash of H == target
    for i in range(7):
        edx = edx * 33 ^ H[i]
    s.add(edx == POLY_TARGET)
    assert s.check() == sat
    m = s.model()
    H_val = [m[H[i]].as_long() for i in range(7)]
    s.add(Or([H[i] != H_val[i] for i in range(7)]))
    assert s.check() != sat, "internal dwords are not unique"
    return H_val


# ---------------------------------------------------- stage 2: Unicorn oracle
class Oracle:
    """Emulate the check function; report per-iteration (H, mix, ecx) and verdict."""
    STACK = 0x7fff0000
    FSB = 0x6f000000

    def __init__(self, elf_path):
        blob = Path(elf_path).read_bytes()
        phoff = struct.unpack_from("<Q", blob, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", blob, 0x36)
        segs = []
        for i in range(phnum):
            o = phoff + i * phentsize
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", blob, o)
            if t == 1:
                segs.append((va, off, fsz, msz))
        lo = min(v for v, _, _, _ in segs) & ~0xfff
        hi = max(v + m for v, _, _, m in segs)

        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(lo, ((hi - lo + 0xfff) & ~0xfff) + 0x1000)
        for va, off, fsz, msz in segs:
            uc.mem_write(va, blob[off:off + fsz])
        uc.mem_map(self.STACK - 0x100000, 0x200000)
        uc.mem_map(self.FSB & ~0xfff, 0x2000)
        uc.reg_write(UC_X86_REG_FS_BASE, self.FSB)
        uc.mem_write(self.FSB + 0x28, b"\xaa" * 8)

        st = {}
        def hook(u, addr, size, data):
            if addr == 0x13c2:                    # store of H[i]; edx=H, esi=mix, ecx=flags
                st["stores"].append((u.reg_read(UC_X86_REG_EDX) & 0xffffffff,
                                     u.reg_read(UC_X86_REG_ESI) & 0xffffffff,
                                     u.reg_read(UC_X86_REG_ECX) & 0xffffffff))
            elif addr in (0x147e, 0x14bb):        # "Access Granted" / "Access Denied" puts
                st["verdict"] = "GRANTED" if addr == 0x147e else "DENIED"
                u.emu_stop()
        uc.hook_add(UC_HOOK_CODE, hook, begin=0x13c2, end=0x13c3)
        uc.hook_add(UC_HOOK_CODE, hook, begin=0x147e, end=0x14c3)

        self.uc, self.st = uc, st
        self.gp = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
                   UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8, UC_X86_REG_R9,
                   UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
                   UC_X86_REG_R14, UC_X86_REG_R15]

    def run(self, flag34):
        self.st.clear()
        self.st["stores"] = []
        for r in self.gp:
            self.uc.reg_write(r, 0)
        self.uc.reg_write(UC_X86_REG_RSP, self.STACK)
        self.uc.mem_write(self.STACK + 0x10, b"\x00" * 0xa0)
        self.uc.mem_write(self.STACK + 0x60, flag34 + b"\x00")
        self.uc.mem_write(self.STACK + 0xe8, b"\xaa" * 8)
        self.uc.reg_write(UC_X86_REG_RBX, self.STACK + 0x60)
        try:
            self.uc.emu_start(0x115e, 0x1600, count=300000)   # enter past len/prefix checks
        except UcError:
            pass
        return dict(self.st)


# ------------------------------------------------ stage 3: invert + DFS
def printable(b):
    return all(0x20 <= c < 0x7f for c in b)


def main():
    elf = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ELF
    HT = solve_internal_dwords()
    print("[+] internal dwords H =", [hex(x) for x in HT])

    orc = Oracle(elf)

    def candidates(prefix, i, samples=12000):
        # mix_i depends on the (fixed) prefix state and the current 4 bytes only;
        # sample its value set, then invert each to the unique word it implies.
        mixes = set()
        for _ in range(samples):
            probe = bytes(0x20 + os.urandom(1)[0] % 0x5f for _ in range(4))
            r = orc.run(b"ASIS{" + prefix + probe + b"AAAA" * (6 - i) + b"}")
            if len(r["stores"]) > i:
                mixes.add(r["stores"][i][1])
        out = []
        for m in mixes:
            word = ((HT[i] ^ m) * INV) & 0xffffffff
            B = word.to_bytes(4, "big")
            if not printable(B):
                continue
            r = orc.run(b"ASIS{" + prefix + B + b"AAAA" * (6 - i) + b"}")
            st = r["stores"]
            if len(st) > i and st[i][0] == HT[i] and (st[i][2] & ~0x8) == 0:
                out.append(B)
        return list(dict.fromkeys(out))

    grants = []

    def dfs(prefix):
        i = len(prefix) // 4
        if i == 7:
            if orc.run(b"ASIS{" + prefix + b"}").get("verdict") == "GRANTED":
                grants.append(prefix)
            return
        for B in candidates(prefix, i):
            print(f"[i={i}] {prefix.decode('latin1')!r:>28} + {B.decode('latin1')!r}")
            dfs(prefix + B)

    dfs(b"")
    print(f"\n[+] {len(grants)} string(s) accepted by the checker")
    for g in grants:
        print("[+] flag:", ("ASIS{" + g.decode("latin1") + "}"))


if __name__ == "__main__":
    main()
