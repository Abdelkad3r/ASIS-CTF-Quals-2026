#!/usr/bin/env python3
"""ASIS Arch virtual machine: instruction decoder, emulator and disassembler.

Reimplemented from qemu-asisarch. Cycle-for-cycle identical to the original on
challenge.rom: 8906 cycles for the accepting input.

Machine state, all inside one flat allocation in the original:

    0x00000 .. 0x0ffff   RAM, 64 KiB
    0x10000 .. 0x1000f   r0 .. r7, 16-bit each
    0x10010              SP, initialised to 0xfff0
    0x10012              PC, initialised from the ROM header
    0x10018              cycle counter, limit 10_000_000

Instructions are four bytes and PC-relative-encrypted: the same four bytes at a
different address decode to a different instruction. See decode().

Usage:  python3 asisarch.py [rom]   < input
"""
from pathlib import Path
import sys

import isa

M16 = 0xffff
HERE = Path(__file__).resolve().parent
DEFAULT_ROM = HERE.parent / "challenge" / "challenge.rom"

SBOX, SEL, OPS = isa.extract()


def rol16(v, n):
    n &= 15
    return ((v << n) | (v >> (16 - n))) & M16 if n else v & M16


def rol8(v, n):
    n &= 7
    return ((v << n) | (v >> (8 - n))) & 0xff if n else v & 0xff


def imm_of(lo, hi):
    """The header/immediate scrambling: swap each nibble, then rotate left 5."""
    return rol16((rol8(hi, 4) << 8) | rol8(lo, 4), 5)


def decode(mem, pc):
    """Decode the instruction at `pc`. Returns (opcode, rd, imm)."""
    raw = (((pc ^ 0x9e37) & M16) * 0x1039 + 0x79b9) & M16
    sel = (raw >> 14) & 3
    k = rol16(raw, 5)
    b = [mem[(pc + off) & M16] for off in SEL[sel]]
    b0, b1, b2, b3 = b

    al = ((((0x5d * pc) & 0xffffffff) ^ k) ^ b2) & 0xff
    op = (rol8(al, ((k >> 5) & 0x1f) % 8) ^ 0x6d) & 0xff

    x = (((7 * pc) & 0xffffffff) ^ ((k >> 2) & M16) ^ b0) & 0xff
    a = ((5 * x) ^ 3) & 7
    rd = ((5 * a) ^ 3) & 7

    imm = imm_of((b1 ^ k) & 0xff, (b3 ^ (k >> 8)) & 0xff)
    return op, rd, imm


def rs_of(imm):
    """Second register operand, packed in the low 3 bits of the immediate."""
    return ((5 * (imm & 7)) ^ 3) & 7


def disasm(op, rd, imm):
    m = OPS.get(op)
    if m is None:
        return f".bad {op:#04x}"
    if m in ("halt", "ret", "nop"):
        return m
    if m in ("out", "in", "push", "pop", "sbox"):
        return f"{m} r{rd}"
    if m in ("jnz", "jz"):
        return f"{m} r{rd}, {imm:#06x}"
    if m in ("jmp", "call"):
        return f"{m} {imm:#06x}"
    if m in ("stw", "ldw", "stb", "ldb"):
        d = imm >> 3
        return (f"{m} [r{rs_of(imm)}+{d:#x}], r{rd}" if m[0] == "s"
                else f"{m} r{rd}, [r{rs_of(imm)}+{d:#x}]")
    if m in ("xor", "sub", "add", "mov"):
        return f"{m} r{rd}, r{rs_of(imm)}"
    return f"{m} r{rd}, {imm:#06x}"


def rom_checksum(image):
    """The header checksum at +0x0c, over the image body."""
    d = 0x31415926
    for c in image:
        d = (rol16(d & M16, 3) ^ c ^ (d >> 16) ^ 0x9e37) & 0xffffffff
    return d


class CPU:
    CYCLE_LIMIT = 10_000_000

    def __init__(self, rom, stdin=b""):
        if rom[:4] != b"AARQ":
            raise ValueError("bad image")
        if rom[4] != 2:
            raise ValueError("wrong machine image")
        image = rom[0x20:]
        if len(image) > 0x10000:
            raise ValueError("image too large")
        want = int.from_bytes(rom[0xc:0x10], "little")
        if rom_checksum(image) != want:
            raise ValueError("ROM checksum mismatch")

        self.mem = bytearray(0x10000)
        self.mem[:len(image)] = image
        self.r = [0] * 8
        self.sp = 0xfff0
        self.pc = imm_of(rom[8], rom[9])
        self.inp, self.ip = bytearray(stdin), 0
        self.out = bytearray()
        self.cycles = 0

    def _getc(self):
        if self.ip < len(self.inp):
            c = self.inp[self.ip]
            self.ip += 1
            return c
        return 0                                    # EOF reads as 0

    def step(self):
        """Execute one instruction. Returns False on halt."""
        mem, pc, r = self.mem, self.pc, self.r
        if pc + 4 > 0x10000:
            raise RuntimeError("PC out of bounds")
        op, rd, imm = decode(mem, pc)
        n = OPS.get(op)
        if n is None:
            raise RuntimeError(f"illegal instruction {op:#04x} at {pc:#06x}")
        self.pc = (pc + 4) & M16

        if n == "halt":
            return False
        elif n == "nop":   pass
        elif n == "li":    r[rd] = imm
        elif n == "mov":   r[rd] = r[rs_of(imm)]
        elif n == "add":   r[rd] = (r[rd] + r[rs_of(imm)]) & M16
        elif n == "sub":   r[rd] = (r[rd] - r[rs_of(imm)]) & M16
        elif n == "xor":   r[rd] ^= r[rs_of(imm)]
        elif n == "addi":  r[rd] = (r[rd] + imm) & M16
        elif n == "subi":  r[rd] = (r[rd] - imm) & M16
        elif n == "xori":  r[rd] ^= imm
        elif n == "andi":  r[rd] &= imm
        elif n == "roli":  r[rd] = rol16(r[rd], (imm & 0x1f) % 16)
        elif n == "sbox":  r[rd] = (SBOX[r[rd] >> 8] << 8) | SBOX[r[rd] & 0xff]
        elif n == "out":   self.out.append(r[rd] & 0xff)
        elif n == "in":    r[rd] = self._getc()
        elif n == "jmp":   self.pc = imm
        elif n == "jz":    self.pc = imm if r[rd] == 0 else self.pc
        elif n == "jnz":   self.pc = imm if r[rd] != 0 else self.pc
        elif n == "call":
            ret = self.pc
            self.sp = (self.sp - 2) & M16
            mem[self.sp] = ret & 0xff
            mem[(self.sp + 1) & M16] = ret >> 8
            self.pc = imm
        elif n == "ret":
            self.pc = mem[self.sp] | (mem[(self.sp + 1) & M16] << 8)
            self.sp = (self.sp + 2) & M16
        elif n == "push":
            self.sp = (self.sp - 2) & M16
            mem[self.sp] = r[rd] & 0xff
            mem[(self.sp + 1) & M16] = r[rd] >> 8
        elif n == "pop":
            r[rd] = mem[self.sp] | (mem[(self.sp + 1) & M16] << 8)
            self.sp = (self.sp + 2) & M16
        else:                                        # ldw / stw / ldb / stb
            a = ((imm >> 3) + r[rs_of(imm)]) & M16
            if n == "stw":
                mem[a] = r[rd] & 0xff
                mem[(a + 1) & M16] = r[rd] >> 8
            elif n == "ldw":
                r[rd] = mem[a] | (mem[(a + 1) & M16] << 8)
            elif n == "stb":
                mem[a] = r[rd] & 0xff
            else:
                r[rd] = mem[a]
        return True

    def run(self):
        while True:
            self.cycles += 1
            if self.cycles > self.CYCLE_LIMIT:
                raise RuntimeError("guest cycle limit exceeded")
            if not self.step():
                return self.out


def load_rom(path=DEFAULT_ROM):
    return Path(path).read_bytes()


if __name__ == "__main__":
    rom = load_rom(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ROM)
    cpu = CPU(rom, sys.stdin.buffer.read())
    cpu.run()
    sys.stdout.write(cpu.out.decode("latin1"))
    print(f"[{cpu.cycles} cycles]", file=sys.stderr)
