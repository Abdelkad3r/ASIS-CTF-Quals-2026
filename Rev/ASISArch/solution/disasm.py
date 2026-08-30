#!/usr/bin/env python3
"""Recursive-descent disassembler for an ASIS Arch ROM.

Linear sweep is useless here: instruction bytes are decrypted with a keystream
derived from the address they sit at, so decoding from the wrong offset yields
garbage that still looks like valid instructions. Start at the entry point in
the ROM header and follow control flow instead.

Usage:  python3 disasm.py [rom] > rom.asm
"""
import sys

from asisarch import DEFAULT_ROM, OPS, decode, disasm, imm_of, load_rom

def main(path):
    rom = load_rom(path)
    mem = bytearray(0x10000)
    image = rom[0x20:]
    mem[:len(image)] = image
    entry = imm_of(rom[8], rom[9])
    print(f"; entry {entry:#06x}, image {len(image):#x} bytes", file=sys.stderr)

    seen, work = {}, [entry]
    while work:
        pc = work.pop()
        while pc + 4 <= 0x10000 and pc not in seen:
            op, rd, imm = decode(mem, pc)
            name = OPS.get(op)
            seen[pc] = (op, rd, imm)
            if name is None:
                break
            if name == "jmp":
                pc = imm
                continue
            if name in ("jz", "jnz", "call"):
                work.append(imm)
            if name in ("halt", "ret"):
                break
            pc += 4

    for pc in sorted(seen):
        op, rd, imm = seen[pc]
        raw = " ".join(f"{mem[pc + i]:02x}" for i in range(4))
        print(f"{pc:04x}:  {raw}   {disasm(op, rd, imm)}")
    print(f"; {len(seen)} instructions reached", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ROM)
