#!/usr/bin/env python3
"""Extract the ASIS Arch ISA tables straight out of the qemu-asisarch binary.

Nothing here is guessed. The emulator keeps three tables in read-only data:

  .rodata      0x2140  4 x 4 bytes  byte permutation used by the fetch stage
  .rodata      0x2160  256 bytes    S-box used by the `sbox` instruction
  .data.rel.ro 0x35e0  256 x 8      opcode -> handler dispatch table

The dispatch table is a table of pointers in a PIE, so it is empty in the file
and filled in at load time by R_X86_64_RELATIVE relocations. Reading those
relocations gives the opcode numbers without running anything.

Only HANDLERS below is human input: it names each handler address after
reading its disassembly (see the writeup). Everything else is derived, so a
different build would fail loudly rather than decode wrongly.
"""
from pathlib import Path
import struct

DEFAULT_BIN = Path(__file__).resolve().parent.parent / "challenge" / "qemu-asisarch"

# handler entry point -> mnemonic, from reading .text (see writeup section 4)
HANDLERS = {
    0x1690: "halt", 0x16a0: "sbox", 0x1700: "out",  0x1730: "in",
    0x1760: "ret",  0x1798: "call", 0x17d0: "pop",  0x1810: "push",
    0x1848: "jnz",  0x1868: "jz",   0x1888: "jmp",  0x1890: "stw",
    0x18d0: "ldw",  0x1918: "stb",  0x1950: "ldb",  0x1988: "xor",
    0x19b0: "sub",  0x19f0: "add",  0x1a30: "mov",  0x1a60: "roli",
    0x1a78: "andi", 0x1a90: "xori", 0x1aa8: "subi", 0x1ad0: "addi",
    0x1b00: "li",   0x1b18: "nop",
}

R_X86_64_RELATIVE = 8


def _sections(blob):
    e_shoff, = struct.unpack_from("<Q", blob, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", blob, 0x3a)
    raw = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, _typ, _fl, addr, off, size, *_ = struct.unpack_from("<IIQQQQIIQQ", blob, o)
        raw.append({"name": name, "addr": addr, "off": off, "size": size})
    base = raw[e_shstrndx]["off"]
    out = {}
    for s in raw:
        end = blob.index(b"\0", base + s["name"])
        out[blob[base + s["name"]:end].decode()] = s
    return out


def extract(path=DEFAULT_BIN):
    """Return (sbox, byte_permutation_table, {opcode: mnemonic})."""
    blob = Path(path).read_bytes()
    sec = _sections(blob)

    ro = sec[".rodata"]
    def rodata(vaddr, n):
        i = ro["off"] + (vaddr - ro["addr"])
        return blob[i:i + n]

    sbox = rodata(0x2160, 256)
    if sorted(sbox) != list(range(256)):
        raise RuntimeError("S-box is not a permutation - wrong binary?")
    sel = [list(rodata(0x2140, 16)[i * 4:i * 4 + 4]) for i in range(4)]

    rela, drr = sec[".rela.dyn"], sec[".data.rel.ro"]
    relocs = {}
    for o in range(rela["off"], rela["off"] + rela["size"], 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", blob, o)
        if r_info & 0xffffffff == R_X86_64_RELATIVE:
            relocs[r_off] = r_add

    ops = {}
    for opcode in range(256):
        target = relocs.get(drr["addr"] + 8 * opcode)
        if target is None:
            continue                      # null entry -> illegal instruction
        if target not in HANDLERS:
            raise RuntimeError(f"opcode {opcode:#x} -> unknown handler {target:#x}")
        ops[opcode] = HANDLERS[target]
    if len(ops) != len(HANDLERS):
        raise RuntimeError(f"expected {len(HANDLERS)} live opcodes, found {len(ops)}")
    return bytes(sbox), sel, ops


if __name__ == "__main__":
    sbox, sel, ops = extract()
    print(f"byte permutation table (indexed by (raw >> 14) & 3):")
    for i, row in enumerate(sel):
        print(f"  sel {i}: {row}")
    print(f"\nS-box: 256-byte permutation, first 8 = {list(sbox[:8])}")
    print(f"\n{len(ops)} live opcodes:")
    for op in sorted(ops):
        print(f"  {op:3d}  {op:#04x}  {ops[op]}")
