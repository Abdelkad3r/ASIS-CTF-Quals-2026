#!/usr/bin/env python3
"""
Hackel - unintended solve: the ciphertext is plaintext.

Flag bits are encoded as *words over the generator alphabet* and printed
verbatim by menu option [2]:

    bit 0  ->  a^k          k in 1..9
    bit 1  ->  a^k b        k in 0..9

The a-padding is noise; the bit is simply "does the word contain b".
No key recovery, no group theory, no oracle queries.

This script:
  1. reads the alphabet from option [1] (the symbol names are server-side params),
  2. decodes the flag offline from option [2],
  3. passes the 5-second speed challenge in option [5] for a server-signed flag.

Usage:  python3 solve_leak.py [host] [port]
"""
from __future__ import annotations
import re
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "65.109.208.91"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3771


class Tube:
    """Minimal line-oriented socket wrapper."""

    def __init__(self, host: str, port: int, timeout: float = 15.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""

    def until(self, needle: bytes, timeout: float = 15.0) -> bytes:
        deadline = time.time() + timeout
        while needle not in self.buf:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            self.buf += chunk
        idx = self.buf.find(needle)
        if idx == -1:
            out, self.buf = self.buf, b""
        else:
            out, self.buf = self.buf[: idx + len(needle)], self.buf[idx + len(needle) :]
        return out

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)


def bits_to_text(bits: str) -> str:
    raw = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))
    return raw.decode("utf-8", "replace")


def main() -> None:
    t = Tube(HOST, PORT)
    t.until(b"> ")

    # [1] Public parameters -- learn which symbols play the role of a and b.
    t.send(b"1\n")
    params = t.until(b"> ").decode()
    lower = re.findall(r"'(.)'", re.search(r"Lower symbols: \[(.*?)\]", params).group(1))
    a_sym, b_sym = lower[0], lower[1]
    print(f"[*] lower alphabet {lower} -> padding={a_sym!r} marker={b_sym!r}")

    # [2] Encrypted flag words -- decode offline.
    t.send(b"2\n")
    body = t.until(b"> ").decode()
    words = [w.strip() for w in re.search(
        r"Encrypted Flag Words \(\d+\):\s*\n\s*(.+)", body).group(1).split(",")]
    bits = "".join("1" if b_sym in w else "0" for w in words)
    print(f"[*] {len(words)} words -> {len(bits)} bits -> {len(bits)//8} bytes")
    print(f"[*] sample: {words[:6]}")
    print(f"[+] FLAG (offline): {bits_to_text(bits)}")

    # [5] Speed challenge -- same encoding, 5-second budget, server prints the flag.
    t.send(b"5\n")
    chal = t.until(b"Your Classification Bits: ").decode()
    cwords = re.search(r"Challenge Words: (.+)", chal).group(1).split()
    answer = "".join("1" if b_sym in w else "0" for w in cwords)
    print(f"[*] speed challenge -> {answer}")
    t.send(answer.encode() + b"\n")
    print(t.until(b"> ", timeout=8).decode().strip())


if __name__ == "__main__":
    main()
