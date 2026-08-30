#!/usr/bin/env python3
"""
Hackel - intended solve: submit an EQUIVALENT key (menu option [4]).

submit_key() never compares the submission against the server's secret. It only
checks that the submitted permutations satisfy the published presentation plus
two structural predicates. So we do not recover the key -- we *construct* any
representation that satisfies the same relations.

Reducing the presentation:

    C = AB,  D = A^-1 B C,  E = CD        (definitions)

makes the remaining eight upper/lower relations tautologies, leaving only

    A^10 = 1,   B^11 = 1

and taking `lower := upper` collapses the four mixed relations too, because
    A b a^9 A -> A B A^10 = AB      and    B a b^10 B -> B A B^11 = BA.

Remaining constraints, from is_symmetric_gen() and the sample check:
    * the generators act transitively on the 11 points  -> B is an 11-cycle
    * at least one generator is an odd permutation      -> A is a 10-cycle
    * a^k b must lie outside <a>                        -> free, since 11 does not divide 10

Usage:  python3 solve_key.py [host] [port]
"""
from __future__ import annotations
import json
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "65.109.208.91"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3771
N = 11


def compose(a, b):
    """Left-to-right: apply a, then b (matches the server's convention)."""
    return tuple(b[i] for i in a)


def invert(p):
    out = [0] * len(p)
    for i, v in enumerate(p):
        out[v] = i
    return tuple(out)


def cycle(n, points):
    out = list(range(n))
    for i, pt in enumerate(points):
        out[pt] = points[(i + 1) % len(points)]
    return tuple(out)


def build_key() -> dict[str, list[int]]:
    A = cycle(N, tuple(range(10)))            # order 10, odd, fixes point 10
    B = cycle(N, tuple(range(11)))            # order 11, transitive
    C = compose(A, B)                         # C  = AB
    D = compose(invert(A), compose(B, C))     # D  = A^-1 B C
    E = compose(C, D)                         # E  = CD
    key: dict[str, list[int]] = {}
    for sym, p in zip("ABCDE", (A, B, C, D, E)):
        key[sym] = list(p)
    for sym, p in zip("abcde", (A, B, C, D, E)):
        key[sym] = list(p)                    # lower := upper
    return key


def main() -> None:
    key = build_key()
    payload = json.dumps(key, separators=(",", ":"))
    print(f"[*] payload ({len(payload)} bytes)\n    {payload}")

    sock = socket.create_connection((HOST, PORT), timeout=15)
    buf = b""

    def until(needle: bytes, timeout: float = 15.0) -> bytes:
        nonlocal buf
        deadline = time.time() + timeout
        while needle not in buf:
            sock.settimeout(max(0.05, deadline - time.time()))
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        idx = buf.find(needle)
        if idx == -1:
            out, buf = buf, b""
        else:
            out, buf = buf[: idx + len(needle)], buf[idx + len(needle) :]
        return out

    until(b"> ")
    sock.sendall(b"4\n")
    until(b"Submit JSON assignment")
    until(b"\n")
    sock.sendall(payload.encode() + b"\n")
    print(until(b"\n").decode().strip())
    print(until(b"\n").decode().strip())


if __name__ == "__main__":
    main()
