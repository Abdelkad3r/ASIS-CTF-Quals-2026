#!/usr/bin/env python3
import hashlib
import secrets
import struct
import zlib

MAGIC = b"\xd8\x06\x00\x1a"
VERSION = 4
q, n, ell, m, t, b = 8380417, 64, 1, 70, 16, 65000
committee_size, threshold = 63, 32
secret_bound = 3
HEADER = "<4sIIIIIIIIIII"

def _a(x, y):
    return [(u + v) % q for u, v in zip(x, y)]

def _p(x, y):
    z = [0] * n
    for i, u in enumerate(x):
        if u:
            for j, v in enumerate(y):
                if v:
                    k = i + j
                    z[k if k < n else k - n] += v * u if k < n else -v * u
    return [u % q for u in z]

def _g(lo, hi):
    return [secrets.randbelow(hi - lo + 1) + lo for _ in range(n)]

def _b(x):
    h = hashlib.shake_256(b"SULTAN/challenge" + x).digest(4096)
    z, seen, i = [0] * n, set(), 0
    while len(seen) < t:
        u = int.from_bytes(h[i:i + 2], "little") % n
        i += 2
        if u not in seen:
            seen.add(u)
            z[u] = 1 if h[i] & 1 else -1
            i += 1
    return z

def _r(x):
    h = hashlib.shake_256(b"SULTAN/audit" + x).digest(4 * n * ell)
    return [
        [int.from_bytes(h[4 * (j * n + i):4 * (j * n + i + 1)], "little") % q for i in range(n)]
        for j in range(ell)
    ]

def _i(x, y):
    return sum(u * v for xp, yp in zip(x, y) for u, v in zip(xp, yp)) % q

def _z(x):
    return struct.pack("<" + "I" * (ell * n), *[u % q for p in x for u in p])

def _secret_bytes(x):
    return struct.pack("<" + "b" * (ell * n), *[u for p in x for u in p])

def encrypt_sultan(secret_data: bytes) -> bytes:
    """
    Encrypts a secret binary payload using the Sultan cryptographic scheme.
    Returns the compressed binary file content (secret.enc) entirely in-memory.
    """
    s = [_g(-secret_bound, secret_bound) for _ in range(ell)]
    w = _secret_bytes(s)
    k = hashlib.shake_256(b"SULTAN/key" + w).digest(32)
    nonce = secrets.token_bytes(24)
    p = hashlib.shake_256(b"SULTAN/stream" + k + nonce).digest(len(secret_data))
    e = bytes(u ^ v for u, v in zip(secret_data, p))
    d = hashlib.blake2s(b"SULTAN/tag" + nonce + e, key=k, digest_size=32).digest()
    
    R, sessions, random_source = [], set(), secrets.SystemRandom()
    for _ in range(m):
        x = secrets.token_bytes(32)
        while x in sessions:
            x = secrets.token_bytes(32)
        sessions.add(x)
        y = bytes(sorted(random_source.sample(range(committee_size), threshold)))
        seed = x + y
        u = [_g(0, q - 1) for _ in range(ell)]
        c = _b(seed)
        v = [_a(up, _p(c, sp)) for up, sp in zip(u, s)]
        R.append(x + y + struct.pack("<I", _i(_r(seed), u) // b) + _z(v))

    raw = bytearray(struct.pack(
        HEADER,
        MAGIC, VERSION, q, n, ell, m, t, b, secret_bound, committee_size, threshold, len(secret_data),
    ))
    raw += nonce + e + d + b"".join(R)
    return zlib.compress(bytes(raw), 9)
