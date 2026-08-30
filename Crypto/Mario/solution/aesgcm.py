"""Minimal AES-GCM and HKDF-SHA256, standard library only.

No crypto library is available in the solving environment (Crypto, Cryptodome
and cryptography are all absent), so the pieces mario.py needs are implemented
here. `selftest()` checks them against FIPS-197 and NIST vectors before use.
"""
import hashlib, hmac, struct

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C]


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out


def _expand_key(key):
    nk, nr = len(key) // 4, len(key) // 4 + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([x ^ y for x, y in zip(w[i - nk], t)])
    return w, nr


def _encrypt_block(w, nr, block):
    st = [list(block[i::4]) for i in range(4)]          # column-major -> rows

    def add_round_key(rnd):
        for c in range(4):
            for r in range(4):
                st[r][c] ^= w[4 * rnd + c][r]

    add_round_key(0)
    for rnd in range(1, nr + 1):
        for r in range(4):
            for c in range(4):
                st[r][c] = _SBOX[st[r][c]]
        for r in range(1, 4):
            st[r] = st[r][r:] + st[r][:r]
        if rnd != nr:
            for c in range(4):
                col = [st[r][c] for r in range(4)]
                st[0][c] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
                st[1][c] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
                st[2][c] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
                st[3][c] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
        add_round_key(rnd)
    return bytes(st[r][c] for c in range(4) for r in range(4))


def _gf128(x, y):
    z, v, r = 0, y, 0xE1 << 120
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        blk = data[i:i + 16].ljust(16, b"\0")
        y = _gf128(y ^ int.from_bytes(blk, "big"), h)
    return y


def gcm_decrypt(key, nonce, ciphertext, aad=b""):
    """AES-GCM with a 96-bit nonce. Returns (plaintext, tag_ok)."""
    w, nr = _expand_key(key)
    h = int.from_bytes(_encrypt_block(w, nr, b"\0" * 16), "big")
    body, tag = ciphertext[:-16], ciphertext[-16:]

    j0 = nonce + b"\0\0\0\1"
    ctr = int.from_bytes(j0, "big")
    out = bytearray()
    for i in range(0, len(body), 16):
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
        ks = _encrypt_block(w, nr, ctr.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(body[i:i + 16], ks))

    pad = lambda b: b + b"\0" * (-len(b) % 16)
    s = _ghash(h, pad(aad) + pad(body) + struct.pack(">QQ", len(aad) * 8, len(body) * 8))
    expect = (s ^ int.from_bytes(_encrypt_block(w, nr, j0), "big")).to_bytes(16, "big")
    return bytes(out), hmac.compare_digest(expect, tag)


def hkdf_sha256(material, length, salt, info=b""):
    prk = hmac.new(salt, material, hashlib.sha256).digest()
    out, t, n = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([n]), hashlib.sha256).digest()
        out += t
        n += 1
    return out[:length]


def selftest():
    """Known-answer tests: FIPS-197 AES-256 and two NIST GCM vectors."""
    w, nr = _expand_key(bytes(range(32)))
    got = _encrypt_block(w, nr, bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert got.hex() == "8ea2b7ca516745bfeafc49904b496089", "AES-256 block KAT failed"

    pt, ok = gcm_decrypt(bytes(32), bytes(12),
                         bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"))
    assert pt == b"" and ok, "GCM empty-message KAT failed"

    pt, ok = gcm_decrypt(bytes(32), bytes(12), bytes.fromhex(
        "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"))
    assert pt == bytes(16) and ok, "GCM one-block KAT failed"


if __name__ == "__main__":
    selftest()
    print("self-test OK")
