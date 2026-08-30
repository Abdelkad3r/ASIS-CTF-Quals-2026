#!/usr/bin/env python3
"""
Pancake Stack -- ASIS CTF Quals 2026 (Crypto).

The scheme is AES-GCM with a "diffused" KDF, broken by keystream reuse:

  * The AES-256 master key k1 = SHA256("K1-SEED" || be32(seed)) uses a 32-bit
    seed, and the challenge publishes hint = SHA256("K1-SEED-HINT" || be32(seed)).
    Brute-forcing 2^32 seeds against the hint recovers seed, hence k1.

  * KeyDerivation depends only on n1 and j = upper96(AES_k1(n2 << drop)).  During
    generation the server finds alt != n2 with upper96(AES_k1(alt<<drop)) ==
    upper96(AES_k1(n2<<drop))  (a collision in the TRUNCATED AES output), and
    encrypts a known all-zero plaintext under (n1, alt), stashing that ciphertext
    inside the sealed ticket z.

    Because j collides, the whole diffused state -- and therefore the GCM
    (key, iv) from derive_keys(k2, n1, state) -- is IDENTICAL for the flag's
    (n1, n2) and the sample's (n1, alt).  GCM is CTR underneath, so the two share
    one keystream.  The sample's plaintext is zeros, so its ciphertext IS the
    keystream:   flag = flag_ciphertext XOR sample_ciphertext.

Pipeline:
  1. brute the 32-bit seed  (seedbrute.c)          -> k1
  2. recompute alt = truncated collision (collide.c)
  3. decrypt the sealed ticket z with key(k1,n1,alt) (AES-GCM, tag verifies)
  4. XOR the flag ciphertext with the recovered keystream.

Requires: a C compiler (clang/gcc) and pycryptodome.
Usage:  python3 solve.py [challenge.json]
"""
from __future__ import annotations
import json, os, shutil, subprocess, sys, tempfile
from hashlib import sha256
from Crypto.Cipher import AES

HERE = os.path.dirname(os.path.abspath(__file__))


def compile_helper(name: str) -> str:
    src = os.path.join(HERE, name + ".c")
    out = os.path.join(tempfile.gettempdir(), name)
    cc = shutil.which("clang") or shutil.which("gcc")
    if not cc:
        sys.exit("error: need clang or gcc")
    flags = ["-O3"]
    if sys.platform != "darwin":
        flags.append("-lcrypto")
    r = subprocess.run([cc, *flags, src, "-o", out], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"compile failed for {name}:\n{r.stderr}")
    return out


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "challenge", "challenge.json")
    d = json.load(open(path))
    DROP = d["d"]
    NONCE_BITS = 128 - DROP
    NONCE_MASK = (1 << NONCE_BITS) - 1
    DROP_MASK = (1 << DROP) - 1
    bw = (NONCE_BITS + 7) // 8

    def format_block(x, sep=0): return (((x & NONCE_MASK) << DROP) | (sep & DROP_MASK)).to_bytes(16, "big")
    def extract_upper(x): return int.from_bytes(x, "big") >> DROP
    def decode_num(s): return int.from_bytes(bytes.fromhex(s), "big") & NONCE_MASK

    n1, n2 = decode_num(d["n"][0]), decode_num(d["n"][1])

    # 1) recover the 32-bit seed from the hint -> k1
    print("[*] brute-forcing 32-bit seed against hint ...", flush=True)
    seedbin = compile_helper("seedbrute")
    out = subprocess.run([seedbin, d["a"]], capture_output=True, text=True).stdout
    seed = None
    for line in out.splitlines():
        if line.startswith("SEED:"):
            seed = int(line.split(":", 1)[1], 16)
    if seed is None:
        sys.exit("[-] seed not found")
    assert sha256(b"K1-SEED-HINT" + seed.to_bytes(4, "big")).hexdigest() == d["a"]
    k1 = sha256(b"K1-SEED" + seed.to_bytes(4, "big")).digest()
    print(f"[+] seed = {seed:#010x}  ->  k1 recovered")

    # 2) recompute alt = truncated collision of AES_k1 for inputs (y << drop)
    e = AES.new(k1, AES.MODE_ECB)
    target = extract_upper(e.encrypt(format_block(n2, 0)))
    base = (target << DROP).to_bytes(16, "big")
    print(f"[*] scanning 2^{DROP} for truncated collision ...", flush=True)
    colbin = compile_helper("collide")
    out = subprocess.run([colbin, k1.hex(), base.hex(), str(DROP)], capture_output=True, text=True).stdout
    alts = []
    for line in out.splitlines():
        if line.startswith("RESULT:"):
            pt = int(line.split(":", 1)[1], 16)
            if (pt & DROP_MASK) == 0:
                y = pt >> DROP
                if y != n2:
                    alts.append(y)
    alts = list(dict.fromkeys(alts))
    print(f"[+] alt candidate(s): {[hex(a) for a in alts]}")

    # 3) decrypt the sealed ticket z with key derived from (k1, n1, alt)
    def try_ticket(alt):
        key = sha256(b"SEALED-TICKET-KEY" + k1 + n1.to_bytes(bw, "big") + alt.to_bytes(bw, "big")).digest()[:16]
        nonce = sha256(b"SEALED-TICKET-IV" + key).digest()[:12]
        c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        try:
            return json.loads(c.decrypt_and_verify(bytes.fromhex(d["z"]["c"]), bytes.fromhex(d["z"]["t"])))
        except Exception:
            return None

    rec = used = None
    for a in alts:
        rec = try_ticket(a)
        if rec:
            used = a
            break
    if not rec:
        sys.exit("[-] no alt decrypted the ticket")
    print(f"[+] ticket decrypted with alt = {used:#x}")

    # 4) keystream reuse: sample plaintext is zeros -> its ciphertext IS the keystream
    keystream = bytes.fromhex(rec["x"]["c"])
    yc = bytes.fromhex(d["y"]["c"])
    flag = bytes(x ^ y for x, y in zip(yc, keystream[:len(yc)]))
    print("\n[+] FLAG:", flag.decode())


if __name__ == "__main__":
    main()
