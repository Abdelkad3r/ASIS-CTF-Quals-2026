#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


DOMAIN = b"\x3a\x91\xf0\x7d\x14\x68\xbc\x29"


def shift(poly, amount):
    n = len(poly)
    amount %= 2 * n
    sign = -1 if amount >= n else 1
    if amount >= n:
        amount -= n

    result = [0] * n
    for i, value in enumerate(poly):
        if i + amount < n:
            result[i + amount] = sign * value
        else:
            result[i + amount - n] = -sign * value
    return result


def derive_key(a, b, salt):
    n = len(a)
    canonical = min(
        tuple(shift(a, i) + shift(b, i))
        for i in range(2 * n)
    )
    encoded = bytes(value + 1 for value in canonical)
    return hashlib.sha3_256(DOMAIN + salt + encoded).digest()


def multiplication_basis(h, q):
    n = len(h)
    rows = []

    # Row combinations produce (a, a*h + q*k).  The hidden (a, b) is in
    # this lattice because a*h = b modulo (q, x^n + 1).
    for i in range(n):
        rows.append(
            [int(i == j) for j in range(n)] + shift(h, i)
        )
    for i in range(n):
        rows.append([0] * n + [q * int(i == j) for j in range(n)])
    return rows


def write_fplll_matrix(path, rows):
    with path.open("w") as handle:
        handle.write("[\n")
        for row in rows:
            handle.write("[" + " ".join(map(str, row)) + "]\n")
        handle.write("]\n")


def parse_fplll_matrix(path):
    text = path.read_text()
    return [
        [int(value) for value in match.split()]
        for match in re.findall(r"\[([\d\s-]+)\]", text)
    ]


def reduce_lattice(rows, workdir, index, block_size):
    source = workdir / f"lock-{index}.matrix"
    lll = workdir / f"lock-{index}.lll"
    reduced = workdir / f"lock-{index}.bkz"
    write_fplll_matrix(source, rows)

    with lll.open("w") as output:
        subprocess.run(
            [
                "fplll", "-a", "lll", "-d", "0.99",
                "-m", "fast", "-f", "double", str(source),
            ],
            stdout=output,
            check=True,
        )

    with reduced.open("w") as output:
        subprocess.run(
            [
                "fplll", "-a", "bkz", "-b", str(block_size),
                "-bkzautoabort", str(lll),
            ],
            stdout=output,
            check=True,
        )
    return parse_fplll_matrix(reduced)


def decrypt_candidate(row, public_h, ciphertext, n, q):
    a, b = row[:n], row[n:]
    salt = bytes.fromhex(ciphertext["S"])
    encrypted = bytes.fromhex(ciphertext["C"])
    expected_tag = bytes.fromhex(ciphertext["T"])
    key = derive_key(a, b, salt)

    associated = json.dumps(
        {"N": n, "Q": q, "H": public_h},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    actual_tag = hmac.new(
        key,
        DOMAIN + associated + salt + encrypted,
        hashlib.sha256,
    ).digest()[:16]
    if not hmac.compare_digest(expected_tag, actual_tag):
        return None

    stream = hashlib.shake_256(DOMAIN + key + salt).digest(len(encrypted))
    return bytes(left ^ right for left, right in zip(encrypted, stream))


def recover_share(rows, public_h, ciphertext, n, q, weight):
    target_norm = 2 * weight
    candidates = sorted(rows, key=lambda row: sum(value * value for value in row))
    for row in candidates:
        if len(row) != 2 * n:
            continue
        if sum(value * value for value in row) != target_norm:
            continue
        if not set(row) <= {-1, 0, 1}:
            continue
        plaintext = decrypt_candidate(row, public_h, ciphertext, n, q)
        if plaintext is not None:
            return plaintext
    raise RuntimeError("BKZ did not recover an authenticated short vector")


def main():
    parser = argparse.ArgumentParser(
        description="Recover the five Fence NTRU keys and decrypt the flag"
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=Path(__file__).with_name("artifacts") / "flag.enc",
    )
    parser.add_argument("--block-size", type=int, default=30)
    parser.add_argument(
        "--workdir",
        type=Path,
        help="keep fplll input/output matrices in this directory",
    )
    args = parser.parse_args()

    if shutil.which("fplll") is None:
        parser.error("fplll is required but was not found in PATH")

    challenge = json.loads(args.input.read_text())
    n, q, weight = challenge["N"], challenge["Q"], challenge["W"]
    public_keys, ciphertexts = challenge["H"], challenge["C"]
    if len(public_keys) != challenge["R"] or len(ciphertexts) != challenge["R"]:
        raise ValueError("inconsistent lock count")

    temporary = None
    if args.workdir is None:
        temporary = tempfile.TemporaryDirectory(prefix="fence-")
        workdir = Path(temporary.name)
    else:
        workdir = args.workdir
        workdir.mkdir(parents=True, exist_ok=True)

    accumulator = bytearray(len(bytes.fromhex(ciphertexts[0]["C"])))
    try:
        for index, (public_h, ciphertext) in enumerate(
            zip(public_keys, ciphertexts), start=1
        ):
            print(f"[*] reducing lock {index}/{len(public_keys)}", flush=True)
            rows = multiplication_basis(public_h, q)
            reduced = reduce_lattice(rows, workdir, index, args.block_size)
            share = recover_share(
                reduced, public_h, ciphertext, n, q, weight
            )
            print(f"[+] lock {index}: authenticated share recovered", flush=True)
            for position, value in enumerate(share):
                accumulator[position] ^= value
    finally:
        if temporary is not None:
            temporary.cleanup()

    flag = bytes(accumulator)
    print(f"[+] plaintext: {flag!r}")
    try:
        print(f"[+] flag: {flag.decode()}")
    except UnicodeDecodeError:
        raise RuntimeError("recovered plaintext is not valid UTF-8")


if __name__ == "__main__":
    main()
