#!/usr/bin/env python3
"""
Sultan -- end-to-end remote exploit.

Downloads one secret.enc, recovers the session's secret string via the LWE-hint
attack (see solve.py), and submits it to /api/verify on the same session cookie
to obtain the flag.  Stdlib only (urllib) + fpylll (via solve.py).

Usage:  python3 pwn.py [base_url]      (default: the live challenge host)
"""
import http.cookiejar
import json
import sys
import time
import urllib.request

import solve

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://91.107.152.21:17131"


def main() -> None:
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    blob = op.open(urllib.request.Request(BASE + "/download"), timeout=30).read()
    cookie = next((c.value for c in cj if c.name == "sultan_session"), None)
    print(f"[*] downloaded secret.enc: {len(blob)} bytes  (session {cookie[:20]}...)")

    t0 = time.time()
    res = solve.recover_secret(blob)
    if not res:
        sys.exit("[-] recovery failed")
    secret = res[0].decode()
    print(f"[*] recovered secret ({len(secret)} chars, tag_ok={res[1]}) in {time.time()-t0:.1f}s: {secret!r}")

    req = urllib.request.Request(
        BASE + "/api/verify",
        data=json.dumps({"guess": secret}).encode(),
        headers={"Content-Type": "application/json"},
    )
    out = json.loads(op.open(req, timeout=30).read())
    if out.get("flag"):
        print(f"\n[+] FLAG: {out['flag']}")
    else:
        print("[-] verify response:", out)


if __name__ == "__main__":
    main()
