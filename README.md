# ASIS CTF Quals 2026

Professional writeups and reproducible solution artifacts for ASIS CTF Quals
2026.

## Writeups

| Challenge | Category | Writeup | Flag |
| --- | --- | --- | --- |
| Fence | Cryptography | [crypto/fence](crypto/fence/) | `ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}` |
| Mic Check | misc / warm-up | [misc/mic-check](misc/mic-check/) &middot; [published](https://claude.ai/code/artifact/96cdf208-78ac-4b31-a496-d065ccd7ea93) | `ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}` |

## Layout

Each challenge lives under its category and includes a detailed `README.md`, a
reproducible `solve.py`, and the available original challenge materials. Some
directories also provide a standalone HTML writeup.

## Running The Solvers

The solvers target Python 3. Challenge-specific requirements and invocation
instructions are documented in each writeup.

```console
$ python3 misc/mic-check/solve.py
$ python3 crypto/fence/solve.py
```

Use these materials only in authorized CTF and educational environments.
