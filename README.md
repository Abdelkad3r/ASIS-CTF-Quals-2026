# ASIS CTF Quals 2026

Solutions and writeups for challenges from **ASIS CTF Quals 2026**.

Each challenge lives in its own directory under its category and contains the original
challenge material, a reproducible solve script, and a step-by-step writeup.

## Writeups

| Challenge | Category | Writeup | Flag |
|---|---|---|---|
| Mic Check | misc / warm-up | [misc/mic-check](misc/mic-check/) &middot; [published](https://claude.ai/code/artifact/96cdf208-78ac-4b31-a496-d065ccd7ea93) | `ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}` |

## Layout

```
<category>/<challenge-slug>/
├── README.md        step-by-step writeup
├── writeup.html     the same writeup as a standalone page
├── challenge.txt    original challenge material, unmodified
└── solve.py         reproducible solver
```

## Running a solver

Solvers target Python 3 and the standard library only:

```console
$ python3 misc/mic-check/solve.py
```
