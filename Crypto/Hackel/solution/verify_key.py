#!/usr/bin/env python3
"""
Hackel - offline verification of the "equivalent key".

Imports the *server's own* checking routines from challenge/hackel.py and runs
our candidate representation through every gate submit_key() applies, so the
key can be proven correct without touching the network.

Usage:  python3 verify_key.py
"""
from __future__ import annotations
import json
import sys
import types
from pathlib import Path

# challenge/hackel.py does `import flag`, which only exists on the server.
sys.modules["flag"] = types.ModuleType("flag")
sys.modules["flag"].get_flag = lambda: "ASIS{local_stub}"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "challenge"))

import hackel as H  # noqa: E402

N = 11
UPPER = ("A", "B", "C", "D", "E")
LOWER = ("a", "b", "c", "d", "e")

# A: 10-cycle on {0..9}, fixing point 10  -> order 10, ODD (sign = (-1)^9)
# B: 11-cycle on all points               -> order 11, transitive
A = H.cyc_perm(N, [tuple(range(10))])
B = H.cyc_perm(N, [tuple(range(11))])
C = H.compose(A, B)                                  # C = AB
D = H.compose(H.invert(A), H.compose(B, C))          # D = A^-1 B C = A^-1 B A B
E = H.compose(C, D)                                  # E = CD

mapping: dict[str, tuple[int, ...]] = {}
for sym, p in zip(UPPER, (A, B, C, D, E)):
    mapping[sym] = p
for sym, p in zip(LOWER, (A, B, C, D, E)):
    mapping[sym] = p                                 # lower := upper

# The relation lists are deterministic given the symbol names, so any seed works.
st = H.init_state(n=N, flag_str="ASIS{local_stub}", seed=1337)

checks = {
    "A^10 == 1":                H.eval_seq(("A",) * 10, mapping, N) == H.perm_id(N),
    "B^11 == 1":                H.eval_seq(("B",) * 11, mapping, N) == H.perm_id(N),
    "upper relations":          H.check_rules(st.rules_upper, mapping, N),
    "lower relations":          H.check_rules(st.rules_lower, mapping, N),
    "mixed relations":          H.check_rules(st.rules_mixed, mapping, N),
    "is_symmetric_gen(upper)":  H.is_symmetric_gen([mapping[s] for s in UPPER], N),
    "is_symmetric_gen(lower)":  H.is_symmetric_gen([mapping[s] for s in LOWER], N),
}

z_span = H.span_group([H.eval_seq(w, mapping, N) for w in st.zero_samples], limit=1000)
o_perms = [H.eval_seq(w, mapping, N) for w in st.one_samples]
checks["one-word outside <a>"] = bool(o_perms) and o_perms[0] not in z_span

width = max(len(k) for k in checks)
for name, ok in checks.items():
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<{width}}")
print(f"\n  |<a>| = {len(z_span)} (expected 10, the order of the 10-cycle)")
print(f"\nALL CHECKS PASS: {all(checks.values())}\n")
print("Payload for menu option [4]:")
print(json.dumps({k: list(v) for k, v in mapping.items()}, separators=(",", ":")))
