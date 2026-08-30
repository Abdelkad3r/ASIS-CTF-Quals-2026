#!/usr/bin/env python3

from __future__ import annotations
import argparse
import io
import json
import random
import socketserver
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from math import factorial
from typing import Sequence, TextIO
import flag

def perm_id(n: int) -> tuple[int, ...]:
	return tuple(range(n))
def perm_val(p: Sequence[int]) -> tuple[int, ...]:
	t = tuple(p)
	if sorted(t) != list(range(len(t))):
		raise ValueError("invalid permutation")
	return t

def compose(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[int, ...]:
	return tuple(b[i] for i in a)

def invert(p: tuple[int, ...]) -> tuple[int, ...]:
	out = [0] * len(p)
	for i, v in enumerate(p):
		out[v] = i
	return tuple(out)

def conj(x: tuple[int, ...], c: tuple[int, ...]) -> tuple[int, ...]:
	return compose(compose(invert(c), x), c)

def cyc_perm(n: int, cycs: list[tuple[int, ...]]) -> tuple[int, ...]:
	out = list(range(n))
	for c in cycs:
		for i, pt in enumerate(c):
			out[pt] = c[(i + 1) % len(c)]
	return perm_val(out)

def span_group(gens: Sequence[tuple[int, ...]], limit: int = 100_000) -> set[tuple[int, ...]]:
	if not gens:
		return set()
	n = len(gens[0])
	all_g = list(dict.fromkeys(list(gens) + [invert(g) for g in gens]))
	seen = {perm_id(n)}
	q = deque([perm_id(n)])
	while q:
		cur = q.popleft()
		for g in all_g:
			nxt = compose(cur, g)
			if nxt not in seen:
				seen.add(nxt)
				if len(seen) > limit:
					return seen
				q.append(nxt)
	return seen

def is_symmetric_gen(gens: Sequence[tuple[int, ...]], n: int) -> bool:
	if not gens or len(gens) < 2:
		return False
	visited = {0}
	q = deque([0])
	while q:
		curr = q.popleft()
		for g in gens:
			nxt = g[curr]
			if nxt not in visited:
				visited.add(nxt)
				q.append(nxt)
	if len(visited) != n:
		return False
	def sign_p(p: tuple[int, ...]) -> int:
		invs = 0
		for i in range(len(p)):
			for j in range(i + 1, len(p)):
				if p[i] > p[j]:
					invs += 1
		return -1 if invs % 2 else 1
	has_odd = any(sign_p(g) == -1 for g in gens)
	return has_odd

def parse_seq(text: str) -> tuple[str, ...]:
	s = text.strip()
	return () if s in {"", "1", "id"} else tuple(s.split() if " " in s else s)

def eval_seq(tokens: tuple[str, ...], mapping: dict[str, tuple[int, ...]], n: int) -> tuple[int, ...]:
	res = perm_id(n)
	for tok in tokens:
		res = compose(res, mapping[tok])
	return res

def check_rules(
	rules: list[tuple[tuple[str, ...], tuple[str, ...]]],
	mapping: dict[str, tuple[int, ...]],
	n: int,
) -> bool:
	for lhs, rhs in rules:
		try:
			if eval_seq(lhs, mapping, n) != eval_seq(rhs, mapping, n):
				return False
		except KeyError:
			return False
	return True

@dataclass(slots=True)
class ChallengeState:
	n: int
	syms_upper: tuple[str, ...]
	syms_lower: tuple[str, ...]
	map_upper: dict[str, tuple[int, ...]]
	map_lower: dict[str, tuple[int, ...]]
	rules_upper: list[tuple[tuple[str, ...], tuple[str, ...]]]
	rules_lower: list[tuple[tuple[str, ...], tuple[str, ...]]]
	rules_mixed: list[tuple[tuple[str, ...], tuple[str, ...]]]
	zero_samples: list[tuple[str, ...]]
	one_samples: list[tuple[str, ...]]
	ciphertexts: list[tuple[str, ...]]
	flag_str: str

def init_state(
	n: int = 11,
	syms_u: Sequence[str] = ("A", "B", "C", "D", "E"),
	syms_l: Sequence[str] = ("a", "b", "c", "d", "e"),
	flag_str: str = "CTF{placeholder}",
	seed: int | None = None,
) -> ChallengeState:
	rng = random.Random(seed)
	u_syms = tuple(syms_u)
	l_syms = tuple(syms_l)
	l_rand = tuple(rng.sample(range(n), n))
	a_l = conj(cyc_perm(n, [tuple(range(10))]), l_rand)
	b_l = conj(cyc_perm(n, [tuple(rng.sample(range(n), n))]), l_rand)
	c_l = compose(a_l, b_l)
	d_l = compose(invert(a_l), compose(b_l, c_l))
	e_l = compose(c_l, d_l)
	map_l = {l_syms[0]: a_l, l_syms[1]: b_l, l_syms[2]: c_l, l_syms[3]: d_l, l_syms[4]: e_l}
	u_rand = tuple(rng.sample(range(n), n))
	A = conj(cyc_perm(n, [tuple(range(10))]), u_rand)
	B = conj(cyc_perm(n, [tuple(rng.sample(range(n), n))]), u_rand)
	C = compose(A, B)
	D = compose(invert(A), compose(B, C))
	E = compose(C, D)
	map_u = {u_syms[0]: A, u_syms[1]: B, u_syms[2]: C, u_syms[3]: D, u_syms[4]: E}
	s0, s1, s2, s3, s4 = u_syms
	rules_u = [
		((s0,) * 10, ()),
		((s1,) * 11, ()),
		((s0, s1), (s2,)),
		((s0, s3), (s1, s2)),
		((s2, s3), (s4,)),
		((s0, s1, s3), (s4,)),
		((s0, s2), (s0, s0, s1)),
		((s3, s4), (s3, s2, s3)),
		((s2, s1), (s0, s1, s1)),
		((s4, s3), (s2, s3, s3)),
	]
	t0, t1, t2, t3, t4 = l_syms
	rules_l = [
		((t0,) * 10, ()),
		((t1,) * 11, ()),
		((t0, t1), (t2,)),
		((t0, t3), (t1, t2)),
		((t2, t3), (t4,)),
		((t0, t1, t3), (t4,)),
		((t0, t2), (t0, t0, t1)),
		((t3, t4), (t3, t2, t3)),
		((t2, t1), (t0, t1, t1)),
		((t4, t3), (t2, t3, t3)),
	]
	rules_m = [
		((s0, t0), (t0, s0)),
		((s0, t1), (t0, t1) + (t0,) * 9 + (s0,)),
		((s1, t1), (t1, s1)),
		((s1, t0), (t1, t0) + (t1,) * 10 + (s1,)),
	]
	zero_words = [(t0,) * rng.randint(1, 9) for _ in range(16)]
	one_words = [(t0,) * rng.randint(0, 9) + (t1,) for _ in range(16)]
	flag_bits = "".join(f"{b:08b}" for b in flag_str.encode("utf-8"))
	flag_words = [
		(t0,) * rng.randint(1, 9) if bit == "0" else (t0,) * rng.randint(0, 9) + (t1,)
		for bit in flag_bits
	]
	return ChallengeState(
		n=n,
		syms_upper=u_syms,
		syms_lower=l_syms,
		map_upper=map_u,
		map_lower=map_l,
		rules_upper=rules_u,
		rules_lower=rules_l,
		rules_mixed=rules_m,
		zero_samples=zero_words,
		one_samples=one_words,
		ciphertexts=flag_words,
		flag_str=flag_str,
	)

BANNER = r"""
========================================================================
  _    _            _        _ 
 | |  | |          | |      | |
 | |__| | __ _  ___| | _____| |
 |  __  |/ _` |/ __| |/ / _ \ |
 | |  | | (_| | (__|   <  __/ |
 |_|  |_|\__,_|\___|_|\_\___|_|
							   
  Hackel Security Service v1.0
========================================================================
"""

class Session:
	def __init__(self, rfile: TextIO, wfile: TextIO, n: int = 11, seed: int | None = None) -> None:
		self.rfile = rfile
		self.wfile = wfile
		self.state = init_state(n=n, flag_str=flag.get_flag(), seed=seed or random.randint(1, 10**8))
	def out(self, msg: str = "") -> None:
		self.wfile.write(msg + "\n")
		self.wfile.flush()
	def get_line(self, max_len: int = 4096) -> str:
		s = self.rfile.readline(max_len)
		if not s:
			raise ConnectionResetError()
		return s.strip()
	def run(self) -> None:
		self.out(BANNER)
		self.out("[*] Connected to Hackel Authentication Core.")
		self.out("")
		while True:
			self.out("---------------------------------------------------")
			self.out("[1] View Public Parameters & Relations")
			self.out("[2] View Training Samples & Encrypted Flag Words")
			self.out("[3] Homomorphic Word Concatenation Oracle")
			self.out("[4] Submit Recovered Equivalent Key (Unlock Flag)")
			self.out("[5] Interactive Speed Challenge (Unlock Flag)")
			self.out("[6] Exit")
			self.out("---------------------------------------------------")
			self.wfile.write("> ")
			self.wfile.flush()
			cmd = self.get_line()
			if cmd == "1":
				self.show_rules()
			elif cmd == "2":
				self.show_samples()
			elif cmd == "3":
				self.oracle()
			elif cmd == "4":
				if self.submit_key():
					break
			elif cmd == "5":
				if self.speed_test():
					break
			elif cmd == "6":
				self.out("Goodbye!")
				break
			else:
				self.out("[-] Invalid option.")
	def show_rules(self) -> None:
		self.out(f"[+] Parameters: degree n = {self.state.n}")
		self.out(f"[+] Upper symbols: {list(self.state.syms_upper)}")
		self.out(f"[+] Lower symbols: {list(self.state.syms_lower)}")
		self.out("[+] Upper Relations:")
		for lhs, rhs in self.state.rules_upper:
			self.out(f"    {''.join(lhs) or '1'} = {''.join(rhs) or '1'}")
		self.out("[+] Lower Relations:")
		for lhs, rhs in self.state.rules_lower:
			self.out(f"    {''.join(lhs) or '1'} = {''.join(rhs) or '1'}")
		self.out("[+] Mixed Relations:")
		for lhs, rhs in self.state.rules_mixed:
			self.out(f"    {''.join(lhs) or '1'} = {''.join(rhs) or '1'}")
	def show_samples(self) -> None:
		self.out(f"[+] Zero Training Words ({len(self.state.zero_samples)}):")
		self.out("    " + ", ".join("".join(w) or "1" for w in self.state.zero_samples))
		self.out(f"[+] One Training Words ({len(self.state.one_samples)}):")
		self.out("    " + ", ".join("".join(w) or "1" for w in self.state.one_samples))
		self.out(f"[+] Encrypted Flag Words ({len(self.state.ciphertexts)}):")
		self.out("    " + ", ".join("".join(w) or "1" for w in self.state.ciphertexts))
	def oracle(self) -> None:
		self.out("Enter Word 1:")
		w1 = parse_seq(self.get_line())
		self.out("Enter Word 2:")
		w2 = parse_seq(self.get_line())
		self.out(f"[+] Homomorphic Product Word: {''.join(w1 + w2) or '1'}")
	def submit_key(self) -> bool:
		self.out("Submit JSON assignment for all generators {'A': [..], ..., 'a': [..]}:")
		raw = self.get_line(max_len=8192)
		try:
			data = json.loads(raw)
			if not isinstance(data, dict):
				self.out("[-] JSON must be a dict.")
				return False
			mapping = {}
			for sym in list(self.state.syms_upper) + list(self.state.syms_lower):
				if sym not in data:
					self.out(f"[-] Missing: {sym}")
					return False
				mapping[sym] = perm_val(data[sym])
			n = self.state.n
			up_g = [mapping[s] for s in self.state.syms_upper]
			low_g = [mapping[s] for s in self.state.syms_lower]
			if not is_symmetric_gen(up_g, n) or not is_symmetric_gen(low_g, n):
				self.out("[-] Generators validation failed.")
				return False
			if (
				not check_rules(self.state.rules_upper, mapping, n)
				or not check_rules(self.state.rules_lower, mapping, n)
				or not check_rules(self.state.rules_mixed, mapping, n)
			):
				self.out("[-] Relations check failed.")
				return False
			z_perms = [eval_seq(w, mapping, n) for w in self.state.zero_samples]
			z_span = span_group(z_perms, limit=1000)
			o_perms = [eval_seq(w, mapping, n) for w in self.state.one_samples]
			if not o_perms or o_perms[0] in z_span:
				self.out("[-] Key consistency verification failed.")
				return False
			self.out("[+] KEY ACCEPTED! Verification successful.")
			self.out(f"[+] FLAG: {self.state.flag_str}")
			return True
		except Exception as exc:
			self.out(f"[-] Invalid format: {exc}")
			return False
	def speed_test(self) -> bool:
		self.out("[+] Interactive Speed Challenge")
		self.out("[+] Classify 16 live words as '0' or '1' within 5.0 seconds.")
		rng = random.Random()
		bits = "".join(str(rng.randint(0, 1)) for _ in range(16))
		l0, l1 = self.state.syms_lower[0], self.state.syms_lower[1]
		words = [
			l0 * rng.randint(1, 9)
			if b == "0"
			else l0 * rng.randint(0, 9) + l1
			for b in bits
		]
		self.out("Challenge Words: " + " ".join(words))
		self.wfile.write("Your Classification Bits: ")
		self.wfile.flush()
		t0 = time.time()
		ans = self.get_line()
		if time.time() - t0 > 5.0:
			self.out("[-] Time limit exceeded.")
			return False
		if ans != bits:
			self.out("[-] Incorrect classifications.")
			return False
		self.out("[+] CHALLENGE PASSED!")
		self.out(f"[+] FLAG: {self.state.flag_str}")
		return True

class Handler(socketserver.StreamRequestHandler):
	timeout = 60
	def handle(self) -> None:
		try:
			r = io.TextIOWrapper(self.rfile, encoding="utf-8", newline="\n", write_through=True)
			w = io.TextIOWrapper(self.wfile, encoding="utf-8", newline="\n", write_through=True)
			Session(r, w, n=11).run()
		except (ConnectionResetError, BrokenPipeError, TimeoutError):
			pass
		except Exception as exc:
			try:
				self.wfile.write(f"\n[-] Fatal Error: {exc}\n".encode("utf-8"))
			except Exception:
				pass

class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True
	daemon_threads = True

def main() -> None:
	parser = argparse.ArgumentParser(description="Hackel Challenge Server")
	parser.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
	parser.add_argument("--port", type=int, default=1337, help="Port (default: 1337)")
	args = parser.parse_args()
	print(f"[*] Starting Hackel server on {args.host}:{args.port}...")
	with TCPServer((args.host, args.port), Handler) as s:
		try:
			s.serve_forever()
		except KeyboardInterrupt:
			print("\n[*] Shutting down.")

if __name__ == "__main__":
	main()