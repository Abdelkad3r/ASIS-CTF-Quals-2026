#!/usr/bin/env python3

import base64
import hashlib
import json
import secrets
import zlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from flag import flag


_n = 32
_l = ((16, 2), (17, 2), (18, 1))
_d = 34
_z = b"linchan/v2"

def _r(A):
	P = {}
	for x in A:
		while x:
			i = x.bit_length() - 1
			if i in P:
				x ^= P[i]
			else:
				P[i] = x
				break
	return len(P)

def _v(A):
	return sum(x << (_n * i) for i, x in enumerate(A))

def _a(A, B):
	return [x ^ y for x, y in zip(A, B)]

def _m(A, B):
	R = []
	for x in A:
		y = 0
		while x:
			b = x & -x
			y ^= B[b.bit_length() - 1]
			x ^= b
		R.append(y)
	return R

def _t(A):
	R = [0] * _n
	for i, x in enumerate(A):
		while x:
			b = x & -x
			R[b.bit_length() - 1] |= 1 << i
			x ^= b
	return R

def _i(A):
	R = [x | (1 << (_n + i)) for i, x in enumerate(A)]
	for i in range(_n):
		j = next((j for j in range(i, _n) if (R[j] >> i) & 1), None)
		if j is None:
			raise ValueError
		R[i], R[j] = R[j], R[i]
		for j in range(_n):
			if j != i and ((R[j] >> i) & 1):
				R[j] ^= R[i]
	return [x >> _n for x in R]

def _g():
	while True:
		A = [secrets.randbits(_n) for _ in range(_n)]
		if _r(A) == _n:
			return A

def _h():
	while True:
		A = [secrets.randbits(25) for _ in range(_n)]
		B = [secrets.randbits(_n) for _ in range(25)]
		X = _m(A, B)
		if _r(X) == 25:
			return X

def _c(x, B):
	R = [0] * _n
	while x:
		b = x & -x
		R = _a(R, B[b.bit_length() - 1])
		x ^= b
	return R

def _u(m):
	B = []
	while len(B) < m:
		x = secrets.randbits(m)
		if _r(B + [x]) == len(B) + 1:
			B.append(x)
	return B

def _b(m, q=False):
	B = [_h(), _h()] if q else []
	while len(B) < m:
		X = [secrets.randbits(_n) for _ in range(_n)]
		if _r([_v(A) for A in B] + [_v(X)]) == len(B) + 1:
			B.append(X)
	return B

def _o(B):
	B = [_c(x, B) for x in _u(len(B))]
	return [_t(A) for A in B] if secrets.randbits(1) else B

def _p(A):
	return b"".join(x.to_bytes(4, "little") for x in A)

def _f(S):
	T = _i(S)
	return min(_p(S), _p(T), _p(_t(S)), _p(_t(T)))

def _k(S):
	X = b"".join(sorted(_f(A) for A in S))
	return hashlib.shake_256(b"linchan-v2/key\0" + X).digest(32)

def _e(B):
	return base64.b85encode(b"".join(_p(A) for A in B)).decode()

def main():
	B, K = [], []
	for m, c in _l:
		for _ in range(c):
			C, S = _b(m, True), _g()
			T = _i(S)
			D = [_m(_m(S, A), T) for A in C]
			B += [(m, _o(C)), (m, _o(D))]
			K.append(S)
		for _ in range(_d):
			B.append((m, _o(_b(m))))
	secrets.SystemRandom().shuffle(B)
	msg = flag if isinstance(flag, bytes) else str(flag).encode()
	nonce = secrets.token_bytes(12)
	ct = nonce + ChaCha20Poly1305(_k(K)).encrypt(nonce, msg, _z)
	X = {
		"v": 2,
		"n": _n,
		"ct": base64.b85encode(ct).decode(),
		"boxes": [{"m": m, "x": _e(C)} for m, C in B],
	}
	raw = json.dumps(X, separators=(",", ":")).encode()
	open("output.txt", "wb").write(base64.b85encode(zlib.compress(raw, 9)))


if __name__ == "__main__":
	main()