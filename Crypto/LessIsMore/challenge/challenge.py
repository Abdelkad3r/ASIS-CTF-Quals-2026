#!/usr/bin/env python3

import hashlib
import os
import pickle
import random
import struct
import sys
import zlib


P, N, K, T, W = 827, 548, 274, 345, 75
REAL, SLOTS, DECOY = 7, 17, 15
MAGIC = b'ASIS117\x04'


def inv(x):
	return pow(x, P - 2, P)

def red(a):
	a = [x[:] for x in a]
	h, w, r = len(a), len(a[0]), 0
	for c in range(w):
		z = next((i for i in range(r, h) if a[i][c]), None)
		if z is None:
			continue
		a[r], a[z] = a[z], a[r]
		u = inv(a[r][c])
		a[r] = [(x * u) % P for x in a[r]]
		for i in range(h):
			if i != r and a[i][c]:
				u = a[i][c]
				a[i] = [(x - u * y) % P for x, y in zip(a[i], a[r])]
		r += 1
		if r == h:
			break
	return a

def stream(seed, tag, n):
	return hashlib.shake_256(tag + seed).digest(8 * n)

def take(seed, tag, n, k):
	b, a = stream(seed, tag, k), list(range(n))
	for i in range(k):
		j = i + int.from_bytes(b[8 * i:8 * i + 8], 'big') % (n - i)
		a[i], a[j] = a[j], a[i]
	return a[:k]

def base():
	return red([[inv((x - y) % P) for y in range(K, K + N)] for x in range(K)])

def keys(seed, count):
	out = []
	for i in range(count):
		z = hashlib.sha512(seed + i.to_bytes(2, 'big')).digest()
		p = take(z, b'p', N, N)
		d = [int.from_bytes(hashlib.sha256(z + j.to_bytes(2, 'big')).digest()[:4], 'big') % (P - 1) + 1 for j in range(N)]
		out.append((p, d))
	return out

def public(g, item):
	p, d = item
	return red([[(g[i][p[j]] * inv(d[j])) % P for j in range(N)] for i in range(K)])

def tree(seed):
	z, depth = 1, 0
	while z < T:
		z <<= 1
		depth += 1
	a = {1: seed}
	for i in range(1, z):
		a[2 * i] = hashlib.sha256(b'l' + a[i]).digest()
		a[2 * i + 1] = hashlib.sha256(b'r' + a[i]).digest()
	return a, depth

def cover(a, depth, f):
	ans = []

	def go(u, lo, hi):
		if lo >= T:
			return
		end = min(hi, T)
		if all(f[i] == 0 for i in range(lo, end)):
			ans.append([u, a[u]])
			return
		if hi - lo == 1:
			return
		md = (lo + hi) >> 1
		go(u << 1, lo, md)
		go((u << 1) | 1, md, hi)

	go(1, 0, 1 << depth)
	return ans

def chal(cmt, salt, msg):
	b = hashlib.shake_256(b'c' + cmt + salt + msg).digest(8 * (2 * T + 2))
	a = list(range(T))
	for i in range(T - 1, 0, -1):
		j = int.from_bytes(b[8 * (T - 1 - i):8 * (T - i)], 'big') % (i + 1)
		a[i], a[j] = a[j], a[i]
	out = [0] * T
	for i in a[:W]:
		out[i] = int.from_bytes(b[8 * (T + i):8 * (T + i + 1)], 'big') % REAL + 1
	return out

def token(cmt, node):
	return node ^ (int.from_bytes(hashlib.sha256(b'm' + cmt).digest()[:2], 'big') & 1023)

def label(cmt, seed):
	return hashlib.sha256(b't' + cmt + seed).digest()[:8]

def bits(v):
	return sum(1 << x for x in v).to_bytes((N + 7) // 8, 'little')

class Box:
	def __init__(self):
		self.g = base()
		self.master = os.urandom(32)
		self.key = keys(self.master, REAL)
		junk = keys(hashlib.sha512(self.master + b'd').digest(), SLOTS - REAL)
		self.pub = [public(self.g, x) for x in self.key + junk]
		random.shuffle(self.pub)
		self.state = [int.from_bytes(os.urandom(1), 'big') & 1 for _ in range(T)]

	def one(self, msg, serial):
		salt = os.urandom(16)
		root = hashlib.sha256(b'r' + self.master + salt + msg).digest()
		tr, depth = tree(root)
		leaf = [tr[(1 << depth) + i] for i in range(T)]
		cmt = hashlib.sha256(b''.join(hashlib.sha256(x).digest() for x in leaf) + salt + msg).digest()
		b = chal(cmt, salt, msg)
		f = [int(x != 0) for x in b]
		target = (37 * serial + 11) % T
		if int.from_bytes(hashlib.sha256(b'v' + root).digest()[:2], 'big') % 100 < 72:
			f[target] = self.state[target]
		self.state = f
		hit = [i for i in range(T) if b[i] and not f[i]]
		path = [[token(cmt, u), seed] for u, seed in cover(tr, depth, f)]
		used, base0, fake = {u for u, _ in path}, 1 << depth, []
		for i in take(root, b'd', T, DECOY * 4):
			if f[i] and len(fake) < DECOY:
				u, e = base0 + i, token(cmt, base0 + i)
				if e not in used:
					seed = hashlib.sha256(b'q' + root + u.to_bytes(2, 'big')).digest()
					path.append([e, seed])
					fake.append(seed)
					used.add(e)
		invs = []
		for p, _ in self.key:
			q = [0] * N
			for i, j in enumerate(p):
				q[j] = i
			invs.append(q)
		rsp = []
		for i, x in enumerate(b):
			if x:
				v = take(leaf[i], b'n', N, K)
				rsp.append([label(cmt, leaf[i]), bits([invs[x - 1][j] for j in v])])
		if int.from_bytes(hashlib.sha256(b'w' + root).digest()[:2], 'big') % 100 < 14:
			j = int.from_bytes(hashlib.sha256(b'x' + root).digest()[:2], 'big') % len(rsp)
			rsp[j][1] = bits(take(root, b'z', N, K))
		for seed in fake:
			rsp.append([label(cmt, seed), bits(take(seed, b'x', N, K))])
		random.shuffle(path)
		random.shuffle(rsp)
		return {'msg': msg, 'salt': salt, 'cmt': cmt, 'path': path, 'rsp': rsp, '_hit': hit}

def pack_key(key):
	out = bytearray()
	for p, d in key:
		u = inv(d[0])
		for x in p:
			out.extend(x.to_bytes(2, 'little'))
		for x in d:
			out.extend((x * u % P).to_bytes(2, 'little'))
	return bytes(out)

def main():
	from flag import flag
	box = Box()
	records, got, serial = [], [0] * REAL, 0
	while min(got) < 90:
		q = box.one(('m%05d' % serial).encode(), serial)
		b = chal(q['cmt'], q['salt'], q['msg'])
		for i in q.pop('_hit'):
			got[b[i] - 1] += 1
		records.append(q)
		serial += 1
	random.shuffle(records)
	pad = hashlib.shake_256(b'o' + pack_key(box.key)).digest(len(flag))
	sealed = bytes(x ^ y for x, y in zip(flag, pad))
	data = {'pub': {'p': P, 'n': N, 'k': K, 't': T, 'w': W, 'real': REAL,
					'slots': SLOTS, 'g': box.g, 'pub': box.pub},
			'records': records, 'sealed': sealed}
	body = zlib.compress(pickle.dumps(data, protocol=5), 9)
	with open('flag.enc', 'wb') as f:
		f.write(MAGIC + struct.pack('>I', len(body)) + body)
	print('records:', len(records), 'per class:', got, 'bytes:', len(body) + 12)

if __name__ == '__main__':
	main()