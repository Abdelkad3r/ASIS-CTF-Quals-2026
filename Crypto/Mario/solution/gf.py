"""GF(16) with modulus x^4+x+1, matching mario.py."""
MOD_POLY = 0x13
MUL = [[0]*16 for _ in range(16)]
for _a in range(16):
    for _b in range(16):
        out, x, y = 0, _a, _b
        while y:
            if y & 1: out ^= x
            y >>= 1; x <<= 1
            if x & 0x10: x ^= MOD_POLY
            x &= 0xF
        MUL[_a][_b] = out

def gf_pow(a, e):
    out, base = 1, a
    while e:
        if e & 1: out = MUL[out][base]
        base = MUL[base][base]; e >>= 1
    return out

def gf_inv(a):
    if a == 0: raise ZeroDivisionError
    return gf_pow(a, 14)

def vec_scale(v, s):
    row = MUL[s]
    return [row[x] for x in v]

def vec_add(a, b):
    return [x ^ y for x, y in zip(a, b)]

def row_reduce(rows):
    mat = [r[:] for r in rows]
    if not mat: return []
    cols = len(mat[0]); rix = 0
    for cix in range(cols):
        pivot = None
        for row in range(rix, len(mat)):
            if mat[row][cix]: pivot = row; break
        if pivot is None: continue
        mat[rix], mat[pivot] = mat[pivot], mat[rix]
        mat[rix] = vec_scale(mat[rix], gf_inv(mat[rix][cix]))
        for row in range(len(mat)):
            if row != rix and mat[row][cix]:
                mat[row] = vec_add(mat[row], vec_scale(mat[rix], mat[row][cix]))
        rix += 1
        if rix == len(mat): break
    return [row for row in mat if any(row)]

def kernel(mat, ncols):
    """Basis of { x : mat . x = 0 } over GF(16)."""
    rr = row_reduce(mat)
    pivots, prow = [], {}
    for r in rr:
        c = next(i for i, v in enumerate(r) if v)
        pivots.append(c); prow[c] = r
    free = [c for c in range(ncols) if c not in prow]
    basis = []
    for f in free:
        v = [0]*ncols; v[f] = 1
        for c in pivots:
            v[c] = prow[c][f]          # char 2: negation is identity
        basis.append(v)
    return basis
