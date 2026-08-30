#!/usr/bin/env python3
"""
Headache -- ASIS CTF Quals 2026.

The oracle is a softmax-attention "PRF":
    T(X) = sum_c  softmax_i( X[i] . (A[c] @ x_tail) )  .  ( X[i] . B[c] )
with x_tail = X[-1], c over 3 channels, A[c] a 4x4 matrix, B[c] a length-4 vector,
all entries ~ U(0.5, 2.0), fresh every round.

To forge tags for random challenge sequences we recover a functionally-equivalent
(A, B) from 150 chosen eval() queries. Since the oracle is noise-free, ANY
parameter set reproducing the tags on generic sequences reproduces T everywhere,
so we do not need the true secret -- only a functional twin. We fit all 60
parameters by Levenberg-Marquardt with an exact analytic Jacobian, restarting
from the known U(0.5,2) prior until the residual collapses to ~1e-15 (B enters
linearly, which makes its Jacobian block trivial and the fit well conditioned).
Restarts run in parallel across CPU cores; challenge queries are pipelined to
stay inside the per-connection time budget. Then we compute T for the challenge
sequences directly.

Usage:  python3.13 solve.py [host] [port]    (default: the remote service)
"""
import sys, json, socket, subprocess, time, hashlib, itertools
import numpy as np
from scipy.optimize import least_squares

NC, DIM = 3, 4
NA = NC*DIM*DIM; NPARAM = NA + NC*DIM
NEG = -1e30

# ----------------------------- model ------------------------------------ #
def unpack(p): return p[:NA].reshape(NC,DIM,DIM), p[NA:].reshape(NC,DIM)

def Tval(X, A, B):
    X = np.asarray(X, float); xt = X[-1]; tot = 0.0
    for c in range(NC):
        e = X @ (A[c] @ xt); e -= e.max(); w = np.exp(e); w /= w.sum()
        tot += float(w @ (X @ B[c]))
    return tot

def pack(Xs):
    N = len(Xs); Lmax = max(len(X) for X in Xs)
    Xp = np.zeros((N,Lmax,DIM)); mask = np.zeros((N,Lmax),bool); xt = np.zeros((N,DIM))
    for n,X in enumerate(Xs):
        X = np.asarray(X,float); L=len(X); Xp[n,:L]=X; mask[n,:L]=True; xt[n]=X[-1]
    return Xp, mask, xt

class Model:
    def __init__(self, Xs, tags):
        self.Xp,self.mask,self.xt = pack(Xs); self.tags = np.asarray(tags,float)
    def rj(self, p):
        A,B = unpack(p); Xp,mask,xt = self.Xp,self.mask,self.xt
        N,Lmax,_ = Xp.shape; T=np.zeros(N); J=np.zeros((N,NPARAM))
        for c in range(NC):
            Mc = xt @ A[c].T
            E = np.einsum('nik,nk->ni', Xp, Mc); E = np.where(mask,E,NEG)
            E -= E.max(axis=1,keepdims=True); W = np.exp(E); W = np.where(mask,W,0.0)
            W /= W.sum(axis=1,keepdims=True)
            o = np.einsum('nik,k->ni', Xp, B[c]); val = np.einsum('ni,ni->n', W, o); T += val
            J[:, NA+c*DIM:NA+(c+1)*DIM] = np.einsum('ni,nik->nk', W, Xp)
            g = W*(o-val[:,None]); XTg = np.einsum('ni,nij->nj', g, Xp)
            J[:, c*DIM*DIM:(c+1)*DIM*DIM] = np.einsum('nj,nk->njk', XTg, xt).reshape(N,DIM*DIM)
        return T-self.tags, J

def fit(Xs, tags, restarts=60, tol=1e-9, seed=0):
    m = Model(Xs, tags); rng = np.random.default_rng(seed); best=None
    for _ in range(restarts):
        p0 = rng.uniform(0.5,2.0,NPARAM)
        sol = least_squares(lambda p:m.rj(p)[0], p0, jac=lambda p:m.rj(p)[1],
                            method='lm', max_nfev=600, xtol=1e-15, ftol=1e-15, gtol=1e-15)
        rmse = float(np.sqrt(np.mean(sol.fun**2)))
        if best is None or rmse<best[0]: best=(rmse,sol.x)
        if rmse<tol: break
    return best


# ------------------------- parallel multi-start ------------------------- #
_GM=None
def _init_worker(Xs, tags):
    global _GM; _GM=Model(Xs, tags)
def _one_restart(seed):
    rng=np.random.default_rng(seed); p0=rng.uniform(0.5,2.0,NPARAM)
    sol=least_squares(lambda p:_GM.rj(p)[0], p0, jac=lambda p:_GM.rj(p)[1],
                      method='lm', max_nfev=600, xtol=1e-15, ftol=1e-15, gtol=1e-15)
    return float(np.sqrt(np.mean(sol.fun**2))), sol.x

def fit_parallel(Xs, tags, max_restarts=240, tol=1e-7, workers=12, base=0):
    import multiprocessing as mp
    best=None
    with mp.Pool(workers, initializer=_init_worker, initargs=(Xs, np.asarray(tags,float))) as pool:
        it=pool.imap_unordered(_one_restart, range(base, base+max_restarts))
        for rmse,x in it:
            if best is None or rmse<best[0]: best=(rmse,x)
            if rmse<tol:
                pool.terminate(); break
    return best

# ----------------------------- transport -------------------------------- #
class Tube:
    def __init__(self, sock=None, proc=None):
        self.proc=proc
        if sock is not None:
            self.rf=sock.makefile('r'); self.wf=sock.makefile('w')
        else:
            self.rf=proc.stdout; self.wf=proc.stdin
    def readline(self):
        return self.rf.readline()
    def readjson(self):
        while True:
            line=self.rf.readline()
            if not line: raise EOFError
            line=line.strip()
            if not line: continue
            try: return json.loads(line)
            except json.JSONDecodeError:
                # server also prints plain banner lines; skip them
                continue
    def send(self, s):
        self.wf.write(s+"\n"); self.wf.flush()

def solve_pow(prefix, bits):
    tgt="0"*(bits//4)
    for n in itertools.count():
        if hashlib.sha256(f"{prefix}{n}".encode()).hexdigest().startswith(tgt):
            return str(n)

def make_queries(rng, n=200):
    Xs=[]; lens=[2,3,4,5,6,7,8,9,11,13,15,17]
    for _ in range(n):
        L=int(lens[rng.integers(len(lens))]); s=float([1.0,1.0,1.5,2.5][rng.integers(4)])
        Xs.append((rng.uniform(-1,1,(L,DIM))*s))
    return Xs

def main():
    host = sys.argv[1] if len(sys.argv)>1 else "65.109.208.91"
    port = int(sys.argv[2]) if len(sys.argv)>2 else 1337
    if host=="LOCAL":
        proc=subprocess.Popen(["python3.13","server.py"], cwd="Headache",
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        t=Tube(proc=proc)
    else:
        s=socket.create_connection((host,port),timeout=60); t=Tube(sock=s)

    # ---- proof of work ----
    while True:
        j=t.readjson()
        if j.get("status")=="pow_request":
            print("[*] solving PoW", j["difficulty_bits"],"bits",flush=True)
            t.send(solve_pow(j["prefix"], j["difficulty_bits"])); continue
        if j.get("status")=="pow_ok":
            print("[*] PoW ok",flush=True); break
        if j.get("status")=="pow_failed":
            print("[-] PoW failed"); return

    rng=np.random.default_rng(1234)
    ROUNDS=7
    for rnd in range(1,ROUNDS+1):
        # collect eval queries -- PIPELINED (send all, then read all) to hide RTT
        Xs=make_queries(rng, 150)
        for X in Xs:
            t.wf.write("eval "+json.dumps(X.tolist())+"\n")
        t.wf.flush()
        tags=[]
        for _ in Xs:
            j=t.readjson()
            if j.get("status")!="ok":
                print("[-] eval err:",j); return
            tags.append(j["tag"])
        t0=time.time(); rmse,p=fit_parallel(Xs,np.array(tags),max_restarts=240,tol=1e-7,workers=14,base=rnd*1000)
        A,B=unpack(p)
        print(f"[*] round {rnd}: fit rmse={rmse:.2e} ({time.time()-t0:.1f}s)",flush=True)
        # challenge
        t.send("challenge")
        j=t.readjson()
        assert j.get("status")=="challenge", j
        seqs=j["sequences"]
        preds=[Tval(np.array(s), A, B) for s in seqs]
        t.send("verify "+json.dumps(preds))
        j=t.readjson()
        print(f"[*] round {rnd} -> {j.get('status')}: {j.get('message','')}",flush=True)
        if "flag" in j:
            print("\n[+] FLAG:", j["flag"]); return
        if j.get("status")!="ok":
            print("[-] round failed:",j); return
    # some servers print a final line
    try:
        print(t.readline().strip())
    except Exception: pass

if __name__=="__main__":
    main()
