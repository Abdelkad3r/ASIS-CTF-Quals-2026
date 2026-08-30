#!/usr/bin/env python3

import numpy as np
import json
import sys
import time
import os
import hashlib
from flag import FLAG

NUM_CHANNELS = 3
DIM = 4
NUM_ROUNDS = 7
MAX_QUERIES_PER_ROUND = 1200
MAX_SEQ_LEN = 20
QUERY_DELAY_SEC = 0.03
POW_DIFFICULTY_BITS = 20
TOLERANCE = 1e-6

def check_proof_of_work():
	prefix = os.urandom(8).hex()
	target_zeros = POW_DIFFICULTY_BITS // 4
	target_prefix = "0" * target_zeros
	print(json.dumps({
		"status": "pow_request",
		"prefix": prefix,
		"difficulty_bits": POW_DIFFICULTY_BITS,
		"prompt": f"Submit nonce such that sha256(prefix + nonce) starts with '{target_prefix}'"
	}))
	sys.stdout.flush()

	line = sys.stdin.readline()
	if not line:
		return False
	nonce = line.strip()
	h = hashlib.sha256(f"{prefix}{nonce}".encode()).hexdigest()
	if h.startswith(target_prefix):
		print(json.dumps({"status": "pow_ok", "message": "Proof of work verified."}))
		sys.stdout.flush()
		return True
	else:
		print(json.dumps({"status": "pow_failed", "message": "Invalid proof of work."}))
		sys.stdout.flush()
		return False

def init_ensemble():
	# Secret Hamiltonian coupling tensors and observable projectors
	coupling_tensors = np.random.uniform(0.5, 2.0, size=(NUM_CHANNELS, DIM, DIM))
	observable_vectors = np.random.uniform(0.5, 2.0, size=(NUM_CHANNELS, DIM))
	return coupling_tensors, observable_vectors

def evaluate_ensemble(X, coupling_tensors, observable_vectors):
	X = np.array(X, dtype=np.float64)
	if X.ndim != 2 or X.shape[1] != DIM or X.shape[0] < 1 or X.shape[0] > MAX_SEQ_LEN:
		return None
	
	x_tail = X[-1]
	total_energy = 0.0
	for c in range(NUM_CHANNELS):
		# Microstate energy potentials under boundary interaction
		microstate_energies = np.einsum('j,jk,ik->i', x_tail, coupling_tensors[c].T, X)
		
		# Partition function with gauge stabilization
		gauge_shift = np.max(microstate_energies)
		boltzmann_weights = np.exp(microstate_energies - gauge_shift)
		partition_fn = np.sum(boltzmann_weights)
		
		# Expected thermal observable across ensemble microstates
		observables = np.dot(X, observable_vectors[c])
		ensemble_expectation = np.dot(boltzmann_weights, observables) / partition_fn
		total_energy += float(ensemble_expectation)
		
	return total_energy

def main():
	print("=== Non-Linear Hamiltonian Authenticator Oracle (H-PRF) ===")
	print(f"Dimension: {DIM}, Rounds to pass: {NUM_ROUNDS}")
	print(f"Max queries per round: {MAX_QUERIES_PER_ROUND}, Max sequence length: {MAX_SEQ_LEN}")
	sys.stdout.flush()

	if not check_proof_of_work():
		return

	print("Commands: 'eval <json_matrix>' or 'challenge'")
	sys.stdout.flush()

	for current_round in range(1, NUM_ROUNDS + 1):
		print(f"\n[+] Entering Round {current_round}/{NUM_ROUNDS}...")
		sys.stdout.flush()
		
		true_A, true_B = init_ensemble()
		queries_used = 0
		round_passed = False
		
		while not round_passed:
			line = sys.stdin.readline()
			if not line:
				return
			line = line.strip()
			if not line:
				continue
				
			parts = line.split(" ", 1)
			cmd = parts[0]
			
			if cmd == "eval":
				if queries_used >= MAX_QUERIES_PER_ROUND:
					print(json.dumps({"status": "error", "message": "Query budget exceeded for this round."}))
					sys.stdout.flush()
					return
				if len(parts) < 2:
					print(json.dumps({"status": "error", "message": "Missing input matrix"}))
				else:
					try:
						X = json.loads(parts[1])
						res = evaluate_ensemble(X, true_A, true_B)
						if res is None:
							print(json.dumps({"status": "error", "message": "Invalid input format or sequence too long"}))
						else:
							queries_used += 1
							if QUERY_DELAY_SEC > 0:
								time.sleep(QUERY_DELAY_SEC)
							print(json.dumps({"status": "ok", "tag": res, "queries_left": MAX_QUERIES_PER_ROUND - queries_used}))
					except Exception as e:
						print(json.dumps({"status": "error", "message": str(e)}))
						
			elif cmd == "challenge":
				lengths = [3, 5, 7, 9, 13, 17]
				test_seqs = [np.random.uniform(-1.0, 1.0, size=(l, DIM)).tolist() for l in lengths]
				true_vals = [evaluate_ensemble(s, true_A, true_B) for s in test_seqs]
				
				print(json.dumps({"status": "challenge", "sequences": test_seqs}))
				sys.stdout.flush()
				
				resp_line = sys.stdin.readline()
				if not resp_line:
					return
				resp_line = resp_line.strip()
				if not resp_line.startswith("verify "):
					print(json.dumps({"status": "error", "message": "Expected 'verify <json_tags>'"}))
					sys.stdout.flush()
					return
					
				try:
					user_preds = json.loads(resp_line[7:])
					if len(user_preds) != len(true_vals):
						print(json.dumps({"status": "error", "message": f"Expected {len(true_vals)} tags"}))
						sys.stdout.flush()
						return
					
					max_err = max(abs(u - t) for u, t in zip(user_preds, true_vals))
					if max_err < TOLERANCE:
						round_passed = True
						if current_round < NUM_ROUNDS:
							print(json.dumps({"status": "ok", "message": f"Round {current_round} authenticated! (max_err={max_err:.2e})"}))
						else:
							print(json.dumps({"status": "ok", "flag": FLAG, "message": f"All rounds authenticated! (max_err={max_err:.2e})"}))
					else:
						print(json.dumps({"status": "error", "message": f"Tag forgery rejected: error {max_err:.4e} exceeds tolerance {TOLERANCE}"}))
						sys.stdout.flush()
						return
				except Exception as e:
					print(json.dumps({"status": "error", "message": str(e)}))
					sys.stdout.flush()
					return
			else:
				print(json.dumps({"status": "error", "message": "Unknown command"}))
			sys.stdout.flush()

	print("\n[+] Authentication verified across all rounds! Congratulations!")
	sys.stdout.flush()

if __name__ == "__main__":
	main()