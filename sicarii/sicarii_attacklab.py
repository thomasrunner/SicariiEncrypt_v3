#!/usr/bin/env python3
# Sicarii AttackLab — dictionary attack (parallel), nonce-reuse scan, mini chosen-PT demo.
# First run
# echo "%PDF This is a fake PDF header" > fake.pdf
# python3 make_ct.py fake.pdf test_ct.bin secret123
# python3 sicarii.py --mode pass --encrypt \
#    --in fake.pdf \
#    --out test_ct.bin \
#    --passcode secret123
# Download file first and place in same folder as sicarii_attacklab.py
# curl -L https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt > rockyou.txt
# How to run python3 sicarii_attacklab.py dict test_ct.bin 25504446 --wordlist rockyou.txt --limit 20000 --threads 8 --skip 2000


import os, sys, argparse, secrets, hashlib
from typing import List, Optional, Iterable, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from math import ceil
from time import perf_counter

try:
    from tqdm import tqdm  # progress bar (pip install tqdm)
except Exception:
    tqdm = None

# --- import your cipher ---
try:
    from sicarii import SicariiCipher       # your current file
except Exception:
    from sicarii_ref import SicariiCipher   # fallback

# ---------- helpers ----------
def sha16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]

def read_bytes(p: str) -> bytes:
    with open(p, "rb") as f: return f.read()

def write_bytes(p: str, b: bytes):
    with open(p, "wb") as f: f.write(b)

# ---------- worker for dict mode ----------
def _try_pw(args: Tuple[bytes, bytes, str]) -> Optional[Tuple[str, bytes]]:
    """Return (pw, pt) if prefix matches, else None."""
    ct, want, pw = args
    try:
        pt = SicariiCipher().decrypt_with_passcode(ct, pw)
        if pt.startswith(want):
            return (pw, pt)
    except Exception:
        pass
    return None

def _batched(seq: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(seq), size):
        yield seq[i:i+size]

# ==============================================================
#  MODE 1: Dictionary / known-plaintext attack (parallel)
# ==============================================================
def attack_dict(ct_path: str,
                prefix_hex: str,
                wordlist: str,
                limit: Optional[int],
                iterations: int,   # kept for CLI parity; not used (cipher has fixed 200k)
                threads: Optional[int],
                skip: int) -> None:

    ct = read_bytes(ct_path)
    ph = prefix_hex[2:] if prefix_hex.lower().startswith("0x") else prefix_hex
    want = bytes.fromhex(ph)

    # read candidates (bounded by --limit) with optional --skip
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        candidates = [ln.strip() for ln in f if ln.strip()]
    if skip:
        candidates = candidates[skip:]
    if limit is not None:
        candidates = candidates[:limit]

    total = len(candidates)
    if total == 0:
        print("[result] No candidates to try.")
        return

    # default threads = CPU cores
    if threads is None or threads <= 0:
        try:
            threads = os.cpu_count() or 1
        except Exception:
            threads = 1

    # prepare job tuples once (cheaper in worker loop)
    jobs = [(ct, want, pw) for pw in candidates]

    print(f"[dict] ciphertext='{ct_path}'  wordlist='{wordlist}'  tries={total}  "
          f"threads={threads}  skip={skip}  known-prefix={prefix_hex}")

    start = perf_counter()

    # Progress bar
    pbar = None
    if tqdm is not None:
        pbar = tqdm(total=total, unit="pw", ncols=80)

    # Strategy: submit in batches to allow early stop on hit
    batch_size = max(512 // threads, 64)   # small but not too chatty
    found: Optional[Tuple[str, bytes]] = None
    tried = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for batch in _batched(jobs, batch_size):
            futures = [ex.submit(_try_pw, j) for j in batch]
            for fut in as_completed(futures):
                res = fut.result()
                tried += 1
                if pbar: pbar.update(1)
                if res is not None:
                    found = res
                    # cancel remaining futures in this batch
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break
            if found is not None:
                break

    if pbar:
        pbar.close()

    elapsed = perf_counter() - start
    rate = tried / elapsed if elapsed > 0 else 0.0

    if found:
        pw, pt = found
        print(f"[HIT] pass='{pw}'  sha16(pt)={sha16(pt)}")
        print(f"[result] Found plausible passcode after {tried} tries "
              f"(elapsed {elapsed:.1f}s, {rate:.2f}/s).")
    else:
        print(f"[result] No passcode found in first {tried} candidates "
              f"(elapsed {elapsed:.1f}s, {rate:.2f}/s).")

# ==============================================================
#  MODE 2: Nonce reuse detector
# ==============================================================
def scan_nonce_reuse(paths: List[str], pass_mode: bool = True) -> None:
    seen = {}
    dupes = []
    for p in paths:
        data = read_bytes(p)
        if pass_mode:
            if len(data) < 40:
                print(f"[warn] {p}: too short"); continue
            key = (data[:16], data[16:40])
        else:
            if len(data) < 24:
                print(f"[warn] {p}: too short"); continue
            key = (data[:24],)
        if key in seen: dupes.append((seen[key], p))
        else: seen[key] = p

    if not dupes:
        print("[result] No nonce reuse detected.")
    else:
        print("[ALERT] Nonce reuse detected:")
        for a, b in dupes: print(f" - {a}  ==  {b}")

# ==============================================================
#  MODE 3: Mini chosen-plaintext demo (N=16)
# ==============================================================
class MiniSicarii:
    N = 16
    def __init__(self, key: bytes):
        self.key = key; self._build()

    def _prf(self, info: bytes, n: int) -> bytes:
        out = bytearray(); ctr = 0
        h = hashlib.sha256
        while len(out) < n:
            out.extend(h(self.key + info + ctr.to_bytes(4,'big')).digest()); ctr += 1
        return bytes(out[:n])

    def _fy(self, rand: bytes) -> list:
        a = list(range(self.N)); rp = 0
        for i in range(self.N-1, 0, -1):
            j = ((rand[rp] << 8) | rand[rp+1]) % (i+1); rp += 2
            a[i], a[j] = a[j], a[i]
        return a

    def _build(self):
        self.row = self._fy(self._prf(b"row", 64))
        inv = [0]*self.N
        for i,v in enumerate(self.row): inv[v] = i
        self.inv = inv
        self.mask = self._fy(self._prf(b"out", 64))

    def encrypt(self, pt: bytes) -> bytes:
        return bytes([ self.mask[self.inv[b % self.N]] for b in pt ])

    def decrypt(self, ct: bytes) -> bytes:
        invmask = [0]*self.N
        for i,v in enumerate(self.mask): invmask[v] = i
        return bytes([ self.row[invmask[b % self.N]] for b in ct ])

def demo_chosen_plaintext() -> None:
    print("[mini] chosen-plaintext learning demo (N=16)")
    import pprint
    key = secrets.token_bytes(32)
    mini = MiniSicarii(key)
    probes = bytes(range(16))
    ct = mini.encrypt(probes)
    comp = {p: c for p, c in zip(probes, ct)}
    pprint.pprint(comp)

# ==============================================================
#  main
# ==============================================================
def main() -> int:
    ap = argparse.ArgumentParser(description="Sicarii AttackLab")
    sub = ap.add_subparsers(dest="cmd")
    def require_cmd(args):
        if args.cmd is None:
            ap.print_help(); sys.exit(2)

    d = sub.add_parser("dict", help="dictionary / known-plaintext attack on passcode mode")
    d.add_argument("ciphertext")
    d.add_argument("prefix_hex", help="known PT prefix as hex (e.g. 25504446 for %PDF)")
    d.add_argument("--wordlist", required=True)
    d.add_argument("--limit", type=int, default=None)
    d.add_argument("--iterations", type=int, default=200_000)  # kept for CLI, not used
    d.add_argument("--threads", type=int, default=0, help="threads to use (default: CPU cores)")
    d.add_argument("--skip", type=int, default=0, help="skip first N candidates (resume)")

    n = sub.add_parser("nr", help="nonce reuse detector")
    n.add_argument("files", nargs="+")
    n.add_argument("--key-mode", action="store_true", help="treat files as key-mode (24B nonce)")

    sub.add_parser("mini", help="mini chosen-plaintext demo (N=16)")

    args = ap.parse_args()
    require_cmd(args)

    if args.cmd == "dict":
        attack_dict(args.ciphertext, args.prefix_hex, args.wordlist,
                    args.limit, args.iterations, args.threads, args.skip)
    elif args.cmd == "nr":
        scan_nonce_reuse(args.files, pass_mode=(not args.key_mode))
    elif args.cmd == "mini":
        demo_chosen_plaintext()
    return 0

if __name__ == "__main__":
    sys.exit(main())
