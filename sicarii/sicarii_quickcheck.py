#!/usr/bin/env python3
# Sicarii quickcheck: lightweight local randomness & avalanche tests.
# Works with sicarii_v3.py (preferred) or sicarii_ref.py fallback.
# How to use
# python3 sicarii_quickcheck.py --mode pass --mb 8
# or
# python3 sicarii_quickcheck.py --mode key --mb 8


import os, sys, argparse, secrets, shutil, subprocess, math, random
from collections import Counter

# --- import your class ---
Cipher = None
for modname in ("sicarii_v3", "sicarii_ref", "sicarii"):
    try:
        m = __import__(modname)
        Cipher = m.SicariiCipher
        break
    except Exception:
        continue
if Cipher is None:
    print("Could not import SicariiCipher from sicarii_v3 / sicarii_ref / sicarii", file=sys.stderr)
    sys.exit(1)

# put near the top (after imports)
try:
    (1).bit_count()
    def bitcount8(x: int) -> int: return x.bit_count()
except AttributeError:
    _POPC8 = [bin(i).count("1") for i in range(256)]
    def bitcount8(x: int) -> int: return _POPC8[x & 0xFF]

MAGIC = b"SC3"
FLAG_MAC = 0x01

def parse_header(ct: bytes, pass_mode: bool, legacy: bool):
    if not legacy and len(ct) >= 5 and ct[:3] == MAGIC:
        flags = ct[4]
        off = 5
        if pass_mode:
            if len(ct) < off + 16: return None
            off += 16  # salt
        if len(ct) < off + 24: return None
        off += 24  # nonce
        mac_len = 32 if (flags & FLAG_MAC) else 0
        return ("sc3", off, mac_len)
    # legacy layout: pass = [16 salt | 24 nonce | body], key = [24 nonce | body]
    if pass_mode:
        return ("legacy", 40, 0) if len(ct) >= 40 else None
    else:
        return ("legacy", 24, 0) if len(ct) >= 24 else None

def get_body(ct: bytes, pass_mode: bool, legacy: bool) -> bytes:
    h = parse_header(ct, pass_mode, legacy)
    if h is None:
        raise ValueError("Not an SC3 ciphertext or too short")
    _, off, mac_len = h
    return ct[off:] if mac_len == 0 else ct[off:-mac_len]


# ---------- simple stats ----------
def monobit(bits: bytes):
    # Count 1-bits vs 0-bits
    ones = 0
    for b in bits:
        ones += bin(b).count("1")
    nbits = 8 * len(bits)
    zeros = nbits - ones
    p1 = ones / nbits if nbits else 0.5
    return {"ones": ones, "zeros": zeros, "p1": p1}

def chi_square_bytes(data: bytes):
    n = len(data)
    if n == 0: return {"chi2": 0.0, "p": 1.0}
    c = Counter(data)
    expected = n / 256.0
    chi2 = sum(((c.get(i,0) - expected)**2)/expected for i in range(256))
    # df = 255; rough two-sided tail via normal approx (ok as a sanity check)
    # We’ll just report chi2; typical "random" should be near 255 ± ~sqrt(510) ~ 22.6
    return {"chi2": chi2}

def serial_correlation(data: bytes):
    n = len(data)
    if n < 2: return {"corr": 0.0}
    s1 = sum(data)
    s2 = sum(x*x for x in data)
    s12 = sum(data[i]*data[(i+1)%n] for i in range(n))  # wrap
    num = n*s12 - s1*s1
    den = n*s2 - s1*s1
    corr = (num/den) if den != 0 else 0.0
    return {"corr": corr}

def runs_test_bits(data: bytes):
    # Translate to bitstring runs
    prev = None
    runs = 0
    ones = zeros = 0
    for b in data:
        for k in range(8):
            bit = (b >> k) & 1
            ones += bit
            zeros += (1-bit)
            if prev is None or bit != prev:
                runs += 1
            prev = bit
    nbits = 8*len(data)
    if nbits == 0: return {"runs": 0, "z": 0.0}
    pi = ones/nbits
    # Wald–Wolfowitz runs test (approx)
    expected = 2*nbits*pi*(1-pi) + 1
    var = 2*nbits*pi*(1-pi)*(2*nbits*pi*(1-pi) - 1)/(nbits-1) if nbits > 1 else 1
    z = (runs - expected)/math.sqrt(var) if var > 0 else 0.0
    return {"runs": runs, "z": z, "pi": pi}

def shannon_entropy(data: bytes):
    n = len(data)
    if n == 0: return {"H": 0.0}
    c = Counter(data)
    H = 0.0
    for v in c.values():
        p = v/n
        H -= p * math.log2(p)
    # for uniform over 256, H≈8.0 bits/byte
    return {"H": H}

# ---------- avalanche (passcode 1-bit tweak) ----------
def avalanche_pass(passcode: str, length: int, legacy: bool):
    s = Cipher()
    m = b"\xAA" * length
    # fixed salt/nonce only if your class supports deterministic hooks; otherwise we just use random
    try:
        # best-effort: try kwargs; fall back to plain call
        salt  = bytes.fromhex("00"*16)
        nonce = bytes.fromhex("11"*24)
        ct1 = s.encrypt_with_passcode(m, passcode)  # legacy has no deterministic args
        ct2 = s.encrypt_with_passcode(m, passcode[:-1] + chr(ord(passcode[-1]) ^ 1))
        b1 = get_body(ct1, True, legacy); b2 = get_body(ct2, True, legacy)
    except TypeError:
        ct1 = s.encrypt_with_passcode(m, passcode)
        ct2 = s.encrypt_with_passcode(m, passcode[:-1] + chr(ord(passcode[-1]) ^ 1))
        b1 = get_body(ct1, True, legacy); b2 = get_body(ct2, True, legacy)

    hd_bits = 0
    L = min(len(b1), len(b2))
    for x, y in zip(b1[:L], b2[:L]):
        hd_bits += bitcount8(x ^ y)  # instead of (x ^ y).bit_count()
    ratio = hd_bits / (8*L) if L else 0.0
    return {"ratio": ratio, "len": L}

# ---------- external suites ----------
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run_dieharder(stream: bytes):
    if not have("dieharder"):
        return "[skip] dieharder not found"
    try:
        p = subprocess.run(["dieharder", "-a", "-g", "200"], input=stream, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        # Print only a compact tail summary lines
        out = p.stdout.decode("utf-8", errors="ignore")
        tail = "\n".join([ln for ln in out.splitlines() if "PASSED" in ln or "WEAK" in ln or "FAILED" in ln][-10:])
        return tail or "[dieharder ran; no summary lines captured]"
    except Exception as e:
        return f"[dieharder error] {e}"

def run_practrand(stream: bytes):
    # PractRand binary often called RNG_test or RNG_test.exe
    cmd = shutil.which("RNG_test") or shutil.which("rng_test")
    if not cmd:
        return "[skip] PractRand (RNG_test) not found"
    try:
        p = subprocess.run([cmd, "stdin"], input=stream, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        # Return last ~15 lines
        out = p.stdout.decode("utf-8", errors="ignore")
        return "\n".join(out.splitlines()[-15:])
    except Exception as e:
        return f"[PractRand error] {e}"

# ---------- keystream generator using ciphertext body ----------
def generate_ct_body_bytes(mode: str, total_bytes: int, mac: bool=False, legacy: bool=False) -> bytes:
    s = Cipher()
    chunk = 1_000_000
    out = bytearray()
    if mode == "pass":
        pw = "correct horse battery staple"
        while len(out) < total_bytes:
            ct = s.encrypt_with_passcode(b"\x00"*chunk, pw)  # your legacy emits salt+nonce only
            out.extend(get_body(ct, True, legacy))
    else:
        key = list(os.urandom(512))
        while len(out) < total_bytes:
            ct = s.encrypt_with_key(b"\x00"*chunk, key)
            out.extend(get_body(ct, False, legacy))
    return bytes(out[:total_bytes])


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Sicarii quick randomness & avalanche tests")
    ap.add_argument("--mode", choices=["pass","key"], default="pass", help="use passcode or key path")
    ap.add_argument("--mb", type=int, default=8, help="megabytes of stream for stats (default 8)")
    ap.add_argument("--mac", action="store_true", help="encrypt with AEAD tag (EtM); stats still use CT body")
    ap.add_argument("--avalanche-len", type=int, default=64*1024, help="bytes for avalanche test (default 64KB)")
    ap.add_argument("--legacy", action="store_true", help="ciphertext is legacy layout (no SC3 header)")

    args = ap.parse_args()

    total = args.mb * 1024 * 1024
    print(f"Sicarii quickcheck | mode={args.mode}  bytes={total:,}  mac={args.mac}")

    # 1) Generate ciphertext body bytes (acts like a keystream sample)
    stream = generate_ct_body_bytes(args.mode, total, mac=args.mac, legacy=args.legacy)
    print(f"Collected {len(stream):,} bytes of CT body.")

    # --- sanity check against os.urandom ---
    print("\n[ Sanity: os.urandom χ² ]")
    import collections
    def chi2(d: bytes):
        n=len(d); c=collections.Counter(d); exp=n/256.0
        return sum(((c.get(i,0)-exp)**2)/exp for i in range(256))
    u = os.urandom(len(stream))
    print("os.urandom chi2:", f"{chi2(u):.1f}")
    print("sicarii   chi2:", f"{chi2(stream):.1f}")

    # --- bucket extremes ---
    cnt = collections.Counter(stream)
    top10 = cnt.most_common(10)
    bot10 = sorted(cnt.items(), key=lambda kv: kv[1])[:10]
    print("\n[ Bucket extremes ]")
    print("Top 10:", top10)
    print("Bot 10:", bot10)
    print("Distinct byte values seen:", len(cnt))

    # Which byte is missing?
    missing = [b for b in range(256) if b not in cnt]
    print("Missing byte:", missing)

    # Try key mode too (single deterministic message to simplify)
    from collections import Counter
    s2 = Cipher()
    msg = b"\x00" * len(stream)
    nonce = bytes.fromhex("22"*24)
    key = list(os.urandom(512))
    ctk = s2.encrypt_with_key(msg, key)
    body_k = get_body(ctk, False, False)
    cnt_k = Counter(body_k)
    print("\n[ Key mode snapshot ]")
    print("Distinct:", len(cnt_k))
    print("Chi2(key mode):", f"{sum(((cnt_k.get(i,0)-len(body_k)/256)**2)/(len(body_k)/256) for i in range(256)):.1f}")
    print("Missing in key mode:", [b for b in range(256) if b not in cnt_k][:10])



    # 2) Built-in stats
    m = monobit(stream); c2 = chi_square_bytes(stream); sc = serial_correlation(stream)
    rt = runs_test_bits(stream); H = shannon_entropy(stream)

    print("\n[ Built-in stats ]")
    print(f"Monobit:   ones={m['ones']:,} zeros={m['zeros']:,} p1={m['p1']:.4f} (expect ~0.5)")
    print(f"Chi-square bytes: chi2={c2['chi2']:.1f} (expect ~255 ± ~23 for uniform)")
    print(f"Serial corr: corr={sc['corr']:.4f} (expect ~0)")
    print(f"Runs test:  runs={rt['runs']:,} z={rt['z']:.2f} pi={rt['pi']:.4f}")
    print(f"Entropy:    H≈{H['H']:.3f} bits/byte (max 8.0)")

    # 3) Avalanche
    try:
        av = avalanche_pass("correct horse battery staple", min(64*1024, total), args.legacy)
        print("\n[ Avalanche (passcode 1-bit tweak) ]")
        print(f"Hamming ratio ≈ {100*av['ratio']:.2f}% over {av['len']:,} bytes (expect ~50%)")
    except Exception as e:
        print("\n[ Avalanche ] skipped:", e)

    # 4) External suites if available
    if have("dieharder"):
        print("\n[ Dieharder summary ]")
        print(run_dieharder(stream))
    else:
        print("\n[ Dieharder ] not found (brew install dieharder)")

    if shutil.which("RNG_test") or shutil.which("rng_test"):
        print("\n[ PractRand tail ]")
        print(run_practrand(stream))
    else:
        print("\n[ PractRand ] RNG_test not found")

    # --- sanity check against os.urandom ---
    print("\n[ Sanity: os.urandom χ² ]")
    u = os.urandom(len(stream))
    from collections import Counter
    def chi2(d):
        n=len(d); c=Counter(d); exp=n/256.0
        return sum(((c.get(i,0)-exp)**2)/exp for i in range(256))
    print("os.urandom chi2:", f"{chi2(u):.1f}")
    print("sicarii   chi2:", f"{chi2(stream):.1f}")

if __name__ == "__main__":
    sys.exit(main())



