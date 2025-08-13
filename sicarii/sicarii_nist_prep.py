#!/usr/bin/env python3
"""
sicarii_nist_prep.py
Generate NIST STS-compatible ASCII bit files (epsilon*) from Sicarii ciphertext bodies.

Usage examples:
  python3 sicarii_nist_prep.py --legacy --mode pass --files 10 --mbits 10
  python3 sicarii_nist_prep.py --legacy --mode key  --files 20 --mbits 1
"""
import os, sys, argparse, secrets

# ---- import your cipher ----
Cipher = None
for modname in ("sicarii", "sicarii_v3", "sicarii_ref"):
    try:
        m = __import__(modname)
        Cipher = m.SicariiCipher
        break
    except Exception:
        continue
if Cipher is None:
    print("Could not import SicariiCipher (tried sicarii / sicarii_v3 / sicarii_ref).", file=sys.stderr)
    sys.exit(1)

MAGIC = b"SC3"; FLAG_MAC = 0x01

def parse_header(ct: bytes, pass_mode: bool, legacy: bool):
    if not legacy and len(ct) >= 5 and ct[:3] == MAGIC:
        ver, flags = ct[3], ct[4]
        off = 5
        if pass_mode:
            if len(ct) < off + 16: return None
            off += 16
        if len(ct) < off + 24: return None
        off += 24
        mac_len = 32 if (flags & FLAG_MAC) else 0
        return ("sc3", off, mac_len)
    # Legacy: pass [16 salt|24 nonce|body], key [24 nonce|body]
    if pass_mode:
        return ("legacy", 40, 0) if len(ct) >= 40 else None
    else:
        return ("legacy", 24, 0) if len(ct) >= 24 else None

def get_body(ct: bytes, pass_mode: bool, legacy: bool) -> bytes:
    h = parse_header(ct, pass_mode, legacy)
    if h is None: raise ValueError("Not an SC3 ciphertext or too short")
    _, off, mac_len = h
    return ct[off:] if mac_len == 0 else ct[off:-mac_len]

# Fast byte->bits table (ASCII '0'/'1')
_B2S = [format(i, "08b") for i in range(256)]

def bytes_to_bitstring(b: bytes) -> str:
    # join via list comprehension for speed
    return "".join(_B2S[x] for x in b)

def make_bitfile(mode: str, nbits: int, legacy: bool, idx: int, outdir: str):
    s = Cipher()
    need_bytes = (nbits + 7) // 8
    chunk = 1_000_000
    buf = bytearray()
    if mode == "pass":
        pw = "correct horse battery staple"
        while len(buf) < need_bytes:
            n = min(chunk, need_bytes - len(buf))
            ct = s.encrypt_with_passcode(b"\x00"*n, pw)
            buf.extend(get_body(ct, True, legacy))
    else:
        key = list(secrets.token_bytes(512))
        while len(buf) < need_bytes:
            n = min(chunk, need_bytes - len(buf))
            ct = s.encrypt_with_key(b"\x00"*n, key)
            buf.extend(get_body(ct, False, legacy))
    buf = bytes(buf[:need_bytes])

    bits = bytes_to_bitstring(buf)
    bits = bits[:nbits]  # truncate to exact bit length

    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"epsilon{idx}")
    with open(path, "w", newline="\n") as f:
        f.write(bits)
    return path, nbits

def main():
    ap = argparse.ArgumentParser(description="Prepare NIST STS epsilon* files from Sicarii")
    ap.add_argument("--mode", choices=["pass","key"], default="pass", help="cipher path to use")
    ap.add_argument("--legacy", action="store_true", help="ciphertext uses legacy layout (no SC3 header)")
    ap.add_argument("--files", type=int, default=10, help="number of files (default 10)")
    ap.add_argument("--mbits", type=int, default=1, help="bits per file in megabits (default 1 Mbit)")
    ap.add_argument("--outdir", type=str, default="data", help="output directory name (default ./data)")
    args = ap.parse_args()

    total_bits = args.mbits * 1_000_000
    print(f"[+] Generating {args.files} file(s), each {total_bits:,} bits "
          f"(~{total_bits/8/1024/1024:.2f} MB), mode={args.mode}, legacy={args.legacy}")
    made = []
    for i in range(1, args.files+1):
        p, n = make_bitfile(args.mode, total_bits, args.legacy, i, args.outdir)
        made.append(p)
        print(f"  - wrote {p} ({n:,} bits)")
    print("\nNext steps (NIST STS):")
    print("  1) Build NIST STS (assess).")
    print("  2) Run from the STS folder, pointing it at this 'data' directory.")
    print(f"     Example: ./assess {total_bits}")
    print("     Then choose 'File Input Mode' and enter the full path to your ./data directory.")
    print("     STS will read the epsilon* files and run the suite.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
