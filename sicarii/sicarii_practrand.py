#!/usr/bin/env python3
"""
sicarri_practrand.py — generate a large Sicarii ciphertext stream and
pipe it to PractRand (RNG_test) if available, or save to file otherwise.

Usage examples:
  python3 sicarii_practrand.py --mode pass --mb 256 --legacy
  python3 sicarii_practrand.py --mode key  --mb 128 --out stream.bin
"""
import os, sys, argparse, shutil, subprocess, secrets

# --- import your cipher (this is the only dependency) ---
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
    # SC3 header: b"SC3"|ver|flags|[salt?]|nonce|[mac?]
    if not legacy and len(ct) >= 5 and ct[:3] == MAGIC:
        ver   = ct[3]; flags = ct[4]; off = 5
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
    kind, off, mac_len = h
    return ct[off:] if mac_len == 0 else ct[off:-mac_len]

def generate_stream(mode: str, total_bytes: int, legacy: bool) -> bytes:
    s = Cipher()
    out = bytearray(); chunk = 1_000_000
    if mode == "pass":
        pw = "correct horse battery staple"
        while len(out) < total_bytes:
            n = min(chunk, total_bytes - len(out))
            ct = s.encrypt_with_passcode(b"\x00"*n, pw)
            out.extend(get_body(ct, True, legacy))
    else:
        key = list(secrets.token_bytes(512))
        while len(out) < total_bytes:
            n = min(chunk, total_bytes - len(out))
            ct = s.encrypt_with_key(b"\x00"*n, key)
            out.extend(get_body(ct, False, legacy))
    return bytes(out[:total_bytes])

def main():
    ap = argparse.ArgumentParser(description="Sicarii → PractRand stream runner")
    ap.add_argument("--mode", choices=["pass","key"], default="pass")
    ap.add_argument("--mb", type=int, default=32, help="megabytes of data (default 32)")
    ap.add_argument("--legacy", action="store_true", help="ciphertext uses legacy layout (no SC3 header)")
    ap.add_argument("--out", type=str, default="", help="also save stream to this file")
    ap.add_argument("--no-run", action="store_true", help="do not run PractRand, just write the file")
    args = ap.parse_args()

    total = args.mb * 1024 * 1024
    print(f"[+] Generating stream: mode={args.mode} size={args.mb}MB legacy={args.legacy}")
    stream = generate_stream(args.mode, total, args.legacy)
    print(f"[+] Generated {len(stream):,} bytes.")

    if args.out:
        with open(args.out, "wb") as f:
            f.write(stream)
        print(f"[+] Saved stream to: {args.out}")

    rng_test = shutil.which("RNG_test") or shutil.which("rng_test")
    if args.no_run or not rng_test:
        if not rng_test:
            print("[!] PractRand (RNG_test) not found in PATH — skipping automatic run.")
        print("    You can run later with:")
        print(f"      RNG_test stdin < {args.out or 'stream.bin'}")
        if not args.out:
            # auto save to a default file for convenience
            with open("stream.bin", "wb") as f:
                f.write(stream)
            print("    (Saved stream to ./stream.bin)")
        return 0

    print(f"[+] Running PractRand: {os.path.basename(rng_test)} stdin")
    try:
        p = subprocess.run([rng_test, "stdin"], input=stream,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        out = p.stdout.decode("utf-8", errors="replace")
        print(out)
        print(f"[+] PractRand exit code: {p.returncode}")
        # PractRand uses non-zero for some statuses; you inspect the tail for anomalies.
        return 0
    except Exception as e:
        print(f"[!] PractRand run error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
