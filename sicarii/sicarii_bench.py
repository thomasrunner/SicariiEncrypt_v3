# How to use python3 sicarii_bench.py
#!/usr/bin/env python3
import os, time, secrets, statistics as stats
from typing import List
from sicarii import SicariiCipher  # or from sicarii import SicariiCipher

# ---------- config ----------
SIZES_MB   = [1, 5, 10]   # change as you like
REPEATS    = 3            # number of timed runs per size
PASSCODE   = "Frank Miller"
# ----------------------------

def mbps(num_bytes: int, seconds: float) -> float:
    return (num_bytes / 1_000_000.0) / max(seconds, 1e-9)

def bench_passcode(s: SicariiCipher, buf: bytes) -> tuple[float, float]:
    # warmup
    ct = s.encrypt_with_passcode(buf, PASSCODE)
    _ = s.decrypt_with_passcode(ct, PASSCODE)
    # timed
    t0 = time.perf_counter()
    ct = s.encrypt_with_passcode(buf, PASSCODE)
    t1 = time.perf_counter()
    pt = s.decrypt_with_passcode(ct, PASSCODE)
    t2 = time.perf_counter()
    assert pt == buf
    return (t1 - t0, t2 - t1)

def bench_key(s: SicariiCipher, buf: bytes) -> tuple[float, float]:
    key512 = list(secrets.token_bytes(512))
    # warmup
    ct = s.encrypt_with_key(buf, key512)
    _ = s.decrypt_with_key(ct, key512)
    # timed
    t0 = time.perf_counter()
    ct = s.encrypt_with_key(buf, key512)
    t1 = time.perf_counter()
    pt = s.decrypt_with_key(ct, key512)
    t2 = time.perf_counter()
    assert pt == buf
    return (t1 - t0, t2 - t1)

def run():
    print("\nSicarii v2 micro-benchmark (CPython)")
    print("sizes:", SIZES_MB, "MB  | repeats:", REPEATS)
    print()

    for size in SIZES_MB:
        nbytes = size * 1_000_000
        buf = os.urandom(nbytes)

        # PASSCODE MODE
        enc_times, dec_times = [], []
        for _ in range(REPEATS):
            s = SicariiCipher()
            te, td = bench_passcode(s, buf)
            enc_times.append(te); dec_times.append(td)
        enc_m, dec_m = stats.mean(enc_times), stats.mean(dec_times)
        print(f"[passcode] {size:>2} MB  enc: {mbps(nbytes, enc_m):7.2f} MB/s  "
              f"dec: {mbps(nbytes, dec_m):7.2f} MB/s  "
              f"(min/max enc {mbps(nbytes, min(enc_times)):.1f}/{mbps(nbytes, max(enc_times)):.1f})")

        # KEY MODE
        enc_times, dec_times = [], []
        for _ in range(REPEATS):
            s = SicariiCipher()
            te, td = bench_key(s, buf)
            enc_times.append(te); dec_times.append(td)
        enc_m, dec_m = stats.mean(enc_times), stats.mean(dec_times)
        print(f"[   key  ] {size:>2} MB  enc: {mbps(nbytes, enc_m):7.2f} MB/s  "
              f"dec: {mbps(nbytes, dec_m):7.2f} MB/s  "
              f"(min/max enc {mbps(nbytes, min(enc_times)):.1f}/{mbps(nbytes, max(enc_times)):.1f})")
        print()

if __name__ == "__main__":
    run()
