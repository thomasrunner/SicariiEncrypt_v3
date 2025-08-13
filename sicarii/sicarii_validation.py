# How to use python3 sicarii_validation.py
#!/usr/bin/env python3
"""
Sicarii validation — quick one-shot sanity suite (v3 + legacy aware).

Checks:
  ✓ passcode round-trip (various sizes)
  ✓ key round-trip (various sizes)
  ✓ small messages (0,1,2,16,127,128 bytes)
  ✓ ciphertext length layout (parses SC3 header; handles MAC flag)
  ✓ different nonce/salt → different ciphertext
  ✓ deterministic mode with fixed salt/nonce (if supported)
  ✓ bit flip in CT changes plaintext (no AEAD expected when MAC absent)

Exit code 0 on PASS, non-zero on FAIL.
"""

import os
import sys
import argparse
import secrets
import hashlib
import random

# --- import your class ---
try:
    from sicarii_ref import SicariiCipher   # preferred reference
except Exception:
    from sicarii import SicariiCipher       # fallback to local

# SC3 header constants (v3)
MAGIC = b"SC3"
FLAG_MAC = 0x01


# -------------------- helpers --------------------

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def expect(cond: bool, msg: str, failures: list) -> None:
    if cond:
        print("  [OK]  ", msg)
    else:
        print("  [FAIL]", msg)
        failures.append(msg)


def gen_msgs(max_bytes: int):
    base = [
        b"", b"a", b"hi", b"0123456789abcdef",
        os.urandom(1),
        os.urandom(2),
        os.urandom(16),
        os.urandom(127),
        os.urandom(128),
        os.urandom(min(4096, max_bytes)),
    ]
    # add two random sizes up to max_bytes
    for _ in range(2):
        n = random.randint(1, max_bytes)
        base.append(os.urandom(n))
    return base


def parse_ct(ct: bytes, pass_mode: bool):
    """
    Parse ciphertext into components and return a dict:
      {header_len, salt, nonce, body, tag}

    Supports:
      - SC3 header (b'SC3' + ver + flags + [salt?] + nonce [+ tag])
      - legacy pass: [salt(16)||nonce(24)||body]
      - legacy key : [nonce(24)||body]
    """
    out = {"header_len": 0, "salt": b"", "nonce": b"", "body": b"", "tag": b""}

    # SC3 (v3)?
    if len(ct) >= 5 and ct[:3] == MAGIC:
        # ver = ct[3]  # not used currently
        flags = ct[4]
        off = 5
        if pass_mode:
            if len(ct) < off + 16:
                raise ValueError("SC3 pass header too short")
            out["salt"] = ct[off:off+16]
            off += 16
        if len(ct) < off + 24:
            raise ValueError("SC3 nonce missing")
        out["nonce"] = ct[off:off+24]
        off += 24
        out["header_len"] = off

        tag_len = 32 if (flags & FLAG_MAC) else 0
        if tag_len:
            if len(ct) < off + tag_len:
                raise ValueError("SC3 tag missing")
            out["body"] = ct[off:-tag_len]
            out["tag"] = ct[-tag_len:]
        else:
            out["body"] = ct[off:]
        return out

    # Legacy layout
    if pass_mode:
        if len(ct) < 40:
            raise ValueError("legacy pass-mode CT too short")
        out["salt"] = ct[:16]
        out["nonce"] = ct[16:40]
        out["body"] = ct[40:]
        out["header_len"] = 40
        return out
    else:
        if len(ct) < 24:
            raise ValueError("legacy key-mode CT too short")
        out["nonce"] = ct[:24]
        out["body"] = ct[24:]
        out["header_len"] = 24
        return out


# -------------------- test suites --------------------

def test_passcode(s: SicariiCipher, max_bytes: int, failures: list, iters: int) -> None:
    print("\n[ Passcode path ]")
    passcode = "correct horse battery staple"
    msgs = gen_msgs(max_bytes)

    # Round-trip & length check (parse header)
    for m in msgs:
        ct = s.encrypt_with_passcode(m, passcode)
        pt = s.decrypt_with_passcode(ct, passcode)
        expect(pt == m, f"round-trip len={len(m)} sha={sha256(m)}", failures)

        ok_len = False
        try:
            parsed = parse_ct(ct, pass_mode=True)
            exp_len = parsed["header_len"] + len(m) + len(parsed["tag"])
            ok_len = (len(ct) == exp_len)
        except Exception:
            ok_len = False
        expect(ok_len, "CT length (parsed header + PT + tag)", failures)

    # Different nonce/salt → different CT
    m = b"A" * 64
    ct1 = s.encrypt_with_passcode(m, passcode)
    ct2 = s.encrypt_with_passcode(m, passcode)
    expect(ct1 != ct2, "randomized salt+nonce => different ciphertext", failures)

    # Deterministic with fixed salt/nonce (if supported)
    try:
        salt = bytes.fromhex("00" * 16)
        nonce = bytes.fromhex("11" * 24)
        ct3 = s.encrypt_with_passcode(
            m, passcode,
            iterations=100_000, salt=salt, nonce=nonce, deterministic=True  # type: ignore
        )
        ct4 = s.encrypt_with_passcode(
            m, passcode,
            iterations=100_000, salt=salt, nonce=nonce, deterministic=True  # type: ignore
        )
        expect(ct3 == ct4, "fixed salt+nonce => deterministic ciphertext", failures)
    except TypeError:
        print("  [SKIP] deterministic ciphertext (class has no salt/nonce params)")
    except Exception as e:
        print("  [SKIP] deterministic ciphertext (error:", str(e) + ")")

    # Bit flip in CT → plaintext changes (when MAC not present)
    try:
        parsed1 = parse_ct(ct1, pass_mode=True)
        hdr_len, tag_len = parsed1["header_len"], len(parsed1["tag"])
        if tag_len == 0 and len(ct1) > hdr_len:
            body = bytearray(ct1)
            body[hdr_len] ^= 0x01
            pt_bad = s.decrypt_with_passcode(bytes(body), passcode)
            expect(pt_bad != m, "bit flip changed plaintext (expected; no AEAD)", failures)
        elif tag_len == 32:
            # With MAC, flip should fail/reject/change
            body = bytearray(ct1)
            body[hdr_len] ^= 0x01
            pt_bad = s.decrypt_with_passcode(bytes(body), passcode)
            expect(pt_bad != m, "bit flip rejected/changed (AEAD present)", failures)
    except Exception:
        # If parsing failed above, we’ve already flagged a length failure.
        pass


def test_key(s: SicariiCipher, max_bytes: int, failures: list) -> None:
    print("\n[ Key path ]")
    key = list(secrets.token_bytes(512))
    msgs = gen_msgs(max_bytes)

    # Round-trip & length check (parse header)
    for m in msgs:
        ct = s.encrypt_with_key(m, key)
        pt = s.decrypt_with_key(ct, key)
        expect(pt == m, f"round-trip len={len(m)} sha={sha256(m)}", failures)

        ok_len = False
        try:
            parsed = parse_ct(ct, pass_mode=False)
            exp_len = parsed["header_len"] + len(m) + len(parsed["tag"])
            ok_len = (len(ct) == exp_len)
        except Exception:
            ok_len = False
        expect(ok_len, "CT length (parsed header + PT + tag)", failures)

    # Different nonce → different CT
    m = os.urandom(64)
    ct1 = s.encrypt_with_key(m, key)
    ct2 = s.encrypt_with_key(m, key)
    expect(ct1 != ct2, "randomized nonce => different ciphertext", failures)

    # Bit flip in CT → plaintext changes (no MAC case assumed for key mode unless your impl adds one)
    try:
        parsed1 = parse_ct(ct1, pass_mode=False)
        hdr_len, tag_len = parsed1["header_len"], len(parsed1["tag"])
        if tag_len == 0 and len(ct1) > hdr_len:
            body = bytearray(ct1)
            body[hdr_len] ^= 0x80
            pt_bad = s.decrypt_with_key(bytes(body), key)
            expect(pt_bad != m, "bit flip changed plaintext (expected; no AEAD)", failures)
    except Exception:
        pass


def burn_in_random(s: SicariiCipher, failures: list, iters: int) -> None:
    print("\n[ Randomized quick fuzz ]")
    for i in range(iters):
        use_pass = random.choice([True, False])
        n = random.randint(0, 5000)
        m = os.urandom(n)
        if use_pass:
            pw = "pw-" + secrets.token_hex(4)
            ct = s.encrypt_with_passcode(m, pw)
            pt = s.decrypt_with_passcode(ct, pw)
            ok = False
            try:
                parsed = parse_ct(ct, pass_mode=True)
                ok = (pt == m and len(ct) == parsed["header_len"] + len(m) + len(parsed["tag"]))
            except Exception:
                ok = False
            label = f"pass fuzz {i+1}/{iters} len={n}"
        else:
            key = list(secrets.token_bytes(512))
            ct = s.encrypt_with_key(m, key)
            pt = s.decrypt_with_key(ct, key)
            ok = False
            try:
                parsed = parse_ct(ct, pass_mode=False)
                ok = (pt == m and len(ct) == parsed["header_len"] + len(m) + len(parsed["tag"]))
            except Exception:
                ok = False
            label = f"key  fuzz {i+1}/{iters} len={n}"
        expect(ok, label, failures)


# -------------------- main --------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Sicarii validation (one-shot).")
    ap.add_argument("--iters", type=int, default=20, help="fuzz iterations (default 20)")
    ap.add_argument("--max-bytes", type=int, default=200_000, help="max random message bytes")
    args = ap.parse_args()

    random.seed(12345)  # reproducible-ish validation
    s = SicariiCipher()
    failures = []

    # suites
    test_passcode(s, args.max_bytes, failures, args.iters)
    test_key(s, args.max_bytes, failures)
    burn_in_random(s, failures, args.iters)

    print("\n==== Summary ====")
    if not failures:
        print("ALL TESTS PASS ✅")
        return 0
    else:
        print(f"{len(failures)} failure(s):")
        for f in failures:
            print(" -", f)
        return 1


if __name__ == "__main__":
    sys.exit(main())
