# python3 sicarii_kat.py
#!/usr/bin/env python3
"""
Sicarii KAT (Known-Answer Tests): generate + validate in one go.

- Writes deterministic test vectors to sicarii_kat.json
- Re-loads and verifies:
    * encrypt(...) reproduces the same ciphertext (if deterministic hooks exist)
    * decrypt(...) returns the original plaintext
Exit 0 on PASS, non-zero on any failure.
"""

import json, os, sys, binascii

# --- import your class ---
try:
    from sicarii_ref import SicariiCipher   # prefer the reference
except Exception:
    from sicarii import SicariiCipher       # fallback

VEC_FILE = "sicarii_kat.json"

def hexify(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def unhex(h: str) -> bytes:
    return binascii.unhexlify(h.encode("ascii"))

def make_vectors() -> list[dict]:
    s = SicariiCipher()

    # --- KEY PATH (deterministic) ---
    key = bytes(range(256)) + bytes(range(255, -1, -1))  # 512 bytes, simple pattern
    msg = b"The quick brown fox jumps over the lazy dog."
    # Fixed nonce for deterministic vector (24 bytes of 0x11)
    nonce = bytes([0x11])*24

    try:
        ct_key = s.encrypt_with_key(msg, list(key), deterministic=True, nonce=nonce)  # type: ignore
        deterministic_ok_key = True
    except TypeError:
        # Old API without test hooks: do a normal encrypt and note we can’t re-encrypt deterministically
        ct_key = s.encrypt_with_key(msg, list(key))
        deterministic_ok_key = False

    vec_key = {
        "mode": "key",
        "key": hexify(key),
        "nonce": hexify(ct_key[:24]) if deterministic_ok_key else hexify(nonce),
        "pt": hexify(msg),
        "ct": hexify(ct_key),
        "deterministic": deterministic_ok_key,
    }

    # --- PASSCODE PATH (deterministic) ---
    s2 = SicariiCipher()
    passcode = "correct horse battery staple"
    msg2 = b"Sicarii KAT passcode path"
    salt  = bytes([0x00])*16
    nonce2 = bytes([0x22])*24

    try:
        ct_pass = s2.encrypt_with_passcode(
            msg2, passcode, deterministic=True, salt=salt, nonce=nonce2  # type: ignore
        )
        deterministic_ok_pass = True
    except TypeError:
        ct_pass = s2.encrypt_with_passcode(msg2, passcode)
        deterministic_ok_pass = False

    vec_pass = {
        "mode": "pass",
        "passcode": passcode,
        "salt": hexify(ct_pass[:16]) if deterministic_ok_pass else hexify(salt),
        "nonce": hexify(ct_pass[16:40]) if deterministic_ok_pass else hexify(nonce2),
        "pt": hexify(msg2),
        "ct": hexify(ct_pass),
        "deterministic": deterministic_ok_pass,
    }

    return [vec_key, vec_pass]

def write_vectors(vecs: list[dict], path: str = VEC_FILE) -> None:
    with open(path, "w") as f:
        json.dump(vecs, f, indent=2)
    print(f"[+] Wrote {path} with {len(vecs)} vectors")

def validate_vectors(path: str = VEC_FILE) -> int:
    with open(path, "r") as f:
        vecs = json.load(f)

    failures = 0
    for i, v in enumerate(vecs, 1):
        s = SicariiCipher()
        mode = v["mode"]
        pt = unhex(v["pt"])
        ct = unhex(v["ct"])

        print(f"\n[Vector {i}] mode={mode}")

        # 1) decrypt check
        if mode == "key":
            key = list(unhex(v["key"]))
            out = s.decrypt_with_key(ct, key)
        else:
            out = s.decrypt_with_passcode(ct, v["passcode"])
        ok_dec = (out == pt)
        print("  - decrypt round-trip:", "OK" if ok_dec else "FAIL")
        failures += 0 if ok_dec else 1

        # 2) re-encrypt reproduces CT (only if deterministic hooks available)
        det = v.get("deterministic", False)
        if mode == "key":
            nonce = unhex(v["nonce"])
            try:
                ct2 = s.encrypt_with_key(pt, key, deterministic=True, nonce=nonce)  # type: ignore
                ok_enc = (ct2 == ct) if det else None
            except TypeError:
                ok_enc = None
        else:
            salt  = unhex(v["salt"])
            nonce = unhex(v["nonce"])
            try:
                ct2 = s.encrypt_with_passcode(pt, v["passcode"], deterministic=True, salt=salt, nonce=nonce)  # type: ignore
                ok_enc = (ct2 == ct) if det else None
            except TypeError:
                ok_enc = None

        if ok_enc is None:
            print("  - re-encrypt check: skipped (no deterministic hooks in this build)")
        else:
            print("  - re-encrypt reproduces CT:", "OK" if ok_enc else "FAIL")
            failures += 0 if ok_enc else 1

    return failures

def main():
    vecs = make_vectors()
    write_vectors(vecs, VEC_FILE)
    fails = validate_vectors(VEC_FILE)
    print("\n==== Summary ====")
    if fails == 0:
        print("ALL TESTS PASS ✅")
        return 0
    else:
        print(f"{fails} failure(s) ❌")
        return 1

if __name__ == "__main__":
    sys.exit(main())
