# How to run python3 sicarii_demo.py
# --- import your class ---
try:
    from sicarii_ref import SicariiCipher   # your stdlib reference
except Exception:
    from sicarii import SicariiCipher       # fallback

if __name__ == "__main__":
    s = SicariiCipher()
    msg = b"Sicarii v3 demo!"

    # Passcode path (with MAC)
    ct = s.encrypt_with_passcode(msg, "correct horse")
    pt = s.decrypt_with_passcode(ct, "correct horse")
    print("pass round-trip:", pt == msg)

    # Key path (no MAC)
    key = s.generate512Key()
    ct2 = s.encrypt_with_key(msg, key)
    pt2 = s.decrypt_with_key(ct2, key)
    print("key  round-trip:", pt2 == msg)
