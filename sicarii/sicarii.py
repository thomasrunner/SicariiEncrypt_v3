#!/usr/bin/env python3
# Sicarii v3 (reference, stdlib-only, educational)
# NOTE: Toy cipher. Do not use in production.

import os, hmac, hashlib, struct
from typing import List, Optional, Union, Tuple

BytesLike = Union[bytes, bytearray, memoryview]
Plain     = Union[str, bytes, bytearray, memoryview]

MAGIC = b"SC3"
VER   = 0x03
FLAG_MAC = 0x01          # Encrypt-then-MAC present

# ------------------------ small helpers ------------------------

def _to_bytes(b: Plain) -> bytes:
    if isinstance(b, (bytes, bytearray, memoryview)): return bytes(b)
    if isinstance(b, str): return b.encode("utf-8")
    raise TypeError("expected bytes or str")

def _u32be(x: int) -> bytes:
    return struct.pack(">I", x & 0xFFFFFFFF)

def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

# --- RFC 5869 HKDF-SHA256 (extract + expand), using nonce as salt ---
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00"*32
    return _hmac(salt, ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = bytearray(); t = b""
    counter = 1
    while len(out) < length:
        t = _hmac(prk, t + info + bytes([counter]))
        out.extend(t)
        counter += 1
    return bytes(out[:length])

def hkdf(ikm: bytes, nonce: bytes, label: str, length: int) -> bytes:
    prk = hkdf_extract(nonce, ikm)
    info = b"Sicarii/" + label.encode("ascii")
    return hkdf_expand(prk, info, length)

# HMAC-SHA256 in counter-mode (PRF stream)
def prf_stream(key: bytes, info: bytes, nbytes: int) -> bytes:
    out = bytearray(); ctr = 0
    while len(out) < nbytes:
        out.extend(_hmac(key, info + _u32be(ctr)))
        ctr += 1
    return bytes(out[:nbytes])

# Fisher–Yates using a given random byte stream
def fy_permutation(rand: bytes) -> List[int]:
    a = list(range(256))
    rp = 0; R = len(rand)
    for i in range(255, 0, -1):
        if rp + 2 > R: rp = 0
        j = ((rand[rp] << 8) | rand[rp+1]) % (i+1)
        rp += 2
        a[i], a[j] = a[j], a[i]
    return a

# ------------------------ main class ------------------------

class SicariiCipher:
    """
    v3: same mechanism, tightened leaks:
      - tables/evolution from HKDF(key, nonce)
      - output-masked indices (π_out)
      - row selection from PRF stream (no CT feedback)
      - optional Encrypt-then-MAC
    """

    def __init__(self):  # internal table: 256 rows of (perm, inv)
        self.kT: List[Tuple[List[int], List[int]]] = []

    # ----- public: keygen/KDF -----
    @staticmethod
    def generate512Key() -> List[int]:
        return list(os.urandom(512))

    # inside class SicariiCipher
    @staticmethod
    def _to_bytes(b):
        if isinstance(b, (bytes, bytearray, memoryview)):
            return bytes(b)
        if isinstance(b, str):
            return b.encode("utf-8")
        raise TypeError("Expected bytes/str/memoryview")


    @staticmethod
    def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dkLen: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dkLen)

    # --- small wrappers to match earlier API ---

    @staticmethod
    def prf_bytes(key: bytes, info: bytes, count: int) -> bytes:
        # reuse the module-level prf_stream
        return prf_stream(key, info, count)

    def _evolution_stream(self, key: bytes, nonce: bytes, nsteps: int, compat: bool = True) -> memoryview:
        # 2 bytes per step: (a_idx, b_idx) for row swaps
        # compat flag kept for signature parity; not used here
        return memoryview(prf_stream(key, nonce + b"\x02", 2*nsteps))


    # ----- internals: derive subkeys, tables, streams -----
    def _derive_keys(self, master: bytes, nonce: bytes) -> dict:
        # Key separation via HKDF labels
        return {
            "tab": hkdf(master, nonce, "tab", 32),   # seed for table rows
            "evo": hkdf(master, nonce, "evo", 32),   # swap stream key
            "row": hkdf(master, nonce, "row", 32),   # row-index stream key
            "out": hkdf(master, nonce, "out", 32),   # output mask key
            "mac": hkdf(master, nonce, "mac", 32),   # tag key (EtM)
        }

    def _build_table(self, k_tab: bytes, nonce: bytes):
        # Build 256 rows; each row uses FY with 512 rand bytes (2 per swap)
        rows: List[Tuple[List[int], List[int]]] = []
        for r in range(256):
            rand = prf_stream(k_tab, nonce + b"\x01" + bytes([r]), 512)
            a = fy_permutation(rand)
            inv = [0]*256
            for idx, v in enumerate(a): inv[v] = idx
            rows.append((a, inv))
        self.kT = rows

    def _evo_stream(self, k_evo: bytes, nonce: bytes, nsteps: int) -> memoryview:
        # 2 bytes per step → (a_idx, b_idx)
        return memoryview(prf_stream(k_evo, nonce + b"\x02", 2*nsteps))

    def _row_stream(self, k_row: bytes, nonce: bytes, nsteps: int) -> memoryview:
        # One row selector byte per step (0..255)
        return memoryview(prf_stream(k_row, nonce + b"\x03", nsteps))

    def _out_permutation(self, k_out: bytes, nonce: bytes) -> Tuple[List[int], List[int]]:
        rand = prf_stream(k_out, nonce + b"\x04", 512)
        pi = fy_permutation(rand)
        inv = [0]*256
        for i, v in enumerate(pi): inv[v] = i
        return pi, inv

    # ----- core transform using subkeys -----
    def _encrypt_body(self, pt: bytes, k: dict, nonce: bytes) -> bytes:
        n = len(pt)
        self._build_table(k["tab"], nonce)
        evo = self._evo_stream(k["evo"], nonce, n)
        row = self._row_stream(k["row"], nonce, n)
        pi_out, _ = self._out_permutation(k["out"], nonce)

        out = bytearray()
        kT = self.kT; mv = memoryview(pt)
        for i in range(n):
            r = row[i]
            a, inv = kT[r]
            pos = inv[mv[i]]                 # column index in row r
            out.append(pi_out[pos])          # masked index
            a_idx = evo[2*i]; b_idx = evo[2*i+1]
            if a_idx != b_idx:
                kT[a_idx], kT[b_idx] = kT[b_idx], kT[a_idx]
        return bytes(out)

    def _decrypt_body(self, body: bytes, k: dict, nonce: bytes) -> bytes:
        n = len(body)
        self._build_table(k["tab"], nonce)
        evo = self._evo_stream(k["evo"], nonce, n)
        row = self._row_stream(k["row"], nonce, n)
        _, pi_inv = self._out_permutation(k["out"], nonce)

        out = bytearray()
        kT = self.kT; mv = memoryview(body)
        for i in range(n):
            r = row[i]
            a, _inv = kT[r]
            pos = pi_inv[mv[i]]              # unmask to column index
            out.append(a[pos])               # row lookup to plaintext
            a_idx = evo[2*i]; b_idx = evo[2*i+1]
            if a_idx != b_idx:
                kT[a_idx], kT[b_idx] = kT[b_idx], kT[a_idx]
        return bytes(out)

    # ----- public API: key path -----
    def encrypt_with_key(self, ary: Plain, key: List[int], compat: bool = True) -> bytes:
        data = self._to_bytes(ary)
        if len(key) != 512: return data
        nonce = os.urandom(24)
        keyb  = bytes(key)
        self._build_table(keyb, nonce)

        # NEW: per-message output mask stream
        mask = self.prf_bytes(keyb, nonce + bytes([0x04]), len(data))

        out = bytearray(nonce)
        state = 0

        evo = self._evolution_stream(keyb, nonce, len(data), compat)
        kT = self.kT; out_append = out.append

        for i, p in enumerate(data):
            a, inv = kT[state]
            pos = inv[p]                # 0..255
            c  = pos ^ mask[i]          # MASKED ciphertext byte
            out_append(c)

            # evolve rows
            a_idx = evo[2*i]; b_idx = evo[2*i + 1]
            if a_idx != b_idx:
                kT[a_idx], kT[b_idx] = kT[b_idx], kT[a_idx]

            state = c                   # row selector = previous CIPHERTEXT byte
        return bytes(out)


    def decrypt_with_key(self, ary: BytesLike, key: List[int], compat: bool = True) -> bytes:
        data = self._to_bytes(ary)
        if len(key) != 512 or len(data) < 24: return data
        nonce, body = data[:24], data[24:]
        keyb  = bytes(key)
        self._build_table(keyb, nonce)

        # NEW: same mask stream
        mask = self.prf_bytes(keyb, nonce + bytes([0x04]), len(body))

        out = bytearray()
        state = 0

        evo = self._evolution_stream(keyb, nonce, len(body), compat)
        kT = self.kT; out_append = out.append

        for i, c in enumerate(body):
            pos = c ^ mask[i]           # UNMASK to get position
            a, _inv = kT[state]
            out_append(a[pos])

            a_idx = evo[2*i]; b_idx = evo[2*i + 1]
            if a_idx != b_idx:
                kT[a_idx], kT[b_idx] = kT[b_idx], kT[a_idx]

            state = c                   # previous CIPHERTEXT byte
        return bytes(out)


    # ----- public API: passcode path -----
    def encrypt_with_passcode(self, ary: Plain, passcode: str, compat: bool = True) -> bytes:
        data = self._to_bytes(ary)
        if len(passcode) < 8: return data
        salt  = os.urandom(16)
        nK    = self.pbkdf2_sha256(passcode.encode('utf-8'), salt, 200_000, 512)
        nonce = os.urandom(24)
        self._build_table(nK, nonce)

        # NEW: mask stream under nK
        mask = self.prf_bytes(nK, nonce + bytes([0x04]), len(data))

        out = bytearray(salt + nonce)
        state = 0
        evo = self._evolution_stream(nK, nonce, len(data), compat)
        kT = self.kT; out_append = out.append

        for i, p in enumerate(data):
            a, inv = kT[state]
            pos = inv[p]
            c  = pos ^ mask[i]
            out_append(c)

            a_idx = evo[2*i]; b_idx = evo[2*i + 1]
            if a_idx != b_idx:
                kT[a_idx], kT[b_idx] = kT[b_idx], kT[a_idx]
            state = c
        return bytes(out)


    def decrypt_with_passcode(self, ary: BytesLike, passcode: str, compat: bool = True) -> bytes:
        data = self._to_bytes(ary)
        if len(data) < 40 or len(passcode) < 8: return data
        salt, nonce, body = data[:16], data[16:40], data[40:]
        nK = self.pbkdf2_sha256(passcode.encode('utf-8'), salt, 200_000, 512)
        self._build_table(nK, nonce)

        # NEW: same mask stream
        mask = self.prf_bytes(nK, nonce + bytes([0x04]), len(body))

        out = bytearray()
        state = 0
        evo = self._evolution_stream(nK, nonce, len(body), compat)
        kT = self.kT; out_append = out.append

        for i, c in enumerate(body):
            pos = c ^ mask[i]
            a, _inv = kT[state]
            out_append(a[pos])

            a_idx = evo[2*i]; b_idx = evo[2*i + 1]
            if a_idx != b_idx:
                kT[a_idx], kT[b_idx] = kT[b_idx], kT[a_idx]
            state = c
        return bytes(out)

