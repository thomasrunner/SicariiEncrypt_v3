# Sicarii — Educational Cipher Suite

Sicarii is a **reference / educational** cipher-like construction written entirely in Python.  
It includes both the core cipher implementation and a suite of companion tools for encryption, decryption, validation, benchmarking, randomness testing, and attack demonstrations.

> ⚠️ **Security disclaimer:**  
> This is **not** a production-ready encryption algorithm.  
> It is designed for **research, experimentation, and teaching**.  
> Do **not** use it to secure real-world sensitive data.

---

## How It Works

## Core Mechanism

At the heart of Sicarii is a **dynamic, stateful 256×256 byte matrix**.

Each encryption step involves:

1. **Dynamic Row Swapping** –  
   The matrix rows are not fixed. They are *continuously permuted* during encryption based on evolving key– and data–dependent state, making the transformation sequence **non-repeating** and input-sensitive.

2. **Byte-Level XOR Diffusion** –  
   Every processed byte undergoes multiple XOR passes against matrix-derived values. This ensures strong **avalanche effect** — a 1-bit change in the input radically alters the output.

3. **Data-Dependent Evolution** –  
   The act of encrypting modifies the internal state, so the same byte value in a different position will see a completely different transformation chain.

4. **512-Byte Expanded Key** –  
   Passcode mode expands a user’s passphrase into a full 512-byte working key via PBKDF2-HMAC-SHA256 (configurable iterations). Key mode skips derivation and uses a raw 512-byte key directly.

Because the transformation matrix is large (65,536 byte slots) and **actively reconfigured** during operation, Sicarii behaves unlike simple substitution–permutation networks:

- It does not rely on a fixed S-box.  
- It embeds *both key schedule* and *data mixing* directly into the evolving matrix.  
- Reuse of the same key still produces dramatically different byte maps for each block.

This design makes Sicarii particularly suited for **educational cryptanalysis labs** — it’s small enough to step through in Python, yet complex enough to demonstrate **why stateful designs resist naive attacks**.

- **Key Material**
  - In *passcode mode*, a user-supplied passphrase is expanded into a **512-byte working key** using PBKDF2-HMAC-SHA256 with a fixed iteration count and salt.
  - In *raw key mode*, the 512-byte key is provided directly.

- **Keystream Generation**
  - A deterministic keystream is generated from the working key, internal state counters, and nonce values.
  - The cipher uses **nonlinear byte-mixing rounds** and **state-dependent feedback** to produce avalanche behavior.

- **Encryption / Decryption**
  - Encryption is a simple XOR of plaintext with the generated keystream.
  - Decryption is the same operation, as in any stream cipher.

- **SC3 Header Format**
  - Every ciphertext starts with an SC3 header, which encodes:
    - Mode of operation (passcode / key)
    - Nonce
    - Optional MAC for Encrypt-then-MAC integrity

- **Deterministic Test Hooks**
  - Built-in reproducibility options allow you to generate identical test vectors for teaching, fuzzing, and regression tests.

---

## Unique Aspects

- **Self-contained Python** — No external crypto libraries required.
- **Full toolchain** — From encryption to statistical randomness tests and even basic attack scripts.
- **Didactic transparency** — Readable code for every step, useful for those learning how ciphers are built.
- **Attack lab included** — Dictionary attacks, nonce reuse detection, and chosen-plaintext examples to teach cryptanalysis principles.

---

## Repository Contents

| File | Purpose |
|------|---------|
| `sicarii.py` | Main cipher implementation (v3 reference). |
| `sicarii_demo.py` | Minimal example of passcode and raw-key encryption/decryption. |
| `sicarii_make_ct.py` | CLI tool to encrypt a file into SC3 format using a passcode. |
| `sicarii_attacklab.py` | Attack lab: dictionary cracking, nonce reuse scan, chosen-plaintext demo. |
| `sicarii_kat.py` | Known-Answer Test generator and verifier for regression testing. |
| `sicarii_nist_prep.py` | Produces keystream bitstreams for NIST STS randomness testing. |
| `sicarii_practrand.py` | Generates large keystreams for PractRand statistical analysis. |
| `sicarii_quickcheck.py` | Lightweight local randomness/avalanche property tests. |
| `sicarii_validation.py` | End-to-end functional validation of encryption/decryption correctness. |
| `sicarii_bench.py` | Simple encryption/decryption performance benchmark. |

## Quantum-Resilience Intuition & Caveats

Sicarii isn’t claiming provable post-quantum security, but its **configuration space explodes** with message length in a way that can **outpace Grover’s √N speed-up** for generic search — if brute force remains the best available quantum attack.

- **Per-message structure:** A 256×256 substitution matrix is rebuilt from `(key || nonce)`, then **dynamically permuted each byte** via a PRF-driven swap of two rows.  
- **Per-byte evolution:** Each step uses:
  - a row-selection byte (256 choices), and  
  - a row-swap pair (~256² choices),  
  giving roughly **256³ ≈ 2²⁴ possibilities per byte** from evolution alone.
- **Output masking:** A fresh 256-byte permutation (π_out) further hides column indices (~256! options).

For a message of length *L*, the number of distinct transformations consistent with the same key/nonce is approximately:

(256!) × (256^3)^L ≈ 2^(L·24) × 256!

Even under Grover’s algorithm, √N only halves the exponent, which still leaves an astronomical search space as *L* grows. The **effective hardness scales linearly in *L*** (24 bits per byte here), so the gap between search cost and attack feasibility widens with message size.

⚠️ **Important:** This is **intuition, not a proof**. Real-world security depends on the absence of structural shortcuts (algebraic, meet-in-the-middle, slide, or cycle attacks). Quantum cryptanalysis can sometimes exploit structure in ways classical attacks cannot. Sicarii should be viewed as **one layer** in a “Swiss cheese” security model, where multiple independent mechanisms cover each other’s gaps.

> **Additional Note:** Sicarii includes attack demos and test harnesses to invite public scrutiny. Parameters like matrix size (*N*) and evolution rules can be tuned to trade performance for a larger theoretical margin.

---

## Example Usage

Encrypt a file with a passcode:
```bash
python3 sicarii_make_ct.py input.txt output.ct --passcode mysecret

python3 sicarii_demo.py decrypt output.ct --passcode mysecret

python3 sicarii_attacklab.py dict test_ct.bin 25504446 --wordlist rockyou.txt --limit 100 --threads 8 --skip 0
