# How to use
# echo "%PDF This is a fake PDF header" > fake.pdf
# python3 make_ct.py fake.pdf test_ct.bin secret123

# make_ct.py
import sys
from sicarii import SicariiCipher

if len(sys.argv) != 4:
    print("usage: python3 make_ct.py <infile> <outfile> <passcode>")
    sys.exit(2)

inf, outf, pw = sys.argv[1], sys.argv[2], sys.argv[3]
with open(inf, "rb") as f: pt = f.read()

s = SicariiCipher()
ct = s.encrypt_with_passcode(pt, pw)
with open(outf, "wb") as f: f.write(ct)

print(f"[ok] wrote {outf} ({len(ct)} bytes; header+body)")
