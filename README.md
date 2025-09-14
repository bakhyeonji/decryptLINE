# LINE Encrypted SQLite Decrypter

**Purpose:** Decrypt LINE-created **encrypted SQLite (.edb)** files to standard **SQLite (.db)** using **AES-128-CBC**.

>**Legal Notice:** Use only on data you own or have explicit permission to analyze. Intended for forensic/research purposes.

---

## Features
- Page-by-page streaming decryption (handles large files)
- Automatic page-1 header restoration → valid `SQLite format 3\0`
- Minimal external deps: just `pycryptodome`

---

## Requirements
- Python 3.9+
- PyCryptodome
```bash
pip install pycryptodome
```

---

## Quick Start
```bash
python decrypt_line_sqlite.py --edb "D:\path\to\encrypted.edb" --result "D:\path\to\decrypted.db" --passphrase "c3c36ce1151757f24f95ce3b42258472"
```
---

## How It Works (Summary)
- **Base key derivation (`derive_encryption_key`)**
  - `pad_password(key_str)` pads to 32 bytes (missing bytes filled with **PDF Standard Padding** constants)
  - `owner_pad = pad_password("")`
  - `digest = MD5(owner_pad)` repeated **50 rounds** (there is a fixed `assert` on the expected digest)
  - `owner_key`: apply **RC4** with `(digest ^ i)` for **20 rounds** over `user_pad`, chaining the output
  - `digest = MD5(user_pad || owner_key)` repeated **50 rounds**
  - **base_key = digest[:16]**

- **Per-page decryption (`decrypt_page_aes128`)**
  - **pagekey** = `MD5(base_key || LE(page) || "sAlT")`
  - **IV** = `MD5(seed)`, where the 16-byte seed is built from a `modmult`-based PRNG (4 × 32-bit little-endian chunks)
  - Decrypt with **AES-128-CBC**
  - **Page 1 special case**: validate header pattern, decrypt with proper offset, and restore `SQLite format 3\0` if needed

---

## Notes & Debugging
- `passphrase` is used **verbatim** (no hex decoding).
- On page 1, key/IV may be printed for debugging.
- If the `assert` fails: check the empty-password padding and MD5 round counts.
- If the output is not recognized as SQLite:
  - Check the input path/file integrity and the page size (from header bytes `data[16:18]`, big-endian)
  - Verify the correct `passphrase`
- [대검찰청] IT 서비스 기반 기술유출범죄 추적 및 대응기술 연구 (2차년도)

---

## License / Credits
- Crypto operations: **PyCryptodome** (AES/MD5)
- RC4: pure-Python implementation in this script
- PDF Standard Padding byte sequence is used for password padding
