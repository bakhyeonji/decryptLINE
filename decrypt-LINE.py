# -*- coding: utf-8 -*-

import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Hash import MD5


__author__ = 'Hyeonji Park'
__email__ = 'agria200@korea.ac.kr'
__version__ = '1.0.0'


PADDING_BYTES = bytes([
    0x28,0xBF,0x4E,0x5E,0x4E,0x75,0x8A,0x41,
    0x64,0x00,0x4E,0x56,0xFF,0xFA,0x01,0x08,
    0x2E,0x2E,0x00,0xB6,0xD0,0x68,0x3E,0x80,
    0x2F,0x0C,0xA9,0xFE,0x64,0x53,0x69,0x7A
])


def md5(data: bytes) -> bytes:
    m = MD5.new()
    m.update(data)
    return m.digest()

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ K)
    return bytes(out)

def pad_password(password: str) -> bytes:
    pb = password.encode('utf-8')
    if len(pb) >= 32:
        return pb[:32]
    padded = bytearray(32)
    padded[:len(pb)] = pb
    padded[len(pb):] = PADDING_BYTES[len(pb):]
    return bytes(padded)

def modmult(a: int, b: int, c: int, m: int, s: int) -> int:
    q = s // a
    s = b * (s - a * q) - c * q
    if s < 0:
        s += m
    return s

def generate_initial_vector(page: int) -> bytes:
    z = page + 1
    initkey = bytearray(16)
    for j in range(4):
        z = modmult(52774, 40692, 3791, 2147483399, z)
        initkey[4*j:4*j+4] = struct.pack('<I', z)
    return md5(bytes(initkey))

def get_page_cipher_params(base_key: bytes, page: int) -> (bytes, bytes):
    nkey = bytearray(base_key) + struct.pack('<I', page) + b'sAlT'
    pagekey = md5(bytes(nkey))
    iv = generate_initial_vector(page)
    return pagekey, iv

def derive_encryption_key(key_str: str) -> bytes:
    # Pad user and owner passwords
    user_pad = pad_password(key_str)
    owner_pad = pad_password("")

    # Compute owner digest = MD5(owner_pad), 50 rounds
    digest = md5(owner_pad)
    for _ in range(50):
        digest = md5(digest)

    assert digest.hex() == "5a00344f40d0a5c52b160b830e6e086e"

    # Derive ownerKey by RC4 20 iterations
    owner_key = bytearray(user_pad)
    for i in range(20):
        mkey = bytes(d ^ i for d in digest)
        owner_key = bytearray(rc4(mkey, owner_key))

    # Compute final digest = MD5(user_pad || owner_key), 50 rounds
    digest = md5(user_pad + owner_key)
    for _ in range(50):
        digest = md5(digest)

    return digest[:16]

def decrypt_page_aes128(base_key: bytes, page: int, data: bytes) -> bytes:
    pagekey, iv = get_page_cipher_params(base_key, page)
    cipher = AES.new(pagekey, AES.MODE_CBC, iv)
    buf = bytearray(data)
    size = len(buf)

    # print(f"[DEBUG] page {page} key: {pagekey.hex()}")
    # print(f"[DEBUG] page {page} iv : {iv.hex()}")

    if page == 1:
        print(f"[DEBUG] page {page} key: {pagekey.hex()}")
        print(f"[DEBUG] page {page} iv : {iv.hex()}")
        orig_hdr = buf[16:24]
        dbPageSize = (orig_hdr[0] << 8) | orig_hdr[1]
        ok_size = (512 <= dbPageSize <= 65536) and (((dbPageSize - 1) & dbPageSize) == 0)
        if ok_size and orig_hdr[5] == 0x40 and orig_hdr[6] == 0x20 and orig_hdr[7] == 0x20:
            buf[16:24] = buf[8:16]
            offset = 16
        else:
            offset = 0
        buf[offset:size] = cipher.decrypt(bytes(buf[offset:size]))
        if offset and buf[16:24] == orig_hdr:
            buf[0:16] = b"SQLite format 3\x00"
    else:
        buf[:] = cipher.decrypt(bytes(buf))
    return bytes(buf)

def decrypt_sqlite_file(encrypted_path: str, decrypted_path: str, key_str: str):
    with open(encrypted_path, 'rb') as f:
        data = f.read()

    page_size = int.from_bytes(data[16:18], 'big')
    total_pages = len(data) // page_size

    print(f"[DEBUG] page_size: {page_size}")
    print(f"[DEBUG] total pages: {total_pages}")

    base_key = derive_encryption_key(key_str)
    print(f"[DEBUG] base key: {base_key.hex()}")

    with open(encrypted_path, 'rb') as fin, open(decrypted_path, 'wb') as fout:
        page = 1
        while True:
            chunk = fin.read(page_size)
            if not chunk:
                break
            fout.write(decrypt_page_aes128(base_key, page, chunk))
            page += 1

def main():

    ap = argparse.ArgumentParser(description="Decrypt LINE Database")
    ap.add_argument("--edb", required=True, help="encrypted LINE edb path")
    ap.add_argument("--passphrase", required=True, help="user passphrase")
    ap.add_argument("--result", require=True, help="decrypted LINE db path")

    decrypt_sqlite_file(ap.edb, ap.result, ap.passphrase)

    return output


if __name__ == "__main__":
    try:
        print("[*] LINE 복호화 시작")
        output = main()
    except Exception as e:
        import traceback
        print("[!] ERROR")
        print(traceback.format_exc())
    finally:
        print(f"[*] output: {output}")
        print("[*] LINE 복호화 종료")