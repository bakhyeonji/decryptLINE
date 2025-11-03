import sys
import re
from pathlib import Path
from typing import List, Set


CHUNK_SIZE = 4 * 1024 * 1024 # 4MB      # 4 MiB
OVERLAP = 256
HEX32_RE = re.compile(rb'[0-9A-Fa-f]{32}')
PATTERN_BYTES = re.compile(rb'encryptionKey.{0,12}?([0-9A-Fa-f]{32})mse', flags=re.IGNORECASE)


def make_utf16l3_pattern():
    key_utf16 = 'encryptionKey'.encode('utf-16le')
    return key_utf16

KEY_UTF16 = make_utf16l3_pattern()


def find_in_bytes(blob: bytes) -> List[str]:
    """Search ascii/utf-8 style occurrences in a bytes blob and return hex candidates as str."""
    matches = []
    for m in PATTERN_BYTES.finditer(blob):
        hexb = m.group(1)
        # sanity check: must be exactly 32 hex chars
        if HEX32_RE.fullmatch(hexb):
            matches.append(hexb.decode('ascii'))
    return matches

def find_in_utf16le(blob: bytes) -> List[str]:
    """
    Search for utf-16le occurrences:
    We look for 'encryptionKey' in utf-16le, then a small window and extract ascii hex bytes interleaved with nulls.
    """
    matches = []
    start = 0
    while True:
        idx = blob.find(KEY_UTF16, start)
        if idx == -1:
            break
        # after idx, skip KEY_UTF16 length
        pos = idx + len(KEY_UTF16)
        # allow up to N bytes (e.g., 64) to skip separators (colons, equals, quotes)
        window = blob[pos: pos + 128]  # 128 bytes window should be enough
        # Look for pattern like: maybe '=' or ':' (utf16le) and then 32 hex characters encoded as ASCII but each followed by \x00
        # We'll search for a sequence of 32 bytes where every even byte is hex char and odd byte is 0x00 or whitespace
        # Create a sliding attempt:
        for off in range(0, max(0, len(window) - 64)):
            candidate = window[off: off + (32 * 2) + 3]  # 32 hex chars -> 64 bytes, + a few for 'mse' (also in utf16le)
            if len(candidate) < (32 * 2) + 6:
                continue
            # build ascii hex from even bytes if odd bytes are 0x00 (or sometimes 0x20)
            try_chars = []
            ok = True
            for i in range(0, 32*2, 2):
                ch = candidate[i]
                pad = candidate[i+1]
                if pad not in (0x00, 0x20):  # allow space as well
                    ok = False
                    break
                # check hex char
                if (48 <= ch <= 57) or (65 <= ch <= 70) or (97 <= ch <= 102):  # 0-9 A-F a-f
                    try_chars.append(chr(ch))
                else:
                    ok = False
                    break
            if not ok:
                continue
            # verify following bytes encode 'm','s','e' in utf16le
            mpos = 32*2
            if mpos + 6 <= len(candidate):
                if candidate[mpos] in (ord('m'),) and candidate[mpos+1] in (0x00,):
                    if candidate[mpos+2] in (ord('s'),) and candidate[mpos+3] in (0x00,):
                        if candidate[mpos+4] in (ord('e'),) and candidate[mpos+5] in (0x00,):
                            hexstr = ''.join(try_chars)
                            matches.append(hexstr)
            # else continue
        start = idx + 2
    return matches

def scan_file(path: Path) -> List[str]:
    """Scan file in chunks and return unique hex32 candidates found (both ascii and utf16le)."""
    candidates: Set[str] = set()
    with path.open('rb') as f:
        prev = b''
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            buffer = prev + chunk
            # search ascii/utf-8 style
            for hexstr in find_in_bytes(buffer):
                candidates.add(hexstr)
            # search utf-16le style
            for hexstr in find_in_utf16le(buffer):
                candidates.add(hexstr)
            # keep overlap
            if len(chunk) >= OVERLAP:
                prev = chunk[-OVERLAP:]
            else:
                prev = chunk
    return sorted(candidates)

def find_passphrase_from_mem(mem_dump: str) -> str:
    path = Path(mem_dump)
    if not path.exists():
        print("[!] Memory dump file not found:", path)
        sys.exit(1)

    candidates = scan_file(path)
    if not candidates:
        print("[!] No passphrase candidates found.")
        passphrase = None
    else:
        print("[*] Found candidates:")
        for c in candidates:
            print("  ", c)
        passphrase = candidates[0]  # choose first as requested
        print("[*] Using passphrase =", passphrase)

    return passphrase