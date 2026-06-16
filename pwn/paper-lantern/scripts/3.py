#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

try:
    import capsule
except ImportError:
    print('[!] Run this script from the dist/ folder, or copy capsule.py next to it.')
    raise

DEFAULT_HOST = '178.105.199.41'
DEFAULT_PORT = 20000
DEFAULT_KEY = 'paper_lantern_key.json'


def parse_int(v):
    if isinstance(v, int):
        return v
    return int(v, 0)


def fdh_from_canonical(canon: bytes, n: int) -> int:
    """RSA-FDH used by the challenge: FDH(SHA256(canonical_records)) mod n."""
    h = hashlib.sha256(canon).digest()
    block = (
        hashlib.sha256(b'paper-lantern/v4:msg' + h).digest()
        + hashlib.sha256(b'paper-lantern/v4:aux' + h).digest()
    )
    m = int.from_bytes(block, 'big') % n
    return m or 1


def connect_client(host: str, port: int):
    c = capsule.Client(host, port)
    c.strict_handshake()
    return c


def load_private_key(path: str):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    n = parse_int(data['n'])
    e = parse_int(data.get('e', '0x10001'))
    d = parse_int(data['d'])
    sig_len = int(data.get('sig_len', (n.bit_length() + 7) // 8))
    return n, e, d, sig_len


def sign_forbidden_opcode(n: int, e: int, d: int):
    # RUN verifies the unsafe capsule with allow_unsafe=1.
    # In that mode, raw opcode 0x7f renders canonically as b'F'.
    # rec_halt() renders as b'H'. So the signed canonical stream is b'FH'.
    unsafe_canon = b'FH'
    unsafe_m = fdh_from_canonical(unsafe_canon, n)
    forged_sig = pow(unsafe_m, d, n)
    assert pow(forged_sig, e, n) == unsafe_m, 'forged signature failed local RSA check'
    return forged_sig, unsafe_m, unsafe_canon


def run_forbidden_program(host: str, port: int, forged_sig: int, sig_len: int):
    c = connect_client(host, port)

    c.send(capsule.FT_NEWCAP)
    assert c.recv()[0] == capsule.RT_OK

    # 0x7f is rejected by SIGN, but RUN executes it as the flag-printing opcode.
    program = capsule.rec_raw(0x7f) + capsule.rec_halt()
    c.send(capsule.FT_APPEND, program)
    r = c.recv()
    assert r[0] == capsule.RT_OK, r

    c.send(capsule.FT_RUN, forged_sig.to_bytes(sig_len, 'big'))
    typ, _, out = c.recv()
    print(out.decode(errors='replace'))
    c.sock.close()


def main():
    ap = argparse.ArgumentParser(description='Step 2: sign forbidden opcode with saved private key and run it.')
    ap.add_argument('host', nargs='?', default=DEFAULT_HOST)
    ap.add_argument('port', nargs='?', type=int, default=DEFAULT_PORT)
    ap.add_argument('--key', default=DEFAULT_KEY, help='JSON key file produced by step 1')
    ap.add_argument('--print-sig-only', action='store_true', help='only print forged signature, do not connect/run')
    args = ap.parse_args()

    n, e, d, sig_len = load_private_key(args.key)
    forged_sig, unsafe_m, unsafe_canon = sign_forbidden_opcode(n, e, d)

    print('[+] signed forbidden capsule')
    print(f'    canonical = {unsafe_canon!r}')
    print(f'    unsafe_m  = {unsafe_m:x}')
    print(f'    sig       = {forged_sig:x}')

    if args.print_sig_only:
        return

    print(f'[*] running forbidden opcode against {args.host}:{args.port}...')
    run_forbidden_program(args.host, args.port, forged_sig, sig_len)


if __name__ == '__main__':
    main()
