#!/usr/bin/env python3
import argparse
import hashlib
import json
import math
from pathlib import Path
import capsule
E = 65537
SAFE_TEXT = b'XXX'
FAULT_BYTE = 0x77
DEFAULT_HOST = '178.105.199.41'
DEFAULT_PORT = 20000


def fdh_from_canonical(canon: bytes, n: int) -> int:
    h = hashlib.sha256(canon).digest()
    block = (
        hashlib.sha256(b'paper-lantern/v4:msg' + h).digest()
        + hashlib.sha256(b'paper-lantern/v4:aux' + h).digest()
    )
    m = int.from_bytes(block, 'big') % n
    return m or 1


def canonical_safe_message(data: bytes = SAFE_TEXT) -> bytes:
    return b'T' + bytes([len(data)]) + data + b'EH'

def connect_client(host: str, port: int):
    c = capsule.Client(host, port)
    c.strict_handshake()
    return c

def get_signature(host: str, port: int, fault: bool = False):
    c = connect_client(host, port)
    c.send(capsule.FT_INFO)
    typ, _, payload = c.recv()
    assert typ == capsule.RT_INFO, payload
    n = int(json.loads(payload)['n'], 16)

    c.send(capsule.FT_NEWCAP)
    assert c.recv()[0] == capsule.RT_OK

    if fault:
        comment = b''.join([
            capsule.comment_literal(b'A' * 64),
            capsule.comment_literal(b'B' * 8),
            capsule.comment_braid_fill(17, FAULT_BYTE),
        ])
        c.send(capsule.FT_COMMENT, comment)
        r = c.recv()
        assert r[0] == capsule.RT_OK, r

    program = capsule.rec_text(SAFE_TEXT) + capsule.rec_echo() + capsule.rec_halt()
    c.send(capsule.FT_APPEND, program)
    r = c.recv()
    assert r[0] == capsule.RT_OK, r

    c.send(capsule.FT_SIGN)
    r = c.recv()
    assert r[0] == capsule.RT_SIG, r
    c.sock.close()
    return n, int.from_bytes(r[2], 'big')


def hx(x: int) -> str:
    return hex(x)


def main():
    ap = argparse.ArgumentParser(description='Step 1: factor RSA n using CRT fault, then save private key.')
    ap.add_argument('host', nargs='?', default=DEFAULT_HOST)
    ap.add_argument('port', nargs='?', type=int, default=DEFAULT_PORT)
    ap.add_argument('--out', default='paper_lantern_key.json', help='output JSON key file')
    args = ap.parse_args()

    print(f'[*] target {args.host}:{args.port}')
    print('[*] asking for normal signature...')
    n, good_sig = get_signature(args.host, args.port, fault=False)

    print('[*] asking for faulty CRT signature...')
    n2, faulty_sig = get_signature(args.host, args.port, fault=True)
    assert n == n2, 'modulus changed between connections'

    safe_canon = canonical_safe_message()
    safe_m = fdh_from_canonical(safe_canon, n)
    assert pow(good_sig, E, n) == safe_m, 'FDH/canonical reconstruction is wrong'

    diff = (pow(faulty_sig, E, n) - safe_m) % n
    p = math.gcd(diff, n)
    if p in (1, n):
        raise RuntimeError('Not factor n')
    q = n // p
    if p > q:
        p, q = q, p

    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)

    key = {
        'n': hx(n),
        'e': hx(E),
        'p': hx(p),
        'q': hx(q),
        'phi': hx(phi),
        'd': hx(d),
        'sig_len': (n.bit_length() + 7) // 8,
        'safe_canonical_hex': safe_canon.hex(),
        'safe_m': hx(safe_m),
        'good_sig': hx(good_sig),
        'faulty_sig': hx(faulty_sig),
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(key, indent=2), encoding='utf-8')

    print('[+] factored n')
    print(f'    p = {p:x}')
    print(f'    q = {q:x}')
    print('[+] private exponent')
    print(f'    d = {d:x}')
    print(f'[+] saved key to {out_path}')


if __name__ == '__main__':
    main()
