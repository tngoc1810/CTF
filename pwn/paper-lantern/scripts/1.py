#!/usr/bin/env python3
import sys
import socket
import struct

FT_HELLO = 0x10
FT_ACK_STRICT = 0x12
FT_NEWCAP = 0x20
FT_APPEND = 0x21
FT_SIGN = 0x22

RT_NAME = {
    0x80: "RT_OK",
    0x81: "RT_ERR",
    0x82: "RT_MODE",
    0x83: "RT_SIG",
    0x84: "RT_OUT",
    0x85: "RT_INFO",
}

REC_TEXT = 0x01
REC_HALT = 0x03

def rec_text(data: bytes) -> bytes:
    return bytes([REC_TEXT, len(data)]) + data

def rec_halt() -> bytes:
    return bytes([REC_HALT])

def rec_raw(kind: int, payload: bytes = b"") -> bytes:
    return bytes([kind]) + payload

class Client:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, int(port)))
        self.seq = 0

    def readn(self, n):
        out = b""
        while len(out) < n:
            chunk = self.s.recv(n - len(out))
            if not chunk:
                raise EOFError("connection closed")
            out += chunk
        return out

    def recv(self, label):
        hdr = self.readn(4)
        ftype, seq, length = struct.unpack("<BBH", hdr)
        payload = self.readn(length)
        name = RT_NAME.get(ftype, f"0x{ftype:02x}")
        text = payload.decode(errors="replace")
        print(f"[{label}] type={name} seq={seq} len={length}")
        print(f"    payload_hex  = {payload.hex()}")
        print(f"    payload_text = {text!r}")
        return ftype, seq, payload

    def send(self, ftype, payload=b"", label="send"):
        print(f"[{label}] type=0x{ftype:02x} seq={self.seq} len={len(payload)} payload={payload.hex()}")
        self.s.sendall(struct.pack("<BBH", ftype, self.seq, len(payload)) + payload)
        self.seq = (self.seq + 1) & 0xff

    def handshake(self):
        self.recv("banner")
        self.send(FT_HELLO, b"\x01", "HELLO strict")
        self.recv("after HELLO")
        self.send(FT_ACK_STRICT, b"", "ACK_STRICT")
        self.recv("after ACK_STRICT")

def test(host, port, name, payload):
    print("=" * 72)
    print(f"TEST: {name}")
    print(f"capsule hex = {payload.hex()}")
    c = Client(host, port)
    c.handshake()

    c.send(FT_NEWCAP, b"", "NEWCAP")
    c.recv("after NEWCAP")

    c.send(FT_APPEND, payload, "APPEND")
    c.recv("after APPEND")

    c.send(FT_SIGN, b"", "SIGN")
    c.recv("after SIGN")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} HOST PORT")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    safe = rec_text(b"A") + rec_halt()
    unsafe_7f = rec_raw(0x7f) + rec_halt()

    test(host, port, "SAFE: TEXT('A') + HALT", safe)
    test(host, port, "UNSAFE: opcode 0x7f + HALT", unsafe_7f)
