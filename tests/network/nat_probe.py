#!/usr/bin/env python3
"""Dual-server STUN probe for the M9 NAT topology harness.

Sends one RFC 5389 binding request to each of two STUN servers from the SAME
UDP socket and prints both XOR-MAPPED-ADDRESS results. Comparing the two
mapped addresses classifies the NAT in front of the socket:

- identical ip:port  -> endpoint-independent mapping (cone NAT emulation)
- different port     -> per-destination mapping (symmetric NAT emulation)

The caller asserts which behavior it expects; the probe only reports.

usage: nat_probe.py SERVER0 SERVER1        # e.g. 203.0.113.2:3478 203.0.113.3:3480
output: NAT_PROBE server0=IP:PORT server1=IP:PORT
"""

import os
import socket
import struct
import sys

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
XOR_MAPPED_ADDRESS = 0x0020


def parse_xor_mapped_address(message: bytes) -> str:
    if len(message) < 20:
        raise ValueError("truncated STUN header")
    message_type, message_length = struct.unpack("!HH", message[:4])
    if (message_type & 0x3FFF) == 0x0111:  # binding error response
        raise ValueError("STUN binding error response")
    if (message_type & 0x3FFF) != 0x0101:  # binding success response
        raise ValueError(f"unexpected STUN message type 0x{message_type:04x}")
    if struct.unpack("!I", message[4:8])[0] != STUN_MAGIC_COOKIE:
        raise ValueError("missing STUN magic cookie")
    attributes = message[20 : 20 + message_length]
    offset = 0
    while offset + 4 <= len(attributes):
        attribute_type, attribute_length = struct.unpack(
            "!HH", attributes[offset : offset + 4])
        value = attributes[offset + 4 : offset + 4 + attribute_length]
        if attribute_type == XOR_MAPPED_ADDRESS and len(value) >= 8:
            family = value[1]
            xport = struct.unpack("!H", value[2:4])[0]
            port = xport ^ (STUN_MAGIC_COOKIE >> 16)
            if family == 0x01 and len(value) >= 8:
                xip = struct.unpack("!I", value[4:8])[0]
                ip_int = xip ^ STUN_MAGIC_COOKIE
                return socket.inet_ntoa(struct.pack("!I", ip_int)) + f":{port}"
            raise ValueError(f"unsupported STUN address family {family}")
        offset += 4 + attribute_length + ((4 - attribute_length % 4) % 4)
    raise ValueError("no XOR-MAPPED-ADDRESS attribute in response")


def query(server: str, sock: socket.socket, attempts: int = 3) -> str:
    host, port = server.rsplit(":", 1)
    address = (host, int(port))
    last_error = "no attempt made"
    for _ in range(attempts):
        transaction_id = os.urandom(12)
        request = (
            struct.pack("!HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE)
            + transaction_id
        )
        try:
            sock.sendto(request, address)
            response, _ = sock.recvfrom(2048)
            if response[8:20] != transaction_id:
                raise ValueError("transaction id mismatch")
            return parse_xor_mapped_address(response)
        except (OSError, ValueError) as error:
            last_error = str(error)
    raise SystemExit(f"NAT_PROBE_FAILED server={server} error={last_error}")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        server0 = query(sys.argv[1], sock)
        server1 = query(sys.argv[2], sock)
    finally:
        sock.close()
    print(f"NAT_PROBE server0={server0} server1={server1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
