#!/usr/bin/env python3
import argparse
import socket
from pathlib import Path


DEFAULT_HOST = "65.109.208.46"
DEFAULT_PORT = 1337


def receive_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Submit the QFilter exploit")
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    payload_path = Path(__file__).with_name("exploit.js")
    payload = payload_path.read_bytes().rstrip(b"\n") + b"\n-- EOF --\n"

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.settimeout(5)
        banner = receive_until(sock, b":\n")
        print(banner.decode(errors="replace"), end="")
        sock.sendall(payload)

        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            print(chunk.decode(errors="replace"), end="")


if __name__ == "__main__":
    main()
