"""This module can be use to fuzz a parameter, or find the EIP/RIP offset.
"""

import argparse

from pwn import cyclic_metasploit, remote


def fuzz(conn, size, prepend_cmd=None):
    payload = bytes(prepend_cmd, encoding="utf8") + cyclic_metasploit(size)  # type: ignore
    print(f"Sending {len(payload)} of bytes")
    conn.send(payload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-ip",
        "--target_ip",
        type=str,
        required=True,
        help="IP Address of the target machine",
    )
    parser.add_argument(
        "-p",
        "--target_port",
        type=int,
        required=True,
        help="Port of the target service",
    )
    parser.add_argument(
        "-s",
        "--payload_size",
        type=int,
        required=True,
        help="Size of the payload that will be sent.",
    )
    parser.add_argument(
        "-c",
        "--prepend_cmd",
        type=str,
        required=False,
        default="",
        help="A data to be prepended in the payload",
    )
    args = parser.parse_args()

    target_ip = args.target_ip
    target_port = args.target_port
    size = args.payload_size
    prepend_cmd = args.prepend_cmd

    conn = remote(target_ip, target_port, typ="tcp")
    fuzz(conn, size, prepend_cmd)
    conn.close()
