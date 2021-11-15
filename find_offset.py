import argparse

from pwn import cyclic_metasploit_find

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a", "--address", type=str, required=True, help="EIP hex value"
    )
    parser.add_argument(
        "-c",
        "--prepend_cmd",
        type=str,
        required=False,
        default="",
        help="EIP hex value",
    )
    args = parser.parse_args()

    hex_val = int(args.address, 16)
    offset = cyclic_metasploit_find(hex_val)
    cmd = args.prepend_cmd

    offset_eip = offset + len(cmd)
    offset_esp = offset_eip + 4  # + 4 bytes after EIP

    print(f"Offset of {args.address}: {offset}")
    print(f"Offset of EIP + cmd len : {offset_eip}")
    print(f"Offset of EIP + cmd len + 4 = ESP: {offset_esp}")
