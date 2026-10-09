import socket, sys, time
host, port = "172.100.100.22", 5000
cmds = sys.argv[1:]
s = socket.create_connection((host, port), timeout=10)
s.settimeout(3)
def rd(wait=2.0):
    end = time.time() + wait; out = b""
    while time.time() < end:
        try:
            d = s.recv(4096)
            if not d: break
            out += d
        except socket.timeout:
            pass
    return out.decode("latin1")
def strip_iac(t):
    return "".join(ch for ch in t if ch == "\n" or ch == "\r" or 32 <= ord(ch) < 127)
s.sendall(b"\r"); print(strip_iac(rd(2)))
for c in cmds:
    s.sendall(c.encode() + b"\r"); print(strip_iac(rd(float(3 if not c.startswith("commit") else 30))))
