#!/usr/bin/env python3
import argparse, base64, socket, sys, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko

LOCK = threading.Lock()

def emit(ip, line):
    with LOCK:
        print(f"{ip:<15} | {line}", flush=True)

def run(ip, user, pw, b64):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(ip, username=user, password=pw, timeout=8,
                  banner_timeout=8, auth_timeout=8,
                  allow_agent=False, look_for_keys=False)
        ch = c.get_transport().open_session()
        ch.settimeout(300)
        ch.exec_command(f"echo {b64} | base64 -d | sh 2>&1")
        buf = b""
        while True:
            try:
                d = ch.recv(4096)
            except socket.timeout:
                emit(ip, "[timeout]"); return
            if not d: break
            buf += d
            while b"\n" in buf:
                ln, buf = buf.split(b"\n", 1)
                emit(ip, ln.decode(errors="replace").rstrip("\r"))
        if buf:
            emit(ip, buf.decode(errors="replace").rstrip("\r"))
        emit(ip, f"[exit {ch.recv_exit_status()}]")
    except Exception as e:
        emit(ip, f"[error] {e}")
    finally:
        try: c.close()
        except: pass

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("-s", "--script", required=True)
    p.add_argument("-H", "--hosts", required=True)
    a = p.parse_args()

    with open(a.script, "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode()
    with open(a.hosts) as fh:
        targets = [l.strip() for l in fh if l.strip()]
    if not targets:
        sys.exit("no targets")

    with ThreadPoolExecutor(max_workers=len(targets)) as ex:
        for f in as_completed([ex.submit(run, ip, a.username, a.password, b64)
                               for ip in targets]):
            f.result()

if __name__ == "__main__":
    main()
