#!/usr/bin/env python3
import os
import socket
import struct
import subprocess
import sys
import threading
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "solve"))
import solver

EXPECTED = "LR{b3tw33n_th3_ACKs_1s_wh3r3_th3_pr0t0c0l_l1v3s}"
HOST = "127.0.0.1"


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection((HOST, port), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def main():
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=os.path.join(BASE, "challenge"),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        assert wait_port(9001), "gate did not start"
        solver.HOST = HOST
        print("[*] probe mode")
        solver.probe_mode(8)
        print("[*] full solve")
        sessions = []
        for i in range(solver.NFRAG):
            sess = solver.run_session(verbose=True)
            tk, uport = solver.udp_fetch(sess)
            print(f"[+] session {i} sid={sess['sid'].hex()} l3={sess['l3']} "
                  f"udp_port={uport} tk={tk.hex()}")
            solver.finale(sess, tk, verbose=True)
            sessions.append(sess)
        flag = solver.decode(sessions).decode(errors="replace")
        print("FLAG:", flag)
        if flag == EXPECTED:
            print("[PASS] e2e ok")
            return 0
        print(f"[FAIL] got {flag!r}")
        return 1
    finally:
        proc.terminate()


if __name__ == "__main__":
    sys.exit(main())
