#!/usr/bin/env python3
import argparse
import concurrent.futures
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

HOST = "127.0.0.1"


def one_session(i):
    t0 = time.monotonic()
    try:
        sess = solver.run_session()
        return True, (time.monotonic() - t0) * 1000, None
    except Exception as e:
        return False, (time.monotonic() - t0) * 1000, repr(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--rounds", type=int, default=3)
    args = ap.parse_args()
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=os.path.join(BASE, "challenge"),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        end = time.time() + 10
        while time.time() < end:
            try:
                socket.create_connection((HOST, 9001), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)
        ok = 0
        fail = 0
        times = []
        for r in range(args.rounds):
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
                for good, ms, err in ex.map(one_session, range(args.workers)):
                    if good:
                        ok += 1
                        times.append(ms)
                    else:
                        fail += 1
                        print("[-]", err)
            time.sleep(0.5)
        import statistics
        print(f"ok={ok} fail={fail} median={statistics.median(times):.0f}ms max={max(times):.0f}ms")
        s = socket.create_connection((HOST, 9001), timeout=5)
        s.close()
        print("[PASS] server responsive after load")
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
