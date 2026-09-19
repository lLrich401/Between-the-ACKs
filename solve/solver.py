#!/usr/bin/env python3
import argparse
import random
import socket
import statistics
import struct
import sys
import time

HOST = None
GATE = 9001
C2 = 9002
UDP_BASE = 20000
NFRAG = 4

DELTA_MIN = 60.0
FIN_DELTA_MAX = 95.0


def connect(port):
    s = socket.create_connection((HOST, port), timeout=15)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def recv_n(s, n, timeout=15.0):
    s.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise EOFError
        buf += c
    return buf


def recv_frame(s, timeout=15.0):
    n = struct.unpack(">H", recv_n(s, 2, timeout))[0]
    return recv_n(s, n, timeout)


def timed_frame(s, timeout=15.0):
    t0 = time.monotonic()
    data = recv_frame(s, timeout)
    return data, (time.monotonic() - t0) * 1000.0


def shaped_probe(s, chunk=4, gap=0.060, probe_len=16):
    payload = bytes(random.randrange(1, 256) for _ in range(probe_len))
    first = True
    for i in range(0, probe_len, chunk):
        if not first:
            time.sleep(gap)
        first = False
        s.sendall(payload[i:i + chunk])


def banner_obs():
    s = connect(GATE)
    shaped_probe(s)
    d1, mA = timed_frame(s, 10.0)
    d2, mB = timed_frame(s, 10.0)
    s.close()
    a = len(d1) - 24
    delta = mA - mB
    shaped = abs(delta) >= DELTA_MIN
    b = 0 if delta < 0 else 1
    return dict(magic=d1[0], a=a, b=b, sid=d1[1:5], d1_ms=mA, d2_ms=mB,
                delta=delta, shaped=shaped)


def run_session(verbose=False):
    for _ in range(6):
        s = connect(GATE)
        shaped_probe(s)
        d1, mA = timed_frame(s, 10.0)
        d2, mB = timed_frame(s, 10.0)
        a = len(d1) - 24
        delta = mA - mB
        if abs(delta) < DELTA_MIN:
            s.close()
            raise RuntimeError("unshaped probe -> decoy banner (equal delays)")
        b = 0 if delta < 0 else 1
        sid = d1[1:5]
        tok = bytes([(3 * a + 5 * b + 0x41) & 0xFF])
        s.sendall(tok)
        resp, ms2 = timed_frame(s, 10.0)
        if resp[0] != 0xC2 or resp[1:5] != sid:
            s.close()
            time.sleep(0.2)
            continue
        if verbose:
            print(f"[+] token ok a={a} b={b} sid={sid.hex()}")
        for i in range(4):
            s.sendall(bytes([sid[i]]))
            echo = recv_n(s, 1, 5.0)
            if echo != bytes([sid[i]]):
                raise RuntimeError("echo mismatch")
            time.sleep(0.070)
        s.shutdown(socket.SHUT_WR)
        hc1, hA = timed_frame(s, 10.0)
        hc2, hB = timed_frame(s, 10.0)
        s.close()
        hdelta = hA - hB
        if abs(hdelta) < DELTA_MIN:
            raise RuntimeError("decoy path (half-close delta ~0)")
        c = 0 if hdelta < 0 else 1
        return dict(a=a, b=b, c=c, sid=sid, l3=len(hc1), hc_ms=hA)
    raise RuntimeError("token rejected repeatedly")


def udp_fetch(sess):
    port = UDP_BASE + sess["l3"] * 7
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(3.0)
    try:
        for _ in range(3):
            u.sendto(sess["sid"], (HOST, port))
            try:
                tk, _ = u.recvfrom(64)
            except socket.timeout:
                continue
            if len(tk) == 8:
                return tk
    finally:
        u.close()
    raise RuntimeError(f"udp silent on {port}")


def finale(sess, tk, verbose=False):
    s = connect(C2)
    s.sendall(sess["sid"] + tk)
    obs = []
    for i in range(12):
        s.sendall(b"\x01")
        f1, mA = timed_frame(s, 10.0)
        f2, mB = timed_frame(s, 10.0)
        obs.append((len(f1), mA - mB))
    blob = recv_frame(s, 10.0)
    s.close()
    real = [ln for ln, delta in obs if abs(delta) < FIN_DELTA_MAX]
    if len(real) != 8:
        raise RuntimeError(f"finale classify failed: real={len(real)}")
    leak = 0
    for ln in real:
        leak = (leak << 2) | (ln - 2)
    sess["leak"] = leak
    sess["blob"] = blob
    if verbose:
        print(f"[+] finale leak={leak:#06x} lens={[o[0] for o in obs]} "
              f"deltas={[round(o[1]) for o in obs]}")
    return leak, blob


def decode(sessions):
    out = b""
    prev = 0
    for sess in sessions:
        k = (sess["leak"] ^ prev) & 0xFFF
        ks = bytes((k ^ ((j * 37) & 0xFF)) & 0xFF for j in range(len(sess["blob"])))
        out += bytes(x ^ y for x, y in zip(sess["blob"], ks))
        prev = sess["leak"]
    return out


def probe_mode(samples):
    lens = []
    deltas = []
    for _ in range(samples):
        o = banner_obs()
        lens.append(24 + o["a"])
        deltas.append(o["delta"])
    print(f"banner payload length: min={min(lens)} max={max(lens)} distinct={len(set(lens))}")
    print(f"delay-pair delta: min={min(deltas):.1f} max={max(deltas):.1f} "
          f"n_pos={sum(1 for d in deltas if d > 0)} n_neg={sum(1 for d in deltas if d < 0)}")


def main():
    global HOST
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--probe", type=int, default=0)
    args = ap.parse_args()
    HOST = args.host
    if args.probe:
        probe_mode(args.probe)
        return
    sessions = []
    for i in range(NFRAG):
        for attempt in range(5):
            try:
                sess = run_session(verbose=True)
                tk = udp_fetch(sess)
                port = UDP_BASE + sess["l3"] * 7
                print(f"[+] session {i} sid={sess['sid'].hex()} l3={sess['l3']} "
                      f"udp_port={port} tk={tk.hex()}")
                finale(sess, tk, verbose=True)
                sessions.append(sess)
                break
            except (RuntimeError, EOFError, ConnectionResetError, socket.timeout, OSError) as e:
                print(f"[-] attempt {attempt + 1}: {e}", file=sys.stderr)
                time.sleep(1.0)
        else:
            raise SystemExit("session failed repeatedly")
        time.sleep(1.2)
    flag = decode(sessions)
    print("FLAG:", flag.decode(errors="replace"))


if __name__ == "__main__":
    main()
