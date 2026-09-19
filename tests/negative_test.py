#!/usr/bin/env python3
import os
import socket
import struct
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "solve"))
import solver

HOST = "127.0.0.1"
UDP_BASE = 20001


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection((HOST, port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def recv_frame(s, timeout=15.0):
    s.settimeout(timeout)
    n = struct.unpack(">H", solver.recv_n(s, 2))[0]
    return solver.recv_n(s, n)


def timed_frame(s, timeout=15.0):
    t0 = time.monotonic()
    data = recv_frame(s, timeout)
    return data, (time.monotonic() - t0) * 1000.0


def test_probe_decoy():
    for _ in range(6):
        s = solver.connect(9001)
        s.sendall(b"A" * 16)
        d1, mA = timed_frame(s, 10)
        d2, mB = timed_frame(s, 10)
        assert d1[0] == 0xC1
        delta = mA - mB
        assert abs(delta) < 60, f"decoy banner should have ~equal delays, delta={delta:.0f}ms"
        a = len(d1) - 24
        b = 0 if delta < 0 else 1
        sid = d1[1:5]
        s.sendall(bytes([(3 * a + 5 * b + 0x41) & 0xFF]))
        resp = timed_frame(s, 10)[0]
        if resp[0] == 0xC2:
            break
        s.close()
    else:
        raise AssertionError("decoy session never accepted token")
    for i in range(4):
        s.sendall(bytes([sid[i]]))
        assert s.recv(1) == bytes([sid[i]])
        time.sleep(0.07)
    s.shutdown(socket.SHUT_WR)
    hc1, hA = timed_frame(s, 10)
    hc2, hB = timed_frame(s, 10)
    s.close()
    hdelta = hA - hB
    assert abs(hdelta) < 60, f"decoy hc should have ~equal delays, delta={hdelta:.0f}ms"
    port = UDP_BASE + (len(hc1) % 2)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2.0)
    u.sendto(sid, (HOST, port))
    silent = False
    try:
        u.recvfrom(64)
    except (socket.timeout, ConnectionResetError, OSError):
        silent = True
    u.close()
    assert silent, "decoy session must not open UDP service"
    print(f"[PASS] single-write probe -> decoy path (banner delta={delta:.0f}ms, "
          f"hc delta={hdelta:.0f}ms, udp silent)")


def test_shaped_vs_unshaped():
    o = solver.banner_obs()
    assert o["shaped"], f"shaped probe must give delta pair, delta={o['delta']:.0f}ms"
    print(f"[PASS] shaped probe -> distinct delay ordering (delta={o['delta']:.0f}ms)")


def test_token_bruteforce_punish():
    s = solver.connect(9001)
    for i in range(5):
        solver.shaped_probe(s)
        d1 = recv_frame(s, 10)
        recv_frame(s, 10)
        assert d1[0] == 0xC1
        s.sendall(bytes([0x00]))
        resp = recv_frame(s, 10)
        assert resp == b"ERR\n"
    s.sendall(bytes([0x00]))
    resp = recv_frame(s, 10)
    assert resp == b"ERR\n", "connection should be poisoned after 5 failures"
    s.sendall(bytes([0x01]))
    resp2 = recv_frame(s, 5)
    assert resp2 == b"ERR\n", "poisoned connection must keep answering ERR"
    print("[PASS] token bruteforce -> session poisoned (ERR loop)")
    s.close()


def test_replay_rejected():
    sess = solver.run_session()
    tk = solver.udp_fetch(sess)
    solver.finale(sess, tk)
    s = solver.connect(9002)
    s.sendall(sess["sid"] + tk)
    resp = recv_frame(s, 10)
    assert resp == b"ERR\n", "replay of sid+tk must be rejected"
    s.close()
    print("[PASS] finale replay rejected")


def main():
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=os.path.join(BASE, "challenge"),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_port(9001)
        solver.HOST = HOST
        test_shaped_vs_unshaped()
        test_probe_decoy()
        test_token_bruteforce_punish()
        test_replay_rejected()
        print("[PASS] all negative tests")
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
