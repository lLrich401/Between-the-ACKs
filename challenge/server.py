#!/usr/bin/env python3
import os
import random
import socket
import struct
import threading
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("BTA_PORT", "9001"))
UDP_BASE = int(os.environ.get("BTA_UDP_BASE", "20001"))
NUDP = 2


def load_flag():
    v = os.environ.get("BTA_FLAG")
    if v:
        return v.encode()
    try:
        with open("/flag", "rb") as f:
            data = f.read().strip()
            if data:
                return data
    except OSError:
        pass
    return b"LR{b3tw33n_th3_ACKs_1s_wh3r3_th3_pr0t0c0l_l1v3s}"


FLAG = load_flag()
NFRAG = 4
MAX_CONN = 64
SESSION_TTL = 600.0
IDLE_TIMEOUT = 30.0
UDP_TTL = 15.0
PER_IP_LIMIT = int(os.environ.get("BTA_PER_IP_LIMIT", "6"))

JIT = 0.025
D_S0 = (0.080, 0.200)
D_S1 = 0.060
D_HC = (0.080, 0.200)
D_HC_DECOY = 0.350
D_FIN_REAL = 0.060
D_FIN_DECOY = 0.250

ERR = b"ERR\n"
MAGIC_S0 = 0xC1
MAGIC_S1 = 0xC2


def jit(base):
    return max(0.005, base + random.uniform(-JIT, JIT))


def split_flag(flag):
    per = (len(flag) + NFRAG - 1) // NFRAG
    return [flag[i * per:(i + 1) * per].ljust(per, b" ") for i in range(NFRAG)]


CHUNKS = split_flag(FLAG)
CHUNK_LEN = len(CHUNKS[0])


def keystream(k, n):
    return bytes((k ^ ((j * 37) & 0xFF)) & 0xFF for j in range(n))


class Sess:
    __slots__ = ("sid", "sid_int", "a", "b", "c", "l3", "fail", "poisoned",
                 "shaped", "echo_ok", "seg_ok", "udp_done", "tk", "used",
                 "ts", "leak", "slot", "udp_deadline")

    def __init__(self):
        self.sid = os.urandom(4)
        self.sid_int = struct.unpack(">I", self.sid)[0]
        self.a = random.randrange(16)
        self.b = random.randrange(2)
        self.c = random.randrange(2)
        self.l3 = random.randrange(1, 701)
        self.fail = 0
        self.poisoned = False
        self.shaped = False
        self.echo_ok = False
        self.seg_ok = False
        self.udp_done = False
        self.tk = None
        self.used = False
        self.ts = time.time()
        self.leak = None
        self.slot = None
        self.udp_deadline = 0.0

    def rechallenge(self):
        self.a = random.randrange(16)
        self.b = random.randrange(2)
        self.c = random.randrange(2)
        self.l3 = random.randrange(1, 701)
        self.echo_ok = False
        self.seg_ok = False

    @property
    def genuine(self):
        return self.shaped and self.seg_ok


class Glob:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions = {}
        self.run_counter = 0
        self.last_leak = 0
        self.conn_sem = threading.Semaphore(MAX_CONN)

    def gc(self):
        now = time.time()
        with self.lock:
            dead = [k for k, v in self.sessions.items() if now - v.ts > SESSION_TTL]
            for k in dead:
                del self.sessions[k]

    def reserve_finale(self, sess):
        with self.lock:
            slot = self.run_counter
            self.run_counter += 1
            prev = self.last_leak
            k = (sess.a * 3 + sess.b * 5 + sess.c * 7 + (sess.l3 & 0x3F)) & 0xFFF
            leak = ((slot & 0xF) << 12) | ((k ^ prev) & 0xFFF)
            self.last_leak = leak
        sess.slot = slot
        sess.leak = leak
        return slot, prev, k, leak


G = Glob()
IP_SEMS = {}
IP_SEMS_LOCK = threading.Lock()


def ip_acquire(ip, timeout=120.0):
    with IP_SEMS_LOCK:
        sem = IP_SEMS.get(ip)
        if sem is None:
            sem = threading.BoundedSemaphore(PER_IP_LIMIT)
            IP_SEMS[ip] = sem
    return sem.acquire(timeout=timeout)


def ip_release(ip):
    sem = IP_SEMS.get(ip)
    if sem is not None:
        try:
            sem.release()
        except ValueError:
            pass


def read_exact(sock, n, timeout):
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
    except socket.timeout:
        return None
    except OSError:
        return None
    return buf


def read_probe(sock):
    sock.settimeout(0.4)
    data = b""
    events = 0
    last = None
    deadline = time.monotonic() + IDLE_TIMEOUT
    while len(data) < 16:
        if time.monotonic() > deadline:
            return None
        try:
            chunk = sock.recv(16 - len(data))
        except socket.timeout:
            continue
        except OSError:
            return None
        if not chunk:
            return None
        now = time.monotonic()
        if last is None or now - last > 0.003:
            events += 1
        last = now
        data += chunk
    return events


def frame(payload):
    return struct.pack(">H", len(payload)) + payload


def make_blob0(sess):
    body = bytearray([MAGIC_S0]) + sess.sid
    total = 24 + sess.a
    pad = bytes(random.randrange(1, 256) for _ in range(total - 5))
    return frame(bytes(body) + pad)


def make_blob1(sess):
    body = bytearray([MAGIC_S1]) + sess.sid
    pad = bytes(random.randrange(1, 256) for _ in range(24 - 5))
    return frame(bytes(body) + pad)


def make_blob_t(sess, magic, total):
    body = bytearray([magic]) + sess.sid
    pad = bytes(random.randrange(1, 256) for _ in range(total - 5))
    return frame(bytes(body) + pad)


def udp_responder(sock, port):
    sock.settimeout(1.0)
    while True:
        try:
            data, addr = sock.recvfrom(16)
        except socket.timeout:
            continue
        except OSError:
            return
        if len(data) != 4:
            continue
        sid_int = struct.unpack(">I", data)[0]
        with G.lock:
            sess = G.sessions.get(sid_int)
            ok = (sess is not None and sess.genuine and sess.tk is not None
                  and not sess.udp_done and not sess.used
                  and time.time() < sess.udp_deadline
                  and UDP_BASE + (sess.l3 % NUDP) == port)
        if ok:
            try:
                sock.sendto(sess.tk, addr)
            except OSError:
                pass
            sess.udp_done = True


def echo_phase(sock, sess):
    got = []
    prev = None
    sock.settimeout(5.0)
    shape_ok = True
    while len(got) < 4:
        try:
            b1 = sock.recv(1)
        except socket.timeout:
            shape_ok = False
            break
        except OSError:
            return False
        if not b1:
            shape_ok = False
            break
        now = time.monotonic()
        if prev is not None:
            gap = now - prev
            if gap < 0.015 or gap > 2.0:
                shape_ok = False
        prev = now
        got.append(b1)
        try:
            sock.sendall(b1)
        except OSError:
            return False
    if len(got) != 4 or not shape_ok:
        drain_quiet(sock, 2.0)
        return False
    sock.settimeout(5.0)
    try:
        nxt = sock.recv(64)
    except socket.timeout:
        nxt = None
    except OSError:
        return False
    if nxt != b"":
        drain_quiet(sock, 2.0)
        return False
    return True


def drain_quiet(sock, timeout):
    sock.settimeout(timeout)
    try:
        while True:
            if not sock.recv(4096):
                break
    except (socket.timeout, OSError):
        pass


def finale(sock, sess):
    slot, prev, k, leak = G.reserve_finale(sess)
    if slot < NFRAG:
        chunk = CHUNKS[slot]
    else:
        chunk = b"EXHAUSTED".ljust(CHUNK_LEN, b" ")
    blob = bytes(a ^ b for a, b in zip(chunk, keystream(k, CHUNK_LEN)))
    real_pos = set(random.sample(range(12), 8))
    bits = [(leak >> (15 - i)) & 1 for i in range(16)]
    ri = 0
    for i in range(12):
        got = read_exact(sock, 1, 10.0)
        if got is None:
            return
        if i in real_pos:
            two = (bits[2 * ri] << 1) | bits[2 * ri + 1]
            ri += 1
            length = 2 + two
            dA, dB = D_FIN_REAL, D_FIN_REAL
        else:
            length = 2 + random.randrange(4)
            dA, dB = D_FIN_REAL, D_FIN_DECOY
        time.sleep(jit(dA))
        try:
            sock.sendall(frame(b"\x00" * length))
        except OSError:
            return
        time.sleep(jit(dB))
        try:
            sock.sendall(frame(b"\x00" * 8))
        except OSError:
            return
    time.sleep(0.05)
    try:
        sock.sendall(frame(blob))
        sock.shutdown(socket.SHUT_WR)
        drain_quiet(sock, 5.0)
    except OSError:
        pass


def handle(conn, addr):
    ip = addr[0]
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sess = Sess()
    with G.lock:
        G.sessions[sess.sid_int] = sess
    try:
        while True:
            if sess.poisoned:
                got = read_exact(conn, 1, IDLE_TIMEOUT)
                if got is None:
                    return
                conn.sendall(frame(ERR))
                continue
            events = read_probe(conn)
            if events is None:
                return
            sess.shaped = events >= 3
            if sess.shaped:
                dA, dB = (D_S0[0], D_S0[1]) if sess.b == 0 else (D_S0[1], D_S0[0])
            else:
                dA = dB = D_S0[1]
            time.sleep(jit(dA))
            conn.sendall(make_blob0(sess))
            time.sleep(jit(dB))
            conn.sendall(make_blob_t(sess, 0xC3, 24))
            tok = read_exact(conn, 1, IDLE_TIMEOUT)
            if tok is None:
                return
            want = bytes([(3 * sess.a + 5 * sess.b + 0x41) & 0xFF])
            if tok == want:
                time.sleep(jit(D_S1))
                conn.sendall(make_blob1(sess))
                sess.echo_ok = True
                seg = echo_phase(conn, sess)
                sess.seg_ok = seg
                if sess.genuine:
                    sess.tk = os.urandom(8)
                    sess.udp_deadline = time.time() + UDP_TTL
                    dA, dB = (D_HC[0], D_HC[1]) if sess.c == 0 else (D_HC[1], D_HC[0])
                else:
                    dA = dB = D_HC_DECOY
                time.sleep(jit(dA))
                conn.sendall(frame(b"\x5A" * sess.l3))
                time.sleep(jit(dB))
                conn.sendall(frame(b"\x5A" * 32))
                try:
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                drain_quiet(conn, 10.0)
                return
            else:
                sess.fail += 1
                conn.sendall(frame(ERR))
                if sess.fail > 4:
                    sess.poisoned = True
                else:
                    sess.rechallenge()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def handle_c2(conn, addr):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        data = read_exact(conn, 12, 15.0)
        if data is None:
            conn.sendall(frame(ERR))
            return
        sid_int = struct.unpack(">I", data[:4])[0]
        with G.lock:
            sess = G.sessions.get(sid_int)
            ok = (sess is not None and sess.udp_done and sess.tk is not None
                  and not sess.used and sess.tk == data[4:12])
            if ok:
                sess.used = True
        if not ok:
            conn.sendall(frame(ERR))
            drain_quiet(conn, 2.0)
            return
        finale(conn, sess)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def gc_loop():
    while True:
        time.sleep(60)
        G.gc()


def listener(port, handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, port))
    srv.listen(64)
    while True:
        conn, addr = srv.accept()
        if not G.conn_sem.acquire(blocking=False):
            try:
                conn.close()
            except OSError:
                pass
            continue
        def worker(c=conn, a=addr, h=handler, gated=(handler is handle)):
            try:
                if gated:
                    if not ip_acquire(a[0]):
                        return
                try:
                    h(c, a)
                finally:
                    if gated:
                        ip_release(a[0])
            finally:
                G.conn_sem.release()
        threading.Thread(target=worker, daemon=True).start()


def main():
    threading.Thread(target=gc_loop, daemon=True).start()
    for i in range(NUDP):
        port = UDP_BASE + i
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((LISTEN_HOST, port))
        threading.Thread(target=udp_responder, args=(s, port), daemon=True).start()
    threading.Thread(target=listener, args=(LISTEN_PORT, handle), daemon=True).start()
    listener(LISTEN_PORT + 1, handle_c2)


if __name__ == "__main__":
    main()
