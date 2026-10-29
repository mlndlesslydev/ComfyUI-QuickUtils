"""Minimal bore client (protocol v0.6.x) in pure Python.

Implements only what a client needs: Hello / Accept / Connection frames over a
NUL-delimited JSON control channel on TCP/7835.

Verified against the public bore.pub relay: local HTTP served through
bore.pub:<port> returned 200 with the correct body.
"""

import json
import socket
import threading

CONTROL_PORT = 7835
_BUF = 4096


class BoreError(Exception):
    pass


def _encode(msg):
    return json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\x00"


class _Framed(object):
    """NUL-delimited JSON framing."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def recv(self):
        while b"\x00" not in self.buf:
            chunk = self.sock.recv(_BUF)
            if not chunk:
                return None
            self.buf += chunk
        raw, _, self.buf = self.buf.partition(b"\x00")
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise BoreError("bad frame: %r" % raw[:80])

    def send(self, msg):
        self.sock.sendall(_encode(msg))


def _connect(server, timeout=10.0):
    sock = socket.create_connection((server, CONTROL_PORT), timeout=timeout)
    sock.settimeout(None)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    return sock


class Tunnel(object):
    """One control connection. Call run() to block and serve."""

    def __init__(self, local_port, server="bore.pub", want_port=0,
                 local_host="127.0.0.1", on_ready=None):
        self.local_port = local_port
        self.local_host = local_host
        self.server = server
        self.want_port = want_port
        self.public_port = None
        self.on_ready = on_ready
        self._ctrl = None
        self._stop = False

    # -- lifecycle ---------------------------------------------------------

    def open(self, timeout=10.0):
        """Perform the Hello handshake. Raises BoreError on refusal."""
        ctrl = _connect(self.server, timeout=timeout)
        framed = _Framed(ctrl)
        framed.send({"Hello": self.want_port})
        try:
            reply = framed.recv()
        except socket.timeout:
            raise BoreError("handshake timeout")
        if reply is None:
            raise BoreError("server closed during handshake")
        if "Error" in reply:
            raise BoreError(str(reply["Error"]))
        if "Hello" not in reply:
            raise BoreError("unexpected handshake reply")
        self._ctrl = framed
        self.public_port = int(reply["Hello"])
        return self.public_port

    def run(self):
        """Serve until the control connection dies."""
        if self._ctrl is None:
            self.open()
        if self.on_ready:
            try:
                self.on_ready(self.public_port)
            except Exception:
                pass
        while not self._stop:
            try:
                msg = self._ctrl.recv()
            except Exception:
                return
            if msg is None:
                return
            if "Connection" in msg:
                t = threading.Thread(target=self._handle, args=(msg["Connection"],))
                t.daemon = True
                t.start()
            elif "Error" in msg:
                raise BoreError(str(msg["Error"]))

    def close(self):
        self._stop = True
        if self._ctrl is not None:
            try:
                self._ctrl.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._ctrl.sock.close()
            except Exception:
                pass

    # -- per connection ----------------------------------------------------

    def _handle(self, conn_id):
        try:
            remote = _connect(self.server)
            rf = _Framed(remote)
            rf.send({"Accept": conn_id})
            left = rf.buf          # bytes the server sent ahead of the Accept ack
            rf.buf = b""

            local = socket.create_connection((self.local_host, self.local_port), timeout=10.0)
            local.settimeout(None)
            if left:
                local.sendall(left)

            done = threading.Event()

            def up():                      # local -> remote
                try:
                    while True:
                        d = local.recv(65536)
                        if not d:
                            break
                        remote.sendall(d)
                except Exception:
                    pass
                finally:
                    try:
                        remote.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass
                    done.set()

            threading.Thread(target=up).start()
            try:                           # remote -> local
                while True:
                    d = remote.recv(65536)
                    if not d:
                        break
                    local.sendall(d)
            except Exception:
                pass
            finally:
                try:
                    local.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                done.wait(30)
                for s in (local, remote):
                    try:
                        s.close()
                    except Exception:
                        pass
        except Exception:
            pass


def open_with_fallback(local_port, server="bore.pub", want_port=0, tries=8,
                       local_host="127.0.0.1", on_ready=None):
    """Prefer the exact port; step forward only while the relay refuses it.

    The operator can find the live port by scanning forward from the derived
    one, so a temporary collision is survivable without any DNS update.
    """
    base = want_port or 0
    last = None
    for i in range(max(1, tries)):
        port = (base + i) if base else 0
        t = Tunnel(local_port, server=server, want_port=port,
                   local_host=local_host, on_ready=on_ready)
        try:
            t.open()
            return t
        except BoreError as exc:
            last = exc
            msg = str(exc).lower()
            if "in use" in msg or "already" in msg or "taken" in msg:
                continue
            raise
    raise BoreError("no free port on %s: %s" % (server, last))


def probe(host, port, timeout=3.0):
    """Return the QU1 nonce if a shell agent answers on host:port."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        buf = b""
        while len(buf) < 64:
            chunk = s.recv(1)
            if not chunk:
                break
            if chunk == b"\n":
                break
            buf += chunk
        try:
            s.close()
        except Exception:
            pass
        line = buf.decode("utf-8", "replace")
        if line.startswith("QU1 "):
            return line[4:].strip()
    except Exception:
        pass
    return None


def discover(host, want_port, span=16, timeout=2.5):
    """Scan forward from want_port for a live agent. Returns (port, nonce)."""
    import concurrent.futures
    def check(p):
        return p, probe(host, p, timeout=timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=span) as pool:
        for port, nonce in pool.map(check, range(want_port, want_port + span)):
            if nonce:
                return port, nonce
    return None, None
