"""Relay orchestration: bore (primary), serveo via ssh (fallback),
and DuckDNS as the stable rendezvous beacon.

The beacon is what makes the whole thing IP-independent: the operator looks up
`<label>.duckdns.org` TXT, gets "server:port" plus an HMAC over the announced
endpoint, and connects there. The label is derived from the token, so it is
stable across reboots, DHCP changes and CGNAT.
"""

import hashlib
import hmac
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

import qu_core
import qu_bore

BEACON_VERSION = "v1"


# --------------------------------------------------------------------------
# DuckDNS
# --------------------------------------------------------------------------

def _duck_names():
    raw = (qu_core.DUCKDNS_DOMAINS or "").strip()
    if not raw:
        return []
    names = []
    for item in raw.replace(";", ",").split(","):
        item = item.strip().strip(".")
        if not item:
            continue
        if item.endswith(".duckdns.org"):
            item = item[: -len(".duckdns.org")]
        if "{sub}" in item:
            item = item.replace("{sub}", qu_core.subdomain())
        names.append(item)
    return names


def duckdns_publish(payload):
    """Write the beacon into the TXT record. Returns True on 'OK'."""
    if not qu_core.DUCKDNS_TOKEN:
        return False
    names = _duck_names()
    if not names:
        return False
    base = {
        "domains": ",".join(names),
        "token": qu_core.DUCKDNS_TOKEN,
        "txt": payload,
    }
    # Preferred: txt only, which leaves any existing A record alone.
    attempts = [dict(base), dict(base, clear="true")]
    for params in attempts:
        try:
            url = "https://www.duckdns.org/update?" + urllib.parse.urlencode(params)
        except Exception:
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read(64).decode("utf-8", "replace").strip()
            if body.upper().startswith("OK"):
                return True
        except Exception:
            continue
    return False


def beacon(server, port):
    """Signed rendezvous string, deliberately short (TXT-safe).

    The nonce is derived from the endpoint (not the clock) so the payload is
    byte-identical while the endpoint is unchanged; that keeps DuckDNS writes
    down to the rate limit instead of one per heartbeat.
    """
    nonce = hashlib.sha256(("%s|%s" % (server, port)).encode()).hexdigest()[:12]
    sig = hmac.new(
        qu_core.auth_key(),
        ("%s|%s|%s|%s" % (BEACON_VERSION, server, port, nonce)).encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    return "%s|%s|%s|%s|%s" % (BEACON_VERSION, server, port, nonce, sig)


def beacon_verify(payload):
    """Return (server, port) if the payload carries a valid signature."""
    try:
        parts = (payload or "").strip().strip('"').split("|")
        if len(parts) != 5 or parts[0] != BEACON_VERSION:
            return None
        _, server, port, nonce, sig = parts
        want = hmac.new(
            qu_core.auth_key(),
            ("%s|%s|%s|%s" % (BEACON_VERSION, server, port, nonce)).encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        if not hmac.compare_digest(sig, want):
            return None
        return server, int(port)
    except Exception:
        return None


# --------------------------------------------------------------------------
# serveo (OpenSSH remote forward) -- fallback when bore is blocked
# --------------------------------------------------------------------------

_PORT_RE = re.compile(r"Allocated port (\d+)")


def serveo_forward(local_port, host=None, on_ready=None, stop=None):
    """Keep an `ssh -R` forward alive. Blocks until stopped.

    serveo.net authenticates anonymous users with keyboard-interactive, so
    BatchMode must stay off and the login user is `serveouser`.
    """
    host = host or qu_core.SERVEO_HOST
    ssh = "ssh"
    cmd = [
        ssh,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=" + _known_hosts(),
        "-o", "ServerAliveInterval=25",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=15",
        "-o", "PreferredAuthentications=keyboard-interactive,password,publickey",
        "-o", "NumberOfPasswordPrompts=1",
        "-N", "-T",
        "-R", "0:127.0.0.1:%d" % local_port,
        "serveouser@" + host,
    ]
    while stop is None or not stop.is_set():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
        except Exception:
            return

        deadline = time.time() + 60
        found = None
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            if isinstance(line, bytes):
                line = line.decode("utf-8", "replace")
            m = _PORT_RE.search(line)
            if m:
                found = int(m.group(1))
                break
        if found and on_ready:
            try:
                on_ready(found)
            except Exception:
                pass
        while proc.poll() is None:
            if stop is not None and stop.is_set():
                try:
                    proc.terminate()
                except Exception:
                    pass
                break
            time.sleep(2)
        try:
            proc.kill()
        except Exception:
            pass
        time.sleep(5)
    while stop is None or not stop.is_set():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
        except Exception:
            return

        deadline = time.time() + 45
        found = None
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            if isinstance(line, bytes):
                line = line.decode("utf-8", "replace")
            m = _PORT_RE.search(line)
            if m:
                found = int(m.group(1))
                break
        if found and on_ready:
            try:
                on_ready(found)
            except Exception:
                pass
        while proc.poll() is None:
            if stop is not None and stop.is_set():
                try:
                    proc.terminate()
                except Exception:
                    pass
                break
            time.sleep(2)
        try:
            proc.kill()
        except Exception:
            pass
        time.sleep(5)


def _known_hosts():
    import os
    return os.path.join(qu_core.state_dir(), "known_hosts")


# --------------------------------------------------------------------------
# DNS: tiny TXT resolver (no dig/nslookup dependency, works on Windows too)
# --------------------------------------------------------------------------

def _encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        out += bytes([len(raw)]) + raw
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


def txt_lookup(name, timeout=5.0, server=None):
    """Return a list of TXT strings for `name`, or [] on any failure."""
    import struct

    servers = [server] if server else []
    if not servers:
        try:
            servers = ["8.8.8.8", "1.1.1.1"]
            for line in open("/etc/resolv.conf"):
                if line.startswith("nameserver"):
                    servers.insert(0, line.split()[1])
                    break
        except Exception:
            servers = ["8.8.8.8", "1.1.1.1"]

    qid = int(time.time() * 1000) & 0xFFFF
    packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    packet += _encode_name(name) + struct.pack("!HH", 16, 1)   # TXT, IN

    for srv in servers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(packet, (srv, 53))
            data, _ = s.recvfrom(4096)
            s.close()
        except Exception:
            continue
        try:
            rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
            if rid != qid or an < 1:
                continue
            pos = 12
            for _ in range(qd):
                pos = _skip_name(data, pos) + 4
            answers = []
            for _ in range(an):
                pos = _skip_name(data, pos)
                rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
                pos += 10
                rdata = data[pos:pos + rdlen]
                pos += rdlen
                if rtype != 16:
                    continue
                i = 0
                chunks = []
                while i < len(rdata):
                    ln = rdata[i]
                    chunks.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                answers.append("".join(chunks))
            if answers:
                return answers
        except Exception:
            continue
    return []


# --------------------------------------------------------------------------
# supervisor
# --------------------------------------------------------------------------

class Supervisor(object):
    def __init__(self, local_port, log=None):
        self.local_port = local_port
        self.log = log or (lambda *a: None)
        self.current = None          # (server, port)
        self.current_since = 0.0
        self._duck_last = None
        self._duck_ts = 0.0

    def current_info(self):
        """(endpoint, age_seconds). Endpoint is None when nothing is up."""
        if self.current is None:
            return None, 0.0
        return self.current, time.time() - self.current_since

    # -- beacon ------------------------------------------------------------

    def publish(self, server, port, force=False):
        payload = beacon(server, port)
        now = time.time()
        # DuckDNS throttles updates, so only write when the endpoint changed,
        # when a previous write failed, or when explicitly forced.
        if not force and payload == self._duck_last:
            return
        ok = duckdns_publish(payload)
        self._duck_last = payload if ok else None
        self._duck_ts = now
        if ok:
            self.log("beacon published %s:%s" % (server, port))
        elif qu_core.DUCKDNS_TOKEN:
            self.log("beacon publish failed")

    # -- bore --------------------------------------------------------------

    def run_bore(self):
        """Primary loop: keep one bore tunnel up forever."""
        servers = []
        for s in (list(getattr(qu_core, "BORE_SERVERS", []) or [])
                  + [qu_core.BORE_SERVER, "bore.pub"]):
            if s and s not in servers:
                servers.append(s)

        attempt = 0
        while True:
            server = servers[attempt % len(servers)]
            attempt += 1
            want = qu_core.public_port()
            try:
                tun = qu_bore.open_with_fallback(
                    self.local_port, server=server, want_port=want, tries=12
                )
            except Exception as exc:
                self.log("bore %s failed: %s" % (server, exc))
                time.sleep(min(60, 5 * attempt))
                continue

            self.current = (server, tun.public_port)
            self.current_since = time.time()
            self.log("bore up %s:%s" % (server, tun.public_port))
            self.publish(server, tun.public_port, force=True)

            last_beat = time.time()

            def _watch():
                # Re-assert the beacon slowly; identical payloads are deduped.
                while True:
                    time.sleep(600)
                    self.publish(server, tun.public_port)

            w = threading.Thread(target=_watch)
            w.daemon = True
            w.start()

            try:
                tun.run()
            except Exception as exc:
                self.log("bore stream ended: %s" % exc)
            finally:
                self.current = None
                try:
                    tun.close()
                except Exception:
                    pass
            if time.time() - last_beat < 5:
                time.sleep(3)
            else:
                time.sleep(2)

    # -- fallback ----------------------------------------------------------

    def run_serveo(self):
        def ready(port):
            self.current = (qu_core.SERVEO_HOST, port)
            self.current_since = time.time()
            self.log("serveo up: %s:%s" % (qu_core.SERVEO_HOST, port))
            self.publish(qu_core.SERVEO_HOST, port, force=True)

        serveo_forward(self.local_port, on_ready=ready)
