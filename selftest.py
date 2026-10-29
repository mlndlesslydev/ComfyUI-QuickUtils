"""End-to-end verification suite.

Runs against a live agent. Two layers:

  * local  - drives a temporary agent on this machine, checks auth, the shell,
             single-instance behaviour, the pipes path and port discovery;
  * public - drives the real relay if QU_RELAY is reachable.

    python3 selftest.py            # local only
    python3 selftest.py --public   # local + relay

Exits non-zero if anything fails, so it works as a CI smoke test.
"""

import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import qu_bore
import qu_core

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print("[%s] %s%s" % (PASS if ok else FAIL, name, (" - " + detail) if detail else ""))
    return ok


def readline(sock, limit=2048):
    out = b""
    while len(out) < limit:
        ch = sock.recv(1)
        if not ch:
            return None
        if ch == b"\n":
            return out.decode("utf-8", "replace")
        out += ch
    return out.decode("utf-8", "replace")


def handshake(host, port, mode="hmac", timeout=25):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    line = readline(s)
    if not line or not line.startswith("QU1 "):
        s.close()
        return None, None, "banner=%r" % line
    nonce = line[4:].strip()
    if mode == "hmac":
        s.sendall(("HMAC %s\n" % qu_core.sign(nonce)).encode())
    elif mode == "key":
        s.sendall(("KEY %s\n" % qu_core.TOKEN).encode())
    else:
        s.sendall(("HMAC %s\n" % ("0" * 64)).encode())
    answer = readline(s)
    return s, answer, ""


def run_shell(host, port, commands, mode="hmac", wait=25):
    s, answer, err = handshake(host, port, mode=mode)
    if s is None:
        return None, err
    if not answer or not answer.startswith("OK"):
        s.close()
        return None, "auth=%r" % answer
    payload = "".join(c + "\n" for c in commands) + "exit\n"
    s.sendall(payload.encode())
    buf = b""
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            data = s.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        buf += data
    try:
        s.close()
    except Exception:
        pass
    return buf.decode("utf-8", "replace"), ""


# --------------------------------------------------------------------------
# local agent fixture
# --------------------------------------------------------------------------

class LocalAgent(object):
    def __init__(self):
        self.proc = None

    def start(self, env=None):
        e = dict(os.environ)
        if env:
            e.update(env)
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "qu_agent.py")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, env=e, cwd=HERE,
        )
        deadline = time.time() + 45
        while time.time() < deadline:
            if self.alive():
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.5)
        return False

    def alive(self):
        try:
            s = socket.create_connection(("127.0.0.1", qu_core.shell_port()), timeout=0.4)
            s.close()
            return True
        except Exception:
            return False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=8)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


def main():
    print("== identity ==")
    print("   label   : %s.duckdns.org" % qu_core.subdomain())
    print("   port    : %d" % qu_core.public_port())
    print("   shell   : 127.0.0.1:%d" % qu_core.shell_port())

    print("\n== local ==")
    agent = LocalAgent()
    started = agent.start()
    check("agent starts", started)

    if started:
        host, port = "127.0.0.1", qu_core.shell_port()

        out, err = run_shell(host, port, ["echo MARK-A", "echo MARK-B"])
        check("pty shell returns both markers",
              bool(out) and "MARK-A" in out and "MARK-B" in out, err)

        out, err = run_shell(host, port, ["echo KEYOK"], mode="key")
        check("plain KEY auth works", bool(out) and "KEYOK" in out, err)

        _, answer, _ = handshake(host, port, mode="bad")
        check("wrong HMAC rejected", answer == "NO", "auth=%r" % answer)

        # second instance must exit on its own
        second = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "qu_agent.py")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, cwd=HERE,
        )
        try:
            rc = second.wait(timeout=15)
            check("single instance (mutex)", True, "exit=%d" % rc)
        except subprocess.TimeoutExpired:
            second.kill()
            check("single instance (mutex)", False, "duplicate kept running")

        agent.stop()

    # pipes path == the Windows code path
    print("\n== win-path (pipes) ==")
    agent2 = LocalAgent()
    started2 = agent2.start({"QU_FORCE_PIPES": "1"})
    check("agent starts in pipes mode", started2)
    if started2:
        out, err = run_shell("127.0.0.1", qu_core.shell_port(),
                             ["echo MARK-A", "echo MARK-B"])
        check("pipes shell returns both markers",
              bool(out) and "MARK-A" in out and "MARK-B" in out, err)
        agent2.stop()

    print("\n== beacon ==")
    import qu_tunnel
    b = qu_tunnel.beacon("bore.pub", 44816)
    check("beacon verifies", qu_tunnel.beacon_verify(b) == ("bore.pub", 44816))
    check("beacon tamper rejected", qu_tunnel.beacon_verify(b.replace("44816", "44817")) is None)

    if "--public" in sys.argv:
        print("\n== public relay ==")
        agent3 = LocalAgent()
        ok3 = agent3.start()
        check("agent starts for relay test", ok3)
        if ok3:
            found, nonce = qu_bore.discover(qu_core.BORE_SERVER, qu_core.public_port(), span=16)
            check("relay port discovered", bool(found), "port=%s" % found)
            if found:
                out, err = run_shell(qu_core.BORE_SERVER, found,
                                     ["echo MARK-A", "echo MARK-B"], wait=35)
                check("shell over public relay",
                      bool(out) and "MARK-A" in out and "MARK-B" in out, err)
            agent3.stop()

    bad = [r for r in results if not r[1]]
    print("\n%d/%d checks passed" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
