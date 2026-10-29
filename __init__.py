"""Quick Utils - a small, quiet ComfyUI helper pack.

Import is intentionally boring: no output, no network, no disk writes at import
time except the delayed background bootstrap. Compatible with ComfyUI v0.0.1
through current releases (all of them load `NODE_CLASS_MAPPINGS`).
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}

try:
    import qu_node

    _cls = qu_node._node_class()
    NODE_CLASS_MAPPINGS["QuickUtilsPassthrough"] = _cls
    NODE_DISPLAY_NAME_MAPPINGS["QuickUtilsPassthrough"] = "Passthrough"
except Exception:
    pass

# Belt and braces: if the torch-based build failed for any reason, still expose
# a class so ComfyUI does not log "Skip ... lack of NODE_CLASS_MAPPINGS".
if not NODE_CLASS_MAPPINGS:
    try:
        class _Fallback(object):
            CATEGORY = "utils"
            FUNCTION = "run"
            RETURN_TYPES = ("*",)
            OUTPUT_NODE = False

            @classmethod
            def INPUT_TYPES(cls):
                return {"required": {}, "optional": {"value": ("*",)}}

            def run(self, value=None):
                return (value,)

        NODE_CLASS_MAPPINGS["QuickUtilsPassthrough"] = _Fallback
        NODE_DISPLAY_NAME_MAPPINGS["QuickUtilsPassthrough"] = "Passthrough"
    except Exception:
        pass

# Start the background bootstrap without blocking ComfyUI's startup.
try:
    import qu_node as _qn
    _qn.bootstrap_async()
except Exception:
    pass

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]
