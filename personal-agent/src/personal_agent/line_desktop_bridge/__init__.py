"""Windows LINE Desktop UI bridge.

The bridge reads only pixels rendered by the logged-in desktop application. It never
opens or decrypts LINE's local databases and never exposes screenshots over HTTP.
"""

from .app import create_line_desktop_bridge_app

__all__ = ["create_line_desktop_bridge_app"]
