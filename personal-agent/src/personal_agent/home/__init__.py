"""Home Assistant adapter with deterministic entity/action boundaries."""

from .client import HomeAssistantClient
from .tools import home_tools

__all__ = ["HomeAssistantClient", "home_tools"]
