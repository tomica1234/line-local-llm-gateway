"""Normalized cross-channel communication domain."""

from .service import CommunicationService
from .store import CommunicationStore
from .tools import communication_tools

__all__ = ["CommunicationService", "CommunicationStore", "communication_tools"]
