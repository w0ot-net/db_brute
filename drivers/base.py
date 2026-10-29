from abc import ABC, abstractmethod
from typing import Optional


class HostUnreachable(Exception):
    """Raised when a target host is unreachable or stops responding."""


class DatabaseDriver(ABC):
    """Abstract base class for database drivers."""

    name: str = ""
    default_port: int = 0

    def configure(self, use_ssl: bool = False, uri: Optional[str] = None) -> None:
        """Apply optional service-specific connection settings."""
        if use_ssl or uri is not None:
            raise ValueError(f"{self.name} does not support --ssl or --uri")

    @abstractmethod
    def connect(self, host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
        """
        Attempt to connect to the database with given credentials.
        Returns True if authentication succeeds, False otherwise.
        """
        pass

    @abstractmethod
    def get_error_message(self, exception: Exception) -> str:
        """
        Extract a human-readable error message from a connection exception.
        """
        pass
