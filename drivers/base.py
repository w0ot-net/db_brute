from abc import ABC, abstractmethod


class HostUnreachable(Exception):
    """Raised when a target host is unreachable or stops responding."""


class DatabaseDriver(ABC):
    """Abstract base class for database drivers."""

    name: str = ""
    default_port: int = 0

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
