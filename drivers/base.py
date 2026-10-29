from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


class HostUnreachable(Exception):
    """Raised when a target host is unreachable or stops responding."""


@dataclass(frozen=True)
class Target:
    """A network target with an optional URL scheme."""

    host: str
    port: int
    scheme: Optional[str] = None

    def display(self) -> str:
        """Return the target in a human-readable, round-trippable form."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        authority = f"{host}:{self.port}"
        return f"{self.scheme}://{authority}" if self.scheme else authority


class DatabaseDriver(ABC):
    """Abstract base class for database drivers."""

    name: str = ""
    default_port: int = 0
    supports_url_targets: bool = False

    def configure(self, use_ssl: bool = False, uri: Optional[str] = None) -> None:
        """Apply optional service-specific connection settings."""
        if use_ssl or uri is not None:
            raise ValueError(f"{self.name} does not support --ssl or --uri")

    def preflight_target(
        self,
        target: Target,
        timeout: int = 5,
    ) -> Optional[str]:
        """Return a reason to skip a target, or None when checks may proceed."""
        return None

    def connect_target(
        self,
        target: Target,
        username: str,
        password: str,
        timeout: int = 5,
    ) -> bool:
        """Attempt authentication against a structured target."""
        return self.connect(target.host, target.port, username, password, timeout)

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
