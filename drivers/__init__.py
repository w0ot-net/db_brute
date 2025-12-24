from .base import DatabaseDriver, HostUnreachable
from .mssql import MSSQLDriver
from .mysql import MySQLDriver
from .postgres import PostgresDriver
from .ssh import SSHDriver

DRIVERS = {
    "mssql": MSSQLDriver,
    "mysql": MySQLDriver,
    "postgres": PostgresDriver,
    "ssh": SSHDriver,
}


def get_driver(name: str) -> DatabaseDriver:
    """Get a driver instance by name."""
    if name not in DRIVERS:
        available = ", ".join(DRIVERS.keys())
        raise ValueError(f"Unknown database: {name}. Available: {available}")
    return DRIVERS[name]()


def list_drivers() -> list[str]:
    """Return list of available driver names."""
    return list(DRIVERS.keys())


__all__ = ["DatabaseDriver", "HostUnreachable", "get_driver", "list_drivers"]
