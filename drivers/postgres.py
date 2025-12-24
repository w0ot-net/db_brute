import psycopg2
from .base import DatabaseDriver


class PostgresDriver(DatabaseDriver):
    """PostgreSQL driver using psycopg2."""

    name = "postgres"
    default_port = 5432

    def connect(self, host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
        """Attempt PostgreSQL authentication."""
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=timeout
            )
            conn.close()
            return True
        except psycopg2.OperationalError:
            return False
        except psycopg2.InterfaceError:
            return False

    def get_error_message(self, exception: Exception) -> str:
        """Extract error message from psycopg2 exception."""
        if hasattr(exception, 'pgerror') and exception.pgerror:
            return exception.pgerror
        return str(exception)
