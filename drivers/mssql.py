import pymssql
from .base import DatabaseDriver


class MSSQLDriver(DatabaseDriver):
    """Microsoft SQL Server driver using pymssql."""

    name = "mssql"
    default_port = 1433

    def connect(self, host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
        """Attempt MSSQL authentication."""
        try:
            conn = pymssql.connect(
                server=host,
                port=str(port),
                user=username,
                password=password,
                login_timeout=timeout,
                timeout=timeout
            )
            conn.close()
            return True
        except pymssql.OperationalError:
            return False
        except pymssql.InterfaceError:
            return False

    def get_error_message(self, exception: Exception) -> str:
        """Extract error message from pymssql exception."""
        if hasattr(exception, 'args') and exception.args:
            return str(exception.args[0])
        return str(exception)
