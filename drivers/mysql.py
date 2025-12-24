import pymysql
from .base import DatabaseDriver


class MySQLDriver(DatabaseDriver):
    """MySQL driver using PyMySQL."""

    name = "mysql"
    default_port = 3306

    def connect(self, host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
        """Attempt MySQL authentication."""
        try:
            conn = pymysql.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=timeout,
                read_timeout=timeout,
                write_timeout=timeout
            )
            conn.close()
            return True
        except pymysql.err.OperationalError:
            return False
        except pymysql.err.InterfaceError:
            return False

    def get_error_message(self, exception: Exception) -> str:
        """Extract error message from pymysql exception."""
        if hasattr(exception, 'args') and len(exception.args) >= 2:
            return str(exception.args[1])
        return str(exception)
