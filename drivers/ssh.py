import logging
import socket

import paramiko

from .base import DatabaseDriver, HostUnreachable


class SSHDriver(DatabaseDriver):
    """SSH driver using Paramiko."""

    name = "ssh"
    default_port = 22

    def connect(self, host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
        """Attempt SSH authentication."""
        paramiko_logger = logging.getLogger("paramiko")
        paramiko_logger.setLevel(logging.CRITICAL)
        paramiko_logger.propagate = False
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                auth_timeout=timeout,
                banner_timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            return True
        except (paramiko.AuthenticationException, paramiko.BadAuthenticationType):
            return False
        except (
            paramiko.SSHException,
            paramiko.ssh_exception.NoValidConnectionsError,
            socket.timeout,
            ConnectionResetError,
            OSError,
        ) as exc:
            raise HostUnreachable(str(exc)) from exc
        finally:
            client.close()

    def get_error_message(self, exception: Exception) -> str:
        """Extract error message from paramiko exception."""
        if hasattr(exception, 'args') and exception.args:
            return str(exception.args[0])
        return str(exception)
