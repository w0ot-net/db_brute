import base64
import http.client
import ssl
from typing import Optional

from .base import DatabaseDriver, HostUnreachable


class TomcatDriver(DatabaseDriver):
    """Apache Tomcat Manager driver using HTTP Basic authentication."""

    name = "tomcat"
    default_port = 8080
    default_uri = "/manager/html"
    success_statuses = {200, 201, *range(300, 310)}

    def __init__(self) -> None:
        self.use_ssl = False
        self.uri = self.default_uri

    def configure(self, use_ssl: bool = False, uri: Optional[str] = None) -> None:
        self.use_ssl = use_ssl
        if uri is None:
            self.uri = self.default_uri
            return
        if not uri:
            raise ValueError("--uri cannot be empty")
        self.uri = uri if uri.startswith("/") else f"/{uri}"

    def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: int = 5,
    ) -> bool:
        """Attempt to authenticate to the Tomcat Manager HTML interface."""
        connection: Optional[http.client.HTTPConnection] = None
        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = http.client.HTTPSConnection(
                    host, port, timeout=timeout, context=context
                )
            else:
                connection = http.client.HTTPConnection(host, port, timeout=timeout)

            token = base64.b64encode(
                f"{username}:{password}".encode("utf-8")
            ).decode("ascii")
            connection.request(
                "GET",
                self.uri,
                headers={
                    "Authorization": f"Basic {token}",
                    "User-Agent": "db_brute",
                },
            )
            response = connection.getresponse()
            return response.status in self.success_statuses
        except (OSError, http.client.HTTPException) as exc:
            raise HostUnreachable(str(exc)) from exc
        finally:
            if connection is not None:
                connection.close()

    def get_error_message(self, exception: Exception) -> str:
        """Extract a human-readable HTTP connection error."""
        return str(exception)
