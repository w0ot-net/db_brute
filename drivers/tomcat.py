import base64
import http.client
import ssl
from typing import Optional

from .base import DatabaseDriver, HostUnreachable, Target


class TomcatDriver(DatabaseDriver):
    """Apache Tomcat Manager driver using HTTP Basic authentication."""

    name = "tomcat"
    default_port = 8080
    supports_url_targets = True
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
        return self._connect(
            host, port, username, password, timeout, use_ssl=self.use_ssl
        )

    def connect_target(
        self,
        target: Target,
        username: str,
        password: str,
        timeout: int = 5,
    ) -> bool:
        """Use a URL target's scheme, falling back to the global SSL option."""
        use_ssl = self._target_uses_ssl(target)
        return self._connect(
            target.host,
            target.port,
            username,
            password,
            timeout,
            use_ssl=use_ssl,
        )

    def preflight_target(
        self,
        target: Target,
        timeout: int = 5,
    ) -> Optional[str]:
        """Require a Tomcat Manager Basic-auth challenge before brute forcing."""
        connection: Optional[http.client.HTTPConnection] = None
        try:
            connection = self._create_connection(
                target.host,
                target.port,
                timeout,
                use_ssl=self._target_uses_ssl(target),
            )
            connection.request(
                "GET",
                self.uri,
                headers={"User-Agent": "db_brute"},
            )
            response = connection.getresponse()
            challenge = response.getheader("WWW-Authenticate", "")
            challenge_lower = challenge.lower()
            if (
                response.status == 401
                and "basic" in challenge_lower
                and "tomcat" in challenge_lower
            ):
                return None

            if 300 <= response.status < 400:
                location = response.getheader("Location")
                if location:
                    return (
                        f"redirected to {location}; use that URL as the target"
                    )
                return f"received HTTP {response.status} redirect without a location"

            return (
                "expected an HTTP 401 Tomcat Basic authentication challenge, "
                f"received HTTP {response.status}"
            )
        except (OSError, http.client.HTTPException) as exc:
            raise HostUnreachable(str(exc)) from exc
        finally:
            if connection is not None:
                connection.close()

    def _connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: int,
        use_ssl: bool,
    ) -> bool:
        connection: Optional[http.client.HTTPConnection] = None
        try:
            connection = self._create_connection(
                host, port, timeout, use_ssl=use_ssl
            )

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

    def _target_uses_ssl(self, target: Target) -> bool:
        """Resolve a target's explicit scheme against the global SSL option."""
        if target.scheme is not None:
            return target.scheme == "https"
        return self.use_ssl

    @staticmethod
    def _create_connection(
        host: str,
        port: int,
        timeout: int,
        use_ssl: bool,
    ) -> http.client.HTTPConnection:
        """Create one HTTP(S) connection using the driver's TLS policy."""
        if not use_ssl:
            return http.client.HTTPConnection(host, port, timeout=timeout)

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(
            host, port, timeout=timeout, context=context
        )

    def get_error_message(self, exception: Exception) -> str:
        """Extract a human-readable HTTP connection error."""
        return str(exception)
