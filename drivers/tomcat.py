import base64
import http.client
import ssl
from typing import Optional
from urllib.parse import urljoin, urlsplit

from .base import DatabaseDriver, HostUnreachable, Target, TargetRejected


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
    ) -> Target:
        """Resolve safe redirects and require a Tomcat Basic-auth challenge."""
        current = target
        visited = set()

        for _ in range(6):
            if current in visited:
                raise TargetRejected("redirect loop detected")
            visited.add(current)

            status, challenge, location = self._preflight_response(
                current, timeout
            )
            challenge_lower = challenge.lower()
            if (
                status == 401
                and "basic" in challenge_lower
                and "tomcat" in challenge_lower
            ):
                return current

            if 300 <= status < 400:
                if not location:
                    raise TargetRejected(
                        f"received HTTP {status} redirect without a location"
                    )
                current = self._resolve_redirect(current, location)
                continue

            raise TargetRejected(
                "expected an HTTP 401 Tomcat Basic authentication challenge, "
                f"received HTTP {status}"
            )

        raise TargetRejected("too many redirects")

    def _preflight_response(
        self,
        target: Target,
        timeout: int,
    ) -> tuple[int, str, Optional[str]]:
        """Request one target without credentials and return auth metadata."""
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
            return (
                response.status,
                response.getheader("WWW-Authenticate", ""),
                response.getheader("Location"),
            )
        except (OSError, http.client.HTTPException) as exc:
            raise HostUnreachable(str(exc)) from exc
        finally:
            if connection is not None:
                connection.close()

    def _resolve_redirect(self, target: Target, location: str) -> Target:
        """Resolve one same-host HTTP(S) redirect to the configured URI."""
        scheme = target.scheme
        if scheme is None:
            scheme = "https" if self._target_uses_ssl(target) else "http"
        base_target = Target(target.host, target.port, scheme)
        redirected_url = urljoin(f"{base_target.display()}{self.uri}", location)
        parsed = urlsplit(redirected_url)
        if parsed.scheme not in ("http", "https"):
            raise TargetRejected("redirect used an unsupported URL scheme")
        if parsed.username is not None or parsed.password is not None:
            raise TargetRejected("redirect URL contained credentials")
        if parsed.hostname is None or parsed.hostname.lower() != target.host.lower():
            raise TargetRejected("redirect target must remain on the original host")
        if parsed.path != self.uri or parsed.query or parsed.fragment:
            raise TargetRejected("redirect target changed the configured manager URI")

        try:
            port = parsed.port
        except ValueError as exc:
            raise TargetRejected("redirect target used an invalid port") from exc
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return Target(parsed.hostname, port, parsed.scheme)

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
