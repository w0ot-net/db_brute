import base64
import io
import ssl
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from db_brute import (
    Status,
    build_parser,
    main,
    parse_credential_file,
    parse_target,
    parse_targets,
    preflight_targets,
)
from drivers import get_driver
from drivers.base import HostUnreachable, Target
from drivers.tomcat import TomcatDriver


class TomcatDriverTests(unittest.TestCase):
    def test_driver_is_registered_with_expected_defaults(self):
        driver = get_driver("tomcat")

        self.assertIsInstance(driver, TomcatDriver)
        self.assertEqual(driver.default_port, 8080)
        self.assertEqual(driver.uri, "/manager/html")

    def test_http_statuses_match_metasploit_behavior_after_preflight(self):
        cases = (
            (200, True),
            (201, True),
            (302, True),
            (401, False),
            (403, False),
        )
        for status, expected in cases:
            with self.subTest(status=status):
                connection = mock.Mock()
                connection.getresponse.return_value.status = status
                with mock.patch(
                    "drivers.tomcat.http.client.HTTPConnection",
                    return_value=connection,
                ):
                    result = TomcatDriver().connect(
                        "tomcat.example", 8080, "admin", "secret", timeout=7
                    )

                self.assertIs(result, expected)
                token = base64.b64encode(b"admin:secret").decode("ascii")
                connection.request.assert_called_once_with(
                    "GET",
                    "/manager/html",
                    headers={
                        "Authorization": f"Basic {token}",
                        "User-Agent": "db_brute",
                    },
                )
                connection.close.assert_called_once_with()

    def test_preflight_accepts_tomcat_basic_authentication_challenge(self):
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 401
        response.getheader.return_value = 'Basic realm="Tomcat Manager Application"'

        with mock.patch(
            "drivers.tomcat.http.client.HTTPConnection",
            return_value=connection,
        ):
            reason = TomcatDriver().preflight_target(
                Target("tomcat.example", 8080, "http"), timeout=7
            )

        self.assertIsNone(reason)
        connection.request.assert_called_once_with(
            "GET",
            "/manager/html",
            headers={"User-Agent": "db_brute"},
        )
        connection.close.assert_called_once_with()

    def test_preflight_rejects_unconditional_redirect(self):
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 302
        response.getheader.side_effect = lambda name, default=None: {
            "WWW-Authenticate": "",
            "Location": "https://tomcat.example:8443/manager/html",
        }.get(name, default)

        with mock.patch(
            "drivers.tomcat.http.client.HTTPConnection",
            return_value=connection,
        ):
            reason = TomcatDriver().preflight_target(
                Target("tomcat.example", 8080, "http")
            )

        self.assertEqual(
            reason,
            "redirected to https://tomcat.example:8443/manager/html; "
            "use that URL as the target",
        )

    def test_preflight_rejects_non_tomcat_authentication_challenge(self):
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 401
        response.getheader.return_value = 'Basic realm="Other Application"'

        with mock.patch(
            "drivers.tomcat.http.client.HTTPConnection",
            return_value=connection,
        ):
            reason = TomcatDriver().preflight_target(
                Target("tomcat.example", 8080, "http")
            )

        self.assertEqual(
            reason,
            "expected an HTTP 401 Tomcat Basic authentication challenge, "
            "received HTTP 401",
        )

    def test_https_and_custom_uri_are_configurable(self):
        driver = TomcatDriver()
        driver.configure(use_ssl=True, uri="custom/manager")
        connection = mock.Mock()
        connection.getresponse.return_value.status = 200
        context = mock.Mock()

        with (
            mock.patch(
                "drivers.tomcat.ssl.create_default_context", return_value=context
            ),
            mock.patch(
                "drivers.tomcat.http.client.HTTPSConnection",
                return_value=connection,
            ) as connection_type,
        ):
            self.assertTrue(
                driver.connect("tomcat.example", 8443, "admin", "admin")
            )

        self.assertEqual(driver.uri, "/custom/manager")
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        connection_type.assert_called_once_with(
            "tomcat.example", 8443, timeout=5, context=context
        )

    def test_url_scheme_overrides_global_ssl_setting_per_target(self):
        driver = TomcatDriver()
        driver.configure(use_ssl=True)
        http_connection = mock.Mock()
        http_connection.getresponse.return_value.status = 200
        https_connection = mock.Mock()
        https_connection.getresponse.return_value.status = 200

        with (
            mock.patch(
                "drivers.tomcat.http.client.HTTPConnection",
                return_value=http_connection,
            ) as http_type,
            mock.patch(
                "drivers.tomcat.http.client.HTTPSConnection",
                return_value=https_connection,
            ) as https_type,
        ):
            self.assertTrue(
                driver.connect_target(
                    Target("tomcat.example", 8080, "http"), "admin", "admin"
                )
            )
            self.assertTrue(
                driver.connect_target(
                    Target("tomcat.example", 8443, "https"), "admin", "admin"
                )
            )

        http_type.assert_called_once_with("tomcat.example", 8080, timeout=5)
        https_type.assert_called_once()

    def test_transport_errors_mark_the_target_unreachable(self):
        connection = mock.Mock()
        connection.request.side_effect = OSError("connection refused")
        with mock.patch(
            "drivers.tomcat.http.client.HTTPConnection", return_value=connection
        ):
            with self.assertRaisesRegex(HostUnreachable, "connection refused"):
                TomcatDriver().connect("tomcat.example", 8080, "admin", "admin")

        connection.close.assert_called_once_with()


class TomcatCredentialTests(unittest.TestCase):
    def test_curated_credential_sources_are_combined_and_deduplicated(self):
        credential_file = (
            Path(__file__).resolve().parents[1] / "credz" / "tomcat.txt"
        )
        credentials = parse_credential_file(credential_file)

        self.assertEqual(len(credentials), 269)
        self.assertEqual(len(credentials), len(set(credentials)))
        self.assertIn(("admin", ""), credentials)
        self.assertIn(("tomcat", ""), credentials)
        self.assertIn(("root", "owaspbwa"), credentials)
        self.assertIn(("j2deployer", "j2deployer"), credentials)
        self.assertIn(("demo", "demo"), credentials)
        self.assertIn(("server_admin", "owaspbwa"), credentials)
        self.assertIn(("vagrant", "vagrant"), credentials)
        self.assertIn(("admin", "admin123"), credentials)
        self.assertIn(("admin", "owaspbwa"), credentials)
        self.assertIn(("fhir", "FHIRDefaultPassword"), credentials)


class TargetParsingTests(unittest.TestCase):
    def test_mixed_url_file_preserves_each_target_scheme(self):
        content = """\
https://172.25.105.215:6121
http://172.25.105.215:6122
http://172.25.244.45:8080
https://172.19.100.60:6121
http://172.19.100.60:6122
"""
        with tempfile.TemporaryDirectory() as directory:
            target_file = Path(directory) / "tomcat-urls.txt"
            target_file.write_text(content, encoding="utf-8")
            targets = parse_targets(None, target_file, default_port=8080)

        self.assertEqual(
            targets,
            [
                Target("172.25.105.215", 6121, "https"),
                Target("172.25.105.215", 6122, "http"),
                Target("172.25.244.45", 8080, "http"),
                Target("172.19.100.60", 6121, "https"),
                Target("172.19.100.60", 6122, "http"),
            ],
        )

    def test_url_defaults_and_legacy_targets_remain_supported(self):
        self.assertEqual(
            parse_target("https://tomcat.example", 8080),
            Target("tomcat.example", 443, "https"),
        )
        self.assertEqual(
            parse_target("http://tomcat.example", 8080),
            Target("tomcat.example", 80, "http"),
        )
        self.assertEqual(
            parse_target("tomcat.example", 8080),
            Target("tomcat.example", 8080),
        )
        self.assertEqual(
            parse_target("tomcat.example:6122", 8080),
            Target("tomcat.example", 6122),
        )

    def test_url_target_rejects_paths_and_credentials(self):
        invalid_targets = (
            "https://admin:password@tomcat.example:8443",
            "https://tomcat.example:8443/manager/html",
            "ftp://tomcat.example:21",
        )
        for target in invalid_targets:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    parse_target(target, 8080)


class StatusTests(unittest.TestCase):
    def test_schemes_have_independent_reachability_and_are_saved(self):
        http_target = Target("tomcat.example", 8080, "http")
        https_target = Target("tomcat.example", 8080, "https")
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "valid.txt"
            status = Status(2, output_file)
            with redirect_stdout(io.StringIO()):
                status.mark_unreachable(http_target, "connection refused")
                status.update(https_target, "admin", "admin", True)

            self.assertTrue(status.is_unreachable(http_target))
            self.assertFalse(status.is_unreachable(https_target))
            self.assertEqual(
                output_file.read_text(encoding="utf-8"),
                "https://tomcat.example:8080:admin:admin\n",
            )

    def test_preflight_filters_unsuitable_targets_before_login_attempts(self):
        accepted = Target("tomcat.example", 8443, "https")
        redirected = Target("tomcat.example", 8080, "http")
        driver = mock.Mock()
        driver.preflight_target.side_effect = lambda target, timeout: (
            None if target == accepted else "redirected"
        )

        output = io.StringIO()
        with redirect_stdout(output):
            targets = preflight_targets(
                driver,
                [accepted, redirected],
                timeout=7,
                threads=2,
            )

        self.assertEqual(targets, [accepted])
        self.assertIn(
            "[!] Skipping http://tomcat.example:8080: redirected",
            output.getvalue(),
        )
        self.assertEqual(driver.preflight_target.call_count, 2)


class CommandLineTests(unittest.TestCase):
    def test_service_option_and_legacy_db_alias_select_tomcat(self):
        parser = build_parser(["mysql", "tomcat"])

        service_args = parser.parse_args(
            ["--service", "tomcat", "-t", "tomcat.example"]
        )
        legacy_args = parser.parse_args(
            ["--db", "tomcat", "-t", "tomcat.example"]
        )

        self.assertEqual(service_args.service, "tomcat")
        self.assertEqual(legacy_args.service, "tomcat")

    def test_http_options_are_rejected_by_non_http_services(self):
        with self.assertRaisesRegex(ValueError, "does not support"):
            get_driver("mysql").configure(use_ssl=True)

    def test_url_targets_are_rejected_by_non_http_services(self):
        arguments = [
            "db_brute.py",
            "--service",
            "mysql",
            "--target",
            "http://mysql.example:3306",
        ]
        with (
            mock.patch.object(sys, "argv", arguments),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as exit_context,
        ):
            main()

        self.assertEqual(exit_context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
