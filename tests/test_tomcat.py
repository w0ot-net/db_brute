import base64
import ssl
import unittest
from pathlib import Path
from unittest import mock

from db_brute import build_parser, parse_credential_file
from drivers import get_driver
from drivers.base import HostUnreachable
from drivers.tomcat import TomcatDriver


class TomcatDriverTests(unittest.TestCase):
    def test_driver_is_registered_with_expected_defaults(self):
        driver = get_driver("tomcat")

        self.assertIsInstance(driver, TomcatDriver)
        self.assertEqual(driver.default_port, 8080)
        self.assertEqual(driver.uri, "/manager/html")

    def test_http_statuses_match_metasploit_success_behavior(self):
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
    def test_metasploit_credential_sources_are_combined_and_deduplicated(self):
        credential_file = (
            Path(__file__).resolve().parents[1] / "credz" / "tomcat.txt"
        )
        credentials = parse_credential_file(credential_file)

        self.assertEqual(len(credentials), 263)
        self.assertEqual(len(credentials), len(set(credentials)))
        self.assertIn(("admin", ""), credentials)
        self.assertIn(("tomcat", ""), credentials)
        self.assertIn(("root", "owaspbwa"), credentials)
        self.assertIn(("j2deployer", "j2deployer"), credentials)


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


if __name__ == "__main__":
    unittest.main()
