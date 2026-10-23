import unittest
from types import SimpleNamespace
from unittest.mock import patch

import main


def dns_record(ip, family):
    sockaddr = (ip, 80) if family == main.socket.AF_INET else (ip, 80, 0, 0)
    return family, main.socket.SOCK_STREAM, 6, "", sockaddr


class SSRFProtectionTests(unittest.TestCase):
    def test_rejects_hostname_with_any_non_public_dns_answer(self):
        with patch.object(
            main.socket,
            "getaddrinfo",
            return_value=[
                dns_record("93.184.216.34", main.socket.AF_INET),
                dns_record("127.0.0.1", main.socket.AF_INET),
            ],
        ):
            with self.assertRaisesRegex(main.URLFetchBlocked, "non-public"):
                main.resolve_public_address("example.com", 80)

    def test_fetch_uses_the_vetted_dns_address_and_caps_html(self):
        expected_address = ("93.184.216.34", 80)
        request_args = {}
        response = SimpleNamespace(
            status=200,
            read=lambda limit: request_args.update(read_limit=limit) or b"x" * limit,
            getheader=lambda name, default="": "text/html; charset=utf-8",
        )

        class StubConnection:
            def __init__(self, host, port, address, timeout):
                request_args.update(host=host, port=port, address=address)

            def request(self, method, target, headers):
                request_args.update(method=method, target=target)

            def getresponse(self):
                return response

            def close(self):
                request_args["closed"] = True

        with (
            patch.object(
                main,
                "resolve_public_address",
                return_value=(main.socket.AF_INET, expected_address),
            ),
            patch.object(main, "PinnedHTTPConnection", StubConnection),
        ):
            result = main.fetch_website_url("http://example.com/path?q=1")

        self.assertEqual(request_args["address"], expected_address)
        self.assertEqual(request_args["target"], "/path?q=1")
        self.assertEqual(request_args["read_limit"], main.MAX_WEBSITE_BYTES + 1)
        self.assertEqual(len(result["body"]), main.MAX_WEBSITE_BYTES)
        self.assertTrue(request_args["closed"])

    def test_website_analysis_does_not_follow_redirects(self):
        with patch.object(
            main,
            "fetch_website_url",
            return_value={
                "status_code": 302,
                "body": b"<html><title>Redirect target</title></html>",
                "content_type": "text/html",
            },
        ):
            result = main.website_analysis("https://example.com")

        self.assertTrue(result["accessible"])
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(result["title"], "")
        self.assertEqual(
            result["indicators"],
            ["Redirect response was not followed for safety."],
        )

    def test_url_validation_rejects_unsafe_url_forms(self):
        urls = [
            "http://127.0.0.1",
            "http://user:password@example.com",
            "http://example.com:8080",
        ]
        for url in urls:
            with self.subTest(url=url):
                valid, message = main.validate_url(url)
                self.assertFalse(valid)
                self.assertTrue(message)

    def test_url_validation_rejects_invalid_idna_before_dns(self):
        with patch.object(
            main.socket,
            "getaddrinfo",
            side_effect=AssertionError("Unexpected DNS lookup for invalid hostname."),
        ):
            valid, message = main.validate_url("https://\u200d.example")

        self.assertFalse(valid)
        self.assertEqual(message, "The URL hostname is invalid.")
