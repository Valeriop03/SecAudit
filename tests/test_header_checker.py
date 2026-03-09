"""Tests for the HTTP header checker module."""

import pytest
import responses as resp_mock

from secaudit.core.target import Target
from secaudit.core.base_module import Severity
from secaudit.modules.header_checker import HeaderCheckerModule


@pytest.fixture
def target():
    return Target("https://example.com")


@pytest.fixture
def checker():
    return HeaderCheckerModule(timeout=5)


class TestHeaderChecker:
    @resp_mock.activate
    def test_detects_missing_security_headers(self, target, checker):
        resp_mock.add(resp_mock.GET, "https://example.com:443", body="<html></html>", status=200)
        resp_mock.add(resp_mock.GET, "http://example.com:80", status=200)

        result = checker.run(target)

        titles = [f.title for f in result.findings]
        assert any("Strict-Transport-Security" in t for t in titles)
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("X-Frame-Options" in t for t in titles)

    @resp_mock.activate
    def test_no_missing_headers_when_all_present(self, target, checker):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }
        resp_mock.add(resp_mock.GET, "https://example.com:443", body="<html></html>", status=200, headers=headers)
        resp_mock.add(resp_mock.GET, "http://example.com:80", status=301, headers={"Location": "https://example.com"})

        result = checker.run(target)

        missing = [f for f in result.findings if "Missing" in f.title]
        assert len(missing) == 0

    @resp_mock.activate
    def test_detects_information_disclosure_headers(self, target, checker):
        headers = {
            "Server": "Apache/2.4.51",
            "X-Powered-By": "PHP/8.1.0",
        }
        resp_mock.add(resp_mock.GET, "https://example.com:443", body="<html></html>", status=200, headers=headers)
        resp_mock.add(resp_mock.GET, "http://example.com:80", status=301, headers={"Location": "https://example.com"})

        result = checker.run(target)

        titles = [f.title for f in result.findings]
        assert any("Server" in t for t in titles)
        assert any("X-Powered-By" in t for t in titles)

    @resp_mock.activate
    def test_detects_weak_csp(self, target, checker):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
        }
        resp_mock.add(resp_mock.GET, "https://example.com:443", body="<html></html>", status=200, headers=headers)
        resp_mock.add(resp_mock.GET, "http://example.com:80", status=301)

        result = checker.run(target)

        weak_csp = [f for f in result.findings if "Weak Content-Security-Policy" in f.title]
        assert len(weak_csp) == 1
        assert weak_csp[0].severity == Severity.MEDIUM

    @resp_mock.activate
    def test_request_failure_sets_error(self, target, checker):
        import requests
        resp_mock.add(resp_mock.GET, "https://example.com:443", body=requests.ConnectionError("refused"))

        result = checker.run(target)
        assert result.has_error
