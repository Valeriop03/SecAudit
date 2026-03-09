"""Tests for the Target class."""

import pytest
from secaudit.core.target import Target


class TestTargetParsing:
    def test_https_url(self):
        t = Target("https://example.com")
        assert t.scheme == "https"
        assert t.host == "example.com"
        assert t.port == 443

    def test_http_url(self):
        t = Target("http://example.com")
        assert t.scheme == "http"
        assert t.port == 80

    def test_url_with_custom_port(self):
        t = Target("https://example.com:8443")
        assert t.port == 8443

    def test_bare_domain_defaults_to_https(self):
        t = Target("example.com")
        assert t.scheme == "https"
        assert t.host == "example.com"

    def test_base_url(self):
        t = Target("https://example.com")
        assert t.base_url == "https://example.com:443"

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            Target("https://")

    def test_ip_target(self):
        t = Target("http://127.0.0.1")
        assert t.is_ip is True

    def test_domain_is_not_ip(self):
        t = Target("https://example.com")
        assert t.is_ip is False
