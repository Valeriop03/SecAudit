"""Tests for the port scanner module."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from secaudit.core.base_module import Severity
from secaudit.core.target import Target
from secaudit.modules.port_scanner import PortScannerModule, DANGEROUS_PORTS


@pytest.fixture
def target():
    return Target("http://127.0.0.1")


@pytest.fixture
def scanner():
    return PortScannerModule(timeout=1)


class TestPortScanner:
    def test_closed_port_returns_none(self, scanner, target):
        result = scanner._scan_port("127.0.0.1", 19999)
        assert result is None

    @patch("secaudit.modules.port_scanner.socket.create_connection")
    def test_open_port_detected(self, mock_conn, scanner, target):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"OpenSSH_8.9"
        mock_conn.return_value = mock_sock

        result = scanner._scan_port("127.0.0.1", 22)
        assert result is not None
        assert result.port == 22
        assert result.service == "SSH"

    @patch("secaudit.modules.port_scanner.socket.create_connection")
    def test_dangerous_port_flagged_as_high(self, mock_conn, target):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b""
        mock_conn.return_value = mock_sock

        scanner = PortScannerModule(ports=[23], timeout=1)  # Telnet
        result = scanner.run(target)

        high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 1
        assert any("23" in f.title for f in high_findings)

    @patch("secaudit.modules.port_scanner.socket.create_connection")
    def test_no_open_ports_returns_info(self, mock_conn, target):
        mock_conn.side_effect = ConnectionRefusedError

        scanner = PortScannerModule(ports=[9999], timeout=1)
        result = scanner.run(target)

        assert any("No common ports open" in f.title for f in result.findings)
