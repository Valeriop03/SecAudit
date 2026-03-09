"""Tests for the report generator."""

import json
from pathlib import Path

import pytest

from secaudit.core.base_module import Finding, ModuleResult, Severity
from secaudit.report.generator import ReportGenerator


@pytest.fixture
def sample_results():
    r1 = ModuleResult(module_name="header_checker", target="https://example.com")
    r1.add_finding(Finding(
        title="Missing HSTS",
        severity=Severity.HIGH,
        description="HSTS header is not set.",
        recommendation="Add HSTS header.",
    ))
    r1.add_finding(Finding(
        title="Open ports",
        severity=Severity.INFO,
        description="Port 80 is open.",
    ))

    r2 = ModuleResult(module_name="ssl_checker", target="https://example.com")
    r2.add_finding(Finding(
        title="Certificate expired",
        severity=Severity.CRITICAL,
        description="Cert expired 5 days ago.",
        evidence="Not After: 2024-01-01",
    ))
    return [r1, r2]


class TestReportGenerator:
    def test_html_report_created(self, tmp_path, sample_results):
        output = tmp_path / "report.html"
        gen = ReportGenerator(sample_results, "https://example.com")
        gen.generate(output)

        assert output.exists()
        content = output.read_text()
        assert "SecAudit" in content
        assert "Missing HSTS" in content
        assert "Certificate expired" in content

    def test_html_contains_severity_badges(self, tmp_path, sample_results):
        output = tmp_path / "report.html"
        gen = ReportGenerator(sample_results, "https://example.com")
        gen.generate(output)

        content = output.read_text()
        assert "CRITICAL" in content
        assert "HIGH" in content
        assert "INFO" in content

    def test_json_report_created(self, tmp_path, sample_results):
        output = tmp_path / "report.json"
        gen = ReportGenerator(sample_results, "https://example.com")
        gen.generate_json(output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["target"] == "https://example.com"
        assert len(data["results"]) == 2
        assert data["results"][0]["module"] == "header_checker"

    def test_json_report_structure(self, tmp_path, sample_results):
        output = tmp_path / "report.json"
        gen = ReportGenerator(sample_results, "https://example.com")
        gen.generate_json(output)

        data = json.loads(output.read_text())
        finding = data["results"][0]["findings"][0]
        assert "title" in finding
        assert "severity" in finding
        assert "description" in finding
