"""
HTTP security headers analysis module.
Checks for presence and correctness of security-related HTTP headers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import requests
from requests.exceptions import RequestException

from ..core.base_module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target


@dataclass
class HeaderSpec:
    """Specification for a security header check."""

    name: str
    severity_missing: Severity
    description_missing: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    validator: Any = None  # Optional callable(value) -> Finding | None


def _validate_csp(value: str) -> Finding | None:
    """Check for dangerous CSP directives."""
    issues = []
    if "unsafe-inline" in value:
        issues.append("'unsafe-inline' allows inline scripts (XSS risk)")
    if "unsafe-eval" in value:
        issues.append("'unsafe-eval' allows eval() (XSS risk)")
    if re.search(r"script-src\s+\*", value):
        issues.append("Wildcard script-src allows scripts from any origin")
    if issues:
        return Finding(
            title="Weak Content-Security-Policy configuration",
            severity=Severity.MEDIUM,
            description="The CSP header is present but contains insecure directives.",
            evidence="; ".join(issues),
            recommendation="Remove 'unsafe-inline', 'unsafe-eval', and wildcard sources from CSP.",
            references=["https://csp.withgoogle.com/docs/strict-csp.html"],
        )
    return None


def _validate_hsts(value: str) -> Finding | None:
    match = re.search(r"max-age=(\d+)", value)
    if not match:
        return Finding(
            title="HSTS max-age not set",
            severity=Severity.MEDIUM,
            description="HSTS header is present but max-age is missing or malformed.",
            evidence=f"Value: {value}",
            recommendation="Set max-age to at least 31536000 (1 year).",
        )
    age = int(match.group(1))
    if age < 31536000:
        return Finding(
            title="HSTS max-age too short",
            severity=Severity.LOW,
            description=f"HSTS max-age is {age}s, recommended minimum is 31536000 (1 year).",
            evidence=f"max-age={age}",
            recommendation="Set max-age to at least 31536000.",
            references=["https://hstspreload.org/"],
        )
    return None


def _validate_xfo(value: str) -> Finding | None:
    if value.upper() not in ("DENY", "SAMEORIGIN"):
        return Finding(
            title="Permissive X-Frame-Options value",
            severity=Severity.MEDIUM,
            description=f"X-Frame-Options value '{value}' may not prevent clickjacking.",
            evidence=f"Value: {value}",
            recommendation="Use 'DENY' or 'SAMEORIGIN'.",
        )
    return None


SECURITY_HEADERS: list[HeaderSpec] = [
    HeaderSpec(
        name="Strict-Transport-Security",
        severity_missing=Severity.HIGH,
        description_missing=(
            "HSTS is missing. The browser may access the site over HTTP, "
            "enabling man-in-the-middle and SSL stripping attacks."
        ),
        recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        validator=_validate_hsts,
    ),
    HeaderSpec(
        name="Content-Security-Policy",
        severity_missing=Severity.HIGH,
        description_missing=(
            "CSP header is missing. Without it, the browser has no restrictions on "
            "which resources can be loaded, greatly increasing XSS risk."
        ),
        recommendation="Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
        validator=_validate_csp,
    ),
    HeaderSpec(
        name="X-Frame-Options",
        severity_missing=Severity.MEDIUM,
        description_missing=(
            "X-Frame-Options is missing. The page can be embedded in iframes by "
            "third-party sites, enabling clickjacking attacks."
        ),
        recommendation="Add: X-Frame-Options: DENY  (or use CSP frame-ancestors directive)",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
        validator=_validate_xfo,
    ),
    HeaderSpec(
        name="X-Content-Type-Options",
        severity_missing=Severity.MEDIUM,
        description_missing=(
            "X-Content-Type-Options is missing. Browsers may MIME-sniff responses, "
            "potentially interpreting innocent files as executable scripts."
        ),
        recommendation="Add: X-Content-Type-Options: nosniff",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    ),
    HeaderSpec(
        name="Referrer-Policy",
        severity_missing=Severity.LOW,
        description_missing=(
            "Referrer-Policy is missing. The browser may send the full URL as a "
            "Referer header to third parties, leaking sensitive path information."
        ),
        recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    ),
    HeaderSpec(
        name="Permissions-Policy",
        severity_missing=Severity.LOW,
        description_missing=(
            "Permissions-Policy is missing. Browser features (camera, microphone, geolocation) "
            "are not explicitly restricted for third-party content."
        ),
        recommendation="Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    ),
]

DANGEROUS_HEADERS = {
    "Server": "Exposes server software and version, aiding fingerprinting",
    "X-Powered-By": "Exposes backend technology stack (e.g., PHP/7.4, ASP.NET)",
    "X-AspNet-Version": "Exposes exact ASP.NET version",
    "X-Generator": "Exposes CMS or framework details",
}


class HeaderCheckerModule(BaseModule):
    """Analyzes HTTP response headers for security misconfigurations."""

    name = "header_checker"
    description = "Checks HTTP security headers for missing or misconfigured directives"

    def run(self, target: Target) -> ModuleResult:
        result = self._result(target)

        try:
            response = requests.get(
                target.base_url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "SecAudit/1.0 Security Scanner"},
                verify=False,  # SSL issues checked separately
            )
        except RequestException as e:
            result.error = f"HTTP request failed: {e}"
            return result

        headers = {k.lower(): v for k, v in response.headers.items()}
        result.metadata["status_code"] = response.status_code
        result.metadata["final_url"] = response.url
        result.metadata["headers"] = dict(response.headers)

        # Check security headers
        for spec in SECURITY_HEADERS:
            value = headers.get(spec.name.lower())
            if value is None:
                result.add_finding(Finding(
                    title=f"Missing security header: {spec.name}",
                    severity=spec.severity_missing,
                    description=spec.description_missing,
                    recommendation=spec.recommendation,
                    references=spec.references,
                ))
            elif spec.validator:
                finding = spec.validator(value)
                if finding:
                    result.add_finding(finding)

        # Check for information-leaking headers
        for header_name, risk_desc in DANGEROUS_HEADERS.items():
            value = headers.get(header_name.lower())
            if value:
                result.add_finding(Finding(
                    title=f"Information disclosure via {header_name} header",
                    severity=Severity.LOW,
                    description=risk_desc,
                    evidence=f"{header_name}: {value}",
                    recommendation=f"Remove or obfuscate the {header_name} response header.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                ))

        # Check for HTTP → HTTPS redirect
        if target.scheme == "https":
            try:
                http_resp = requests.get(
                    target.base_url.replace("https://", "http://"),
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False,
                )
                if http_resp.status_code not in (301, 302, 307, 308):
                    result.add_finding(Finding(
                        title="HTTP does not redirect to HTTPS",
                        severity=Severity.HIGH,
                        description=(
                            "The server does not redirect plain HTTP traffic to HTTPS. "
                            "Users connecting over HTTP will not be upgraded to a secure connection."
                        ),
                        evidence=f"HTTP response code: {http_resp.status_code}",
                        recommendation="Configure a permanent 301 redirect from HTTP to HTTPS.",
                    ))
            except RequestException:
                pass

        return result
