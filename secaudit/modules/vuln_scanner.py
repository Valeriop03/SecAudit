"""
Web vulnerability scanner module.
Performs active checks for common web application vulnerabilities.

WARNING: Only use against systems you own or have explicit written permission to test.
Unauthorized testing is illegal and unethical.
"""

from __future__ import annotations

import html
import re
import urllib.parse
from typing import NamedTuple

import requests
from requests.exceptions import RequestException

from ..core.base_module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target


class Payload(NamedTuple):
    value: str
    detect: str  # regex to detect reflection/error
    vuln_type: str


# Reflected XSS payloads — we only detect reflection, not actual execution
XSS_PAYLOADS: list[Payload] = [
    Payload('<script>alert("xss")</script>', r'<script>alert\("xss"\)</script>', "Reflected XSS"),
    Payload('"><img src=x onerror=1>', r'"><img src=x onerror=1>', "Reflected XSS"),
    Payload("'><svg/onload=1>", r"'><svg/onload=1>", "Reflected XSS"),
]

# SQL Injection error-based detection
SQLI_PAYLOADS: list[Payload] = [
    Payload("'", r"SQL syntax|mysql_fetch|ORA-\d+|syntax error|SQLSTATE", "SQL Injection"),
    Payload("1' OR '1'='1", r"SQL syntax|mysql_fetch|ORA-\d+|syntax error|SQLSTATE", "SQL Injection"),
    Payload("1; SELECT SLEEP(0)--", r"SQL syntax|mysql_fetch|ORA-\d+|syntax error", "SQL Injection"),
]

# Open redirect payloads
REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
]

# SSTI (Server-Side Template Injection) detection
SSTI_PAYLOADS: list[Payload] = [
    Payload("{{7*7}}", r"\b49\b", "SSTI"),
    Payload("${7*7}", r"\b49\b", "SSTI"),
    Payload("<%= 7*7 %>", r"\b49\b", "SSTI"),
]

# Parameters commonly used in redirects
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnurl", "redir", "goto", "target"]

# Parameters commonly used to inject into page content
INJECTION_PARAMS = ["q", "s", "search", "query", "id", "name", "user", "username",
                    "input", "text", "data", "value", "page", "msg", "message", "comment"]


class VulnScannerModule(BaseModule):
    """
    Active web vulnerability scanner.
    Tests for XSS, SQLi, Open Redirect, SSTI, and CORS misconfigurations.
    """

    name = "vuln_scanner"
    description = "Actively tests for common web vulnerabilities (XSS, SQLi, Open Redirect, SSTI, CORS)"

    def __init__(self, timeout: int = 10, verbose: bool = False, follow_redirects: bool = False) -> None:
        super().__init__(timeout=timeout, verbose=verbose)
        self.follow_redirects = follow_redirects
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "SecAudit/1.0 Security Scanner"
        self.session.verify = False

    def _get(self, url: str, params: dict | None = None) -> requests.Response | None:
        try:
            return self.session.get(url, params=params, timeout=self.timeout, allow_redirects=False)
        except RequestException:
            return None

    def _extract_params(self, target: Target) -> list[str]:
        """Discover URL parameters by inspecting links on the homepage."""
        resp = self._get(target.base_url)
        if not resp:
            return []
        params = set(INJECTION_PARAMS)
        # Also grab params from links found on the page
        for match in re.finditer(r'href=["\']([^"\']+)["\']', resp.text):
            href = match.group(1)
            parsed = urllib.parse.urlparse(href)
            qs = urllib.parse.parse_qs(parsed.query)
            params.update(qs.keys())
        return list(params)[:20]  # Limit to avoid noise

    def _check_xss(self, target: Target, params: list[str], result: ModuleResult) -> None:
        for param in params:
            for payload in XSS_PAYLOADS:
                resp = self._get(target.base_url, {param: payload.value})
                if resp and re.search(payload.detect, resp.text, re.IGNORECASE):
                    # Confirm it's not HTML-encoded
                    if html.escape(payload.value) not in resp.text or payload.value in resp.text:
                        result.add_finding(Finding(
                            title=f"Potential Reflected XSS via '{param}' parameter",
                            severity=Severity.HIGH,
                            description=(
                                f"The parameter '{param}' reflects unsanitized input in the HTTP response. "
                                "This may allow an attacker to inject and execute arbitrary JavaScript."
                            ),
                            evidence=f"Payload: {payload.value!r} reflected in response",
                            recommendation=(
                                "Encode all user-supplied input before rendering in HTML. "
                                "Implement a strict Content-Security-Policy."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            ],
                        ))
                        break  # One finding per param is enough

    def _check_sqli(self, target: Target, params: list[str], result: ModuleResult) -> None:
        for param in params:
            for payload in SQLI_PAYLOADS:
                resp = self._get(target.base_url, {param: payload.value})
                if resp and re.search(payload.detect, resp.text, re.IGNORECASE):
                    result.add_finding(Finding(
                        title=f"Potential SQL Injection via '{param}' parameter",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The parameter '{param}' triggers a database error message when injected with SQL syntax. "
                            "This indicates the input is not properly sanitized before being used in a SQL query."
                        ),
                        evidence=f"Payload: {payload.value!r} | DB error detected in response",
                        recommendation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings. "
                            "Apply the principle of least privilege on database accounts."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        ],
                    ))
                    break

    def _check_open_redirect(self, target: Target, result: ModuleResult) -> None:
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS:
                resp = self._get(target.base_url, {param: payload})
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        result.add_finding(Finding(
                            title=f"Open Redirect via '{param}' parameter",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The '{param}' parameter can redirect users to an arbitrary external URL. "
                                "Attackers can use this to craft phishing URLs that appear to originate from your domain."
                            ),
                            evidence=f"?{param}={payload} → Location: {location}",
                            recommendation=(
                                "Validate redirect targets against an allowlist of trusted URLs. "
                                "Avoid redirecting to user-supplied URLs entirely."
                            ),
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                        ))
                        break

    def _check_ssti(self, target: Target, params: list[str], result: ModuleResult) -> None:
        for param in params:
            for payload in SSTI_PAYLOADS:
                resp = self._get(target.base_url, {param: payload.value})
                if resp and re.search(payload.detect, resp.text):
                    result.add_finding(Finding(
                        title=f"Potential Server-Side Template Injection (SSTI) via '{param}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The parameter '{param}' appears to be evaluated as a template expression. "
                            "SSTI can lead to Remote Code Execution (RCE) on the server."
                        ),
                        evidence=f"Payload: {payload.value!r} → Response contains '49'",
                        recommendation=(
                            "Never pass user-controlled data directly to template engines. "
                            "Use sandboxed template environments and validate/sanitize all input."
                        ),
                        references=["https://portswigger.net/research/server-side-template-injection"],
                    ))
                    break

    def _check_cors(self, target: Target, result: ModuleResult) -> None:
        """Check for CORS misconfiguration."""
        try:
            resp = self.session.get(
                target.base_url,
                timeout=self.timeout,
                headers={"Origin": "https://evil.com"},
                allow_redirects=True,
            )
        except RequestException:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            result.add_finding(Finding(
                title="Permissive CORS: Access-Control-Allow-Origin: *",
                severity=Severity.MEDIUM,
                description=(
                    "The server allows cross-origin requests from any domain. "
                    "Combined with cookies, this can lead to data theft."
                ),
                evidence="Access-Control-Allow-Origin: *",
                recommendation=(
                    "Restrict CORS to specific trusted origins. "
                    "Never use '*' with Access-Control-Allow-Credentials: true."
                ),
                references=["https://portswigger.net/web-security/cors"],
            ))
        elif "evil.com" in acao:
            severity = Severity.CRITICAL if acac.lower() == "true" else Severity.HIGH
            result.add_finding(Finding(
                title="CORS origin reflection vulnerability",
                severity=severity,
                description=(
                    "The server reflects the attacker-controlled Origin header back in ACAO. "
                    + ("With Allow-Credentials: true, this allows credential theft." if acac.lower() == "true" else "")
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}  |  Allow-Credentials: {acac}",
                recommendation=(
                    "Implement an explicit allowlist of trusted origins. "
                    "Do not reflect the Origin header without validation."
                ),
                references=["https://portswigger.net/web-security/cors/access-control-allow-origin"],
            ))

    def run(self, target: Target) -> ModuleResult:
        result = self._result(target)

        params = self._extract_params(target)
        if not params:
            params = INJECTION_PARAMS[:5]

        # Run all checks
        self._check_cors(target, result)
        self._check_open_redirect(target, result)
        self._check_xss(target, params, result)
        self._check_sqli(target, params, result)
        self._check_ssti(target, params, result)

        if not result.findings:
            result.add_finding(Finding(
                title="No common vulnerabilities detected",
                severity=Severity.INFO,
                description=(
                    "Basic vulnerability checks passed. Note: this is not a comprehensive assessment. "
                    "Manual testing and dedicated tools (Burp Suite, OWASP ZAP) are recommended."
                ),
            ))

        return result
