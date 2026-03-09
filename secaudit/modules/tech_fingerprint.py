"""
Technology fingerprinting module.
Identifies the technology stack used by the target web application
via HTTP headers, cookies, HTML patterns, and common file paths.
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
class TechSignature:
    name: str
    category: str
    patterns: list[dict[str, str]] = field(default_factory=list)
    # Each pattern: {"source": "header|cookie|body|header_name", "regex": "..."}


TECH_SIGNATURES: list[TechSignature] = [
    # Web Servers
    TechSignature("Apache", "Web Server", [
        {"source": "header:server", "regex": r"Apache"},
        {"source": "body", "regex": r"Apache/[\d.]+"},
    ]),
    TechSignature("Nginx", "Web Server", [
        {"source": "header:server", "regex": r"nginx"},
    ]),
    TechSignature("IIS", "Web Server", [
        {"source": "header:server", "regex": r"Microsoft-IIS"},
        {"source": "header:x-powered-by", "regex": r"ASP\.NET"},
    ]),
    TechSignature("LiteSpeed", "Web Server", [
        {"source": "header:server", "regex": r"LiteSpeed"},
    ]),
    # Frameworks / Languages
    TechSignature("PHP", "Language", [
        {"source": "header:x-powered-by", "regex": r"PHP/[\d.]+"},
        {"source": "cookie", "regex": r"PHPSESSID"},
    ]),
    TechSignature("ASP.NET", "Framework", [
        {"source": "header:x-powered-by", "regex": r"ASP\.NET"},
        {"source": "cookie", "regex": r"ASP\.NET_SessionId|\.ASPXAUTH"},
        {"source": "header:x-aspnet-version", "regex": r".+"},
    ]),
    TechSignature("Django", "Framework", [
        {"source": "cookie", "regex": r"csrftoken|sessionid"},
        {"source": "body", "regex": r"csrfmiddlewaretoken"},
    ]),
    TechSignature("Ruby on Rails", "Framework", [
        {"source": "header:x-powered-by", "regex": r"Phusion Passenger"},
        {"source": "cookie", "regex": r"_session_id"},
    ]),
    TechSignature("Express.js", "Framework", [
        {"source": "header:x-powered-by", "regex": r"Express"},
    ]),
    TechSignature("Laravel", "Framework", [
        {"source": "cookie", "regex": r"laravel_session|XSRF-TOKEN"},
    ]),
    # CMS
    TechSignature("WordPress", "CMS", [
        {"source": "body", "regex": r"/wp-content/|/wp-includes/|wp-json"},
        {"source": "header:link", "regex": r"wp-json"},
        {"source": "cookie", "regex": r"wordpress_|wp-settings-"},
    ]),
    TechSignature("Drupal", "CMS", [
        {"source": "body", "regex": r"Drupal\.settings|/sites/default/files"},
        {"source": "header:x-generator", "regex": r"Drupal"},
        {"source": "cookie", "regex": r"DRUPAL_UID|Drupal\.visitor"},
    ]),
    TechSignature("Joomla", "CMS", [
        {"source": "body", "regex": r"/media/jui/|Joomla!"},
        {"source": "cookie", "regex": r"joomla_user_state"},
    ]),
    TechSignature("Shopify", "E-Commerce", [
        {"source": "body", "regex": r"Shopify\.theme|cdn\.shopify\.com"},
        {"source": "cookie", "regex": r"_shopify_"},
    ]),
    TechSignature("WooCommerce", "E-Commerce", [
        {"source": "body", "regex": r"woocommerce|wc-api"},
    ]),
    # JavaScript Frameworks
    TechSignature("React", "JS Framework", [
        {"source": "body", "regex": r"__reactFiber|__REACT_DEVTOOLS|react-root"},
    ]),
    TechSignature("Angular", "JS Framework", [
        {"source": "body", "regex": r"ng-version|ng-app|angular\.js"},
    ]),
    TechSignature("Vue.js", "JS Framework", [
        {"source": "body", "regex": r"__vue__|data-v-|vue\.js"},
    ]),
    TechSignature("Next.js", "JS Framework", [
        {"source": "body", "regex": r"__NEXT_DATA__|_next/static"},
        {"source": "header:x-powered-by", "regex": r"Next\.js"},
    ]),
    # CDN / Infrastructure
    TechSignature("Cloudflare", "CDN/Security", [
        {"source": "header:server", "regex": r"cloudflare"},
        {"source": "header:cf-ray", "regex": r".+"},
        {"source": "cookie", "regex": r"__cfduid|cf_clearance|__cf_bm"},
    ]),
    TechSignature("AWS CloudFront", "CDN", [
        {"source": "header:via", "regex": r"CloudFront"},
        {"source": "header:x-amz-cf-id", "regex": r".+"},
    ]),
    TechSignature("Fastly", "CDN", [
        {"source": "header:via", "regex": r"varnish"},
        {"source": "header:x-fastly-request-id", "regex": r".+"},
    ]),
    # Analytics / Marketing
    TechSignature("Google Analytics", "Analytics", [
        {"source": "body", "regex": r"google-analytics\.com/analytics\.js|gtag\(|UA-\d+-\d+"},
    ]),
    TechSignature("Google Tag Manager", "Tag Manager", [
        {"source": "body", "regex": r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+"},
    ]),
]

# Paths that reveal information about the tech stack
PROBE_PATHS = [
    ("/wp-login.php", "WordPress login page"),
    ("/wp-admin/", "WordPress admin"),
    ("/administrator/", "Joomla administrator"),
    ("/admin/", "Generic admin panel"),
    ("/phpmyadmin/", "phpMyAdmin database interface"),
    ("/.git/HEAD", "Exposed Git repository"),
    ("/.env", "Exposed environment file"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/actuator/health", "Spring Boot Actuator"),
    ("/api/swagger.json", "Swagger/OpenAPI docs"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/robots.txt", "Robots.txt (informational)"),
    ("/.well-known/security.txt", "Security contact info"),
]


class TechFingerprintModule(BaseModule):
    """Fingerprints web technologies and probes for exposed sensitive paths."""

    name = "tech_fingerprint"
    description = "Identifies the technology stack and probes for sensitive exposed paths"

    def _fetch(self, url: str) -> requests.Response | None:
        try:
            return requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "SecAudit/1.0 Security Scanner"},
                verify=False,
            )
        except RequestException:
            return None

    def _detect_technologies(self, response: requests.Response) -> list[TechSignature]:
        detected = []
        body = response.text
        headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = "; ".join(f"{k}={v}" for k, v in response.cookies.items())

        for sig in TECH_SIGNATURES:
            for pattern in sig.patterns:
                source = pattern["source"]
                regex = pattern["regex"]
                target_text = ""

                if source == "body":
                    target_text = body
                elif source == "cookie":
                    target_text = cookies
                elif source.startswith("header:"):
                    header_name = source.split(":", 1)[1]
                    target_text = headers.get(header_name, "")
                else:
                    target_text = body

                if re.search(regex, target_text, re.IGNORECASE):
                    detected.append(sig)
                    break

        return detected

    def run(self, target: Target) -> ModuleResult:
        result = self._result(target)

        response = self._fetch(target.base_url)
        if not response:
            result.error = "Failed to fetch target"
            return result

        # Technology detection
        detected = self._detect_technologies(response)
        if detected:
            by_category: dict[str, list[str]] = {}
            for tech in detected:
                by_category.setdefault(tech.category, []).append(tech.name)

            result.metadata["technologies"] = {
                cat: techs for cat, techs in by_category.items()
            }

            summary_lines = [f"{cat}: {', '.join(techs)}" for cat, techs in by_category.items()]
            result.add_finding(Finding(
                title=f"Technology stack identified ({len(detected)} technologies)",
                severity=Severity.INFO,
                description="The following technologies were fingerprinted on the target.",
                evidence="\n".join(summary_lines),
                recommendation=(
                    "Minimize information disclosure: remove X-Powered-By headers, "
                    "obfuscate Server headers, and use generic cookie names."
                ),
            ))

        # Probe sensitive paths
        sensitive_found = []
        for path, description in PROBE_PATHS:
            url = f"{target.base_url}{path}"
            resp = self._fetch(url)
            if resp and resp.status_code in (200, 403):
                sensitive_found.append((path, description, resp.status_code))

        for path, description, status in sensitive_found:
            is_critical = path in ("/.env", "/.git/HEAD", "/phpmyadmin/", "/server-status")
            severity = Severity.CRITICAL if (status == 200 and is_critical) else (
                Severity.HIGH if status == 200 else Severity.MEDIUM
            )
            result.add_finding(Finding(
                title=f"Sensitive path accessible: {path}",
                severity=severity,
                description=f"{description} is reachable (HTTP {status}).",
                evidence=f"GET {target.base_url}{path} → {status}",
                recommendation=(
                    f"Restrict access to {path} via web server configuration or firewall rules. "
                    "If not needed, remove or disable it entirely."
                ),
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            ))

        return result
