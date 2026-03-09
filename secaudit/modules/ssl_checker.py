"""
SSL/TLS configuration analysis module.
Checks certificate validity, protocol versions, and cipher suites.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass

from ..core.base_module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target

DEPRECATED_PROTOCOLS = {
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
}

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA128",
}


@dataclass
class CertInfo:
    subject: dict
    issuer: dict
    not_before: datetime.datetime
    not_after: datetime.datetime
    san: list[str]
    version: int


class SSLCheckerModule(BaseModule):
    """Analyzes SSL/TLS configuration for weaknesses."""

    name = "ssl_checker"
    description = "Analyzes SSL/TLS certificate and protocol configuration"

    def _get_cert_info(self, host: str, port: int) -> tuple[dict, CertInfo | None, str]:
        """Returns (raw_cert_dict, CertInfo, error_string)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    raw_cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    if not raw_cert:
                        return {}, None, "No certificate returned"

                    def parse_rdns(rdns_seq: tuple) -> dict:
                        result = {}
                        for rdn in rdns_seq:
                            for key, val in rdn:
                                result[key] = val
                        return result

                    subject = parse_rdns(raw_cert.get("subject", ()))
                    issuer = parse_rdns(raw_cert.get("issuer", ()))

                    not_before = ssl.cert_time_to_seconds(raw_cert["notBefore"])
                    not_after = ssl.cert_time_to_seconds(raw_cert["notAfter"])

                    san_list = []
                    for san_type, san_val in raw_cert.get("subjectAltName", ()):
                        san_list.append(f"{san_type}:{san_val}")

                    cert_info = CertInfo(
                        subject=subject,
                        issuer=issuer,
                        not_before=datetime.datetime.fromtimestamp(not_before, tz=datetime.timezone.utc),
                        not_after=datetime.datetime.fromtimestamp(not_after, tz=datetime.timezone.utc),
                        san=san_list,
                        version=raw_cert.get("version", 0),
                    )
                    metadata = {
                        "cipher": cipher,
                        "protocol": protocol,
                    }
                    return metadata, cert_info, ""
        except ssl.SSLError as e:
            return {}, None, f"SSL error: {e}"
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {}, None, f"Connection error: {e}"

    def _check_deprecated_protocols(self, host: str, port: int) -> list[str]:
        """Try to connect using deprecated protocol versions."""
        deprecated_found = []
        for version, name in DEPRECATED_PROTOCOLS.items():
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                    with ctx.wrap_socket(raw_sock, server_hostname=host):
                        deprecated_found.append(name)
            except (ssl.SSLError, OSError):
                pass
        return deprecated_found

    def run(self, target: Target) -> ModuleResult:
        result = self._result(target)

        if target.scheme != "https" and target.port not in (443, 8443):
            result.add_finding(Finding(
                title="Target does not use HTTPS",
                severity=Severity.HIGH,
                description="The target is not using HTTPS. All traffic is transmitted in cleartext.",
                recommendation="Configure the server to use HTTPS with a valid TLS certificate.",
            ))
            return result

        conn_meta, cert_info, error = self._get_cert_info(target.host, target.port)

        if error:
            result.error = error
            result.add_finding(Finding(
                title="SSL/TLS connection failed",
                severity=Severity.CRITICAL,
                description=f"Could not establish an SSL/TLS connection: {error}",
                recommendation="Ensure the server has a valid, properly configured TLS certificate.",
            ))
            return result

        result.metadata["ssl"] = conn_meta

        # Certificate expiry checks
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        days_remaining = (cert_info.not_after - now).days

        if days_remaining < 0:
            result.add_finding(Finding(
                title="SSL certificate has EXPIRED",
                severity=Severity.CRITICAL,
                description=f"The certificate expired {abs(days_remaining)} day(s) ago.",
                evidence=f"Not After: {cert_info.not_after.isoformat()}",
                recommendation="Renew the SSL certificate immediately. Consider using Let's Encrypt for auto-renewal.",
                references=["https://letsencrypt.org/"],
            ))
        elif days_remaining < 14:
            result.add_finding(Finding(
                title="SSL certificate expiring very soon",
                severity=Severity.HIGH,
                description=f"Certificate expires in {days_remaining} day(s).",
                evidence=f"Not After: {cert_info.not_after.isoformat()}",
                recommendation="Renew the certificate immediately.",
            ))
        elif days_remaining < 30:
            result.add_finding(Finding(
                title="SSL certificate expiring soon",
                severity=Severity.MEDIUM,
                description=f"Certificate expires in {days_remaining} day(s).",
                evidence=f"Not After: {cert_info.not_after.isoformat()}",
                recommendation="Schedule certificate renewal.",
            ))
        else:
            result.add_finding(Finding(
                title=f"SSL certificate valid ({days_remaining} days remaining)",
                severity=Severity.INFO,
                description=f"Certificate is valid until {cert_info.not_after.date()}.",
            ))

        # Self-signed certificate check
        if cert_info.subject == cert_info.issuer:
            result.add_finding(Finding(
                title="Self-signed certificate detected",
                severity=Severity.HIGH,
                description=(
                    "The certificate is self-signed and will not be trusted by browsers. "
                    "This exposes users to man-in-the-middle attacks."
                ),
                evidence=f"Issuer == Subject: {cert_info.issuer}",
                recommendation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt, DigiCert).",
            ))

        # Subject Alternative Names check
        if not cert_info.san:
            result.add_finding(Finding(
                title="Certificate has no Subject Alternative Names (SAN)",
                severity=Severity.MEDIUM,
                description=(
                    "Modern browsers require SANs and may reject certificates that rely only on CN."
                ),
                recommendation="Reissue the certificate with appropriate SAN entries.",
            ))

        # Cipher suite analysis
        cipher_info = conn_meta.get("cipher")
        if cipher_info:
            cipher_name = cipher_info[0] if cipher_info else ""
            for weak in WEAK_CIPHERS:
                if weak in cipher_name.upper():
                    result.add_finding(Finding(
                        title=f"Weak cipher suite in use: {cipher_name}",
                        severity=Severity.HIGH,
                        description=f"The negotiated cipher suite contains '{weak}', which is cryptographically weak.",
                        evidence=f"Cipher: {cipher_name}",
                        recommendation="Disable weak ciphers. Prefer ECDHE+AES+GCM or ChaCha20-Poly1305.",
                        references=["https://ciphersuite.info/"],
                    ))
                    break

        # Deprecated protocol check
        deprecated = self._check_deprecated_protocols(target.host, target.port)
        for proto in deprecated:
            result.add_finding(Finding(
                title=f"Deprecated protocol supported: {proto}",
                severity=Severity.HIGH,
                description=f"{proto} is deprecated and has known vulnerabilities (POODLE, BEAST).",
                evidence=f"Server accepted connection using {proto}",
                recommendation=f"Disable {proto} in your web server/load balancer configuration.",
                references=["https://datatracker.ietf.org/doc/rfc8996/"],
            ))

        return result
