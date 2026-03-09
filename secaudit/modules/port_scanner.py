"""
Port scanner module using concurrent socket connections.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ..core.base_module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target

# Well-known ports with associated services and risk notes
COMMON_PORTS: dict[int, dict] = {
    21:   {"service": "FTP",        "risk": "Cleartext protocol, credentials exposed"},
    22:   {"service": "SSH",        "risk": None},
    23:   {"service": "Telnet",     "risk": "Cleartext protocol, highly insecure"},
    25:   {"service": "SMTP",       "risk": "May be used for spam relay if misconfigured"},
    53:   {"service": "DNS",        "risk": None},
    80:   {"service": "HTTP",       "risk": "Cleartext web traffic"},
    110:  {"service": "POP3",       "risk": "Cleartext email retrieval"},
    111:  {"service": "RPCBind",    "risk": "Can expose sensitive RPC services"},
    135:  {"service": "MSRPC",      "risk": "Common attack vector on Windows"},
    139:  {"service": "NetBIOS",    "risk": "Windows file sharing, often targeted"},
    143:  {"service": "IMAP",       "risk": "Cleartext email access"},
    443:  {"service": "HTTPS",      "risk": None},
    445:  {"service": "SMB",        "risk": "High-risk: EternalBlue, WannaCry vector"},
    3306: {"service": "MySQL",      "risk": "Database exposed to network"},
    3389: {"service": "RDP",        "risk": "Remote desktop, brute-force target"},
    5432: {"service": "PostgreSQL", "risk": "Database exposed to network"},
    5900: {"service": "VNC",        "risk": "Remote desktop, often weak auth"},
    6379: {"service": "Redis",      "risk": "Often unauthenticated by default"},
    8080: {"service": "HTTP-Alt",   "risk": "Alternative HTTP, may expose admin panels"},
    8443: {"service": "HTTPS-Alt",  "risk": None},
    27017:{"service": "MongoDB",    "risk": "Database exposed to network, often no auth"},
}

DANGEROUS_PORTS = {23, 21, 110, 143, 139, 445, 3389, 5900, 6379, 27017, 111, 135}


@dataclass
class OpenPort:
    port: int
    service: str
    banner: str = ""


class PortScannerModule(BaseModule):
    """Concurrent TCP port scanner with banner grabbing."""

    name = "port_scanner"
    description = "Scans for open TCP ports and identifies running services"

    def __init__(
        self,
        ports: list[int] | None = None,
        max_workers: int = 100,
        timeout: int = 2,
        verbose: bool = False,
    ) -> None:
        super().__init__(timeout=timeout, verbose=verbose)
        self.ports = ports or list(COMMON_PORTS.keys())
        self.max_workers = max_workers

    def _scan_port(self, host: str, port: int) -> OpenPort | None:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                banner = self._grab_banner(sock)
                service = COMMON_PORTS.get(port, {}).get("service", "unknown")
                return OpenPort(port=port, service=service, banner=banner)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _grab_banner(self, sock: socket.socket) -> str:
        try:
            sock.settimeout(1.5)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:200]  # Limit banner length
        except Exception:
            return ""

    def run(self, target: Target) -> ModuleResult:
        result = self._result(target)
        host = target.host
        open_ports: list[OpenPort] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_port, host, port): port
                for port in self.ports
            }
            for future in as_completed(futures):
                port_result = future.result()
                if port_result:
                    open_ports.append(port_result)

        open_ports.sort(key=lambda p: p.port)
        result.metadata["open_ports"] = [
            {"port": p.port, "service": p.service, "banner": p.banner}
            for p in open_ports
        ]

        if not open_ports:
            result.add_finding(Finding(
                title="No common ports open",
                severity=Severity.INFO,
                description="No commonly used ports were found open on the target.",
            ))
            return result

        # Report all open ports as INFO
        ports_summary = ", ".join(f"{p.port}/{p.service}" for p in open_ports)
        result.add_finding(Finding(
            title=f"Open ports detected ({len(open_ports)} found)",
            severity=Severity.INFO,
            description=f"Found {len(open_ports)} open port(s): {ports_summary}",
            evidence=ports_summary,
            recommendation="Ensure only necessary ports are exposed. Apply firewall rules.",
        ))

        # Flag dangerous ports
        for op in open_ports:
            if op.port in DANGEROUS_PORTS:
                info = COMMON_PORTS.get(op.port, {})
                result.add_finding(Finding(
                    title=f"Risky service exposed: {info.get('service', 'Unknown')} (port {op.port})",
                    severity=Severity.HIGH,
                    description=info.get("risk", "Potentially dangerous service exposed."),
                    evidence=f"Port {op.port} is open" + (f" | Banner: {op.banner}" if op.banner else ""),
                    recommendation=(
                        f"Restrict access to port {op.port} using firewall rules. "
                        "If not needed, disable the service entirely."
                    ),
                    references=["https://attack.mitre.org/techniques/T1046/"],
                ))

        return result
