"""
Target representation and validation for SecAudit.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Target:
    """Represents a scan target with parsed URL components."""

    raw: str
    scheme: str = field(init=False)
    host: str = field(init=False)
    port: int = field(init=False)
    path: str = field(init=False)
    ip: str = field(init=False, default="")

    def __post_init__(self) -> None:
        raw = self.raw.strip()
        if not re.match(r"^https?://", raw):
            raw = "https://" + raw

        parsed = urlparse(raw)
        self.scheme = parsed.scheme
        self.host = parsed.hostname or ""
        self.path = parsed.path or "/"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)

        if not self.host:
            raise ValueError(f"Invalid target: {self.raw}")

        self._resolve_ip()

    def _resolve_ip(self) -> None:
        try:
            self.ip = socket.gethostbyname(self.host)
        except socket.gaierror:
            self.ip = ""

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    def __str__(self) -> str:
        return self.base_url
