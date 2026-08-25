"""Engagement context — the shared state modules read from and write to.

A single `EngagementContext` carries the domain/DC being assessed, the current
credentials, discovered targets, the attack graph, and the output directory.
Modules receive it in `run(ctx)` so recon feeds the same graph an attack-path
finder later walks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from adreaper.core.graph import ADGraph


@dataclass
class Credential:
    """One AD credential. Supports password, NTLM hash (PtH), and Kerberos keys."""

    username: str = ""
    password: str = ""
    domain: str = ""
    nt_hash: str = ""          # LM:NT or just NT hex — pass-the-hash
    aes_key: str = ""          # AES128/256 kerberos key
    use_kerberos: bool = False

    @property
    def is_empty(self) -> bool:
        return not (self.username or self.password or self.nt_hash or self.aes_key)

    @property
    def has_secret(self) -> bool:
        return bool(self.password or self.nt_hash or self.aes_key)

    def normalized_hash(self) -> str:
        """Return LMHASH:NTHASH form impacket expects, or '' if none."""
        if not self.nt_hash:
            return ""
        if ":" in self.nt_hash:
            return self.nt_hash
        empty_lm = "aad3b435b51404eeaad3b435b51404ee"
        return f"{empty_lm}:{self.nt_hash}"

    def display(self) -> str:
        if self.is_empty:
            return "<anonymous / null session>"
        who = f"{self.domain}\\{self.username}" if self.domain else self.username
        if self.nt_hash:
            return f"{who} (hash)"
        if self.aes_key:
            return f"{who} (aes)"
        if self.password:
            return f"{who} (password)"
        return who


@dataclass
class Target:
    """A single host under assessment."""

    host: str                       # IP or hostname
    hostname: str = ""              # resolved NetBIOS/DNS name
    os: str = ""
    ports: set[int] = field(default_factory=set)
    is_dc: bool = False

    def __hash__(self) -> int:
        return hash(self.host.lower())


@dataclass
class EngagementContext:
    """Everything a module needs to do its job, and where its output goes."""

    domain: str = ""
    dc_ip: str = ""
    credential: Credential = field(default_factory=Credential)
    targets: list[Target] = field(default_factory=list)
    graph: ADGraph = field(default_factory=ADGraph)
    output_dir: Path = field(default_factory=lambda: Path("adreaper_loot"))
    timeout: int = 10
    threads: int = 10
    authorized: bool = False        # set once the authorized-use gate is passed

    def loot_dir(self) -> Path:
        """Per-domain loot directory, created on demand."""
        sub = self.domain or "unknown"
        p = self.output_dir / _safe(sub)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def add_target(self, host: str, **kw) -> Target:
        for t in self.targets:
            if t.host.lower() == host.lower():
                return t
        t = Target(host=host, **kw)
        self.targets.append(t)
        return t

    def primary_target(self) -> Optional[str]:
        """Best host to talk to: an explicit DC IP, else the first target."""
        if self.dc_ip:
            return self.dc_ip
        return self.targets[0].host if self.targets else None


def _safe(name: str) -> str:
    keep = "-_.() "
    return "".join(c if (c.isalnum() or c in keep) else "_" for c in name).strip() or "unknown"
