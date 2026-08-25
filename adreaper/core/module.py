"""The module contract every ADreaper capability implements.

A module is a self-contained subclass of `BaseModule` that declares typed
`options`, then implements `run(ctx)` returning a `ModuleResult`. The framework
handles discovery, option parsing/validation, dependency checks, and reporting,
so a module author only writes the technique.
"""

from __future__ import annotations

import importlib.util
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from adreaper.core.context import EngagementContext


class OptionType(str, Enum):
    STRING = "string"
    INT = "int"
    BOOL = "bool"
    FLOAT = "float"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


@dataclass
class Option:
    """A typed, self-describing module option (Metasploit datastore style)."""

    name: str
    description: str
    required: bool = False
    default: Any = None
    type: OptionType = OptionType.STRING
    choices: Optional[list[str]] = None

    def coerce(self, raw: Any) -> Any:
        """Convert a raw (usually string) value into the option's declared type."""
        if raw is None:
            return self.default
        if self.type is OptionType.BOOL:
            if isinstance(raw, bool):
                return raw
            return str(raw).strip().lower() in ("1", "true", "yes", "y", "on")
        if self.type is OptionType.INT:
            return int(raw)
        if self.type is OptionType.FLOAT:
            return float(raw)
        value = str(raw)
        if self.choices and value not in self.choices:
            raise ValueError(f"{self.name}: {value!r} not in {self.choices}")
        return value


@dataclass
class Finding:
    """A single security-relevant observation destined for the report."""

    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: str = ""
    target: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "target": self.target,
            "references": self.references,
        }


@dataclass
class ModuleResult:
    """Structured outcome of a module run; consumed by the reporting engine."""

    module: str
    success: bool = True
    error: str = ""
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0

    def add_finding(self, title: str, severity: Severity = Severity.INFO, **kw: Any) -> Finding:
        f = Finding(title=title, severity=severity, **kw)
        self.findings.append(f)
        return f

    def fail(self, error: str) -> "ModuleResult":
        self.success = False
        self.error = error
        return self

    def finish(self) -> "ModuleResult":
        self.ended_at = time.time()
        return self

    @property
    def duration(self) -> float:
        return (self.ended_at or time.time()) - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "success": self.success,
            "error": self.error,
            "duration_sec": round(self.duration, 2),
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }


class BaseModule(ABC):
    """Base class for all ADreaper modules.

    Subclasses set the class-level metadata and `options`, then implement
    `run(ctx)`. Requirements listed in `requires` are importable module names
    checked before the module runs (e.g. "impacket", "ldap3").
    """

    name: str = "category/unnamed"
    description: str = ""
    author: str = "unknown"
    category: str = "misc"
    references: list[str] = []
    requires: list[str] = []          # importable python module names
    options: list[Option] = []

    def __init__(self) -> None:
        self._values: dict[str, Any] = {}
        for opt in self.options:
            self._values[opt.name] = opt.default

    # -- option handling --------------------------------------------------

    def _option(self, name: str) -> Option:
        for o in self.options:
            if o.name.lower() == name.lower():
                return o
        raise KeyError(f"unknown option: {name}")

    def set_option(self, name: str, raw: Any) -> None:
        opt = self._option(name)
        self._values[opt.name] = opt.coerce(raw)

    def set_options(self, mapping: dict[str, Any]) -> None:
        for k, v in mapping.items():
            if v is None:
                continue
            try:
                self.set_option(k, v)
            except KeyError:
                # Ignore globals that aren't this module's options (e.g. --domain).
                continue

    def opt(self, name: str, default: Any = None) -> Any:
        return self._values.get(self._option(name).name, default)

    def validate(self) -> list[str]:
        """Return a list of human-readable problems (missing required options)."""
        problems = []
        for o in self.options:
            if o.required and self._values.get(o.name) in (None, ""):
                problems.append(f"required option '{o.name}' is not set")
        return problems

    def missing_requirements(self) -> list[str]:
        """Return importable requirements that are not installed."""
        return [m for m in self.requires if importlib.util.find_spec(m) is None]

    # -- helpers for module authors --------------------------------------

    def result(self) -> ModuleResult:
        return ModuleResult(module=self.name)

    # -- the technique ----------------------------------------------------

    @abstractmethod
    def run(self, ctx: EngagementContext) -> ModuleResult:
        """Execute the module against the engagement context and return a result."""
        raise NotImplementedError
