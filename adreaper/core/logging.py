"""Centralized, colorized logging for ADreaper.

Uses `rich` when available, degrades to plain stdout otherwise so the framework
core never hard-depends on it. Import `log` and call the level helpers:

    from adreaper.core.logging import log
    log.info("enumerating LDAP...")
    log.ok("found 42 users")
    log.warn("null session refused")
    log.error("bind failed: %s", err)
"""

from __future__ import annotations

import sys
from typing import Any

try:
    from rich.console import Console

    _console: "Console | None" = Console(stderr=False, highlight=False)
    _err_console: "Console | None" = Console(stderr=True, highlight=False)
except Exception:  # pragma: no cover - rich should be present, but stay safe
    _console = None
    _err_console = None


_LEVELS = {
    "debug": ("[*]", "dim"),
    "info": ("[*]", "cyan"),
    "ok": ("[+]", "bold green"),
    "warn": ("[!]", "yellow"),
    "error": ("[-]", "bold red"),
}


class _Logger:
    """Tiny leveled logger with rich-or-plain output."""

    def __init__(self) -> None:
        self.verbose = False
        self.quiet = False

    def _emit(self, level: str, msg: str, args: tuple[Any, ...], to_err: bool) -> None:
        if self.quiet and level in ("debug", "info"):
            return
        if level == "debug" and not self.verbose:
            return
        if args:
            try:
                msg = msg % args
            except Exception:
                msg = f"{msg} {args}"
        prefix, style = _LEVELS.get(level, ("[*]", ""))
        console = _err_console if to_err else _console
        if console is not None:
            console.print(f"[{style}]{prefix}[/] {msg}" if style else f"{prefix} {msg}")
        else:
            stream = sys.stderr if to_err else sys.stdout
            print(f"{prefix} {msg}", file=stream)

    def debug(self, msg: str, *args: Any) -> None:
        self._emit("debug", msg, args, to_err=False)

    def info(self, msg: str, *args: Any) -> None:
        self._emit("info", msg, args, to_err=False)

    def ok(self, msg: str, *args: Any) -> None:
        self._emit("ok", msg, args, to_err=False)

    def warn(self, msg: str, *args: Any) -> None:
        self._emit("warn", msg, args, to_err=True)

    def error(self, msg: str, *args: Any) -> None:
        self._emit("error", msg, args, to_err=True)


log = _Logger()
"""Process-wide logger instance."""


def console() -> "Console | None":
    """Return the shared rich Console (or None if rich is unavailable)."""
    return _console
