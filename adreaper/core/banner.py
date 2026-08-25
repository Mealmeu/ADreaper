"""Startup banner and the authorized-use gate.

Like Metasploit's and NetExec's legal notices, ADreaper reminds the operator on
every run that this is for authorized testing, and records a one-time
acknowledgement so the reminder is not naggy on subsequent runs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from adreaper import __version__
from adreaper.core.logging import log

BANNER = r"""
    _    ____
   / \  |  _ \ _ __ ___  __ _ _ __   ___ _ __
  / _ \ | | | | '__/ _ \/ _` | '_ \ / _ \ '__|
 / ___ \| |_| | | |  __/ (_| | |_) |  __/ |
/_/   \_\____/|_|  \___|\__,_| .__/ \___|_|
                             |_|   ☠  v{ver}
     Active Directory penetration framework
"""

_STATE = Path.home() / ".adreaper" / "authorized"

_NOTICE = (
    "ADreaper is for AUTHORIZED security testing only. Point it only at systems "
    "you own or have explicit written permission to assess. Unauthorized use may "
    "be a crime (e.g. CFAA / Computer Misuse Act / local cybercrime law). "
    "See DISCLAIMER.md."
)


def print_banner() -> None:
    text = BANNER.format(ver=__version__)
    try:
        print(text)
    except UnicodeEncodeError:
        enc = (sys.stdout.encoding or "ascii")
        print(text.encode(enc, errors="replace").decode(enc))


def _already_acknowledged() -> bool:
    return os.environ.get("ADREAPER_AUTHORIZED") == "1" or _STATE.exists()


def _record_ack() -> None:
    try:
        _STATE.parent.mkdir(parents=True, exist_ok=True)
        _STATE.write_text("acknowledged\n", encoding="utf-8")
    except Exception:
        pass  # non-fatal; we'll just ask again next time


def authorization_gate(assume_yes: bool = False) -> bool:
    """Return True if the operator is cleared to proceed.

    `assume_yes` (the --authorized flag or ADREAPER_AUTHORIZED=1) is the
    non-interactive path for lab automation and CI. Interactive runs are asked
    once and the acknowledgement is remembered.
    """
    if assume_yes or _already_acknowledged():
        return True

    log.warn(_NOTICE)
    if not sys.stdin.isatty():
        # Non-interactive and not pre-authorized: refuse rather than guess.
        log.error(
            "Non-interactive session without authorization. Re-run with "
            "--authorized or set ADREAPER_AUTHORIZED=1 to confirm you have permission."
        )
        return False
    try:
        answer = input("[?] Do you have written authorization to test these targets? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if answer.strip().lower() in ("y", "yes"):
        _record_ack()
        return True
    log.error("Authorization not confirmed — aborting.")
    return False
