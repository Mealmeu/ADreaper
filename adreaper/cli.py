"""ADreaper command-line interface.

Subcommands:
    list                     list available modules
    info   <module>          show a module's options and metadata
    run    <module> [-o k=v] run a module against the engagement
    console                  interactive Metasploit-style console
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from adreaper import __version__
from adreaper.core import loader
from adreaper.core.banner import authorization_gate, print_banner
from adreaper.core.context import Credential, EngagementContext
from adreaper.core.logging import log
from adreaper.core.module import BaseModule
from adreaper.core.report import Report

# importable-name -> pip hint, for friendly "please install" messages
_PIP_HINT = {"dns": "dnspython", "ldap3": "ldap3", "impacket": "impacket"}


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

def _engagement_parser() -> argparse.ArgumentParser:
    """Shared engagement/credential args, reused by every command that needs them."""
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("engagement")
    g.add_argument("-d", "--domain", default="", help="target AD domain (e.g. corp.local)")
    g.add_argument("--dc-ip", default="", help="domain controller IP")
    g.add_argument("--target", default="", help="target host (IP or name)")
    c = p.add_argument_group("credentials")
    c.add_argument("-u", "--username", default="", help="username")
    c.add_argument("-p", "--password", default="", help="password")
    c.add_argument("-H", "--hash", dest="nt_hash", default="", help="NT or LM:NT hash (pass-the-hash)")
    c.add_argument("--aes", default="", help="Kerberos AES key")
    c.add_argument("-k", "--kerberos", action="store_true", help="use Kerberos authentication")
    o = p.add_argument_group("options")
    o.add_argument("--timeout", type=int, default=10, help="network timeout (s)")
    o.add_argument("--threads", type=int, default=10, help="worker threads")
    o.add_argument("--output", default="adreaper_loot", help="loot/output directory")
    o.add_argument("--authorized", action="store_true",
                   help="confirm you are authorized to test (skips the prompt)")
    o.add_argument("-v", "--verbose", action="store_true")
    o.add_argument("-q", "--quiet", action="store_true")
    return p


def build_parser() -> argparse.ArgumentParser:
    eng = _engagement_parser()
    parser = argparse.ArgumentParser(
        prog="adreaper",
        description="ADreaper — modular Active Directory penetration framework (authorized use only).",
    )
    parser.add_argument("--version", action="version", version=f"ADreaper {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", parents=[eng], help="list available modules")

    p_info = sub.add_parser("info", parents=[eng], help="show module details")
    p_info.add_argument("module", help="module name, e.g. recon/ldap_enum")

    p_run = sub.add_parser("run", parents=[eng], help="run a module")
    p_run.add_argument("module", help="module name, e.g. recon/ldap_enum")
    p_run.add_argument("-o", "--option", action="append", default=[], metavar="KEY=VALUE",
                       help="module-specific option (repeatable)")

    sub.add_parser("console", parents=[eng], help="interactive console")
    return parser


def build_context(args: argparse.Namespace) -> EngagementContext:
    log.verbose = getattr(args, "verbose", False)
    log.quiet = getattr(args, "quiet", False)
    cred = Credential(
        username=args.username, password=args.password, domain=args.domain,
        nt_hash=args.nt_hash, aes_key=args.aes, use_kerberos=args.kerberos,
    )
    ctx = EngagementContext(
        domain=args.domain, dc_ip=args.dc_ip, credential=cred,
        output_dir=Path(args.output), timeout=args.timeout, threads=args.threads,
    )
    if args.target:
        ctx.add_target(args.target)
    return ctx


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_list(args) -> int:
    cats = loader.categories()
    if not cats:
        log.warn("no modules found")
        return 1
    from adreaper.core.logging import console
    con = console()
    total = 0
    for cat, mods in cats.items():
        if con:
            con.print(f"\n[bold underline]{cat}[/]")
        else:
            print(f"\n{cat}")
        for m in mods:
            total += 1
            line = f"  {m.name:<24} {m.description}"
            con.print(line) if con else print(line)
    print(f"\n{total} module(s). Run `adreaper info <name>` for details.")
    return 0


def cmd_info(args) -> int:
    cls = loader.get(args.module)
    if cls is None:
        log.error("unknown module: %s", args.module)
        return 1
    print(f"\n  Module: {cls.name}")
    print(f"  {cls.description}\n")
    print(f"  Category : {cls.category}")
    print(f"  Author   : {cls.author}")
    if cls.requires:
        print(f"  Requires : {', '.join(cls.requires)}")
    if cls.references:
        print("  References:")
        for r in cls.references:
            print(f"    - {r}")
    print("\n  Options:")
    if not cls.options:
        print("    (none)")
    else:
        print(f"    {'NAME':<14}{'REQ':<5}{'DEFAULT':<12}DESCRIPTION")
        for o in cls.options:
            req = "yes" if o.required else "no"
            dflt = "" if o.default is None else str(o.default)
            print(f"    {o.name:<14}{req:<5}{dflt:<12}{o.description}")
    print()
    return 0


def _instantiate(args) -> Optional[BaseModule]:
    cls = loader.get(args.module)
    if cls is None:
        log.error("unknown module: %s", args.module)
        return None
    mod = cls()
    # Fold engagement globals into module options where the names match.
    mod.set_options({"target": args.target, "domain": args.domain, "dc_ip": args.dc_ip})
    for pair in getattr(args, "option", []) or []:
        if "=" not in pair:
            log.error("bad -o value (need KEY=VALUE): %s", pair)
            return None
        k, v = pair.split("=", 1)
        try:
            mod.set_option(k.strip(), v.strip())
        except KeyError:
            log.error("module %s has no option %r", mod.name, k.strip())
            return None
        except ValueError as e:
            log.error("bad value for %s: %s", k, e)
            return None
    return mod


def _check_and_run(mod: BaseModule, ctx: EngagementContext, report: Report) -> bool:
    problems = mod.validate()
    if problems:
        for p in problems:
            log.error(p)
        return False
    missing = mod.missing_requirements()
    if missing:
        hints = ", ".join(_PIP_HINT.get(m, m) for m in missing)
        log.error("module needs: %s  ->  pip install %s", ", ".join(missing), hints)
        return False
    log.info("running %s ...", mod.name)
    try:
        result = mod.run(ctx)
    except KeyboardInterrupt:
        log.warn("interrupted")
        return False
    except Exception as e:
        log.error("%s crashed: %s", mod.name, e)
        if log.verbose:
            import traceback
            traceback.print_exc()
        return False
    report.add(result)
    if result.success:
        log.ok("%s done in %.1fs — %d finding(s)", mod.name, result.duration, len(result.findings))
    else:
        log.error("%s failed: %s", mod.name, result.error)
    return result.success


def cmd_run(args) -> int:
    ctx = build_context(args)
    if not authorization_gate(args.authorized):
        return 2
    mod = _instantiate(args)
    if mod is None:
        return 1
    report = Report()
    _check_and_run(mod, ctx, report)
    paths = report.write(ctx)
    _print_summary(ctx, paths)
    return 0


def _print_summary(ctx: EngagementContext, paths: dict) -> None:
    counts = ctx.graph.counts()
    if len(ctx.graph):
        summary = " | ".join(f"{k}={v}" for k, v in counts.items())
        log.ok("graph: %s", summary)
    for label, path in paths.items():
        log.ok("%s -> %s", label, path)


# ---------------------------------------------------------------------------
# interactive console
# ---------------------------------------------------------------------------

def cmd_console(args) -> int:
    ctx = build_context(args)
    if not authorization_gate(args.authorized):
        return 2
    from adreaper.core.console import Console
    Console(ctx).loop()
    return 0


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _make_output_safe() -> None:
    """Never crash on a console that can't encode a glyph (e.g. Windows cp949)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def main(argv: Optional[list[str]] = None) -> int:
    _make_output_safe()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    if args.command != "console":
        print_banner()

    dispatch = {
        "list": cmd_list,
        "info": cmd_info,
        "run": cmd_run,
        "console": cmd_console,
    }
    try:
        return dispatch[args.command](args)
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
