"""Interactive Metasploit-style console.

    adreaper > use recon/ldap_enum
    adreaper (recon/ldap_enum) > set dc-ip 10.0.0.10
    adreaper (recon/ldap_enum) > set username alice
    adreaper (recon/ldap_enum) > run

State (engagement context + collected report) persists across `run`s so recon
accumulates into one graph you can inspect with `graph` and dump with `report`.
"""

from __future__ import annotations

from typing import Optional

from adreaper.core import loader
from adreaper.core.context import EngagementContext
from adreaper.core.logging import log
from adreaper.core.module import BaseModule
from adreaper.core.report import Report

# engagement-level keys settable with `set`, mapped onto the context/credential
_GLOBAL_KEYS = {"domain", "dc-ip", "dc_ip", "target", "username", "password",
                "hash", "aes", "timeout", "threads"}

_HELP = """
commands:
  list [category]        list modules (optionally filtered by category)
  search <term>          find modules by name / description / category
  use <module>           select a module
  info [module]          show module details (current module if omitted)
  options                show current module options and engagement settings
  set <key> <value>      set a module option or engagement value (domain, dc-ip, ...)
  unset <key>            clear a module option
  run                    run the current module
  graph                  show attack-graph statistics
  report                 write report.md / results.json / graph.json to loot dir
  creds                  show current credentials
  back                   deselect the current module
  help                   this help
  exit / quit            leave
"""


def search_modules(modules, term: str) -> list:
    """Return module classes whose name / description / category contains `term`
    (case-insensitive), sorted by name. Pure — no I/O."""
    t = (term or "").lower().strip()
    if not t:
        return []
    hits = [m for m in modules
            if t in m.name.lower() or t in (m.description or "").lower()
            or t in (m.category or "").lower()]
    return sorted(hits, key=lambda m: m.name)


class Console:
    def __init__(self, ctx: EngagementContext) -> None:
        self.ctx = ctx
        self.module: Optional[BaseModule] = None
        self.report = Report()
        loader.discover()

    # -- prompt/loop ------------------------------------------------------

    def _prompt(self) -> str:
        if self.module:
            return f"adreaper ({self.module.name}) > "
        return "adreaper > "

    def loop(self) -> None:
        log.info("interactive console — type 'help', 'exit' to quit")
        while True:
            try:
                line = input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            if not self._dispatch(line):
                break

    # -- dispatch ---------------------------------------------------------

    def _dispatch(self, line: str) -> bool:
        parts = line.split()
        cmd, rest = parts[0].lower(), parts[1:]
        handler = {
            "help": self._help, "?": self._help,
            "list": self._list, "show": self._list,
            "search": self._search,
            "use": self._use, "info": self._info,
            "options": self._options, "set": self._set, "unset": self._unset,
            "run": self._run, "exploit": self._run,
            "graph": self._graph, "report": self._report, "creds": self._creds,
            "back": self._back,
        }.get(cmd)
        if cmd in ("exit", "quit"):
            return False
        if handler is None:
            log.error("unknown command: %s (try 'help')", cmd)
            return True
        try:
            handler(rest)
        except Exception as e:
            log.error("%s", e)
        return True

    # -- handlers ---------------------------------------------------------

    def _help(self, _rest) -> None:
        print(_HELP)

    def _list(self, rest) -> None:
        cats = loader.categories()
        filt = rest[0] if rest else None
        for cat, mods in cats.items():
            if filt and cat != filt:
                continue
            print(f"\n{cat}")
            for m in mods:
                print(f"  {m.name:<24} {m.description}")
        print()

    def _search(self, rest) -> None:
        if not rest:
            log.error("usage: search <term>")
            return
        term = " ".join(rest)
        hits = search_modules(loader.all_modules().values(), term)
        if not hits:
            log.info("no modules match %r", term)
            return
        print()
        for m in hits:
            print(f"  {m.name:<26} {m.description}")
        print()

    def _use(self, rest) -> None:
        if not rest:
            log.error("usage: use <module>")
            return
        cls = loader.get(rest[0])
        if cls is None:
            log.error("unknown module: %s", rest[0])
            return
        self.module = cls()
        # seed module options from current engagement globals
        self.module.set_options({
            "target": self.ctx.dc_ip or (self.ctx.targets[0].host if self.ctx.targets else ""),
            "domain": self.ctx.domain,
        })
        log.ok("using %s", cls.name)

    def _info(self, rest) -> None:
        name = rest[0] if rest else (self.module.name if self.module else None)
        if not name:
            log.error("no module selected")
            return
        cls = loader.get(name)
        if cls is None:
            log.error("unknown module: %s", name)
            return
        print(f"\n  {cls.name} — {cls.description}")
        print(f"  category: {cls.category} · author: {cls.author}")
        if cls.requires:
            print(f"  requires: {', '.join(cls.requires)}")
        print("  options:")
        for o in cls.options:
            req = "*" if o.required else " "
            print(f"   {req} {o.name:<14} {o.description} (default: {o.default})")
        print()

    def _options(self, _rest) -> None:
        print("\n  engagement:")
        print(f"    domain    = {self.ctx.domain}")
        print(f"    dc-ip     = {self.ctx.dc_ip}")
        print(f"    target    = {self.ctx.targets[0].host if self.ctx.targets else ''}")
        print(f"    identity  = {self.ctx.credential.display()}")
        if self.module:
            print(f"\n  module ({self.module.name}):")
            for o in self.module.options:
                print(f"    {o.name:<14} = {self.module.opt(o.name)}")
        print()

    def _set(self, rest) -> None:
        if len(rest) < 2:
            log.error("usage: set <key> <value>")
            return
        key, value = rest[0].lower(), " ".join(rest[1:])
        if key in _GLOBAL_KEYS:
            self._set_global(key, value)
            return
        if self.module:
            try:
                self.module.set_option(key, value)
                log.ok("%s => %s", key, self.module.opt(key))
                return
            except KeyError:
                pass
            except ValueError as e:
                log.error("%s", e)
                return
        log.error("unknown option: %s", key)

    def _set_global(self, key: str, value: str) -> None:
        cred = self.ctx.credential
        if key == "domain":
            self.ctx.domain = value
            cred.domain = value
        elif key in ("dc-ip", "dc_ip"):
            self.ctx.dc_ip = value
        elif key == "target":
            self.ctx.targets.clear()
            self.ctx.add_target(value)
        elif key == "username":
            cred.username = value
        elif key == "password":
            cred.password = value
        elif key == "hash":
            cred.nt_hash = value
        elif key == "aes":
            cred.aes_key = value
        elif key == "timeout":
            self.ctx.timeout = int(value)
        elif key == "threads":
            self.ctx.threads = int(value)
        log.ok("%s => %s", key, value if key != "password" else "*" * len(value))

    def _unset(self, rest) -> None:
        if not (self.module and rest):
            log.error("usage: unset <key> (module selected)")
            return
        try:
            self.module.set_option(rest[0], None)
            log.ok("unset %s", rest[0])
        except KeyError:
            log.error("unknown option: %s", rest[0])

    def _run(self, _rest) -> None:
        if not self.module:
            log.error("no module selected (use <module>)")
            return
        problems = self.module.validate()
        if problems:
            for p in problems:
                log.error(p)
            return
        missing = self.module.missing_requirements()
        if missing:
            log.error("module needs: %s (pip install them)", ", ".join(missing))
            return
        log.info("running %s ...", self.module.name)
        try:
            result = self.module.run(self.ctx)
        except Exception as e:
            log.error("%s crashed: %s", self.module.name, e)
            return
        self.report.add(result)
        if result.success:
            log.ok("done in %.1fs — %d finding(s)", result.duration, len(result.findings))
        else:
            log.error("failed: %s", result.error)

    def _graph(self, _rest) -> None:
        counts = self.ctx.graph.counts()
        if not len(self.ctx.graph):
            log.info("graph is empty — run a recon module first")
            return
        print("\n  attack graph:")
        for k, v in counts.items():
            print(f"    {k:<12} {v}")
        print()

    def _report(self, _rest) -> None:
        paths = self.report.write(self.ctx)
        for label, path in paths.items():
            log.ok("%s -> %s", label, path)

    def _creds(self, _rest) -> None:
        print(f"  {self.ctx.credential.display()}")

    def _back(self, _rest) -> None:
        self.module = None
