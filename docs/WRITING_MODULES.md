# Writing an ADreaper module

A module is a single Python file under `adreaper/modules/<category>/` containing
a subclass of `BaseModule`. The loader discovers it automatically — no
registration, no imports to edit.

## Minimal module

```python
from adreaper.core.context import EngagementContext
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity


class MyModule(BaseModule):
    name = "recon/my_module"          # unique, used by `use` / `run`
    description = "One line describing what it does."
    author = "you"
    category = "recon"                # groups it under `list`
    requires = ["ldap3"]              # importable deps checked before run()
    references = ["https://attack.mitre.org/techniques/Txxxx/"]
    options = [
        Option("target", "host to hit", required=True),
        Option("port", "tcp port", default=389, type=OptionType.INT),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = self.opt("target")
        # ... do the work ...
        res.add_finding(
            "Something noteworthy",
            Severity.MEDIUM,
            description="why it matters",
            target=target,
            references=["https://..."],
        )
        return res.finish()
```

## Rules & conventions

1. **Lazy-import heavy/optional deps inside `run()`**, not at module top. The
   loader imports every module file at startup; a top-level `import impacket`
   would break discovery on a box without it. List the dep in `requires` and
   `import` it in `run()`.
2. **Read from and write to `ctx`.** Credentials live on `ctx.credential`, the
   DC on `ctx.dc_ip`, discovered hosts on `ctx.targets`. Push everything you
   learn into `ctx.graph` so other modules and the report can use it.
3. **Return findings, don't print them.** Use `res.add_finding(...)` with an
   honest `Severity`. The reporting engine renders and ranks them.
4. **Fail gracefully.** Return `res.fail("reason").finish()` on error — never
   raise out of `run()` for expected failures (unreachable host, bad creds).
5. **No destructive behavior.** ADreaper modules assess; they do not delete
   accounts, wipe data, deploy implants, or clear logs. PRs that do are rejected.
6. **Lockout awareness.** Any module that submits credentials must respect the
   domain lockout policy and default to low-and-slow.

## Feeding the graph

```python
from adreaper.core.graph import NodeType, EdgeType

uid = ctx.graph.add_node("S-1-5-21-...-1105", NodeType.USER, "alice",
                         {"enabled": True}).id
gid = ctx.graph.add_node("S-1-5-21-...-512", NodeType.GROUP, "Domain Admins",
                         {"high_value": True}).id
ctx.graph.add_edge(uid, gid, EdgeType.MEMBER_OF)
```

`add_node` upserts by id (use the objectSid when you have it), so multiple
modules can enrich the same node.

## Keep the decision logic testable (the ADreaper pattern)

Network I/O can't run in CI, but the *interesting* part of a module — how it
decides a template is ESC1, which principals can read LAPS, how a gPLink parses —
can and should. Every module keeps that logic in **pure module-level functions**
that take plain data and return plain data, and lets `run()` be a thin shell that
only does the LDAP/SMB call and hands the raw structures to those functions:

```python
def assess_template(t: dict) -> list[dict]:      # pure: dict in, findings out
    ...

class EscEnum(BaseModule):
    def run(self, ctx):
        res = self.result()
        for tmpl in self._read_templates(ctx):   # the only part that needs the network
            for f in assess_template(tmpl):       # pure, unit-tested
                res.add_finding(f["title"], Severity(f["severity"]), ...)
        return res.finish()
```

The unit tests then call `assess_template({...})` directly — no domain required.
See `assess_template` / `assess_ca` (adcs), `can_read_laps` (laps_enum),
`parse_gplink` (gpo_enum), `assess_trust` (trust_enum), `decrypt_cpassword`
(gpp_decrypt) and their tests for the shape to copy.

## Cite MITRE ATT&CK

Put the relevant `https://attack.mitre.org/techniques/T....` URLs in a finding's
`references`. The report parses them into a coverage matrix (tactic / technique /
count), so honest references make the whole engagement report richer for free.

## Testing

Put unit tests under `tests/`, one file per module (`test_<module>.py`). Keep them
**offline** — exercise the pure functions above; never touch a live network. Add a
`test_module_discovered` assertion so a typo in `name` fails loudly:

```python
def test_module_discovered():
    assert "recon/my_module" in loader.discover(force=True)
```

Run the suite (CI runs exactly this on Python 3.10–3.12):

```bash
python -m pytest -q
```
