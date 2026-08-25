# ADreaper — Architecture & Conventions

Reference for contributors working in this repository.

## What This Is

**ADreaper** — a modular Active Directory penetration-testing framework written
in Python. It unifies AD reconnaissance, a BloodHound-style attack graph, a
Metasploit-style module engine, and reporting into one tool for **authorized**
security assessments. Open source (MIT).

This is an offensive-security *assessment* tool, not malware. See
[DISCLAIMER.md](../DISCLAIMER.md) — the authorized-use posture is a hard design
constraint, not a footnote.

## Layout

```
adreaper/
  cli.py            argparse CLI: list / info / run / console
  __main__.py       python -m adreaper
  core/
    module.py       BaseModule ABC, Option, ModuleResult, Finding, Severity
    context.py      EngagementContext, Credential, Target
    graph.py        ADGraph — nodes/edges, path search, JSON persistence
    loader.py       auto-discovery of modules under adreaper/modules/
    report.py       Markdown + JSON + graph.json reporting
    logging.py      leveled logger (rich-or-plain), `log.info/ok/warn/error`
    banner.py       banner + authorized-use gate
    console.py      interactive Metasploit-style REPL
  modules/
    recon/          dns_enum, smb_enum, ldap_enum, acl_enum
    kerberos/       asreproast, kerberoast
    analysis/       pathfinder
    credentials/    password_spray
tests/              offline unit tests (pytest)
docs/               WRITING_MODULES.md, ARCHITECTURE.md
```

## Run / test

```bash
pip install -e ".[ad,dev]"     # or: pip install -r requirements.txt
python -m adreaper list
python -m pytest -q
ruff check .
```

## Conventions

- **Python, framework core has no heavy deps.** Core imports only `rich`. AD
  protocol libs (`impacket`, `ldap3`, `dnspython`) are **optional** and must be
  imported lazily *inside* `run()`, never at module top — the loader imports
  every module file at startup and must not fail on a box missing them. Declare
  them in the module's `requires` list instead.
- **One module = one file** under `adreaper/modules/<category>/`, subclassing
  `BaseModule`. No registration needed; the loader finds it by class. Module
  `name` is `"<category>/<slug>"` and must be unique.
- **Typed options** via the `Option` dataclass; never parse raw argv in a module.
- **Findings, not prints.** Emit results with `res.add_finding(title, Severity, ...)`.
  Pick honest severities and cite MITRE ATT&CK / references where relevant.
- **Fail soft.** Expected failures return `res.fail(msg).finish()`; don't raise.
- **Everything flows through `ctx`.** Read creds/targets from `EngagementContext`;
  push discovered objects into `ctx.graph` (upsert by objectSid) so modules
  compose and the report/graph stay unified.
- **Logging** via `from adreaper.core.logging import log` → `log.info/ok/warn/error`.
  Keep console output ASCII-safe (Windows consoles may be cp949); put localized
  text in UTF-8 files, not in banners/prompts.

## Hard rules (safety)

- **No destructive or malicious capabilities.** No account/data deletion, no
  ransomware behavior, no self-propagation, no C2 implants, no anti-forensics /
  log-clearing, no built-in mass-targeting. ADreaper assesses; it does not wreck.
- **Credential-submitting modules are lockout-aware** and default to
  low-and-slow. Honor the domain `lockoutThreshold` read during recon.
- **Keep the authorized-use gate intact.** `authorization_gate()` runs before any
  `run`/`console`. Don't remove it or default it to "yes".

## Roadmap (see README)

Session/local-admin edges → BloodHound-compatible export → AD CS module set →
Kerberos ticket operations (PtT/S4U). Each lands as new files under
`adreaper/modules/` following the module contract in
[WRITING_MODULES.md](WRITING_MODULES.md).
