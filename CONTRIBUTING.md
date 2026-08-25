# Contributing to ADreaper

Thanks for wanting to make ADreaper better. This is an **authorized-use**
security-assessment tool; contributions must keep it that way.

## Ground rules

- **Assessment, not destruction.** We accept enumeration, analysis, credential
  and Kerberos testing, attack-path reasoning, and reporting. We reject anything
  destructive or malicious: account/data deletion, ransomware behavior,
  self-propagation, C2 implants, anti-forensics / log-clearing, or built-in
  mass-targeting. See [DISCLAIMER.md](DISCLAIMER.md) and
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **Lockout-safe credential modules.** Anything that submits credentials must be
  lockout-aware and default to low-and-slow.
- **Keep the authorized-use gate intact.**

## Development setup

```bash
git clone https://github.com/<you>/ADreaper.git
cd ADreaper
pip install -e ".[ad,dev]"
python -m pytest -q
ruff check .
```

## Adding a module

One module = one file under `adreaper/modules/<category>/`, subclassing
`BaseModule`. The loader auto-discovers it — no registration. Read
[docs/WRITING_MODULES.md](docs/WRITING_MODULES.md) for the contract. In short:

- Declare typed `options`; never parse argv yourself.
- Lazy-import heavy deps (`impacket`, `ldap3`, `dnspython`) **inside `run()`**,
  and list them in `requires`.
- Emit `res.add_finding(...)` with honest `Severity` and MITRE ATT&CK refs.
- Push discovered objects into `ctx.graph` (upsert by objectSid).
- Fail soft: `res.fail(msg).finish()`, don't raise on expected errors.

## Tests

Keep tests **offline** (no live network / DC). Factor pure logic (hash
formatting, path rendering, safety planning) out of the network code and test
that — see `tests/test_kerberos_hashes.py` and `tests/test_spray.py` for the
pattern. Run `python -m pytest -q` before opening a PR.

## Pull requests

- Small, focused PRs. One capability per PR where possible.
- Describe the technique, cite references, and note authorized-use implications.
- CI (pytest + ruff, Python 3.9–3.13) must pass.
