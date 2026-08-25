# Changelog

All notable changes to ADreaper are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses SemVer.

## [Unreleased]

### Added
- **`recon/acl_enum`** — parses each object's `nTSecurityDescriptor` DACL plus
  delegation attributes and turns *control* relationships into graph edges:
  GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, ForceChangePassword,
  AddMember, AllExtendedRights, constrained delegation (AllowedToDelegate), RBCD
  (AddAllowedToAct), and DCSync. These feed `analysis/pathfinder` directly, so a
  low-priv principal with control over a privileged object shows up as a short
  path to Domain Admin. Flags dangerous ACLs over high-value objects as findings.
- New edge types: `AllExtendedRights`, `AddAllowedToAct`.
- **Kerberos toolkit**
  - `kerberos/asreproast` — AS-REP roasting for accounts without pre-auth;
    auto-targets accounts flagged by recon, writes crackable `$krb5asrep$` hashes.
  - `kerberos/kerberoast` — request TGS for SPN accounts; writes `$krb5tgs$`
    hashes (hashcat 13100 / JtR).
- **`analysis/pathfinder`** — shortest privilege-escalation paths from owned /
  chosen principals to high-value targets (Domain Admins & friends), rendered as
  readable chains and saved to `attack_paths.txt`.
- **`credentials/password_spray`** — lockout-aware, low-and-slow SMB spray;
  reuses the lockout threshold discovered during recon, aborts on lockout,
  supports pass-the-hash spray.
- Graph: high-value node detection, `owned` marking, and helpers used by the
  pathfinder and spray modules.
- Project: GitHub Actions CI (pytest + ruff, Python 3.9–3.13), `CONTRIBUTING.md`,
  `SECURITY.md`, `.gitattributes`.

## [0.1.0] - 2026-08-25

### Added
- Framework core: module engine (`BaseModule`, typed `Option`, `ModuleResult`,
  `Finding`, `Severity`), auto-discovery loader, `EngagementContext`,
  BloodHound-style `ADGraph` with BFS path search and JSON persistence,
  Markdown + JSON reporting, rich-or-plain logging, interactive console.
- Authorized-use gate + banner + `DISCLAIMER.md`.
- Recon modules: `recon/dns_enum`, `recon/smb_enum`, `recon/ldap_enum`
  (flags AS-REP roasting, Kerberoasting, unconstrained delegation, MAQ).
- Packaging (`pyproject.toml`), tests, `docs/WRITING_MODULES.md`.
