<h1 align="center">☠️ ADreaper</h1>

<p align="center">
  <b>A modern, modular Active Directory penetration-testing framework.</b><br>
  Enumeration · Attack-path graphing · Reporting — unified in one tool.
</p>

<p align="center">
  <img alt="python" src="https://img.shields.io/badge/python-3.9%2B-blue">
  <img alt="platform" src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="status" src="https://img.shields.io/badge/status-alpha-orange">
</p>

---

> ## ⚠️ LEGAL / AUTHORIZED USE ONLY
>
> **ADreaper is a security-assessment tool built for authorized penetration testing,
> red-team engagements, security research, CTF competitions, and defensive
> validation of your own or explicitly permitted Active Directory environments.**
>
> Running these techniques against systems you do not own or lack **written
> authorization** to test is illegal in most jurisdictions (e.g. the U.S. CFAA,
> the UK Computer Misuse Act, Korea's 정보통신망법). The authors accept **no
> liability** for misuse. By using this software you confirm you have permission
> to test the targets you point it at. See [DISCLAIMER.md](DISCLAIMER.md).

---

## Why ADreaper?

Metasploit is a fantastic *general* exploitation framework, but Active Directory
assessment today means juggling a dozen separate tools — `nmap`, `impacket`,
`ldapdomaindump`, `BloodHound`/`SharpHound`, `NetExec`, `Certipy`, `Rubeus`.
Each speaks its own format; correlating their output is manual work.

**ADreaper unifies the AD kill-chain into one framework:**

| Pillar | What it does |
|--------|--------------|
| 🔎 **Enumeration** | LDAP / SMB / DNS collectors that require no exploit to run |
| 🕸️ **Attack graph** | Every module feeds one central BloodHound-style graph (nodes + edges) |
| 🧩 **Module engine** | Metasploit-style `list` / `info` / `run`, typed options, auto-discovery |
| 📄 **Reporting** | Findings + graph exported to Markdown / JSON out of the box |
| 🛡️ **Safety rails** | Authorized-use gate, lockout-aware defaults, no destructive defaults |

## Install

```bash
git clone https://github.com/<you>/ADreaper.git
cd ADreaper
pip install -e .
```

Or without installing:

```bash
pip install -r requirements.txt
python -m adreaper --help
```

## Quick start

```bash
# Discover domain controllers for a domain (no credentials needed)
adreaper run recon/dns_enum --domain corp.local

# Enumerate SMB on a host (null session or credentials)
adreaper run recon/smb_enum --target 10.0.0.10 -u alice -p 'Passw0rd!' -d corp.local

# Full LDAP enumeration -> feeds the attack graph
adreaper run recon/ldap_enum --dc-ip 10.0.0.10 -d corp.local -u alice -p 'Passw0rd!'

# Enrich the graph with ACL / delegation / RBCD / DCSync control edges
adreaper run recon/acl_enum --dc-ip 10.0.0.10 -d corp.local -u alice -p 'Passw0rd!'

# AS-REP roast accounts recon flagged (no creds needed)
adreaper run kerberos/asreproast -d corp.local --dc-ip 10.0.0.10

# Kerberoast SPN accounts (needs valid creds)
adreaper run kerberos/kerberoast -d corp.local --dc-ip 10.0.0.10 -u alice -p 'Passw0rd!'

# Find privilege-escalation paths to Domain Admins in the collected graph
adreaper run analysis/pathfinder -d corp.local

# Lockout-safe password spray (reuses the threshold recon discovered)
adreaper run credentials/password_spray -d corp.local --dc-ip 10.0.0.10 -o password='Winter2026!'

# List / inspect modules
adreaper list
adreaper info recon/ldap_enum

# Interactive console (Metasploit-style)
adreaper console
```

Results and the collected graph land in `./adreaper_loot/<domain>/` as Markdown
and JSON, plus a SharpHound-style `<domain>_bloodhound.zip` you can upload
straight into the BloodHound GUI (`analysis/bloodhound_export`).

## Roadmap

- [x] Module engine + typed options + auto-discovery
- [x] Central AD attack graph
- [x] Recon: DNS / SMB / LDAP collectors
- [x] Markdown + JSON reporting
- [x] Kerberos toolkit — AS-REP roast, Kerberoast (ticket ops next)
- [x] Credential testing — lockout-safe spraying, pass-the-hash
- [x] Automated attack-path finder (Domain Admin path search)
- [x] ACL / delegation / RBCD / DCSync control edges (deeper attack paths)
- [x] Session collection (HasSession) and local-admin (AdminTo) edges
- [x] BloodHound-compatible graph export (SharpHound JSON + zip)
- [x] AD CS (Certipy-style) ESC1–ESC4 template + ESC7 CA-object auditing
- [x] Domain/forest trust enumeration (SID-filtering / RC4 risk, TRUSTS edges)
- [x] GPP cpassword credential recovery from SYSVOL (MS14-025)
- [ ] Kerberos ticket ops — S4U / RBCD abuse, ticket forging
- [ ] DCSync secret extraction (drsuapi) once a control edge is proven

## Contributing

Modules are self-contained subclasses of `adreaper.core.module.BaseModule`
dropped under `adreaper/modules/<category>/`. See [docs/WRITING_MODULES.md](docs/WRITING_MODULES.md).

## License

MIT — see [LICENSE](LICENSE).
