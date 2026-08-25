# Disclaimer & Responsible Use

ADreaper is provided for **lawful, authorized security testing and education only**.

## You must have authorization

Before you point ADreaper at any host, domain, or network, you must have
**explicit, written permission** from the owner of that infrastructure — for
example a signed penetration-testing scope-of-work, a bug-bounty program that
covers the target, a lab you own, or a CTF you are entered in.

Unauthorized access to computer systems is a crime in most countries,
including but not limited to:

- **United States** — Computer Fraud and Abuse Act (18 U.S.C. § 1030)
- **United Kingdom** — Computer Misuse Act 1990
- **European Union** — Directive 2013/40/EU on attacks against information systems
- **Republic of Korea** — 정보통신망 이용촉진 및 정보보호 등에 관한 법률 (정보통신망법)

## No warranty, no liability

The software is provided "as is", without warranty of any kind. The authors and
contributors are **not responsible** for any damage, data loss, service
disruption, or legal consequence arising from the use or misuse of this tool.
**You** are solely responsible for your actions.

## Design choices that reflect this

- ADreaper prints an authorization banner and records acknowledgement on first run.
- Credential-testing modules default to **lockout-aware, low-and-slow** behavior.
- No module performs destructive actions (account deletion, data wiping,
  ransomware-style behavior) — by design and by policy.
- ADreaper is an assessment tool, not malware: it contains no self-propagation,
  no C2 implants, and no anti-forensics/log-clearing features.

If your intended use does not fit the above, **do not use this software.**
