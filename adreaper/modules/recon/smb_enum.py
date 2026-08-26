"""SMB reconnaissance — host fingerprint, signing posture, and share listing.

Talks SMB to a target host (null session or supplied credentials), reads the
server's identity and security posture, and enumerates accessible shares. SMB
signing state is a classic finding: DCs require it, but member servers often do
not, enabling NTLM relay.
"""

from __future__ import annotations

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity


class SmbEnum(BaseModule):
    name = "recon/smb_enum"
    description = "Fingerprint a host over SMB, check signing, and list shares."
    author = "Mealmeu"
    category = "recon"
    requires = ["impacket"]
    references = ["https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2/"]
    options = [
        Option("target", "Host (IP or name) to enumerate; defaults to engagement target",
               type=OptionType.STRING),
        Option("port", "SMB port", default=445, type=OptionType.INT),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = self.opt("target") or ctx.primary_target()
        if not target:
            return res.fail("no target set (use --target or --dc-ip)").finish()

        from impacket.smbconnection import SMBConnection  # type: ignore

        cred = ctx.credential
        port = int(self.opt("port", 445))
        log.info("connecting to SMB %s:%d", target, port)

        try:
            conn = SMBConnection(target, target, sess_port=port, timeout=ctx.timeout)
        except Exception as e:
            return res.fail(f"SMB connect failed: {e}").finish()

        # Host fingerprint is available pre-auth.
        server_os = _safe(conn.getServerOS)
        server_name = _safe(conn.getServerName)
        server_domain = _safe(conn.getServerDomain)
        signing = _bool(conn.isSigningRequired)

        log.ok("%s | %s | domain=%s | signing=%s",
               server_name or target, server_os or "?", server_domain or "?", signing)

        comp_id = (server_name or target).upper()
        ctx.graph.add_node(comp_id, NodeType.COMPUTER, server_name or target, {
            "ip": target, "os": server_os, "smb_signing": signing, "netbios_domain": server_domain,
        })
        t = ctx.add_target(target, hostname=server_name)
        t.os = server_os or t.os

        res.data["fingerprint"] = {
            "name": server_name, "os": server_os, "domain": server_domain, "signing_required": signing,
        }
        res.add_finding(
            f"SMB host fingerprinted: {server_name or target}",
            Severity.INFO,
            description=f"OS: {server_os or 'unknown'} · NetBIOS domain: {server_domain or 'unknown'}",
            target=target,
        )

        if signing is False:
            res.add_finding(
                "SMB signing not required",
                Severity.MEDIUM,
                description=(
                    "The host does not require SMB signing, which permits NTLM relay "
                    "attacks against it. Enforce SMB signing on all hosts."
                ),
                target=target,
                references=["https://attack.mitre.org/techniques/T1557/001/"],
            )

        # Authentication (null session or provided creds).
        auth_ok, auth_desc = self._authenticate(conn, cred)
        if not auth_ok:
            res.add_finding(
                "SMB authentication failed",
                Severity.INFO,
                description=auth_desc,
                target=target,
            )
            res.data["authenticated"] = False
            return res.finish()

        res.data["authenticated"] = True
        if cred.is_empty:
            res.add_finding(
                "Null session permitted",
                Severity.MEDIUM,
                description="The host accepts unauthenticated (null) SMB sessions.",
                target=target,
                references=["https://attack.mitre.org/techniques/T1135/"],
            )

        # Share enumeration.
        try:
            shares = conn.listShares()
        except Exception as e:
            log.warn("could not list shares: %s", e)
            shares = []

        share_names = []
        for s in shares:
            sn = s["shi1_netname"][:-1] if s["shi1_netname"].endswith("\x00") else s["shi1_netname"]
            share_names.append(sn)
        if share_names:
            log.ok("shares: %s", ", ".join(share_names))
            res.data["shares"] = share_names
            interesting = [s for s in share_names if s.upper() not in ("IPC$", "PRINT$")]
            res.add_finding(
                f"{len(share_names)} SMB share(s) enumerated",
                Severity.LOW if interesting else Severity.INFO,
                description="Accessible shares: " + ", ".join(share_names),
                evidence="\n".join(share_names),
                target=target,
            )

        try:
            conn.close()
        except Exception:
            pass
        return res.finish()

    def _authenticate(self, conn, cred) -> tuple[bool, str]:
        lm = nt = ""
        norm = cred.normalized_hash()
        if norm:
            lm, nt = norm.split(":", 1)
        try:
            conn.login(
                cred.username, cred.password, cred.domain, lmhash=lm, nthash=nt,
            )
            return True, "authenticated"
        except Exception as e:
            return False, f"login failed: {e}"


def _safe(fn):
    try:
        return fn()
    except Exception:
        return ""


def _bool(fn):
    try:
        return bool(fn())
    except Exception:
        return None
