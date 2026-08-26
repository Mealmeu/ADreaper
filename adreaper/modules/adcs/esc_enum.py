"""AD CS enumeration and ESC vulnerability detection (Certipy-style).

Enumerates certificate templates and enrollment services (CAs) from the
Configuration partition over LDAP and flags the classic escalation paths that
are determinable from directory data:

- ESC1  requester supplies the SAN + client-auth EKU + low-priv enrollment
        (no manager approval / co-sign) -> impersonate any principal
- ESC2  Any-Purpose (or no) EKU + low-priv enrollment
- ESC3  Certificate Request Agent EKU + low-priv enrollment
- ESC4  low-priv principals can *edit* the template ACL -> reshape into ESC1

ESC6 (CA EDITF_ATTRIBUTESUBJECTALTNAME2) and ESC8 (web-enrollment NTLM relay)
depend on CA registry/HTTP state that isn't in LDAP; the CAs are listed so an
operator can check those out of band.
"""

from __future__ import annotations

from typing import Optional

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity

# EKU OIDs that permit domain authentication with the issued certificate
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
PKINIT_CLIENT = "1.3.6.1.5.5.2.3.4"
ANY_PURPOSE = "2.5.29.37.0"
CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
_AUTH_EKUS = {CLIENT_AUTH, SMARTCARD_LOGON, PKINIT_CLIENT, ANY_PURPOSE}

# msPKI-Certificate-Name-Flag / msPKI-Enrollment-Flag bits
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002

# extended-right GUIDs granting enrollment
GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# broad/low-privilege trustees whose enroll/control rights make a template dangerous
LOW_PRIV_SIDS = {"S-1-5-11", "S-1-1-0", "S-1-5-32-545"}   # Auth Users, Everyone, Users
LOW_PRIV_RIDS = {513, 515, 514}                           # Domain Users/Computers/Guests

# access-mask bits (subset, mirrors recon/acl_enum)
RIGHT_GENERIC_ALL = 0x10000000
RIGHT_GENERIC_WRITE = 0x40000000
RIGHT_WRITE_DACL = 0x00040000
RIGHT_WRITE_OWNER = 0x00080000
RIGHT_WRITE_PROP = 0x00000020
RIGHT_CONTROL_ACCESS = 0x00000100
RIGHT_DS_FULL_CONTROL = 0x000F01FF
ACE_ALLOWED = 0x00
ACE_ALLOWED_OBJECT = 0x05


class AdcsEscEnum(BaseModule):
    name = "adcs/esc_enum"
    description = "Enumerate AD CS templates/CAs and flag ESC1-ESC4 misconfigurations."
    author = "Mealmeu"
    category = "adcs"
    requires = ["ldap3", "impacket"]
    references = [
        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        "https://attack.mitre.org/techniques/T1649/",
    ]
    options = [
        Option("target", "DC host/IP to bind (defaults to --dc-ip)", type=OptionType.STRING),
        Option("ssl", "Use LDAPS (port 636)", default=False, type=OptionType.BOOL),
        Option("port", "LDAP port (default 389, or 636 with ssl)", type=OptionType.INT),
    ]

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        target = self.opt("target") or ctx.primary_target()
        if not ctx.domain:
            return res.fail("no domain set (use --domain)").finish()
        if not target:
            return res.fail("no DC target (use --dc-ip or --target)").finish()

        from ldap3 import ALL, ANONYMOUS, NTLM, SUBTREE, Connection, Server  # type: ignore
        from ldap3.core.exceptions import LDAPException  # type: ignore
        from ldap3.protocol.microsoft import security_descriptor_control  # type: ignore

        use_ssl = bool(self.opt("ssl"))
        port = int(self.opt("port") or (636 if use_ssl else 389))
        cred = ctx.credential
        try:
            server = Server(target, port=port, use_ssl=use_ssl, get_info=ALL,
                            connect_timeout=ctx.timeout)
            if cred.is_empty:
                conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
            else:
                user = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
                conn = Connection(server, user=user,
                                  password=cred.normalized_hash() or cred.password,
                                  authentication=NTLM, auto_bind=True)
        except LDAPException as e:
            return res.fail(f"LDAP bind failed: {e}").finish()
        except Exception as e:
            return res.fail(f"LDAP connection error: {e}").finish()

        config_nc = _config_nc(server, ctx.domain)
        pki_base = f"CN=Public Key Services,CN=Services,{config_nc}"
        controls = security_descriptor_control(sdflags=0x04)  # DACL only

        # --- enrollment services (CAs) ---
        cas, published = self._enum_cas(conn, pki_base, ctx, res, SUBTREE)

        # --- certificate templates ---
        tmpl_base = f"CN=Certificate Templates,{pki_base}"
        count = self._enum_templates(conn, tmpl_base, ctx, res, SUBTREE, controls, published)

        try:
            conn.unbind()
        except Exception:
            pass
        log.ok("AD CS: %d CA(s), %d template(s) assessed", len(cas), count)
        res.data.update({"cas": cas, "templates_assessed": count})
        return res.finish()

    # -- CAs --------------------------------------------------------------

    def _enum_cas(self, conn, pki_base, ctx, res, scope):
        base = f"CN=Enrollment Services,{pki_base}"
        attrs = ["cn", "dNSHostName", "certificateTemplates"]
        cas, published = [], set()
        try:
            conn.search(base, "(objectClass=pKIEnrollmentService)", search_scope=scope,
                        attributes=attrs)
        except Exception as e:
            log.warn("CA enumeration failed: %s", e)
            return cas, published
        for entry in conn.response:
            if entry.get("type") != "searchResEntry":
                continue
            a = entry["attributes"]
            name = _first(a.get("cn"))
            host = _first(a.get("dNSHostName"))
            templ = _as_list(a.get("certificateTemplates"))
            published.update(t.lower() for t in templ)
            cas.append({"name": name, "host": host, "templates": templ})
            ctx.graph.add_node(f"CA:{name}".upper(), NodeType.CA, name,
                               {"host": host, "published_templates": templ})
            res.add_finding(
                f"Certificate Authority: {name} ({host})",
                Severity.INFO,
                description="Check ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) and ESC8 (web enrollment "
                            "NTLM relay) against this CA out of band (e.g. certipy).",
                target=host or name,
            )
        return cas, published

    # -- templates --------------------------------------------------------

    def _enum_templates(self, conn, base, ctx, res, scope, controls, published) -> int:
        attrs = ["cn", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                 "msPKI-RA-Signature", "pKIExtendedKeyUsage", "nTSecurityDescriptor"]
        try:
            conn.search(base, "(objectClass=pKICertificateTemplate)", search_scope=scope,
                        attributes=attrs, controls=controls)
        except Exception as e:
            log.warn("template enumeration failed: %s", e)
            return 0
        count = 0
        for entry in conn.response:
            if entry.get("type") != "searchResEntry":
                continue
            a = entry["attributes"]
            t = self._normalize_template(a, published)
            count += 1
            ctx.graph.add_node(f"TEMPLATE:{t['name']}".upper(), NodeType.CERT_TEMPLATE, t["name"],
                               {"enabled": t["enabled"], "ekus": t["ekus"]})
            for f in assess_template(t):
                res.add_finding(
                    f"AD CS {f['esc']}: template '{t['name']}' — {f['detail']}",
                    Severity(f["severity"]),
                    description=f["description"],
                    target=t["name"],
                    references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                )
        return count

    def _normalize_template(self, a: dict, published: set) -> dict:
        name = _first(a.get("cn")) or _first(a.get("displayName"))
        name_flag = _as_int(_first(a.get("msPKI-Certificate-Name-Flag")))
        enroll_flag = _as_int(_first(a.get("msPKI-Enrollment-Flag")))
        ra_sig = _as_int(_first(a.get("msPKI-RA-Signature")))
        ekus = _as_list(a.get("pKIExtendedKeyUsage"))
        client_auth, any_purpose, enroll_agent = derive_ekus(ekus)
        low_enroll, low_control, controllers = self._sd_rights(_raw(a.get("nTSecurityDescriptor")))
        return {
            "name": name,
            "enabled": name.lower() in published if name else False,
            "enrollee_supplies_subject": bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
            "manager_approval": bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS),
            "authorized_signatures": ra_sig,
            "ekus": ekus,
            "client_auth": client_auth,
            "any_purpose": any_purpose,
            "enrollment_agent": enroll_agent,
            "low_priv_enroll": low_enroll,
            "low_priv_control": low_control,
            "controllers": controllers,
        }

    def _sd_rights(self, sd_raw: bytes):
        """Return (low_priv_enroll, low_priv_control, controller_sids)."""
        if not sd_raw:
            return False, False, []
        from impacket.ldap import ldaptypes  # type: ignore
        from impacket.uuid import bin_to_string  # type: ignore

        low_enroll = low_control = False
        controllers = []
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw)
            dacl = sd["Dacl"]
            if not dacl:
                return False, False, []
            for ace in dacl["Data"]:
                if ace["AceType"] not in (ACE_ALLOWED, ACE_ALLOWED_OBJECT):
                    continue
                body = ace["Ace"]
                try:
                    mask = int(body["Mask"]["Mask"])
                    sid = body["Sid"].formatCanonical()
                except Exception:
                    continue
                if not _is_low_priv(sid):
                    continue
                guid = None
                if ace["AceType"] == ACE_ALLOWED_OBJECT and (body["Flags"] & 0x01):
                    try:
                        guid = bin_to_string(body["ObjectType"]).lower()
                    except Exception:
                        guid = None
                # enrollment right
                if (mask & RIGHT_GENERIC_ALL) or (
                    (mask & RIGHT_CONTROL_ACCESS) and guid in (GUID_ENROLL, GUID_AUTOENROLL, None)
                ):
                    low_enroll = True
                # write control -> ESC4
                if mask & (RIGHT_GENERIC_ALL | RIGHT_GENERIC_WRITE | RIGHT_WRITE_DACL | RIGHT_WRITE_OWNER):
                    low_control = True
                    controllers.append(sid)
                elif (mask & RIGHT_DS_FULL_CONTROL) == RIGHT_DS_FULL_CONTROL:
                    low_control = True
                    controllers.append(sid)
        except Exception as e:
            log.debug("template SD parse failed: %s", e)
        return low_enroll, low_control, controllers


# ---------------------------------------------------------------------------
# pure logic (unit-tested)
# ---------------------------------------------------------------------------

def derive_ekus(ekus: list[str]) -> tuple[bool, bool, bool]:
    """Return (client_auth, any_purpose, enrollment_agent) from an EKU list.

    An empty EKU list means the certificate is valid for any purpose.
    """
    eset = set(ekus)
    any_purpose = (ANY_PURPOSE in eset) or (len(ekus) == 0)
    client_auth = any_purpose or bool(eset & _AUTH_EKUS)
    enrollment_agent = CERT_REQUEST_AGENT in eset
    return client_auth, any_purpose, enrollment_agent


def assess_template(t: dict) -> list[dict]:
    """Return the ESC findings for one normalized template dict."""
    findings: list[dict] = []

    if t.get("low_priv_control"):
        findings.append({
            "esc": "ESC4", "severity": "HIGH",
            "detail": "low-privileged principals can edit the template",
            "description": "A low-privileged principal holds Write/Owner/GenericAll over the "
                           "template object and can reconfigure it (e.g. into ESC1).",
        })

    enrollable = (t.get("low_priv_enroll") and not t.get("manager_approval")
                  and int(t.get("authorized_signatures", 0)) == 0)
    if not enrollable:
        return findings

    if t.get("enrollee_supplies_subject") and t.get("client_auth"):
        findings.append({
            "esc": "ESC1", "severity": "CRITICAL",
            "detail": "requester supplies SAN + client-auth EKU + low-priv enrollment",
            "description": "Any enrollee can request a client-auth certificate for an arbitrary "
                           "principal (incl. Domain Admins) — full domain compromise.",
        })
    if t.get("any_purpose") or not t.get("ekus"):
        findings.append({
            "esc": "ESC2", "severity": "HIGH",
            "detail": "Any-Purpose (or no) EKU with low-priv enrollment",
            "description": "Issued certificates are valid for any purpose, including authentication.",
        })
    if t.get("enrollment_agent"):
        findings.append({
            "esc": "ESC3", "severity": "HIGH",
            "detail": "Certificate Request Agent EKU with low-priv enrollment",
            "description": "An enrollment-agent certificate lets the holder enroll on behalf of others.",
        })
    return findings


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _is_low_priv(sid: str) -> bool:
    if sid in LOW_PRIV_SIDS:
        return True
    try:
        return int(sid.rsplit("-", 1)[-1]) in LOW_PRIV_RIDS
    except (ValueError, AttributeError):
        return False


def _config_nc(server, domain: str) -> str:
    try:
        cnc = server.info.other.get("configurationNamingContext")
        if cnc:
            return cnc[0] if isinstance(cnc, (list, tuple)) else str(cnc)
    except Exception:
        pass
    dc = ",".join(f"DC={p}" for p in domain.split("."))
    return f"CN=Configuration,{dc}"


def _first(v, default=""):
    if isinstance(v, (list, tuple)):
        return v[0] if v else default
    return v if v is not None else default


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


def _as_int(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _raw(v) -> bytes:
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return b""
