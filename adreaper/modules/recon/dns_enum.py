"""DNS reconnaissance — locate domain controllers via AD service (SRV) records.

Active Directory publishes its infrastructure in DNS. Querying the well-known
`_ldap._tcp.dc._msdcs.<domain>` and related SRV records reveals every domain
controller and global-catalog server without any credentials — the natural
first step of an assessment.
"""

from __future__ import annotations

from adreaper.core.context import EngagementContext
from adreaper.core.graph import NodeType
from adreaper.core.logging import log
from adreaper.core.module import BaseModule, ModuleResult, Option, OptionType, Severity


class DnsEnum(BaseModule):
    name = "recon/dns_enum"
    description = "Locate domain controllers and services via AD DNS SRV records."
    author = "ADreaper Contributors"
    category = "recon"
    requires = ["dns"]  # dnspython
    references = ["https://learn.microsoft.com/windows-server/identity/ad-ds/"]
    options = [
        Option("nameserver", "DNS server to query (default: system resolver / dc-ip)",
               type=OptionType.STRING),
        Option("timeout", "Per-query timeout in seconds", default=5, type=OptionType.INT),
    ]

    # SRV record prefixes -> what they represent
    _SRV = {
        "_ldap._tcp.dc._msdcs.{d}": "Domain Controller (LDAP)",
        "_kerberos._tcp.dc._msdcs.{d}": "Domain Controller (Kerberos)",
        "_gc._tcp.{d}": "Global Catalog",
        "_ldap._tcp.pdc._msdcs.{d}": "PDC Emulator",
        "_kpasswd._tcp.{d}": "Kerberos password change",
    }

    def run(self, ctx: EngagementContext) -> ModuleResult:
        res = self.result()
        domain = ctx.domain
        if not domain:
            return res.fail("no domain set (use --domain)").finish()

        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        ns = self.opt("nameserver") or ctx.dc_ip
        if ns:
            resolver.nameservers = [ns]
        resolver.lifetime = float(self.opt("timeout", 5))
        resolver.timeout = float(self.opt("timeout", 5))

        log.info("querying AD DNS records for %s via %s", domain, ns or "system resolver")

        dc_hosts: dict[str, set[str]] = {}
        for tmpl, label in self._SRV.items():
            qname = tmpl.format(d=domain)
            try:
                answers = resolver.resolve(qname, "SRV")
            except Exception as e:
                log.debug("no SRV for %s (%s)", qname, e)
                continue
            for rdata in answers:
                target = str(rdata.target).rstrip(".")
                port = rdata.port
                dc_hosts.setdefault(target, set()).add(f"{label}:{port}")
                log.ok("%s -> %s:%d", label, target, port)

        if not dc_hosts:
            res.add_finding(
                "No AD DNS SRV records resolved",
                Severity.INFO,
                description=(
                    f"No _msdcs SRV records for {domain} were resolvable from the chosen "
                    "resolver. The domain may be internal-only; try --nameserver <dc-ip>."
                ),
                target=domain,
            )
            return res.finish()

        # Add the domain and each DC to the graph, and resolve A records.
        domain_id = domain.upper()
        ctx.graph.add_node(domain_id, NodeType.DOMAIN, domain, {"source": "dns_enum"})

        for host, roles in sorted(dc_hosts.items()):
            ips = self._resolve_a(resolver, host)
            ctx.graph.add_node(
                host.upper(), NodeType.COMPUTER, host,
                {"is_dc": True, "roles": sorted(roles), "ip": sorted(ips)},
            )
            ctx.add_target(ips[0] if ips else host, hostname=host, is_dc=True)
            res.add_finding(
                f"Domain controller discovered: {host}",
                Severity.INFO,
                description="Exposed via AD DNS SRV records.",
                evidence=f"roles: {', '.join(sorted(roles))}\nips: {', '.join(sorted(ips)) or 'n/a'}",
                target=host,
            )

        res.data["domain_controllers"] = {h: sorted(r) for h, r in dc_hosts.items()}
        log.ok("found %d domain controller host(s)", len(dc_hosts))
        return res.finish()

    @staticmethod
    def _resolve_a(resolver, host: str) -> list[str]:
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                for r in resolver.resolve(host, rtype):
                    ips.append(str(r))
            except Exception:
                continue
        return ips
