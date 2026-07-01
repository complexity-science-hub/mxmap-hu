"""Provider DNS fingerprint signatures and pattern matching."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .models import Provider


class ProviderSignature(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Provider
    mx_patterns: tuple[str, ...] = ()
    spf_includes: tuple[str, ...] = ()
    dkim_selectors: tuple[str, ...] = ()
    dkim_cname_patterns: tuple[str, ...] = ()
    autodiscover_patterns: tuple[str, ...] = ()
    cname_patterns: tuple[str, ...] = ()
    dmarc_patterns: tuple[str, ...] = ()
    smtp_banner_patterns: tuple[str, ...] = ()
    txt_verification_patterns: tuple[str, ...] = ()
    asns: tuple[int, ...] = ()


SIGNATURES: list[ProviderSignature] = [
    # US / global cloud
    ProviderSignature(
        provider=Provider.MS365,
        mx_patterns=(
            "mail.protection.outlook.com",
            "mail.protection.outlook.de",
            "mx.microsoft",
            "protection.outlook.com",
            "protection.outlook.de",
        ),
        spf_includes=(
            "spf.protection.outlook.com",
            "spf.protection.outlook.de",
        ),
        dkim_selectors=("selector1", "selector2"),
        dkim_cname_patterns=("onmicrosoft.com",),
        autodiscover_patterns=("autodiscover.outlook.com",),
        cname_patterns=(
            "mail.protection.outlook.com",
            "mail.protection.outlook.de",
            "mx.microsoft",
            "protection.outlook.com",
            "protection.outlook.de",
        ),
        dmarc_patterns=("rua.agari.com",),
        smtp_banner_patterns=(
            "microsoft esmtp mail service",
            "protection.outlook.com",
            "protection.outlook.de",
            "mx.microsoft",
        ),
        txt_verification_patterns=("ms=ms",),
        asns=(8075,),
    ),
    ProviderSignature(
        provider=Provider.GOOGLE,
        mx_patterns=(
            "aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "alt2.aspmx.l.google.com",
            "alt3.aspmx.l.google.com",
            "alt4.aspmx.l.google.com",
            "googlemail.com",
            "smtp.google.com",
        ),
        spf_includes=("_spf.google.com",),
        dkim_selectors=(
            "google",
            "google2048",
        ),
        dkim_cname_patterns=("domainkey.google.com",),
        autodiscover_patterns=("google.com",),
        cname_patterns=(
            "google.com",
            "googlemail.com",
        ),
        smtp_banner_patterns=(
            "mx.google.com",
            "google esmtp",
        ),
        txt_verification_patterns=("google-site-verification=",),
        asns=(15169, 396982),
    ),
    ProviderSignature(
        provider=Provider.AWS,
        mx_patterns=(
            "amazonaws.com",
            "awsapps.com",
            "amazonses.com",
        ),
        spf_includes=("amazonses.com",),
        dkim_cname_patterns=("dkim.amazonses.com",),
        autodiscover_patterns=("awsapps.com",),
        cname_patterns=(
            "amazonaws.com",
            "awsapps.com",
            "amazonses.com",
        ),
        smtp_banner_patterns=(
            "amazonaws",
            "amazonses",
        ),
        txt_verification_patterns=("amazonses",),
        asns=(16509, 14618),
    ),
    # EU providers
    ProviderSignature(
        # Czech
        provider=Provider.FORPSI,
        mx_patterns=(
            "forpsi.com",
            "forpsi.hu",
            "forpsi.net",
            "mxavas.forpsi.com",
        ),
        spf_includes=(
            "_spf.forpsi.com",
            "forpsi.com",
        ),
        cname_patterns=(
            "forpsi.com",
            "forpsi.hu",
            "forpsi.net",
        ),
        smtp_banner_patterns=("forpsi",),
        asns=(24806,),
    ),
    ProviderSignature(
        # Slovak
        provider=Provider.WEBSUPPORT,
        mx_patterns=(
            "websupport.hu",
            "websupport.sk",
            "websupport.eu",
            "mailin1.websupport.sk",
            "mailin2.websupport.sk",
            "mail.websupport.eu",
        ),
        spf_includes=(
            "_spf.m1.websupport.sk",
            "m1.websupport.sk",
            "websupport.hu",
            "websupport.sk",
            "websupport.eu",
        ),
        cname_patterns=(
            "websupport.hu",
            "websupport.sk",
            "websupport.eu",
        ),
        smtp_banner_patterns=("websupport",),
    ),
    ProviderSignature(
        # Zoho Mail — present in 4 municipalities
        provider=Provider.ZOHO,
        mx_patterns=(
            "mx.zoho.com",
            "mx2.zoho.com",
            "mx3.zoho.com",
            "zoho.com",
        ),
        spf_includes=(
            "zoho.com",
            "spf.zoho.com",
            "spf.zoho.eu",
        ),
        dkim_selectors=("zoho",),
        cname_patterns=(
            "zoho.com",
            "zoho.eu",
        ),
        smtp_banner_patterns=("zoho",),
    ),
    ProviderSignature(
        # Swiss
        provider=Provider.MIGADU,
        mx_patterns=(
            "aspmx1.migadu.com",
            "aspmx2.migadu.com",
            "mx.migadu.com",
        ),
        spf_includes=(
            "spf.migadu.com",
            "migadu.com",
        ),
        cname_patterns=("migadu.com",),
        smtp_banner_patterns=("migadu",),
    ),
    ProviderSignature(
        # Lithuania
        provider=Provider.HOSTINGER,
        mx_patterns=(
            "mx1.hostinger.com",
            "mx2.hostinger.com",
            "hostinger.com",
        ),
        spf_includes=(
            "_spf.mail.hostinger.com",
            "_spf.mx.hostinger.com",
            "spf.mx.hostinger.com",
            "hostinger.com",
        ),
        cname_patterns=("hostinger.com",),
        smtp_banner_patterns=("hostinger",),
    ),
    ProviderSignature(
        # Czech
        provider=Provider.VSHOSTING,
        mx_patterns=(
            "vshosting.cloud",
            "vshosting.cz",
        ),
        spf_includes=(
            "_spf.vshosting.cloud",
            "vshosting.cloud",
        ),
        cname_patterns=(
            "vshosting.cloud",
            "vshosting.cz",
        ),
        smtp_banner_patterns=("vshosting",),
    ),
    ProviderSignature(
        # Swiss
        provider=Provider.WEBNODE,
        mx_patterns=(
            "imap.mail.webnode.com",
            "webnode.com",
        ),
        spf_includes=(
            "spfuser.webnode.com",
            "webnode.com",
        ),
        cname_patterns=("webnode.com",),
        smtp_banner_patterns=("webnode",),
    ),
    ProviderSignature(
        # Czech/EU
        provider=Provider.NETCLASS,
        mx_patterns=(
            "netclass.eu",
            "nc-mail.eu",
        ),
        spf_includes=(
            "_spf.netclass.eu",
            "netclass.eu",
        ),
        cname_patterns=("netclass.eu",),
        smtp_banner_patterns=("netclass",),
    ),
    ProviderSignature(
        provider=Provider.HOSTNS_IO,
        mx_patterns=(
            "hostns.io",
            "mx.hostns.io",
        ),
        spf_includes=(
            "spf.hostns.io",
            "hostns.io",
        ),
        cname_patterns=("hostns.io",),
        smtp_banner_patterns=("hostns.io",),
    ),
    # Hungarian providers
    ProviderSignature(
        provider=Provider.DOTROLL,
        mx_patterns=(
            "loginssl.com",
            "dotroll.com",
        ),
        spf_includes=(
            "spf.webspacecontrol.com",
            "webspacecontrol.com",
            "loginssl.com",
        ),
        cname_patterns=(
            "loginssl.com",
            "webspacecontrol.com",
            "dotroll.com",
        ),
        smtp_banner_patterns=(
            "loginssl.com",
            "webspacecontrol",
            "dotroll",
        ),
    ),
    ProviderSignature(
        provider=Provider.INTEGRITY,
        mx_patterns=(
            "integrity.hu",
            "mx.integrity.hu",
        ),
        spf_includes=(
            "_spf.integrity.hu",
            "integrity.hu",
        ),
        cname_patterns=("integrity.hu",),
        smtp_banner_patterns=(
            "integrity.hu",
            "integrity",
        ),
        asns=(28924,),
    ),
    ProviderSignature(
        provider=Provider.MEGACP,
        mx_patterns=(
            "megacp.com",
            "bmx.megacp.com",
            "pmx.megacp.com",
            "smx.megacp.com",
            "secdns.eu",
            "email-host.eu",
            "bighost.hu",
            "bestcpanel.eu",
            "iworx-host.com",  # sister domain
        ),
        spf_includes=(
            "megacp.com",
            "secdns.eu",
            "email-host.eu",
            "bighost.hu",
            "iworx-host.com",
        ),
        cname_patterns=(
            "megacp.com",
            "secdns.eu",
            "email-host.eu",
            "bighost.hu",
            "bestcpanel.eu",
        ),
        smtp_banner_patterns=(
            "megacp",
            "secdns",
            "bestcpanel",
        ),
    ),
    ProviderSignature(
        provider=Provider.WEBTAR,
        mx_patterns=(
            "webtar.hu",
            "mx1.webtar.hu",
            "mx2.webtar.hu",
            "mx3.webtar.hu",
        ),
        spf_includes=(
            "_spf.webtar.hu",
            "webtar.hu",
        ),
        cname_patterns=("webtar.hu",),
        smtp_banner_patterns=(
            "webtar.hu",
            "webtar",
        ),
    ),
    ProviderSignature(
        provider=Provider.T_ONLINE,
        mx_patterns=(
            "mx.t-online.hu",
            "t-online.hu",
            "telekom.hu",
        ),
        spf_includes=(
            "_spf.t-online.hu",
            "t-online.hu",
            "telekom.hu",
        ),
        cname_patterns=(
            "t-online.hu",
            "telekom.hu",
        ),
        smtp_banner_patterns=(
            "t-online.hu",
            "telekom.hu",
        ),
        asns=(5483,),
    ),
    ProviderSignature(
        provider=Provider.ISISCOM,
        mx_patterns=(
            "isiscom.hu",
            "mx0.isiscom.hu",
        ),
        spf_includes=("isiscom.hu",),
        cname_patterns=("isiscom.hu",),
        smtp_banner_patterns=(
            "isiscom.hu",
            "isis-com",
        ),
    ),
    ProviderSignature(
        provider=Provider.GLOBALNET2000,
        mx_patterns=(
            "globalnet2000.hu",
            "ns.globalnet2000.hu",
        ),
        spf_includes=("globalnet2000.hu",),
        cname_patterns=("globalnet2000.hu",),
        smtp_banner_patterns=(
            "globalnet2000.hu",
            "globalnet",
        ),
    ),
    ProviderSignature(
        provider=Provider.LINUXWEB,
        mx_patterns=(
            "linuxweb.hu",
            "mail.linuxweb.hu",
        ),
        spf_includes=("linuxweb.hu",),
        cname_patterns=("linuxweb.hu",),
        smtp_banner_patterns=(
            "linuxweb.hu",
            "linuxweb",
        ),
    ),
    ProviderSignature(
        provider=Provider.MEDIACENTER,
        mx_patterns=(
            "mediacenter.hu",
            "posta.mediacenter.hu",
            "posta2.mediacenter.hu",
            "posta3.mediacenter.hu",
        ),
        spf_includes=("mediacenter.hu",),
        cname_patterns=("mediacenter.hu",),
        smtp_banner_patterns=(
            "mediacenter.hu",
            "mediacenter",
        ),
    ),
    ProviderSignature(
        provider=Provider.TOLNA_NET,
        mx_patterns=(
            "tolna.net",
            "mail10.tolna.net",
        ),
        spf_includes=("tolna.net",),
        cname_patterns=("tolna.net",),
        smtp_banner_patterns=("tolna.net",),
        asns=(8462,),
    ),
    ProviderSignature(
        provider=Provider.GYOR_NET,
        mx_patterns=(
            "gyor.net",
            "mx1.gyor.net",
            "mx2.gyor.net",
        ),
        spf_includes=("gyor.net",),
        cname_patterns=("gyor.net",),
        smtp_banner_patterns=("gyor.net",),
    ),
    ProviderSignature(
        provider=Provider.RACKHOST,
        mx_patterns=(
            "rackhost.hu",
            "alt2-mx.rackhost.hu",
            "mx02.rackhost.hu",
        ),
        spf_includes=(
            "_cspf.rackhost.hu",
            "rackhost.hu",
        ),
        cname_patterns=("rackhost.hu",),
        smtp_banner_patterns=("rackhost",),
        asns=(29278, 210579),
    ),
    ProviderSignature(
        # Tarhely.eu / Tarhelykozpont — same company
        # tarhelypark.hu also resolves to this family
        provider=Provider.TARHELY_EU,
        mx_patterns=(
            "tarhely.eu",
            "mail.tarhely.eu",
            "tarhelykozpont.hu",
            "mail.tarhelykozpont.hu",
            "tarhelypark.hu",
            "mail.tarhelypark.hu",
            "mail.cpanel",
            "cpanel",
        ),
        spf_includes=(
            "tarhely.eu",
            "tarhelykozpont.hu",
            "tarhelypark.hu",
        ),
        cname_patterns=(
            "tarhely.eu",
            "tarhelykozpont.hu",
            "tarhelypark.hu",
        ),
        smtp_banner_patterns=(
            "tarhely.eu",
            "tarhelykozpont.hu",
            "tarhelypark.hu",
        ),
    ),
    ProviderSignature(
        # now routes through ezit.hu as primary MX
        provider=Provider.POSTMASTER_HU,
        mx_patterns=(
            "postmaster.hu",
            "mx.ezit.hu",
            "mx2.postmaster.hu",
            "ezit.hu",
        ),
        spf_includes=(
            "postmaster.hu",
            "ezit.hu",
        ),
        cname_patterns=(
            "postmaster.hu",
            "ezit.hu",
        ),
        smtp_banner_patterns=(
            "postmaster.hu",
            "ezit.hu",
            "ezit",
        ),
    ),
    ProviderSignature(
        provider=Provider.ATW,
        mx_patterns=(
            "atw.hu",
            "mail.atw.hu",
            "mail2.atw.hu",
            "m.atw.hu",
        ),
        spf_includes=(
            "atw.hu",
            "atw.co.hu",
        ),
        cname_patterns=(
            "atw.hu",
            "atw.co.hu",
        ),
        smtp_banner_patterns=(
            "atw.hu",
            "atw internet",
        ),
        asns=(41075,),
    ),
    ProviderSignature(
        # Dima / DiMail / SmtpCsomag — same company, multiple brands.
        provider=Provider.DIMA,
        mx_patterns=(
            "dima.hu",
            "dimail.hu",
            "smtpcsomag.hu",
            "postal.dimail.hu",
            "web.dima.hu",
        ),
        spf_includes=(
            "spf.smtpcsomag.hu",
            "spf.dimail.hu",
            "smtpcsomag.hu",
            "dimail.hu",
            "dima.hu",
        ),
        cname_patterns=(
            "dima.hu",
            "dimail.hu",
            "smtpcsomag.hu",
        ),
        smtp_banner_patterns=(
            "dima.hu",
            "dimail.hu",
            "smtpcsomag.hu",
        ),
    ),
    ProviderSignature(
        provider=Provider.NETHELY,
        mx_patterns=(
            "nethely.hu",
            "mx1.nethely.hu",
            "mx2.nethely.hu",
        ),
        spf_includes=(
            "_spf.nethely.hu",
            "nethely.hu",
        ),
        cname_patterns=("nethely.hu",),
        smtp_banner_patterns=(
            "nethely.hu",
            "nethely",
        ),
    ),
    ProviderSignature(
        # Ratior / Infonom — same infrastructure
        provider=Provider.RATIOR,
        mx_patterns=(
            "ratior.hu",
            "mail.ratior.hu",
            "relay.ratior.com",
            "infonom.net",
        ),
        spf_includes=(
            "spf1.ratior.hu",
            "ratior.hu",
            "infonom.net",
        ),
        cname_patterns=(
            "ratior.hu",
            "infonom.net",
        ),
        smtp_banner_patterns=(
            "ratior.hu",
            "infonom.net",
        ),
    ),
    ProviderSignature(
        provider=Provider.MICROWARE,
        mx_patterns=("microware.hu",),
        spf_includes=("microware.hu",),
        cname_patterns=("microware.hu",),
        smtp_banner_patterns=(
            "microware.hu",
            "microware",
        ),
    ),
    ProviderSignature(
        provider=Provider.WEB200,
        mx_patterns=(
            "web200.hu",
            "mail.web200.hu",
        ),
        spf_includes=(
            "spf.web200.hu",
            "web200.hu",
        ),
        cname_patterns=("web200.hu",),
        smtp_banner_patterns=("web200.hu",),
    ),
    ProviderSignature(
        provider=Provider.MAXER,
        mx_patterns=(
            "maxer.hu",
            "mail4.maxer.hu",
            "mailgw.maxer.hu",
            "mailgw2.maxer.hu",
        ),
        spf_includes=("maxer.hu",),
        cname_patterns=("maxer.hu",),
        smtp_banner_patterns=(
            "maxer.hu",
            "maxer",
        ),
    ),
    ProviderSignature(
        provider=Provider.ABPLUSZ,
        mx_patterns=(
            "abplusz.hu",
            "mail.abplusz.hu",
        ),
        spf_includes=(
            "_spf.abplusz.hu",
            "abplusz.hu",
        ),
        cname_patterns=("abplusz.hu",),
        smtp_banner_patterns=(
            "abplusz.hu",
            "abplusz",
        ),
    ),
    ProviderSignature(
        provider=Provider.ININET,
        mx_patterns=(
            "ininet.hu",
            "mx01.m.ininet.hu",
            "mx02.m.ininet.hu",
        ),
        spf_includes=(
            "spf.ininet.hu",
            "ininet.hu",
        ),
        cname_patterns=("ininet.hu",),
        smtp_banner_patterns=("ininet.hu",),
    ),
    ProviderSignature(
        provider=Provider.INTEGRANET,
        mx_patterns=(
            "integranet.hu",
            "mail.integranet.hu",
        ),
        spf_includes=("integranet.hu",),
        cname_patterns=("integranet.hu",),
        smtp_banner_patterns=("integranet.hu",),
    ),
    ProviderSignature(
        provider=Provider.AVPMS,
        mx_patterns=(
            "avpms.hu",
            "mx-bck.avpms.hu",
            "mx-htr.avpms.hu",
            "mx-two.avpms.hu",
            "mx-zr.avpms.hu",
        ),
        spf_includes=("avpms.hu",),
        cname_patterns=("avpms.hu",),
        smtp_banner_patterns=("avpms.hu",),
    ),
    ProviderSignature(
        provider=Provider.MAXMAIL,
        mx_patterns=(
            "maxmail.hu",
            "maxmail.datatrans.hu",
        ),
        spf_includes=("maxmail.hu",),
        cname_patterns=("maxmail.hu",),
        smtp_banner_patterns=("maxmail.hu",),
    ),
    ProviderSignature(
        provider=Provider.UIWEBSERVICES,
        mx_patterns=(
            "uiwebservices.hu",
            "mail.uiwebservices.hu",
        ),
        spf_includes=("uiwebservices.hu",),
        cname_patterns=("uiwebservices.hu",),
        smtp_banner_patterns=(
            "uiwebservices.hu",
            "ui webservices",
        ),
    ),
    ProviderSignature(
        provider=Provider.ASPNET,
        mx_patterns=(
            "aspnet.hu",
            "mx1.aspnet.hu",
            "mx2.aspnet.hu",
            "mx3.aspnet.hu",
        ),
        spf_includes=("aspnet.hu",),
        cname_patterns=("aspnet.hu",),
        smtp_banner_patterns=("aspnet.hu",),
    ),
    ProviderSignature(
        provider=Provider.DTNET,
        mx_patterns=(
            "dtnet.hu",
            "mail.dtnet.hu",
        ),
        spf_includes=("dtnet.hu",),
        cname_patterns=("dtnet.hu",),
        smtp_banner_patterns=("dtnet.hu",),
    ),
    ProviderSignature(
        provider=Provider.SPAMZABALO,
        mx_patterns=(
            "spamzabalo.hu",
            "spamzabalo.eu",
            "pmx1.spamzabalo.hu",
            "smx1.spamzabalo.eu",
        ),
        spf_includes=(
            "spf.spamzabalo.hu",
            "spamzabalo.hu",
            "spamzabalo.eu",
        ),
        cname_patterns=(
            "spamzabalo.hu",
            "spamzabalo.eu",
        ),
        smtp_banner_patterns=(
            "spamzabalo.hu",
            "spamzabalo.eu",
            "spamzabalo",
        ),
    ),
    ProviderSignature(
        provider=Provider.HOSTING4U,
        mx_patterns=(
            "hosting4u.hu",
            "mx1.hosting4u.hu",
        ),
        spf_includes=(
            "spf.hosting4u.hu",
            "hosting4u.hu",
        ),
        cname_patterns=("hosting4u.hu",),
        smtp_banner_patterns=(
            "hosting4u.hu",
            "hosting4u",
        ),
    ),
    ProviderSignature(
        provider=Provider.GIGANET,
        mx_patterns=(
            "giganet.hu",
            "mailgw.giganet.hu",
        ),
        spf_includes=(
            "_spf.giganet.hu",
            "giganet.hu",
        ),
        cname_patterns=("giganet.hu",),
        smtp_banner_patterns=(
            "giganet.hu",
            "giganet",
        ),
    ),
    ProviderSignature(
        provider=Provider.SMTP_HU,
        mx_patterns=(
            "smtp.hu",
            "mailmx.smtp.hu",
        ),
        spf_includes=(
            "spf.smtp.hu",
            "smtp.hu",
        ),
        cname_patterns=("smtp.hu",),
        smtp_banner_patterns=("smtp.hu",),
    ),
    ProviderSignature(
        provider=Provider.UNAS,
        mx_patterns=(
            "unas.hu",
            "mail.unas.hu",
            "unas.eu",
        ),
        spf_includes=(
            "spf.unas.eu",
            "unas.eu",
            "unas.hu",
        ),
        cname_patterns=(
            "unas.hu",
            "unas.eu",
        ),
        smtp_banner_patterns=(
            "unas.hu",
            "unas.eu",
            "unas",
        ),
    ),
]


GATEWAY_KEYWORDS: dict[str, list[str]] = {
    "seppmail": ["seppmail.cloud", "seppmail.com"],
    "barracuda": [
        "barracudanetworks.com",
        "barracuda.com",
        "ess.de.barracudanetworks.com",
    ],
    "trendmicro": ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com"],
    "proofpoint": ["ppe-hosted.com", "pphosted.com"],
    "sophos": ["hydra.sophos.com"],
    "cisco": ["iphmx.com"],
    "mimecast": ["mimecast.com"],
    "spamvor": ["spamvor.com"],
    "abxsec": ["abxsec.com"],
    "messagelabs": ["messagelabs.com"],
    "spamhero": ["spamhero.com", "spamhero.net"],
    "spamexperts": ["spamexperts.com", "spamexperts.eu", "spamexperts.net"],
    "spamfilter": ["spamfilter.io"],
}


HUN_ISP_ASNS: dict[int, str] = {
    # National / large access networks
    5483: "Magyar Telekom",
    21334: "One Hungary / Vodafone",
    20845: "DIGI",
    213155: "Yettel Hungary",
    8448: "Telenor / Yettel legacy",
    12301: "Invitech",
    8462: "Tarr",
    35311: "PR-TELECOM",
    28924: "Integrity",
    62214: "Rackforest",
    # Government / education
    1955: "KIFU / HBONE",
}


def match_patterns(value: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Case-insensitive substring match of value against any pattern."""
    if not value or not patterns:
        return False
    lower = value.lower()
    return any(p.lower() in lower for p in patterns)
