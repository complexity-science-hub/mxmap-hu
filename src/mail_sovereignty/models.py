"""Pydantic models for the mail sovereignty classifier."""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class Provider(str, enum.Enum):
    # US / global cloud
    MS365 = "ms365"
    GOOGLE = "google"
    AWS = "aws"

    # EU providers
    FORPSI = "forpsi"
    WEBSUPPORT = "websupport"
    ZOHO = "zoho"
    MIGADU = "migadu"
    HOSTINGER = "hostinger"
    VSHOSTING = "vshosting"
    WEBNODE = "webnode"
    NETCLASS = "netclass"
    HOSTNS_IO = "hostns-io"

    # Hungarian providers
    HUN_ISP = "hungarian-isp"
    INDEPENDENT = "independent"
    DOTROLL = "dotroll"
    INTEGRITY = "integrity"
    MEGACP = "megacp"
    WEBTAR = "webtar"
    T_ONLINE = "t-online"
    ISISCOM = "isiscom"
    GLOBALNET2000 = "globalnet2000"
    LINUXWEB = "linuxweb"
    MEDIACENTER = "mediacenter"
    TOLNA_NET = "tolna-net"
    GYOR_NET = "gyor-net"
    RACKHOST = "rackhost"
    TARHELY_EU = "tarhely-eu"
    POSTMASTER_HU = "postmaster-hu"
    ATW = "atw"
    DIMA = "dima"
    NETHELY = "nethely"
    RATIOR = "ratior"
    MICROWARE = "microware"
    WEB200 = "web200"
    MAXER = "maxer"
    ABPLUSZ = "abplusz"
    ININET = "ininet"
    INTEGRANET = "integranet"
    AVPMS = "avpms"
    MAXMAIL = "maxmail"
    UIWEBSERVICES = "uiwebservices"
    ASPNET = "aspnet"
    DTNET = "dtnet"
    SPAMZABALO = "spamzabalo"
    HOSTING4U = "hosting4u"
    GIGANET = "giganet"
    SMTP_HU = "smtp-hu"
    UNAS = "unas"

    # Other
    # UNRESOLVED does NOT mean "domain/DNS could not be resolved" — the
    # domain has a working MX record, but it matched no known provider
    # signature and didn't look Hungarian-hosted either (see
    # classifier._aggregate). UNKNOWN means no MX record was found at all.
    UNRESOLVED = "unresolved"
    UNKNOWN = "unknown"


class SignalKind(str, enum.Enum):
    MX = "mx"
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    AUTODISCOVER = "autodiscover"
    CNAME_CHAIN = "cname_chain"
    SMTP = "smtp"
    TENANT = "tenant"
    ASN = "asn"
    TXT_VERIFICATION = "txt_verification"
    SPF_IP = "spf_ip"


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: SignalKind
    provider: Provider
    weight: float = Field(ge=0.0, le=1.0)
    detail: str
    raw: str = ""


class ClassificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Provider
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = []
    gateway: str | None = None
    mx_hosts: list[str] = []
    spf_raw: str = ""
