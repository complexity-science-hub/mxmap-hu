import asyncio
import csv
import json
import re
import ssl
import time
import unicodedata
import warnings
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from collections import Counter

import httpx
import stamina
from loguru import logger

from mail_sovereignty.constants import (
    CONCURRENCY_POSTPROCESS,
    EMAIL_RE,
    SOURCE_KEYS,
    SKIP_DOMAINS,
    SPARQL_QUERY,
    SPARQL_URL,
    SUBPAGES,
    TYPO3_RE,
)
from mail_sovereignty.dns import lookup_mx


def url_to_domain(url: str | None) -> str | None:
    """Extract the base domain from a URL."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None


def _normalize_name(name: str) -> str:
    """Normalize a municipality name for comparison."""

    normalized = unicodedata.normalize("NFD", name)

    # Filter out the accent marks (combining characters)
    ascii_bytes = normalized.encode("ASCII", "ignore")

    # Decode back to string and lowercase it
    return ascii_bytes.decode("ASCII").lower().strip()


def _slugify(s):
    """Convert a pre-normalised string to a URL-safe slug."""
    s = re.sub(r"['\u2019`]", "", s)
    s = re.sub(r"[^a-z0-9]+", "-", s)

    return s.strip("-")


def guess_domains(name: str) -> list[str]:
    """Generate a set of plausible domain guesses for a municipality."""

    ascii_name = _normalize_name(name)
    slugs = {_slugify(ascii_name)} - {""}

    candidates = set()
    suffixes = ["kozseg", "nagykozseg", "varos", "falu", "onkormanyzat"]
    for slug in slugs:
        candidates.add(f"{slug}.hu")
        candidates.add(f"{slug}.asp.lgov.hu")
        for suffix in suffixes:
            candidates.add(f"{slug}{suffix}.hu")
            candidates.add(f"{slug}-{suffix}.hu")

    return sorted(candidates)


def detect_mismatch(name: str, website_domain: str) -> bool:
    """Detect if a website domain doesn't match the municipality name.

    Returns True if the domain appears unrelated to the municipality name.
    """
    if not name or not website_domain:
        return False

    domain_lower = website_domain.lower()
    if domain_lower.startswith("www."):
        domain_lower = domain_lower[4:]

    ascii_name = _normalize_name(name)
    slugs = {_slugify(ascii_name)} - {""}
    domain_base = (
        domain_lower.rsplit(".", 1)[0] if "." in domain_lower else domain_lower
    )
    domain_labels = [label for label in domain_base.split(".") if label]
    domain_label_slugs = {_slugify(label) for label in domain_labels} - {""}
    domain_compact = _slugify(domain_base).replace("-", "")

    for slug in slugs:
        if slug in domain_lower:
            return False
        if slug in domain_label_slugs:
            return False
        if slug.replace("-", "") and slug.replace("-", "") in domain_compact:
            return False

    words = re.findall(r"[a-z]{4,}", ascii_name)
    for word in words:
        if word in domain_compact:
            return False

    return True


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=3,
    wait_initial=2.0,
)
async def _fetch_sparql(
    client: httpx.AsyncClient, url: str, data: dict, headers: dict
) -> httpx.Response:
    r = await client.post(url, data=data, headers=headers)
    r.raise_for_status()
    return r


async def fetch_wikidata() -> dict[str, dict[str, str]]:
    """Query Wikidata for all Hungarian municipalities."""
    logger.info("Fetching municipalities from Wikidata")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "MXmap/1.0 (https://github.com/davidhuser/mxmap)",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await _fetch_sparql(client, SPARQL_URL, {"query": SPARQL_QUERY}, headers)
        data = r.json()

    municipalities = {}
    for row in data["results"]["bindings"]:
        raw_id = row.get("id", {}).get("value", "").strip()
        if not raw_id:
            continue

        id = raw_id.zfill(5) if raw_id.isdigit() else raw_id
        name = row.get("itemLabel", {}).get("value", f"ID-{id}")
        website = row.get("website", {}).get("value", "")
        county = row.get("countyLabel", {}).get("value", "")

        if id not in municipalities:
            municipalities[id] = {
                "id": id,
                "name": name,
                "website": website,
                "county": county,
            }
        else:
            if not municipalities[id]["website"] and website:
                municipalities[id]["website"] = website
            if not municipalities[id]["county"] and county:
                municipalities[id]["county"] = county
            if not municipalities[id]["name"] and name:
                municipalities[id]["name"] = name

    logger.info(
        "Wikidata: {} municipalities, {} with websites",
        len(municipalities),
        sum(1 for m in municipalities.values() if m["website"]),
    )
    return municipalities


def load_overrides(overrides_path: Path) -> dict[str, dict[str, str]]:
    """Load manual overrides from JSON file."""
    if not overrides_path.exists():
        return {}
    with open(overrides_path, encoding="utf-8") as f:
        return json.load(f)


def load_municipalities_csv(csv_path: Path) -> dict[str, dict[str, str]]:
    """Load the municipalities CSV and normalize it to the resolver schema."""
    municipalities: dict[str, dict[str, str]] = {}
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if not row:
                continue

            # The source file stores each CSV line as a single quoted field.
            parts = row[0].split(",", 2) if len(row) == 1 else row
            if len(parts) != 3:
                continue

            name, id, county = (part.strip() for part in parts)
            if not id or not name:
                continue

            municipalities[id] = {
                "id": id,
                "name": name,
                "county": county,
            }
    return municipalities


def decrypt_typo3(encoded: str, offset: int = 2) -> str:
    """Decrypt TYPO3 linkTo_UnCryptMailto Caesar cipher.

    TYPO3 encrypts mailto: links with a Caesar shift on three ASCII ranges:
      0x2B-0x3A (+,-./0123456789:)  -- covers . : and digits
      0x40-0x5A (@A-Z)             -- covers @ and uppercase
      0x61-0x7A (a-z)             -- covers lowercase
    Default encryption offset is -2, so decryption is +2 with wrap.
    """
    ranges = [(0x2B, 0x3A), (0x40, 0x5A), (0x61, 0x7A)]
    result = []
    for c in encoded:
        code = ord(c)
        decrypted = False
        for start, end in ranges:
            if start <= code <= end:
                size = end - start + 1
                n = start + (code - start + offset) % size
                result.append(chr(n))
                decrypted = True
                break
        if not decrypted:
            result.append(c)
    return "".join(result)


def _is_valid_domain(domain: str) -> bool:
    """Quick syntactic check — reject domains that will fail DNS lookup."""
    if not domain or len(domain) > 253:
        return False
    if "\\" in domain or "/" in domain:
        return False
    return all(0 < len(label) <= 63 for label in domain.split("."))


def _is_skip_domain(domain: str) -> bool:
    domain = domain.lower().removeprefix("www.").rstrip(".")

    return domain in SKIP_DOMAINS or any(
        domain.endswith("." + suffix) for suffix in SKIP_DOMAINS
    )


def extract_email_domain_counts(html: str) -> Counter[str]:
    """Count email domains found in HTML, including TYPO3-obfuscated emails."""
    counts: Counter[str] = Counter()

    for email in EMAIL_RE.findall(html):
        domain = email.split("@")[1].lower()
        if not _is_skip_domain(domain) and _is_valid_domain(domain):
            counts[domain] += 1

    for email in re.findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower().rstrip("\\/.")
            if not _is_skip_domain(domain) and _is_valid_domain(domain):
                counts[domain] += 1

    for encoded in TYPO3_RE.findall(html):
        for offset in range(-25, 26):
            decoded = decrypt_typo3(encoded, offset).replace("mailto:", "")
            if "@" in decoded and EMAIL_RE.search(decoded):
                domain = decoded.split("@")[1].lower()
                if not _is_skip_domain(domain) and _is_valid_domain(domain):
                    counts[domain] += 1
                break

    for match in re.findall(
        r"[\w.-]+\s*[\[(]at[\])]\s*[\w.-]+\.\w+", html, re.IGNORECASE
    ):
        normalized = re.sub(r"\s*[\[(]at[\])]\s*", "@", match, flags=re.IGNORECASE)
        if "@" in normalized:
            domain = normalized.split("@")[1].lower()
            if not _is_skip_domain(domain) and _is_valid_domain(domain):
                counts[domain] += 1

    return counts


def build_urls(domain: str) -> list[str]:
    """Build candidate base URLs to try in priority order (no subpages)."""
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    if domain.startswith("www."):
        bare = domain[4:]
    else:
        bare = domain

    return [
        f"https://www.{bare}",
        f"https://{bare}",
        f"http://www.{bare}",  # villages hidden away behind God's back
        f"http://{bare}",
    ]


def _is_ssl_error(exc: BaseException) -> bool:
    """Check if an exception (or any in its chain) is an SSL verification error."""
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, ssl.SSLError):
            return True
        if any(
            s in str(current)
            for s in (
                "CERTIFICATE_VERIFY_FAILED",
                "TLSV1_ALERT",
                "SSL_ERROR",
            )
        ):
            return True
        current = current.__cause__ if current.__cause__ is not current else None
    return False


async def _fetch_insecure(url: str) -> httpx.Response:
    """Fetch a URL with SSL verification disabled (single request)."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        async with httpx.AsyncClient(verify=False) as insecure_client:
            return await insecure_client.get(url, follow_redirects=True, timeout=15)


def _process_scrape_response(
    response: httpx.Response,
    domain: str,
    all_domains: Counter[str],
    redirect_domain: str | None,
) -> tuple[Counter[str], str | None]:
    """Extract emails and detect redirects from a scrape response."""
    if response.status_code != 200:
        return all_domains, redirect_domain

    if redirect_domain is None:
        final_domain = url_to_domain(str(response.url))
        if final_domain and final_domain != domain:
            redirect_domain = final_domain
            logger.info("Redirect detected: {} -> {}", domain, redirect_domain)

    all_domains.update(extract_email_domain_counts(response.text))
    return all_domains, redirect_domain


async def _try_fetch(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    """Fetch a single URL, returning None on any network error."""
    try:
        return await client.get(url, follow_redirects=True, timeout=15)
    except httpx.ConnectError as exc:
        if _is_ssl_error(exc):
            logger.info("SSL error on {}, retrying without verification", url)
            try:
                return await _fetch_insecure(url)
            except Exception as retry_exc:
                logger.debug("Insecure retry {} failed: {}", url, retry_exc)
                return None
        logger.debug("Scrape {} failed: {}", url, exc)
        return None
    except Exception as exc:
        logger.debug("Scrape {} failed: {}", url, exc)
        return None


async def scrape_email_domains(
    client: httpx.AsyncClient, domain: str
) -> tuple[Counter[str], str | None]:
    """Scrape a municipality website for email domains.

    Tries each base URL (https://www., https://, http://www., http://) in order.
    If the root of a base returns 200, scrapes all subpages for that base and stops.
    If the root fails or returns non-200, moves to the next base.
    """
    if not domain:
        return Counter(), None

    all_domains: Counter[str] = Counter()
    redirect_domain: str | None = None

    for base in build_urls(domain):
        root = await _try_fetch(client, base + "/")
        if root is None or root.status_code != 200:
            continue

        all_domains, redirect_domain = _process_scrape_response(
            root, domain, all_domains, redirect_domain
        )
        for path in SUBPAGES:
            response = await _try_fetch(client, base + path)
            if response is not None:
                all_domains, redirect_domain = _process_scrape_response(
                    response, domain, all_domains, redirect_domain
                )
        break

    return all_domains, redirect_domain


async def _collect_website_source_candidates(
    client: httpx.AsyncClient,
    website_domain: str | None,
) -> tuple[str | None, Counter[str], Counter[str]]:
    """Collect website-domain, scrape candidates, and redirect candidates."""
    scrape_counts: Counter[str] = Counter()
    redirect_counts: Counter[str] = Counter()

    if not website_domain:
        return None, scrape_counts, redirect_counts

    website_domains, redirect_domain = await scrape_email_domains(
        client, website_domain
    )

    candidates = website_domains.most_common()
    mx_results = await asyncio.gather(*[lookup_mx(d) for d, _ in candidates])
    for (domain, count), mx in zip(candidates, mx_results):
        if mx:
            scrape_counts[domain] += count

    if redirect_domain:
        if await lookup_mx(redirect_domain):
            redirect_counts[redirect_domain] += 1

    return website_domain, scrape_counts, redirect_counts


def _add_scrape_candidates(
    *,
    sources: dict[str, set[str]],
    scrape_counts: Counter[str],
    source_key: str,
    name: str,
    evidence: Counter[str] | None = None,
) -> None:
    for email_domain, count in scrape_counts.most_common():
        if detect_mismatch(name, email_domain):
            logger.debug(
                "Filtered mismatching {} candidate for {}: {}",
                source_key,
                name,
                email_domain,
            )
            continue
        sources[source_key].add(email_domain)
        if evidence is not None:
            evidence[email_domain] += count


def _add_redirect_candidates(
    *,
    sources: dict[str, set[str]],
    redirect_counts: Counter[str],
    source_key: str,
    name: str,
) -> None:
    for redirect_domain, _count in redirect_counts.most_common():
        if _is_skip_domain(redirect_domain):
            logger.debug(
                "Filtered skipped redirect candidate for {}: {}",
                name,
                redirect_domain,
            )
            continue
        if detect_mismatch(name, redirect_domain):
            logger.debug(
                "Filtered mismatching {} candidate for {}: {}",
                source_key,
                name,
                redirect_domain,
            )
            continue
        sources[source_key].add(redirect_domain)


def _agreed(
    pools: list[set[str]], evidence: Counter[str], min_count: int = 2
) -> str | None:
    """Return the best domain present in min_count+ of the given pools, or None.

    No family grouping — each pool is counted independently.
    Tiebreak: highest evidence count, then alphabetical.
    When min_count=1, returns the best domain across all non-empty pools (used in fallback).
    """
    all_domains: set[str] = set().union(*pools)
    candidates = {
        d for d in all_domains if sum(1 for p in pools if d in p) >= min_count
    }
    if not candidates:
        return None
    return min(candidates, key=lambda d: (-evidence[d], d))


async def resolve_municipality_domain(
    municipality: dict[str, str],
    overrides: dict[str, dict[str, str]],
    client: httpx.AsyncClient,
) -> dict[str, Any]:
    id = municipality["id"]
    name = municipality["name"]
    county = municipality.get("county", "")

    entry: dict[str, Any] = {"id": id, "name": name, "county": county}
    sources: dict[str, set[str]] = {key: set() for key in SOURCE_KEYS}
    domain_evidence: Counter[str] = Counter()
    website_candidate_cache: dict[
        str, tuple[str | None, Counter[str], Counter[str]]
    ] = {}

    async def _get_cached(
        website_value: str | None,
    ) -> tuple[str | None, Counter[str], Counter[str]]:
        website_domain = url_to_domain(website_value)
        if not website_domain:
            return None, Counter(), Counter()
        if website_domain not in website_candidate_cache:
            website_candidate_cache[
                website_domain
            ] = await _collect_website_source_candidates(client, website_domain)
        cached_domain, cached_sc, cached_rc = website_candidate_cache[website_domain]
        return cached_domain, Counter(cached_sc), Counter(cached_rc)

    def _downgrade(confidence: str) -> str:
        return {"high": "medium", "medium": "low", "low": "low", "none": "none"}[
            confidence
        ]

    def _make_result(
        domain: str, source: str, confidence: str, flags: list[str]
    ) -> dict[str, Any]:
        final_flags = list(flags)
        final_confidence = confidence
        if domain and source != "override":
            if detect_mismatch(name, domain):
                final_flags.append("domain_mismatch")
                final_confidence = _downgrade(final_confidence)
            if domain.endswith(".asp.lgov.hu"):
                final_flags.append("lgov_platform")
                final_confidence = _downgrade(final_confidence)
        if municipality.get("id_only"):
            final_flags.append("id_only")
        entry.update(
            {
                "domain": domain,
                "source": source,
                "confidence": final_confidence,
                "sources_detail": {k: sorted(v) for k, v in sources.items()},
                "flags": final_flags,
            }
        )
        return entry

    # ── Step 1: Override ──────────────────────────────────────────────────────
    override = overrides.get(id, {})
    override_domain = url_to_domain(override.get("domain"))
    override_website = url_to_domain(override.get("website"))

    if override_domain and await lookup_mx(override_domain):
        sources["override"].add(override_domain)
        return _make_result(override_domain, "override", "high", [])

    if (
        override_website
        and override_website != override_domain
        and await lookup_mx(override_website)
    ):
        sources["override"].add(override_website)
        return _make_result(override_website, "override", "high", [])

    if override_website:
        _, sc, rc = await _get_cached(override_website)
        _add_scrape_candidates(
            sources=sources,
            scrape_counts=sc,
            source_key="override_scrape",
            name=name,
            evidence=domain_evidence,
        )
        _add_redirect_candidates(
            sources=sources,
            redirect_counts=rc,
            source_key="override_redirect",
            name=name,
        )

    # ── Step 2: Wikidata ──────────────────────────────────────────────────────
    website_wd = municipality.get("website", "")
    wd_domain, wd_sc, wd_rc = await _get_cached(website_wd)

    if (
        wd_domain
        and not _is_skip_domain(wd_domain)
        and not detect_mismatch(name, wd_domain)
        and await lookup_mx(wd_domain)
    ):
        sources["wikidata"].add(wd_domain)

    _add_scrape_candidates(
        sources=sources,
        scrape_counts=wd_sc,
        source_key="wikidata_scrape",
        name=name,
        evidence=domain_evidence,
    )
    _add_redirect_candidates(
        sources=sources,
        redirect_counts=wd_rc,
        source_key="wikidata_redirect",
        name=name,
    )

    # ── Step 3: Guess — MX phase ──────────────────────────────────────────────
    guesses: list[str] = []
    for guess in guess_domains(name):
        if _is_skip_domain(guess):
            logger.debug("Filtered skipped guess candidate for {}: {}", name, guess)
            continue
        guesses.append(guess)
        if await lookup_mx(guess):
            sources["guess"].add(guess)

    # ── Step 4: Agreement check (before guess scrape) ─────────────────────────
    domain = _agreed(
        [
            sources["override_scrape"],
            sources["override_redirect"],
            sources["wikidata"],
            sources["wikidata_scrape"],
            sources["wikidata_redirect"],
            sources["guess"],
        ],
        domain_evidence,
    )
    if domain:
        return _make_result(domain, "source_agreement", "high", [])

    # ── Step 5: Guess — scrape phase ─────────────────────────────────────────
    for guess in guesses:
        _, sc, rc = await _get_cached(guess)
        _add_scrape_candidates(
            sources=sources,
            scrape_counts=sc,
            source_key="guess_scrape",
            name=name,
            evidence=domain_evidence,
        )
        _add_redirect_candidates(
            sources=sources,
            redirect_counts=rc,
            source_key="guess_redirect",
            name=name,
        )

    guess_family = (
        sources["guess"] | sources["guess_scrape"] | sources["guess_redirect"]
    )
    domain = _agreed(
        [
            sources["override_scrape"],
            sources["override_redirect"],
            sources["wikidata"],
            sources["wikidata_scrape"],
            sources["wikidata_redirect"],
            guess_family,
        ],
        domain_evidence,
    )
    if domain:
        return _make_result(domain, "source_agreement", "medium", [])

    # ── Step 6: Priority fallback ─────────────────────────────────────────────
    # sources_disagree when 2+ trusted sources contributed but couldn't agree;
    # single_source when only one trusted source had candidates.
    # Guesses don't count as a trusted party for this flag.
    trusted = [
        sources["override_scrape"] | sources["override_redirect"],
        sources["wikidata"] | sources["wikidata_scrape"] | sources["wikidata_redirect"],
    ]
    trusted_with_candidates = [f for f in trusted if f]
    fallback_flags = (
        ["sources_disagree"] if len(trusted_with_candidates) >= 2 else ["single_source"]
    )

    for key, tier_confidence in [
        ("override_scrape", "medium"),
        ("override_redirect", "medium"),
        ("wikidata", "low"),
        ("wikidata_scrape", "low"),
        ("wikidata_redirect", "low"),
        ("guess", "low"),
        ("guess_scrape", "low"),
        ("guess_redirect", "low"),
    ]:
        if not sources[key]:
            continue
        flags = (
            ["guess_only"]
            if key.startswith("guess") and not trusted_with_candidates
            else fallback_flags
        )
        winner = _agreed([sources[key]], domain_evidence, min_count=1)
        return _make_result(winner, key, tier_confidence, flags)

    # ── Step 7: No winner ────────────────────────────────────────────────────
    return _make_result("", "none", "none", [])


def _add_shared_domain_flags(results: dict[str, dict[str, Any]]) -> None:
    """Flag domains used by more than one municipality.
    Mutates results in-place.
    """
    domain_to_id: dict[str, list[str]] = {}

    for id, result in results.items():
        domain = str(result.get("domain", "")).lower().strip().rstrip(".")
        if not domain:
            continue

        domain_to_id.setdefault(domain, []).append(id)

    for domain, ids in domain_to_id.items():
        if len(ids) < 2:
            continue

        for id in ids:
            result = results[id]
            flags = list(result.get("flags", []))

            if "shared_domain" not in flags:
                flags.append("shared_domain")

            result["flags"] = flags


async def run(output_path: Path, overrides_path: Path) -> None:
    overrides = load_overrides(overrides_path)

    municipalities_csv = (
        Path(__file__).resolve().parents[2] / "data" / "municipalities.csv"
    )
    municipalities_base = load_municipalities_csv(municipalities_csv)

    # Wikidata provides website URLs
    wikidata = await fetch_wikidata()

    # Merge: for each id municipality, attach Wikidata website if available
    municipalities: dict[str, dict[str, Any]] = {}
    for id, entry in municipalities_base.items():
        entry: dict[str, Any] = {
            "id": id,
            "name": entry["name"],
            "county": entry["county"],
            "website": "",
        }
        if id in wikidata:
            entry["website"] = wikidata[id].get("website", "")
        municipalities[id] = entry

    # Log municipalities in id but missing from Wikidata
    id_only = set(municipalities_base) - set(wikidata)
    if id_only:
        logger.warning(
            "{} municipalities in id but missing from Wikidata", len(id_only)
        )
        for id in sorted(id_only, key=str):
            m = municipalities_base[id]
            logger.warning("    {:>5}  {}", id, m["name"])
            municipalities[id]["id_only"] = True

    # Log municipalities in Wikidata but not in ID (potentially dissolved)
    wikidata_only = set(wikidata) - set(municipalities_base)
    if wikidata_only:
        logger.warning(
            "{} municipalities in Wikidata but missing from ID", len(wikidata_only)
        )
        for id in sorted(wikidata_only, key=str):
            m = wikidata[id]
            logger.warning("    {:>5}  {}", id, m["name"])

    # Add municipalities that are only in overrides (missing from both)
    for id, override in overrides.items():
        if id not in municipalities and "name" in override:
            municipalities[id] = {
                "id": id,
                "name": override["name"],
                "website": "",
                "county": override.get("county", ""),
            }
            logger.info("Added override-only municipality: {} {}", id, override["name"])

    total = len(municipalities)
    logger.info("Resolving email domains for {} municipalities", total)

    # Use a shared client for scraping with limited concurrency
    scrape_semaphore = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)

    async def _resolve_with_shared_client(
        m: dict[str, str], shared_client: httpx.AsyncClient
    ) -> dict[str, Any] | None:
        async with scrape_semaphore:
            try:
                return await resolve_municipality_domain(m, overrides, shared_client)
            except Exception:
                logger.exception("Resolution failed for {} ({})", m["name"], m["id"])
                return None

    results: dict[str, dict[str, Any]] = {}
    done = 0
    skipped = 0

    async with httpx.AsyncClient(
        headers={
            "User-Agent": "mxmap.hu/1.0 (https://github.com/complexity-science-hub/mxmap-hu)"
        },
        follow_redirects=True,
    ) as shared_client:
        tasks = [
            _resolve_with_shared_client(m, shared_client)
            for m in municipalities.values()
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result is None:
                skipped += 1
                continue
            results[result["id"]] = result
            done += 1
            logger.info(
                "[{:>4}/{}] {} ({}): domain={} source={} confidence={}",
                done,
                total,
                result["name"],
                result["id"],
                result.get("domain", ""),
                result.get("source", ""),
                result.get("confidence", ""),
            )

    if skipped:
        logger.warning("Skipped {} municipalities due to errors", skipped)

    _add_shared_domain_flags(results)

    # Print summary
    source_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for r in results.values():
        source_counts[r["source"]] = source_counts.get(r["source"], 0) + 1
        confidence_counts[r["confidence"]] = (
            confidence_counts.get(r["confidence"], 0) + 1
        )

    logger.info("--- Domain resolution: {} municipalities ---", len(results))
    logger.info("By source:")
    for source in [
        "override",
        "source_agreement",
        "override_scrape",
        "override_redirect",
        "wikidata",
        "wikidata_scrape",
        "wikidata_redirect",
        "guess",
        "guess_scrape",
        "guess_redirect",
        "none",
    ]:
        logger.info("  {:<20} {:>5}", source, source_counts.get(source, 0))
    logger.info("By confidence:")
    for conf in ["high", "medium", "low", "none"]:
        logger.info("  {:<12} {:>5}", conf, confidence_counts.get(conf, 0))

    # Print flagged entries for review (skip overridden — already confirmed)
    unreviewed = {
        id: r for id, r in results.items() if id not in overrides and r.get("flags")
    }

    disagreements = [r for r in unreviewed.values() if "sources_disagree" in r["flags"]]
    if disagreements:
        logger.warning("{} domains with source disagreement:", len(disagreements))
        for r in sorted(disagreements, key=lambda x: str(x["id"])):
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}  sources={}",
                r["id"],
                r["name"],
                r["county"],
                r["domain"],
                r.get("sources_detail", {}),
            )

    mismatches = [r for r in unreviewed.values() if "domain_mismatch" in r["flags"]]
    if mismatches:
        logger.warning("{} domains with domain mismatch:", len(mismatches))
        for r in sorted(mismatches, key=lambda x: str(x["id"])):
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}",
                r["id"],
                r["name"],
                r["county"],
                r["domain"],
            )

    guess_only = [r for r in unreviewed.values() if "guess_only" in r["flags"]]
    if guess_only:
        logger.warning("{} domains resolved by guess only:", len(guess_only))
        for r in sorted(guess_only, key=lambda x: str(x["id"])):
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}",
                r["id"],
                r["name"],
                r["county"],
                r["domain"],
            )

    lgov = [r for r in unreviewed.values() if "lgov_platform" in r.get("flags", [])]
    if lgov:
        logger.info("{} domains resolved via asp.lgov.hu platform:", len(lgov))
        for r in sorted(lgov, key=lambda x: str(x["id"])):
            logger.info(
                "  {:>5}  {:<30} {:<20} domain={}",
                r["id"],
                r["name"],
                r["county"],
                r["domain"],
            )

    # Print low confidence and unresolved entries for review
    low_entries = [
        r
        for id, r in results.items()
        if id not in overrides and r["confidence"] in ("low", "none")
    ]
    if low_entries:
        logger.warning("{} domains needing review:", len(low_entries))
        for r in sorted(low_entries, key=lambda x: str(x["id"])):
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}  source={}",
                r["id"],
                r["name"],
                r["county"],
                r["domain"] or "none",
                r["source"],
            )

    sorted_results = dict(sorted(results.items(), key=lambda kv: str(kv[0])))

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "municipalities": sorted_results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    size_kb = len(json.dumps(output, ensure_ascii=False)) / 1024
    logger.info("Wrote {} ({} KB)", output_path, size_kb)
