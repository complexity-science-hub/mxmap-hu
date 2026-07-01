"""Classification pipeline: orchestrate classify_many() and write data.json."""

from __future__ import annotations

from collections import Counter, defaultdict
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from loguru import logger

from .classifier import classify_many
from .models import ClassificationResult, Provider

# Map internal Provider enum values to data.json output names
PROVIDER_OUTPUT_NAMES: dict[str, str] = {
    "ms365": "microsoft",
}

_CATEGORY_MAP: dict[str, str] = {
    # Global / US cloud
    "microsoft": "us-cloud",
    "google": "us-cloud",
    "aws": "us-cloud",
    # Generic
    "unresolved": "unresolved",
    "unknown": "unknown",
    # Hungarian providers
    "independent": "hungarian-based",
    "hungarian-isp": "hungarian-based",
    "dotroll": "hungarian-based",
    "megacp": "hungarian-based",
    "mediacenter": "hungarian-based",
    "integrity": "hungarian-based",
    "postmaster-hu": "hungarian-based",
    "atw": "hungarian-based",
    "rackhost": "hungarian-based",
    "maxer": "hungarian-based",
    "abplusz": "hungarian-based",
    "dima": "hungarian-based",
    "nethely": "hungarian-based",
    "tarhely-eu": "hungarian-based",
    "ratior": "hungarian-based",
    "web200": "hungarian-based",
    "tolna-net": "hungarian-based",
    "linuxweb": "hungarian-based",
    "gyor-net": "hungarian-based",
    "integranet": "hungarian-based",
    "t-online": "hungarian-based",
    "webtar": "hungarian-based",
    "avpms": "hungarian-based",
    "isiscom": "hungarian-based",
    "maxmail": "hungarian-based",
    "microware": "hungarian-based",
    "globalnet2000": "hungarian-based",
    "uiwebservices": "hungarian-based",
    "aspnet": "hungarian-based",
    "ininet": "hungarian-based",
    "dtnet": "hungarian-based",
    "spamzabalo": "hungarian-based",
    "hosting4u": "hungarian-based",
    "giganet": "hungarian-based",
    "smtp-hu": "hungarian-based",
    "unas": "hungarian-based",
    # EU providers
    "forpsi": "european-based",
    "websupport": "european-based",
    "zoho": "european-based",
    "migadu": "european-based",
    "hostinger": "european-based",
    "vshosting": "european-based",
    "netclass": "european-based",
    "webnode": "european-based",
    "hostns-io": "european-based",
}


_FRONTEND_FIELDS = {
    "name",
    "domain",
    "county",
    "mx",
    "spf",
    "provider",
    "category",
    "classification_confidence",
    "classification_signals",
    "gateway",
}


def _minify_for_frontend(full_output: dict[str, Any]) -> dict[str, Any]:
    """Strip fields the frontend doesn't use, producing a compact payload."""
    municipalities = {}
    for id, entry in full_output["municipalities"].items():
        mini = {k: v for k, v in entry.items() if k in _FRONTEND_FIELDS}
        mini["classification_signals"] = [
            {"kind": s["kind"], "provider": s["provider"], "detail": s["detail"]}
            for s in entry.get("classification_signals", [])
        ]
        municipalities[id] = mini
    return {
        "generated": full_output["generated"],
        "commit": full_output.get("commit"),
        "municipalities": municipalities,
    }


def _output_provider(provider: Provider) -> str:
    """Map Provider enum to output name for data.json."""
    return PROVIDER_OUTPUT_NAMES.get(provider.value, provider.value)


def _serialize_result(
    entry: dict[str, Any], result: ClassificationResult
) -> dict[str, Any]:
    """Serialize a ClassificationResult into a data.json municipality entry."""
    provider = _output_provider(result.provider)
    category = _CATEGORY_MAP.get(provider, "unknown")
    out: dict[str, Any] = {
        "id": entry["id"],
        "name": entry["name"],
        "county": entry.get("county", ""),
        "domain": entry.get("domain", ""),
        "mx": result.mx_hosts,
        "spf": result.spf_raw,
        "provider": provider,
        "category": category,
        "classification_confidence": round(result.confidence * 100, 1),
        "classification_signals": [
            {
                "kind": e.kind.value,
                "provider": PROVIDER_OUTPUT_NAMES.get(
                    e.provider.value, e.provider.value
                ),
                "weight": e.weight,
                "detail": e.detail,
            }
            for e in result.evidence
        ],
    }

    if result.gateway:
        out["gateway"] = result.gateway

    # Pass through resolve-level fields
    if "sources_detail" in entry:
        out["sources_detail"] = entry["sources_detail"]
    if "flags" in entry:
        out["resolve_flags"] = entry["flags"]

    return out


async def run(domains_path: Path, output_path: Path) -> None:
    with open(domains_path, encoding="utf-8") as f:
        domains_data = json.load(f)

    entries = domains_data["municipalities"]
    total = len(entries)

    logger.info("Classifying {} municipalities", total)
    t0 = time.monotonic()

    # Build domain -> entry mapping
    domain_to_entries: dict[str, list[dict[str, Any]]] = {}
    no_domain_entries: list[dict[str, Any]] = []
    for entry in entries.values():
        domain = entry.get("domain", "")
        if domain:
            domain_to_entries.setdefault(domain, []).append(entry)
        else:
            no_domain_entries.append(entry)

    unique_domains = list(domain_to_entries.keys())

    results: dict[str, dict[str, Any]] = {}
    done = 0
    # TEMP LOGGING START
    _unresolved_mx: Counter[str] = Counter()
    _unresolved_spf: Counter[str] = Counter()
    _unresolved_gw: Counter[str] = Counter()
    _unresolved_samples: dict[str, list[str]] = defaultdict(list)
    _independent_mx: Counter[str] = Counter()
    _independent_spf: Counter[str] = Counter()
    _independent_gw: Counter[str] = Counter()
    _independent_samples: dict[str, list[str]] = defaultdict(list)
    # TEMP LOGGING END

    # Handle entries without domains
    for entry in no_domain_entries:
        results[entry["id"]] = {
            "id": entry["id"],
            "name": entry["name"],
            "county": entry.get("county", ""),
            "domain": "",
            "mx": [],
            "spf": "",
            "provider": "unknown",
            "category": "unknown",
            "classification_confidence": 0.0,
            "classification_signals": [],
        }
        if "sources_detail" in entry:
            results[entry["id"]]["sources_detail"] = entry["sources_detail"]
        if "flags" in entry:
            results[entry["id"]]["resolve_flags"] = entry["flags"]

    # Classify domains
    async for domain, classification in classify_many(unique_domains):
        for entry in domain_to_entries[domain]:
            serialized = _serialize_result(entry, classification)
            results[entry["id"]] = serialized

        # TEMP LOGGING START
        if classification.provider.value == "unresolved":
            for host in classification.mx_hosts:
                labels = host.rstrip(".").split(".")
                root = ".".join(labels[-2:]) if len(labels) >= 2 else host
                _unresolved_mx[root] += 1
                _unresolved_samples[root].append(domain)
            for tok in classification.spf_raw.split():
                if tok.lower().startswith("include:"):
                    inc = tok[8:]
                    _unresolved_spf[inc] += 1
            if classification.gateway:
                _unresolved_gw[classification.gateway] += 1
        if classification.provider.value == "independent":
            for host in classification.mx_hosts:
                labels = host.rstrip(".").split(".")
                root = ".".join(labels[-2:]) if len(labels) >= 2 else host
                _independent_mx[root] += 1
                _independent_samples[root].append(domain)
            for tok in classification.spf_raw.split():
                if tok.lower().startswith("include:"):
                    inc = tok[8:]
                    _independent_spf[inc] += 1
            if classification.gateway:
                _independent_gw[classification.gateway] += 1
        # TEMP LOGGING END

        done += len(domain_to_entries[domain])
        cat_progress: dict[str, int] = {}
        for r in results.values():
            cat = _CATEGORY_MAP.get(r["provider"], "unknown")
            cat_progress[cat] = cat_progress.get(cat, 0) + 1
        logger.info(
            "[{:>4}/{}] {}: provider={} confidence={:.2f} signals={}",
            done,
            total,
            domain,
            classification.provider.value,
            classification.confidence,
            len(classification.evidence),
        )

    # Final counts
    counts = {}
    cat_counts: dict[str, int] = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1
        cat = _CATEGORY_MAP.get(r["provider"], "unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    elapsed = time.monotonic() - t0
    logger.info(
        "--- Classification: {} municipalities in {:.1f}s ---", len(results), elapsed
    )
    logger.info(
        "  US Cloud         {:>5}  (MS={} Google={} AWS={})",
        cat_counts.get("us-cloud", 0),
        counts.get("microsoft", 0),
        counts.get("google", 0),
        counts.get("aws", 0),
    )
    logger.info(
        "  Hungarian Based  {:>5}  (named={} isp={} independent={})",
        cat_counts.get("hungarian-based", 0),
        cat_counts.get("hungarian-based", 0)
        - counts.get("hungarian-isp", 0)
        - counts.get("independent", 0),
        counts.get("hungarian-isp", 0),
        counts.get("independent", 0),
    )
    logger.info(
        "  EU Based         {:>5}",
        cat_counts.get("european-based", 0),
    )
    logger.info(
        "  Unresolved       {:>5}",
        cat_counts.get("unresolved", 0),
    )
    logger.info("  Unknown/No MX    {:>5}", cat_counts.get("unknown", 0))
    # TEMP LOGGING START
    if _unresolved_mx:
        logger.info("--- UNRESOLVED: top MX roots ---")
        for root, cnt in _unresolved_mx.most_common(20):
            samples = ", ".join(sorted(set(_unresolved_samples[root]))[:3])
            logger.info("  {:<35} {:>3}  {}", root, cnt, samples)
    if _unresolved_spf:
        logger.info("--- UNRESOLVED: top SPF includes ---")
        for inc, cnt in _unresolved_spf.most_common(15):
            logger.info("  {:<40} {:>3}", inc, cnt)
    if _unresolved_gw:
        logger.info("--- UNRESOLVED: gateways ---")
        for gw, cnt in _unresolved_gw.most_common():
            logger.info("  {:<20} {:>3}", gw, cnt)
    if _independent_mx:
        logger.info("--- INDEPENDENT: top MX roots ---")
        for root, cnt in _independent_mx.most_common(20):
            samples = ", ".join(sorted(set(_independent_samples[root]))[:3])
            logger.info("  {:<35} {:>3}  {}", root, cnt, samples)
    if _independent_spf:
        logger.info("--- INDEPENDENT: top SPF includes ---")
        for inc, cnt in _independent_spf.most_common(15):
            logger.info("  {:<40} {:>3}", inc, cnt)
    if _independent_gw:
        logger.info("--- INDEPENDENT: gateways ---")
        for gw, cnt in _independent_gw.most_common():
            logger.info("  {:<20} {:>3}", gw, cnt)
    # TEMP LOGGING END

    sorted_counts = dict(sorted(counts.items()))
    sorted_munis = dict(sorted(results.items(), key=lambda kv: int(kv[0])))

    commit = (
        subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        or None
    )

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commit": commit,
        "total": len(results),
        "counts": sorted_counts,
        "municipalities": sorted_munis,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    size_kb = len(json.dumps(output)) / 1024

    mini_output = _minify_for_frontend(output)
    mini_path = output_path.with_suffix(".min.json")
    with open(mini_path, "w", encoding="utf-8") as f:
        json.dump(mini_output, f, ensure_ascii=False, separators=(",", ":"))

    mini_size_kb = mini_path.stat().st_size / 1024
    logger.info("Wrote {} ({} KB)", output_path, size_kb)
    logger.info("Wrote {} ({:.0f} KB)", mini_path, mini_size_kb)
