"""Statistical analysis of municipality email classification data."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

from .pipeline import _CATEGORY_MAP

# ---------------------------------------------------------------------------
# ANSI color helpers (respect NO_COLOR convention and pipe detection)
# ---------------------------------------------------------------------------

try:
    _is_tty = os.isatty(sys.stdout.fileno())
except Exception:
    _is_tty = False

_NO_COLOR = os.environ.get("NO_COLOR") is not None or not _is_tty


def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return str(text)
    return f"\033[{code}m{text}\033[0m"


def _bold(t: str) -> str:
    return _c("1", t)


def _dim(t: str) -> str:
    return _c("2", t)


def _red(t: str) -> str:
    return _c("31", t)


def _green(t: str) -> str:
    return _c("32", t)


def _yellow(t: str) -> str:
    return _c("33", t)


def _blue(t: str) -> str:
    return _c("34", t)


def _plain(t: str) -> str:
    return t


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

_BAR_FULL = "#"
_BAR_EMPTY = "."


def _bar(value: float, max_value: float, width: int = 25) -> str:
    if max_value == 0:
        return _BAR_EMPTY * width
    filled = int(round(value / max_value * width))
    return _BAR_FULL * filled + _BAR_EMPTY * (width - filled)


def _pct(n: int, total: int) -> str:
    if total == 0:
        return "  0.0%"
    return f"{n / total * 100:5.1f}%"


def _header(title: str) -> None:
    line = "=" * 66
    print(f"\n{_bold(line)}")
    print(f"  {_bold(title)}")
    print(_bold(line))


def _sep() -> None:
    print("  " + "-" * 62)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_data(path: Path) -> dict[str, Any]:
    """Load data.json and return the full dict."""
    if not path.exists():
        print(f"Error: {path} not found. Run the pipeline first.", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CATEGORIES_ORDERED = [
    "us-cloud",
    "hungarian-based",
    "european-based",
    "unresolved",
    "unknown",
]

_CATEGORY_LABELS: dict[str, str] = {
    "us-cloud": "US Cloud",
    "hungarian-based": "Hungarian Based",
    "european-based": "European Based",
    "unresolved": "Unresolved",
    "unknown": "Unknown",
}

_CATEGORY_COLOR: dict[str, Callable[[str], str]] = {
    "us-cloud": _red,
    "hungarian-based": _green,
    "european-based": _blue,
    "unresolved": _yellow,
    "unknown": _dim,
}

_PRIMARY_SIGNAL_KINDS = {"mx", "spf", "dkim", "autodiscover"}


def _category(provider: str) -> str:
    return _CATEGORY_MAP.get(provider, "unknown")


def _color_for(provider: str) -> Callable[[str], str]:
    return _CATEGORY_COLOR.get(_category(provider), _plain)


# ---------------------------------------------------------------------------
# 1. Overall Summary
# ---------------------------------------------------------------------------


def report_overall_summary(data: dict[str, Any], munis: dict[str, Any]) -> None:
    _header("OVERALL SUMMARY")
    total = len(munis)
    generated = data.get("generated", "?")
    commit = data.get("commit", "?")
    print(f"  Generated: {generated}  (commit {commit})")
    print(f"  Total municipalities: {total:,}")

    # Category split
    cat_counts: Counter[str] = Counter()
    for m in munis.values():
        cat_counts[_category(m["provider"])] += 1

    print()
    print(f"  {'Category':<18} {'Count':>6}  {'%':>6}  Bar")
    _sep()
    for cat in _CATEGORIES_ORDERED:
        cnt = cat_counts.get(cat, 0)
        if cnt == 0:
            continue
        label = _CATEGORY_LABELS[cat]
        color = _CATEGORY_COLOR[cat]
        print(
            f"  {color(f'{label:<18}')} {cnt:>6,}  {_pct(cnt, total)}  "
            f"{color(_bar(cnt, total))}"
        )

    # Provider distribution — top 15 by count
    prov_counts: Counter[str] = Counter()
    for m in munis.values():
        prov_counts[m["provider"]] += 1

    print()
    print(f"  {'Provider':<20} {'Count':>6}  {'%':>6}  Bar")
    _sep()
    max_cnt = max(prov_counts.values()) if prov_counts else 1
    top15 = prov_counts.most_common(15)
    for prov, cnt in top15:
        color = _color_for(prov)
        print(
            f"  {color(f'{prov:<20}')} {cnt:>6,}  {_pct(cnt, total)}  "
            f"{color(_bar(cnt, max_cnt))}"
        )
    shown = sum(cnt for _, cnt in top15)
    if shown < total:
        rest = total - shown
        print(
            f"  {_dim(f'(other providers)' + '  ' * 6)} {rest:>6,}  {_pct(rest, total)}"
        )


# ---------------------------------------------------------------------------
# 2. County Breakdown
# ---------------------------------------------------------------------------


def report_county(munis: dict[str, Any]) -> None:
    _header("COUNTY BREAKDOWN (sorted by US-Cloud %)")

    by_county: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for m in munis.values():
        by_county[m.get("county", "(unknown)")].append(m)

    rows: list[tuple[str, int, dict[str, int], float]] = []
    for county, entries in by_county.items():
        total = len(entries)
        cat_counts: Counter[str] = Counter(_category(e["provider"]) for e in entries)
        us_pct = cat_counts.get("us-cloud", 0) / total * 100 if total else 0
        rows.append((county, total, dict(cat_counts), us_pct))

    rows.sort(key=lambda r: r[3], reverse=True)

    print(
        f"  {'County':<28}{'Total':>5}"
        f"{'US':>5}{'HU':>5}{'EU':>5}{'Unres':>6}"
        f"  {'US%':>6}  {'HU%':>6}"
    )
    _sep()

    for county, total, cc, us_pct in rows:
        us_cnt = cc.get("us-cloud", 0)
        hu_cnt = cc.get("hungarian-based", 0)
        eu_cnt = cc.get("european-based", 0)
        unres = cc.get("unresolved", 0) + cc.get("unknown", 0)
        hu_pct = hu_cnt / total * 100 if total else 0
        color = _red if us_pct >= 50 else (_yellow if us_pct >= 30 else _green)
        label = (county[:26] + "..") if len(county) > 26 else county
        print(
            f"  {label:<28}{total:>5}"
            f"{us_cnt:>5}{hu_cnt:>5}{eu_cnt:>5}{unres:>6}"
            f"  {color(f'{us_pct:5.1f}%')}"
            f"  {f'{hu_pct:5.1f}%':>6}"
        )


# ---------------------------------------------------------------------------
# 3. Confidence Distribution
# ---------------------------------------------------------------------------


def report_confidence(munis: dict[str, Any]) -> None:
    _header("CONFIDENCE DISTRIBUTION")

    confidences = [m["classification_confidence"] for m in munis.values()]
    total = len(confidences)

    buckets = [(90, 100), (80, 90), (70, 80), (60, 70), (50, 60), (0, 50)]
    bucket_counts = []
    for lo, hi in buckets:
        cnt = sum(1 for c in confidences if lo <= c <= (hi if hi == 100 else hi - 0.01))
        bucket_counts.append(cnt)

    max_cnt = max(bucket_counts) if bucket_counts else 1
    print(f"  {'Range':<12} {'Count':>6}  {'%':>6}  Bar")
    _sep()
    for (lo, hi), cnt in zip(buckets, bucket_counts):
        label = f"{lo}-{hi}%"
        print(f"  {label:<12} {cnt:>6,}  {_pct(cnt, total)}  {_bar(cnt, max_cnt)}")

    avg = sum(confidences) / total if total else 0
    print(f"\n  Average confidence: {_bold(f'{avg:.1f}%')}")

    # Per-category confidence stats
    by_cat: dict[str, list[float]] = defaultdict(list)
    for m in munis.values():
        by_cat[_category(m["provider"])].append(m["classification_confidence"])

    print()
    print(f"  {'Category':<18} {'Avg':>6}  {'Min':>6}  {'<60':>5}")
    _sep()
    for cat in _CATEGORIES_ORDERED:
        confs = by_cat.get(cat, [])
        if not confs:
            continue
        avg_p = sum(confs) / len(confs)
        min_p = min(confs)
        low = sum(1 for c in confs if c < 60)
        low_str = _red(f"{low:>5}") if low > 0 else f"{low:>5}"
        label = _CATEGORY_LABELS[cat]
        print(f"  {label:<18} {avg_p:>5.1f}%  {min_p:>5.1f}%  {low_str}")


# ---------------------------------------------------------------------------
# 4. Signal Analysis
# ---------------------------------------------------------------------------


def report_signals(munis: dict[str, Any]) -> None:
    _header("SIGNAL ANALYSIS")

    total = len(munis)

    signal_counts: Counter[str] = Counter()
    combo_counts: Counter[str] = Counter()
    single_signal: list[dict[str, Any]] = []
    zero_signal: list[dict[str, Any]] = []

    for m in munis.values():
        signals = m.get("classification_signals", [])
        kinds = sorted({s["kind"] for s in signals})
        for k in kinds:
            signal_counts[k] += 1
        if kinds:
            combo_counts["+".join(kinds)] += 1
        if len(kinds) == 1:
            single_signal.append(m)
        elif len(kinds) == 0:
            zero_signal.append(m)

    print("  Signal coverage (% of municipalities with each signal):\n")
    print(f"  {'Signal':<20} {'Count':>6}  {'%':>6}")
    _sep()
    for kind, cnt in signal_counts.most_common():
        print(f"  {kind:<20} {cnt:>6,}  {_pct(cnt, total)}")

    print("\n  Top 15 signal combinations:\n")
    print(f"  {'#':<4} {'Combination':<50} {'Count':>6}")
    _sep()
    for i, (combo, cnt) in enumerate(combo_counts.most_common(15), 1):
        print(f"  {i:<4} {combo:<50} {cnt:>6,}")

    print(f"\n  Single-signal municipalities: {_yellow(str(len(single_signal)))}")
    for m in single_signal[:5]:
        sig = m["classification_signals"][0]
        print(f"    {m['id']:>6}  {m['name']:<30} {sig['kind']}:{sig['provider']}")
    if len(single_signal) > 5:
        print(f"    {_dim(f'... and {len(single_signal) - 5} more')}")

    print(f"\n  Zero-signal municipalities: {_yellow(str(len(zero_signal)))}")
    for m in zero_signal[:5]:
        print(f"    {m['id']:>6}  {m['name']:<30} provider={m['provider']}")
    if len(zero_signal) > 5:
        print(f"    {_dim(f'... and {len(zero_signal) - 5} more')}")


# ---------------------------------------------------------------------------
# 5. Gateway Report
# ---------------------------------------------------------------------------


def report_gateways(munis: dict[str, Any]) -> None:
    _header("GATEWAY REPORT")

    total = len(munis)
    with_gw = {k: m for k, m in munis.items() if m.get("gateway")}
    without_gw = {k: m for k, m in munis.items() if not m.get("gateway")}

    print(
        f"  Municipalities with gateway: "
        f"{_bold(str(len(with_gw)))} / {total} ({len(with_gw) / total * 100:.1f}%)"
    )

    gw_counts: Counter[str] = Counter(m["gateway"] for m in with_gw.values())
    if gw_counts:
        print()
        print(f"  {'Gateway':<20} {'Count':>6}")
        _sep()
        for gw, cnt in gw_counts.most_common():
            print(f"  {gw:<20} {cnt:>6,}")

    print("\n  Category distribution:\n")
    print(f"  {'Category':<18}  {'With GW':>8} {'%':>6}  {'No GW':>8} {'%':>6}")
    _sep()
    for cat in _CATEGORIES_ORDERED:
        cnt_w = sum(1 for m in with_gw.values() if _category(m["provider"]) == cat)
        cnt_wo = sum(1 for m in without_gw.values() if _category(m["provider"]) == cat)
        if cnt_w == 0 and cnt_wo == 0:
            continue
        label = _CATEGORY_LABELS[cat]
        print(
            f"  {label:<18}"
            f"  {cnt_w:>8,} {_pct(cnt_w, len(with_gw) or 1)}"
            f"  {cnt_wo:>8,} {_pct(cnt_wo, len(without_gw) or 1)}"
        )


# ---------------------------------------------------------------------------
# 6. Domain Sharing
# ---------------------------------------------------------------------------


def report_domain_sharing(munis: dict[str, Any]) -> None:
    _header("SHARED DOMAINS")

    by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for m in munis.values():
        if m.get("domain"):
            by_domain[m["domain"]].append(m)

    shared = {d: ms for d, ms in by_domain.items() if len(ms) > 1}
    shared_sorted = sorted(shared.items(), key=lambda x: len(x[1]), reverse=True)

    print(f"  Domains used by multiple municipalities: {_bold(str(len(shared)))}")
    if not shared_sorted:
        return

    print()
    print(f"  {'Domain':<30} {'Count':>5}  {'Provider':<14} Municipalities")
    _sep()
    for domain, ms in shared_sorted:
        names = ", ".join(m["name"] for m in ms[:4])
        suffix = f", +{len(ms) - 4}" if len(ms) > 4 else ""
        print(f"  {domain:<30} {len(ms):>5}  {ms[0]['provider']:<14} {names}{suffix}")


# ---------------------------------------------------------------------------
# 7. Low-Confidence / Review Candidates
# ---------------------------------------------------------------------------


def report_low_confidence(munis: dict[str, Any]) -> None:
    _header("LOW-CONFIDENCE / REVIEW CANDIDATES")

    low = [m for m in munis.values() if m["classification_confidence"] < 60]
    low.sort(key=lambda m: m["classification_confidence"])

    print(f"  Municipalities with confidence < 60%: {_red(str(len(low)))}")
    if low:
        print()
        print(
            f"  {'ID':>6}  {'Name':<28} {'County':<20} {'Provider':<16} "
            f"{'Conf':>5}  Signals"
        )
        _sep()
        for m in low:
            signals = "+".join(
                sorted({s["kind"] for s in m.get("classification_signals", [])})
            )
            county = m.get("county", "")
            county_label = (county[:18] + "..") if len(county) > 18 else county
            print(
                f"  {m['id']:>6}  {m['name']:<28} "
                f"{county_label:<20}  "
                f"{m['provider']:<16} "
                f"{m['classification_confidence']:>4.0f}%  {signals}"
            )

    # Conflicting primary signals
    conflicts: list[tuple[dict[str, Any], str, set[str]]] = []
    for m in munis.values():
        signals = m.get("classification_signals", [])
        winner = m["provider"]
        primary_by_other: dict[str, set[str]] = defaultdict(set)
        for s in signals:
            if s["kind"] in _PRIMARY_SIGNAL_KINDS and s["provider"] != winner:
                primary_by_other[s["provider"]].add(s["kind"])
        for other_prov, kinds in primary_by_other.items():
            conflicts.append((m, other_prov, kinds))

    print(
        f"\n  Conflicting primary signals "
        f"(non-winner has MX/SPF/DKIM/AD): {_yellow(str(len(conflicts)))}"
    )
    if conflicts:
        conflicts.sort(key=lambda x: len(x[2]), reverse=True)
        print()
        print(f"  {'ID':>6}  {'Name':<28} {'Winner':<16} {'Conflict':>14}  Signals")
        _sep()
        for m, other, kinds in conflicts[:20]:
            print(
                f"  {m['id']:>6}  {m['name']:<28} {m['provider']:<16} "
                f"{other:>14}  {'+'.join(sorted(kinds))}"
            )
        if len(conflicts) > 20:
            print(f"    {_dim(f'... and {len(conflicts) - 20} more')}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    data = load_data(Path("data/data.json"))
    munis = data["municipalities"]

    report_overall_summary(data, munis)
    report_county(munis)
    report_confidence(munis)
    report_signals(munis)
    report_gateways(munis)
    report_domain_sharing(munis)
    report_low_confidence(munis)

    print()
