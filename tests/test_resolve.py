import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
import stamina

from mail_sovereignty.resolve import (
    _is_ssl_error,
    _process_scrape_response,
    build_urls,
    decrypt_typo3,
    detect_mismatch,
    extract_email_domain_counts,
    fetch_wikidata,
    guess_domains,
    load_overrides,
    resolve_municipality_domain,
    run,
    scrape_email_domains,
    url_to_domain,
)


# ── url_to_domain() ─────────────────────────────────────────────────


class TestUrlToDomain:
    def test_full_url_with_path(self):
        assert url_to_domain("https://www.debrecen.hu/some/path") == "debrecen.hu"

    def test_no_scheme(self):
        assert url_to_domain("debrecen.hu") == "debrecen.hu"

    def test_strips_www(self):
        assert url_to_domain("https://www.example.hu") == "example.hu"

    def test_empty_string(self):
        assert url_to_domain("") is None

    def test_none(self):
        assert url_to_domain(None) is None

    def test_bare_domain(self):
        assert url_to_domain("example.hu") == "example.hu"

    def test_http_scheme(self):
        assert url_to_domain("http://example.hu/page") == "example.hu"


# ── guess_domains() ─────────────────────────────────────────────────


class TestGuessDomains:
    def test_simple_name(self):
        domains = guess_domains("Debrecen")
        assert "debrecen.hu" in domains
        assert "debrecen.asp.lgov.hu" in domains

    def test_umlaut(self):
        domains = guess_domains("Győr")
        assert "gyor.hu" in domains

    def test_suffixes(self):
        domains = guess_domains("Debrecen")
        assert "debrecen-kozseg.hu" in domains
        assert "debrecen-nagykozseg.hu" in domains
        assert "debrecen-varos.hu" in domains
        assert "debrecen-falu.hu" in domains
        assert "debrecen-onkormanyzat.hu" in domains
        assert "debrecenkozseg.hu" in domains
        assert "debrecennagykozseg.hu" in domains
        assert "debrecenvaros.hu" in domains
        assert "debrecenfalu.hu" in domains
        assert "debrecenonkormanyzat.hu" in domains


# ── detect_mismatch() ────────────────────────────────────────


class TestDetectWebsiteMismatch:
    def test_matching_domain(self):
        assert detect_mismatch("Eger", "eger.hu") is False

    def test_umlaut_with_stadt_suffix(self):
        assert detect_mismatch("Győr", "gyorvaros.hu") is False

    def test_mismatch(self):
        assert detect_mismatch("Eger", "totally-unrelated.hu") is True

    def test_empty_name(self):
        assert detect_mismatch("", "example.hu") is False

    def test_empty_domain(self):
        assert detect_mismatch("Test", "") is False

    def test_www_prefix_stripped(self):
        assert detect_mismatch("Eger", "www.eger.hu") is False


# ── fetch_wikidata() ─────────────────────────────────────────────────


class TestFetchWikidata:
    @respx.mock
    async def test_success(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "id": {"value": "01234"},
                                "itemLabel": {"value": "Debrecen"},
                                "website": {"value": "https://www.debrecen.hu"},
                                "countyLabel": {"value": "Hajdú-Bihar"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert "01234" in result
        assert result["01234"]["name"] == "Debrecen"

    @respx.mock
    async def test_deduplication(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "id": {"value": "01234"},
                                "itemLabel": {"value": "Debrecen"},
                                "website": {"value": "https://www.debrecen.hu"},
                                "countyLabel": {"value": "Hajdú-Bihar"},
                            },
                            {
                                "id": {"value": "01234"},
                                "itemLabel": {"value": "Debrecen"},
                                "website": {"value": "https://www.debrecen.hu/alt"},
                                "countyLabel": {"value": "Hajdú-Bihar"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert len(result) == 1


# ── load_overrides() ─────────────────────────────────────────────────


class TestLoadOverrides:
    def test_load_existing(self, tmp_path):
        p = tmp_path / "overrides.json"
        p.write_text('{"01234": {"domain": "gyor.hu", "reason": "test"}}')
        result = load_overrides(p)
        assert "01234" in result
        assert result["01234"]["domain"] == "gyor.hu"

    def test_load_nonexistent(self, tmp_path):
        result = load_overrides(tmp_path / "nonexistent.json")
        assert result == {}


# ── decrypt_typo3() ──────────────────────────────────────────────────


class TestDecryptTypo3:
    def test_known_encrypted(self):
        encrypted = "kygjrm8yYz,af"
        decrypted = decrypt_typo3(encrypted)
        assert decrypted == "mailto:a@b.ch"

    def test_empty_string(self):
        assert decrypt_typo3("") == ""

    def test_offset_10_celerina(self):
        """Site encrypted with +10 offset; decrypt with -10 (== 16 mod 26)."""
        encoded = "wksvdy4sxpyJmovobsxk8mr"
        decrypted = decrypt_typo3(encoded, offset=-10)
        assert decrypted == "mailto:info@celerina.ch"

    def test_standard_offset_still_works(self):
        """No regression: offset=2 (default) still decrypts standard TYPO3."""
        encrypted = "kygjrm8yYz,af"
        assert decrypt_typo3(encrypted, offset=2) == "mailto:a@b.ch"


# ── extract_email_domain_counts() ──────────────────────────────────────────


class TestExtractEmailDomains:
    def test_plain_email(self):
        html = "Contact us at info@gemeinde.hu for more info."
        assert "gemeinde.hu" in extract_email_domain_counts(html)

    def test_mailto_link(self):
        html = '<a href="mailto:contact@town.hu">Email</a>'
        assert "town.hu" in extract_email_domain_counts(html)

    def test_typo3_obfuscated(self):
        html = """linkTo_UnCryptMailto('kygjrm8yYz,af')"""
        domains = extract_email_domain_counts(html)
        assert "b.ch" in domains

    def test_typo3_url_encoded_quotes(self):
        """TYPO3 regex matches %27 (URL-encoded single quote)."""
        html = "linkTo_UnCryptMailto(%27kygjrm8yYz,af%27)"
        domains = extract_email_domain_counts(html)
        assert "b.ch" in domains

    def test_typo3_auto_offset_detection(self):
        """Auto-detect offset for non-standard TYPO3 encryption (e.g. offset 10)."""
        html = "linkTo_UnCryptMailto(%27wksvdy4sxpyJmovobsxk8mr%27)"
        domains = extract_email_domain_counts(html)
        assert "celerina.ch" in domains

    def test_skip_domains_filtered(self):
        html = "admin@example.com test@sentry.io"
        domains = extract_email_domain_counts(html)
        assert "example.com" not in domains
        assert "sentry.io" not in domains

    def test_no_emails(self):
        html = "<html><body>No contact here</body></html>"
        assert not extract_email_domain_counts(html)

    def test_mailto_trailing_backslash(self):
        """BadEscape: backslash in mailto href should be stripped."""
        html = '<a href="mailto:info@debrecenex.hu\\">contact</a>'
        domains = extract_email_domain_counts(html)
        assert "debrecenex.hu" in domains

    def test_mailto_trailing_slash(self):
        """Trailing slash from malformed mailto should be stripped."""
        html = '<a href="mailto:info@townhall.hu/">contact</a>'
        domains = extract_email_domain_counts(html)
        assert "townhall.hu" in domains

    def test_bracket_at_obfuscation(self):
        html = "gemeinde[at]graechen.hu"
        assert "graechen.hu" in extract_email_domain_counts(html)

    def test_paren_at_obfuscation(self):
        html = "info(at)gemeinde.hu"
        assert "gemeinde.hu" in extract_email_domain_counts(html)

    def test_bracket_at_with_spaces(self):
        html = "info [at] town.hu"
        assert "town.hu" in extract_email_domain_counts(html)

    def test_bracket_at_uppercase(self):
        html = "admin[AT]village.hu"
        assert "village.hu" in extract_email_domain_counts(html)

    def test_bracket_at_skip_domain(self):
        html = "user[at]example.com"
        assert not extract_email_domain_counts(html)

    def test_domain_label_too_long(self):
        """Domains with labels > 63 chars should be filtered out."""
        long_label = "a" * 64
        html = f"contact@{long_label}.hu"
        assert not extract_email_domain_counts(html)

    def test_domain_with_slash_filtered(self):
        """Domains containing a slash (URL fragment) should be filtered out."""
        html = "user@galeriedelachampagne.hu/subpage"
        domains = extract_email_domain_counts(html)
        for d in domains:
            assert "/" not in d


# ── build_urls() ─────────────────────────────────────────────────────


class TestBuildUrls:
    def test_bare_domain(self):
        urls = build_urls("example.hu")
        assert "https://www.example.hu" in urls
        assert "https://example.hu" in urls

    def test_www_prefix(self):
        urls = build_urls("www.example.hu")
        assert "https://www.example.hu" in urls
        assert "https://example.hu" in urls


# ── scrape_email_domains() ───────────────────────────────────────────


class TestScrapeEmailDomains:
    async def test_empty_domain(self):
        result, redirect = await scrape_email_domains(None, "")
        assert not result
        assert redirect is None

    async def test_with_emails_found(self):
        class FakeResponse:
            status_code = 200
            text = "Contact us at info@gemeinde.hu"
            url = httpx.URL("https://www.gemeinde.hu/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "gemeinde.hu")
        assert "gemeinde.hu" in result
        assert redirect is None

    async def test_cross_domain_redirect_detected(self):
        """When website redirects to a different domain, redirect_domain is returned."""

        class FakeResponse:
            status_code = 200
            text = "Contact us at gemeinde@3908.hu"
            url = httpx.URL("https://www.3908.hu/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "gemeinde-saas-balen.hu")
        assert "3908.hu" in result
        assert redirect == "3908.hu"

    async def test_www_redirect_not_flagged(self):
        """Redirect from mygemeinde.hu to www.mygemeinde.hu is NOT a cross-domain redirect."""

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@mygemeinde.hu"
            url = httpx.URL("https://www.mygemeinde.hu/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "mygemeinde.hu")
        assert "mygemeinde.hu" in result
        assert redirect is None


# ── resolve_municipality_domain() ────────────────────────────────────


class TestResolveMunicipalityDomain:
    async def test_override_takes_priority(self):
        m = {
            "id": "01234",
            "name": "Győr",
            "county": "Győr-Moson-Sopron",
            "website": "https://www.gyor-varos.hu",
        }
        overrides = {"01234": {"domain": "gyor.hu", "reason": "test"}}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mail.protection.outlook.com"],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "gyor.hu"
        assert result["source"] == "override"
        assert result["confidence"] == "high"
        assert "sources_detail" in result
        assert "flags" in result

    async def test_multi_source_scrape_and_wikidata(self):
        """When scrape and wikidata agree, confidence is high."""
        m = {
            "id": "999",
            "name": "Test",
            "county": "",
            "website": "https://www.test.hu",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@test.hu"
            url = httpx.URL("https://www.test.hu/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "test.hu":
                return ["mail.test.hu"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "test.hu"
        assert result["confidence"] == "high"
        assert "test.hu" in result["sources_detail"]["wikidata_scrape"]
        assert "test.hu" in result["sources_detail"]["wikidata"]

    async def test_scrape_only_low(self):
        """When only wikidata_scrape finds a domain (no agreement), confidence is low."""
        # Use test-portal.hu as the website — not a guess domain for "Test"
        # (guesses are test.hu, test-varos.hu, etc.), so the scrape cache is not shared.
        m = {
            "id": "999",
            "name": "Test",
            "county": "",
            "website": "https://www.test-portal.hu",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@email-test.hu"
            url = httpx.URL("https://www.test-portal.hu/")

        async def fake_get(url, **_):
            if url.startswith("https://www.test-portal.hu") or url.startswith(
                "https://test-portal.hu"
            ):
                return FakeResponse()
            return httpx.Response(404)

        client = AsyncMock()
        client.get = AsyncMock(side_effect=fake_get)

        async def fake_lookup_mx(domain):
            if domain == "email-test.hu":
                return ["mail.email-test.hu"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "email-test.hu"
        assert result["source"] == "wikidata_scrape"
        assert result["confidence"] == "low"

    async def test_scrape_finds_different_domain_than_website(self):
        """Emőd case: website emod.hu has MX, but scraping finds emodph.hu."""
        m = {
            "id": "04677",
            "name": "Emőd",
            "county": "Borsod-Abaúj-Zemplén",
            "website": "https://www.emod.hu",
        }

        overrides = {}

        class FakeResponse:
            status_code = 200
            text = '<a href="mailto:hivatalemod@emodph.hu">Email</a>'
            url = httpx.URL("https://www.emod.hu/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "emod.hu":
                return ["emod.hu"]
            if domain == "emodph.hu":
                return ["emodph.hu"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        # Both scrape and wikidata found domains
        assert "emodph.hu" in result["sources_detail"]["wikidata_scrape"]
        assert "emod.hu" in result["sources_detail"]["wikidata"]

    async def test_none_when_no_domain_found(self):
        m = {"id": "999", "name": "Zzz", "county": "", "website": ""}
        overrides = {}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == ""
        assert result["source"] == "none"
        assert result["confidence"] == "none"
        assert "sources_detail" in result
        assert "flags" in result

    async def test_guess_only_low_confidence(self):
        """When only guess finds a domain, confidence is low."""
        m = {
            "id": "999",
            "name": "Testingen",
            "county": "Győr-Moson-Sopron",
            "website": "",
        }
        overrides = {}
        client = AsyncMock()

        async def fake_lookup_mx(domain):
            if domain == "testingen.hu":
                return ["mail.testingen.hu"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "testingen.hu"
        assert result["source"] == "guess"
        assert result["confidence"] == "low"
        assert "guess_only" in result["flags"]

    async def test_id_only_flag(self):
        """Municipalities only in ID get the id_only flag."""
        m = {
            "id": "999",
            "name": "NewTown",
            "county": "",
            "website": "",
            "id_only": True,
        }
        overrides = {}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert "id_only" in result["flags"]

    async def test_redirect_domain_used_as_source(self):
        """Gulács case: website gulacs.hu redirects to gulacskozseg.hu."""
        m = {
            "id": "29443",
            "name": "Gulács",
            "county": "Szabolcs-Szatmár-Bereg",
            "website": "https://www.gulacs.hu",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Hivatal: hivatal@gulacskozseg.hu"
            url = httpx.URL("https://www.gulacskozseg.hu/")  # redirected URL

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "gulacskozseg.hu":
                return ["mail.gulacskozseg.hu"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "gulacskozseg.hu"
        assert "gulacskozseg.hu" in result["sources_detail"]["wikidata_scrape"]
        assert "gulacskozseg.hu" in result["sources_detail"]["wikidata_redirect"]
        assert (
            result["confidence"] == "high"
        )  # wikidata_scrape + wikidata_redirect agree

    async def test_sources_disagree_flag(self):
        """sources_disagree when override scrape and wikidata find different domains."""
        m = {
            "id": "01234",
            "name": "Debrecen",
            "county": "Hajdú-Bihar",
            "website": "https://www.debrecen-info.hu",
        }
        # Override has a website (not a direct domain), so override scrape runs
        overrides = {"01234": {"website": "https://www.debrecen-hivatal.hu"}}

        async def fake_get(url, **_):
            if "debrecen-hivatal.hu" in url:

                class R:
                    status_code = 200
                    text = '<a href="mailto:hivatal@debrecen-ph.hu">contact</a>'
                    url = httpx.URL("https://www.debrecen-hivatal.hu/")

                return R()
            return httpx.Response(404)

        client = AsyncMock()
        client.get = AsyncMock(side_effect=fake_get)

        async def fake_lookup_mx(domain):
            if domain in ("debrecen-info.hu", "debrecen-ph.hu"):
                return [f"mail.{domain}"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert "sources_disagree" in result["flags"]
        assert "debrecen-info.hu" in result["sources_detail"]["wikidata"]
        assert "debrecen-ph.hu" in result["sources_detail"]["override_scrape"]


# ── run() ────────────────────────────────────────────────────────────


# Sample municipalities CSV (matches data/municipalities.csv format)
SAMPLE_CSV = '"name,id,county"\n"Debrecen,01234,Hajdú-Bihar"\n'
EMPTY_CSV = '"name,id,county"\n'


class TestResolveRun:
    @respx.mock
    async def test_writes_output(self, tmp_path):
        csv_path = tmp_path / "municipalities.csv"
        csv_path.write_text(SAMPLE_CSV, encoding="utf-8")

        # Mock Wikidata
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "id": {"value": "01234"},
                                "itemLabel": {"value": "Debrecen"},
                                "website": {"value": "https://www.debrecen.hu"},
                                "countyLabel": {"value": "Hajdú-Bihar"},
                            },
                        ]
                    }
                },
            )
        )

        respx.get(url__regex=r"https://.*debrecen\.hu.*").mock(
            return_value=httpx.Response(404)
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.debrecen.hu"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv=csv_path)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 1
        assert "01234" in data["municipalities"]

    @respx.mock
    async def test_adds_override_only_municipalities(self, tmp_path):
        csv_path = tmp_path / "municipalities.csv"
        csv_path.write_text(EMPTY_CSV, encoding="utf-8")

        # Mock Wikidata (empty)
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={"results": {"bindings": []}},
            )
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.test.hu"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text(
                '{"02056": {"domain": "gyongyos.hu", "name": "Gyöngyös", "county": "Heves", "reason": "Missing from Wikidata"}}',
                encoding="utf-8",
            )
            await run(output, overrides, municipalities_csv=csv_path)

        data = json.loads(output.read_text())
        assert "02056" in data["municipalities"]
        assert data["municipalities"]["02056"]["source"] == "override"

    @respx.mock
    async def test_csv_wikidata_merge(self, tmp_path):
        """CSV municipalities get Wikidata website URLs merged in."""
        csv_path = tmp_path / "municipalities.csv"
        csv_path.write_text(SAMPLE_CSV, encoding="utf-8")

        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "id": {"value": "01234"},
                                "itemLabel": {"value": "Debrecen"},
                                "website": {"value": "https://www.debrecen.hu"},
                                "countyLabel": {"value": "Hajdú-Bihar"},
                            },
                        ]
                    }
                },
            )
        )

        respx.get(url__regex=r"https://.*debrecen\.hu.*").mock(
            return_value=httpx.Response(404)
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.debrecen.hu"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv=csv_path)

        data = json.loads(output.read_text())
        entry = data["municipalities"]["01234"]
        assert entry["name"] == "Debrecen"
        assert "sources_detail" in entry


# ── Wikidata retry ────────────────────────────────────────────────

WIKIDATA_JSON = {
    "results": {
        "bindings": [
            {
                "id": {"value": "01234"},
                "itemLabel": {"value": "Debrecen"},
                "website": {"value": "https://www.debrecen.hu"},
                "countyLabel": {"value": "Hajdú-Bihar"},
            },
        ]
    }
}


class TestFetchWikidataRetry:
    @respx.mock
    async def test_retries_on_503_then_succeeds(self):
        stamina.set_testing(False)
        route = respx.post("https://query.wikidata.org/sparql").mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(200, json=WIKIDATA_JSON),
            ]
        )
        result = await fetch_wikidata()
        assert "01234" in result
        assert route.call_count == 2

    @respx.mock
    async def test_raises_after_all_retries_exhausted(self):
        stamina.set_testing(False)
        route = respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(503)
        )
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_wikidata()
        assert route.call_count == 3


# ── Scrape error logging ─────────────────────────────────────────


class TestScrapeErrorLogging:
    async def test_logs_debug_on_exception(self, caplog):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=ConnectionError("refused"))

        result, redirect = await scrape_email_domains(client, "fail.hu")

        assert not result
        assert redirect is None
        assert any("Scrape" in msg and "refused" in msg for msg in caplog.messages)


# ── Error isolation in resolve run() ─────────────────────────────


class TestResolveRunErrorIsolation:
    @respx.mock
    async def test_skips_failing_municipality(self, tmp_path):
        """One failing resolution should not crash the whole run."""
        csv_path = tmp_path / "municipalities.csv"
        csv_path.write_text(
            '"name,id,county"\n"Debrecen,01234,Hajdú-Bihar"\n"Nyíregyháza,00942,Szabolcs-Szatmár-Bereg"\n',
            encoding="utf-8",
        )
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )

        call_count = 0

        async def _flaky_resolve(m, overrides, client):
            nonlocal call_count
            call_count += 1
            if m["id"] == "00942":
                raise RuntimeError("boom")
            return {
                "id": m["id"],
                "name": m["name"],
                "county": m.get("county", ""),
                "domain": "test.hu",
                "source": "guess",
                "confidence": "low",
                "sources_detail": {},
                "flags": [],
            }

        with patch(
            "mail_sovereignty.resolve.resolve_municipality_domain",
            side_effect=_flaky_resolve,
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv=csv_path)

        data = json.loads(output.read_text())
        # Debrecen succeeded, Nyíregyháza was skipped
        assert "01234" in data["municipalities"]
        assert "00942" not in data["municipalities"]


class TestResolveRunLogging:
    @respx.mock
    async def test_logs_id_only_warning(self, tmp_path, caplog):
        """CSV-only municipalities should produce a warning log."""
        # CSV has Debrecen, Wikidata is empty -> Debrecen is id-only
        csv_path = tmp_path / "municipalities.csv"
        csv_path.write_text(SAMPLE_CSV, encoding="utf-8")
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv=csv_path)

        assert any(
            "municipalities in id but missing from Wikidata" in msg
            for msg in caplog.messages
        )


# ── _process_scrape_response() ────────────────────────────────────────


class TestProcessScrapeResponse:
    def test_non_200_returns_unchanged(self):
        r = httpx.Response(404, request=httpx.Request("GET", "https://example.hu"))
        domains, redirect = _process_scrape_response(r, "example.hu", set(), None)
        assert not domains
        assert redirect is None

    def test_200_extracts_email_and_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@3908.hu",
            request=httpx.Request("GET", "https://www.3908.hu/"),
        )
        domains, redirect = _process_scrape_response(
            r, "gemeinde-saas-balen.hu", set(), None
        )
        assert "3908.hu" in domains
        assert redirect == "3908.hu"

    def test_200_same_domain_no_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@mygemeinde.hu",
            request=httpx.Request("GET", "https://www.mygemeinde.hu/"),
        )
        domains, redirect = _process_scrape_response(r, "mygemeinde.hu", set(), None)
        assert "mygemeinde.hu" in domains
        assert redirect is None

    def test_preserves_existing_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@other.hu",
            request=httpx.Request("GET", "https://www.other.hu/"),
        )
        domains, redirect = _process_scrape_response(
            r, "example.hu", set(), "already.hu"
        )
        assert "other.hu" in domains
        assert redirect == "already.hu"


# ── _is_ssl_error() ─────────────────────────────────────────────────


class TestIsSslError:
    def test_direct_ssl_error(self):
        import ssl

        exc = ssl.SSLCertVerificationError("certificate verify failed")
        assert _is_ssl_error(exc) is True

    def test_nested_ssl_error(self):
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL error")
        connect_exc.__cause__ = ssl_exc
        assert _is_ssl_error(connect_exc) is True

    def test_non_ssl_error(self):
        exc = ConnectionRefusedError("Connection refused")
        assert _is_ssl_error(exc) is False

    def test_string_fallback(self):
        exc = Exception("CERTIFICATE_VERIFY_FAILED in handshake")
        assert _is_ssl_error(exc) is True


# ── SSL retry in scrape_email_domains() ──────────────────────────────


class TestSslRetry:
    @pytest.mark.asyncio
    async def test_ssl_error_triggers_insecure_retry(self):
        """SSL error should trigger an insecure retry that recovers."""
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL handshake failed")
        connect_exc.__cause__ = ssl_exc

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        fake_response = AsyncMock()
        fake_response.status_code = 200
        fake_response.text = "Contact: gemeinde@3908.hu"
        fake_response.url = httpx.URL("https://www.3908.hu/")

        with patch(
            "mail_sovereignty.resolve._fetch_insecure",
            new_callable=AsyncMock,
            return_value=fake_response,
        ) as mock_fetch:
            domains, redirect = await scrape_email_domains(
                client, "gemeinde-saas-balen.hu"
            )

        assert "3908.hu" in domains
        assert redirect == "3908.hu"
        mock_fetch.assert_called()

    @pytest.mark.asyncio
    async def test_non_ssl_connect_error_no_retry(self):
        """Non-SSL ConnectError should not trigger insecure retry."""
        connect_exc = httpx.ConnectError("Connection refused")

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        with patch(
            "mail_sovereignty.resolve._fetch_insecure",
            new_callable=AsyncMock,
        ) as mock_fetch:
            domains, redirect = await scrape_email_domains(client, "example.hu")

        assert not domains
        assert redirect is None
        mock_fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_ssl_retry_failure_continues(self):
        """If insecure retry also fails, scrape should continue gracefully."""
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL handshake failed")
        connect_exc.__cause__ = ssl_exc

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        with patch(
            "mail_sovereignty.resolve._fetch_insecure",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("still broken"),
        ):
            domains, redirect = await scrape_email_domains(client, "example.hu")

        assert not domains
        assert redirect is None
