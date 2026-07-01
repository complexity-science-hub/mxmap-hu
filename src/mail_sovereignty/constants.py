import re

SPARQL_URL = "https://query.wikidata.org/sparql"
SPARQL_QUERY = """
SELECT ?item ?itemLabel ?id ?website ?countyLabel WHERE {
  # Hungarian settlements/municipalities with a KSH code.
  # P939 = KSH code, usually 5 digits, e.g. 05430.
  ?item wdt:P939 ?id .
  ?item wdt:P17 wd:Q28 .              # country: Hungary

  # Prefer current Hungarian municipalities/settlements.
  # Some Hungarian items are typed as town/city/etc., so P939 + country is more robust
  # than requiring only P31=Q2590631.
  OPTIONAL {
    ?item wdt:P31/wdt:P279* wd:Q2590631 .
  }

  # Exclude dissolved places.
  FILTER NOT EXISTS {
    ?item wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }

  # Exclude entities explicitly replaced by a successor.
  FILTER NOT EXISTS {
    ?item wdt:P1366 ?successor .
  }

  # Exclude ended municipality-of-Hungary type statements, if present.
  FILTER NOT EXISTS {
    ?item p:P31 ?stmt .
    ?stmt ps:P31 ?class .
    ?class wdt:P279* wd:Q2590631 .
    ?stmt pq:P582 ?endTime .
    FILTER(?endTime <= NOW())
  }

  OPTIONAL { ?item wdt:P856 ?website . }   # official website

  # County, if present.
  OPTIONAL {
    ?item wdt:P131+ ?county .
    ?county wdt:P31 wd:Q188604 .        
  }

  SERVICE wikibase:label {
    bd:serviceParam wikibase:language "hu,en" .
  }
}
ORDER BY xsd:integer(?ksh)
"""

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(
    r"linkTo_UnCryptMailto\((?:['\"]|%27|%22)([^'\"]+?)(?:['\"]|%27|%22)"
)


SOURCE_KEYS = (
    "override",
    "override_scrape",
    "override_redirect",
    "wikidata",
    "wikidata_scrape",
    "wikidata_redirect",
    "guess",
    "guess_scrape",
    "guess_redirect",
)

SKIP_DOMAINS = {
    # Examples / metadata
    "example.com",
    "example.org",
    "example.hu",
    "w3.org",
    "schema.org",
    # Google / analytics / embeds
    "google.com",
    "google.hu",
    "gstatic.com",
    "googleapis.com",
    "googletagmanager.com",
    "google-analytics.com",
    "recaptcha.net",
    "docs.google.com",
    "forms.gle",
    # Social / video
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "youtu.be",
    "tiktok.com",
    "x.com",
    "twitter.com",
    # Hungarian central government / public admin portals
    "magyarorszag.hu",
    "mo.hu",
    "ugyfelkapu.gov.hu",
    "epapir.gov.hu",
    "e-onkormanyzat.gov.hu",
    "kormany.hu",
    "allamkincstar.gov.hu",
    "kozadat.hu",
    "naih.hu",
    "njt.hu",
    "net.jogtar.hu",
    "nfk.gov.hu",
    # Generic email providers
    "gmail.com",
    "freemail.hu",
    "citromail.hu",
    "indamail.hu",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "mail.com",
    "t-online.hu",
    # CMS / hosting / third-party tools
    "wordpress.org",
    "wordpress.com",
    "wix.com",
    "wixsite.com",
    "webnode.hu",
    "webnode.com",
    "blog.hu",
    "jotform.com",
    "calendly.com",
    "sentry.io",
    "eoldal.hu",
}

SUBPAGES = [
    # contact pages
    "/kapcsolat",
    "/elerhetoseg",
    "/elerhetosegek",
    "/onkormanyzat",
    "/polgarmesteri-hivatal",
    # Public-interest data pages
    "/kozerdeku-adatok",
    "/kozerdeku",
    "/altalanos-kozzeteteli-lista",
    "/kozzeteteli-lista",
    # Administration pages
    "/ugyfelfogadas",
    "/ugyintezes",
    "/e-ugyintezes",
    "/elektronikus-ugyintezes",
    # Legal/footer pages
    "/impresszum",
    "/adatvedelem",
]

CONCURRENCY_POSTPROCESS = 10
