#!/usr/bin/env python3
"""
KOBİ CTI Portalı - veri toplayıcı
==================================
Açık kaynak tehdit istihbaratı kaynaklarını indirir, normalize eder ve
GitHub Pages'in sunacağı statik JSON / TXT dosyalarını üretir.

Yalnızca Python standart kütüphanesi kullanır (pip kurulumu gerekmez).

Kullanım:
    python scripts/fetch_feeds.py            # gerçek kaynaklardan topla
    python scripts/fetch_feeds.py --demo     # internet olmadan demo veri üret

Ortam değişkenleri (opsiyonel, GitHub Secrets olarak tanımlanabilir):
    ABUSECH_AUTH_KEY   abuse.ch Auth-Key (URLhaus / ThreatFox / Feodo)
    RANSOMWARELIVE_KEY ransomware.live PRO API anahtarı (yoksa ücretsiz uç kullanılır)
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import email.utils
import gzip
import html
import io
import ipaddress
import json
import os
import random
import re
import sys
import time
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
FEEDS = ROOT / "feeds"
UA = "KOBI-CTI-Portal/1.0 (+https://pages.github.com; open-source threat intel aggregator)"
NOW = dt.datetime.now(dt.timezone.utc)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TAG_RE = re.compile(r"<[^>]+>")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


# --------------------------------------------------------------------------- #
# Yardımcılar
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def http_get(url: str, headers: dict | None = None, timeout: int = 60, retries: int = 3) -> bytes:
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    last = None
    for attempt in range(1, retries + 1):
        try:
            with urlopen(Request(url, headers=h), timeout=timeout) as r:
                body = r.read()
                if r.headers.get("Content-Encoding") == "gzip" or body[:2] == b"\x1f\x8b":
                    body = gzip.decompress(body)
                return body
        except Exception as e:  # noqa: BLE001
            last = e
            log(f"  ! {url} deneme {attempt}/{retries}: {e}")
            time.sleep(2 * attempt)
    raise RuntimeError(f"{url}: {last}")


def get_json(url: str, **kw):
    return json.loads(http_get(url, **kw).decode("utf-8", "replace"))


def iso(d: dt.datetime | None) -> str | None:
    if not d:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(s) -> dt.datetime | None:
    if not s:
        return None
    s = str(s).strip()
    for fn in (
        lambda x: dt.datetime.fromisoformat(x.replace("Z", "+00:00")),
        lambda x: email.utils.parsedate_to_datetime(x),
        lambda x: dt.datetime.strptime(x[:19], "%Y-%m-%d %H:%M:%S"),
        lambda x: dt.datetime.strptime(x[:10], "%Y-%m-%d"),
    ):
        try:
            d = fn(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            return d
        except Exception:  # noqa: BLE001
            continue
    return None


def clean_text(s: str | None, limit: int = 400) -> str:
    if not s:
        return ""
    s = html.unescape(TAG_RE.sub(" ", s))
    s = re.sub(r"\s+", " ", s).strip()
    return (s[: limit - 1] + "…") if len(s) > limit else s


def safe_url(u: str | None) -> str:
    u = (u or "").strip()
    return u if u.lower().startswith(("http://", "https://")) else ""


def is_public_ip(v: str) -> bool:
    try:
        ip = ipaddress.ip_address(v)
        return ip.is_global
    except ValueError:
        return False


def ioc_type(v: str) -> str:
    if IPV4_RE.match(v):
        return "ip"
    if HASH_RE.match(v):
        return "hash"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    return "domain"


def write_json(name: str, obj) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    p = DATA / name
    p.write_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    log(f"  → data/{name} ({p.stat().st_size/1024:.0f} KB)")


def read_previous(name: str, default):
    p = DATA / name
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    return default


class Status:
    """Her kaynağın sağlık durumunu meta.json'a yazmak için tutar."""

    def __init__(self):
        self.items: list[dict] = []

    def ok(self, key, name, url, count, note=""):
        self.items.append({"key": key, "name": name, "url": url, "ok": True, "count": count,
                           "note": note, "checked": iso(NOW)})

    def fail(self, key, name, url, err):
        self.items.append({"key": key, "name": name, "url": url, "ok": False, "count": 0,
                           "note": str(err)[:300], "checked": iso(NOW)})


# --------------------------------------------------------------------------- #
# Kaynaklar
# --------------------------------------------------------------------------- #
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_API = "https://api.first.org/data/v1/epss?cve="
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"
USOM_API = "https://www.usom.gov.tr/api/address/index?page={page}"
RWL_FREE = "https://api.ransomware.live/v2/recentvictims"
RWL_PRO = "https://api-pro.ransomware.live/victims/recent"


def fetch_kev(st: Status):
    raw = get_json(KEV_URL)
    out = []
    for v in raw.get("vulnerabilities", []):
        out.append({
            "cve": v.get("cveID", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "desc": clean_text(v.get("shortDescription"), 600),
            "action": clean_text(v.get("requiredAction"), 400),
            "added": v.get("dateAdded", ""),
            "due": v.get("dueDate", ""),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "cwes": v.get("cwes") or [],
            "notes": [u for u in re.split(r"\s*;\s*|\s+", v.get("notes") or "") if safe_url(u)][:4],
        })
    out.sort(key=lambda x: x["added"], reverse=True)
    st.ok("kev", "CISA KEV", KEV_URL, len(out), f"Katalog sürümü {raw.get('catalogVersion', '?')}")
    return out


def fetch_epss(cves: list[str], st: Status) -> dict:
    want = set(cves)
    scores: dict[str, list[float]] = {}
    try:
        body = http_get(EPSS_URL, timeout=120).decode("utf-8", "replace")
        model = ""
        lines = body.splitlines()
        if lines and lines[0].startswith("#"):
            model = lines[0].lstrip("#")
            lines = lines[1:]
        for row in csv.DictReader(lines):
            c = row.get("cve")
            if c in want:
                scores[c] = [round(float(row["epss"]), 5), round(float(row["percentile"]), 4)]
        st.ok("epss", "FIRST EPSS", EPSS_URL, len(scores), model[:120])
        return scores
    except Exception as e:  # noqa: BLE001
        log(f"  EPSS CSV başarısız, API'ye düşülüyor: {e}")
    lst = sorted(want)
    for i in range(0, len(lst), 80):
        chunk = lst[i:i + 80]
        try:
            res = get_json(EPSS_API + ",".join(chunk))
            for d in res.get("data", []):
                scores[d["cve"]] = [round(float(d["epss"]), 5), round(float(d["percentile"]), 4)]
        except Exception as e:  # noqa: BLE001
            log(f"  EPSS API parça hatası: {e}")
        time.sleep(0.5)
    if scores:
        st.ok("epss", "FIRST EPSS (API)", EPSS_API, len(scores))
    else:
        st.fail("epss", "FIRST EPSS", EPSS_URL, "skor alınamadı")
    return scores


def abusech_headers():
    k = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    return {"Auth-Key": k} if k else {}


def fetch_feodo(st: Status, cap: int):
    raw = get_json(FEODO_URL, headers=abusech_headers())
    out = []
    for r in raw[:cap]:
        ip = r.get("ip_address")
        if not ip:
            continue
        out.append({"v": ip, "t": "ip", "s": "Feodo Tracker", "m": r.get("malware") or "botnet C2",
                    "d": (r.get("first_seen") or "")[:10], "st": r.get("status") or "",
                    "x": f"port {r.get('port')} · {r.get('as_name') or ''} · {r.get('country') or ''}".strip(" ·"),
                    "ref": f"https://feodotracker.abuse.ch/browse/host/{ip}/"})
    st.ok("feodo", "abuse.ch Feodo Tracker", FEODO_URL, len(out), "Botnet C2 sunucuları")
    return out


def fetch_urlhaus(st: Status, cap: int):
    body = http_get(URLHAUS_URL, headers=abusech_headers(), timeout=120).decode("utf-8", "replace")
    rows = [ln for ln in body.splitlines() if ln and not ln.startswith("#")]
    out = []
    reader = csv.reader(rows)
    for r in reader:
        if len(r) < 8:
            continue
        _id, added, url, status, _last, threat, tags, link = r[:8]
        out.append({"v": url, "t": "url", "s": "URLhaus", "m": threat or "malware_download",
                    "d": added[:10], "st": status, "x": tags.replace(",", ", "),
                    "ref": safe_url(link)})
    # önce çevrimiçi olanlar
    out.sort(key=lambda x: (x["st"] != "online", x["d"]), reverse=False)
    out = out[:cap]
    st.ok("urlhaus", "abuse.ch URLhaus", URLHAUS_URL, len(out), "Son 30 gün zararlı URL")
    return out


def fetch_threatfox(st: Status, cap: int):
    raw = get_json(THREATFOX_URL, headers=abusech_headers(), timeout=120)
    items = []
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, list):
                for x in v:
                    x.setdefault("id", k)
                    items.append(x)
    elif isinstance(raw, list):
        items = raw
    out = []
    for x in items:
        val = (x.get("ioc_value") or x.get("ioc") or "").strip()
        typ = x.get("ioc_type") or ""
        if not val:
            continue
        if typ == "ip:port":
            val = val.rsplit(":", 1)[0]
            t = "ip"
        elif typ == "domain":
            t = "domain"
        elif typ == "url":
            t = "url"
        elif "hash" in typ:
            t = "hash"
        else:
            t = ioc_type(val)
        out.append({"v": val, "t": t, "s": "ThreatFox", "m": x.get("malware_printable") or x.get("malware") or "",
                    "d": (x.get("first_seen_utc") or x.get("first_seen") or "")[:10],
                    "c": x.get("confidence_level"), "x": x.get("threat_type") or "",
                    "ref": f"https://threatfox.abuse.ch/ioc/{x.get('id')}/" if x.get("id") else ""})
    out.sort(key=lambda x: x["d"], reverse=True)
    out = out[:cap]
    st.ok("threatfox", "abuse.ch ThreatFox", THREATFOX_URL, len(out), "Son 48 saat IOC")
    return out


def fetch_usom(st: Status, pages: int, cap: int):
    out = []
    total = None
    for p in range(1, pages + 1):
        try:
            res = get_json(USOM_API.format(page=p), timeout=45)
        except Exception as e:  # noqa: BLE001
            if p == 1:
                raise
            log(f"  USOM sayfa {p} alınamadı: {e}")
            break
        models = res.get("models") or res.get("data") or []
        total = res.get("totalCount", total)
        if not models:
            break
        for m in models:
            v = (m.get("url") or "").strip()
            if not v:
                continue
            out.append({"v": v, "t": ioc_type(v), "s": "USOM", "m": m.get("desc") or "",
                        "d": (m.get("date") or "")[:10], "x": m.get("source") or "",
                        "c": m.get("criticality_level"),
                        "ref": "https://www.usom.gov.tr/adres"})
        time.sleep(0.4)
    out = out[:cap]
    st.ok("usom", "USOM Zararlı Bağlantılar", "https://www.usom.gov.tr/adres", len(out),
          f"Toplam kayıt: {total}" if total else "")
    return out


def fetch_rss(feeds: list[dict], st: Status, days: int, cap: int):
    cutoff = NOW - dt.timedelta(days=days)
    items = []
    ns = {"atom": "http://www.w3.org/2005/Atom", "dc": "http://purl.org/dc/elements/1.1/"}
    for f in feeds:
        try:
            root = ET.fromstring(http_get(f["url"], timeout=40))
            n = 0
            entries = root.findall(".//item") or root.findall(".//atom:entry", ns)
            for it in entries:
                title = it.findtext("title") or it.findtext("atom:title", namespaces=ns) or ""
                link = it.findtext("link") or ""
                if not link:
                    le = it.find("atom:link", ns)
                    link = le.get("href") if le is not None else ""
                date = (it.findtext("pubDate") or it.findtext("dc:date", namespaces=ns)
                        or it.findtext("atom:updated", namespaces=ns)
                        or it.findtext("atom:published", namespaces=ns))
                desc = it.findtext("description") or it.findtext("atom:summary", namespaces=ns) or ""
                d = parse_date(date) or NOW
                if d < cutoff:
                    continue
                text = f"{title} {desc}"
                items.append({"title": clean_text(title, 220), "link": safe_url(link.strip()),
                              "date": iso(d), "source": f["name"], "summary": clean_text(desc, 320),
                              "cves": sorted({c.upper() for c in CVE_RE.findall(text)})[:8]})
                n += 1
            st.ok(f"rss:{f['name']}", f"RSS · {f['name']}", f["url"], n)
        except Exception as e:  # noqa: BLE001
            st.fail(f"rss:{f['name']}", f"RSS · {f['name']}", f["url"], e)
    seen, uniq = set(), []
    for it in sorted(items, key=lambda x: x["date"], reverse=True):
        k = it["link"] or it["title"]
        if k in seen:
            continue
        seen.add(k)
        uniq.append(it)
    return uniq[:cap]


def fetch_ransomware(st: Status, country: str):
    key = os.environ.get("RANSOMWARELIVE_KEY", "").strip()
    if key:
        raw = get_json(RWL_PRO, headers={"X-API-KEY": key})
        src = RWL_PRO
    else:
        raw = get_json(RWL_FREE)
        src = RWL_FREE
    if isinstance(raw, dict):
        raw = raw.get("victims") or raw.get("data") or []
    out = []
    for v in raw:
        out.append({
            "victim": clean_text(v.get("victim") or v.get("post_title") or v.get("name") or "", 120),
            "group": v.get("group") or v.get("group_name") or "",
            "date": (v.get("attackdate") or v.get("discovered") or v.get("published") or "")[:10],
            "country": (v.get("country") or "").upper(),
            "sector": v.get("activity") or v.get("sector") or "",
            "site": v.get("domain") or v.get("website") or "",
        })
    out.sort(key=lambda x: x["date"], reverse=True)
    local = [x for x in out if x["country"] == country]
    st.ok("ransomware", "ransomware.live", src, len(out), f"{country}: {len(local)} kayıt")
    return out


# --------------------------------------------------------------------------- #
# Engelleme listeleri (GitHub Pages üzerinden firewall'lara sunulur)
# --------------------------------------------------------------------------- #
def host_of(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower().strip(".")
    except Exception:  # noqa: BLE001
        return ""


def allowed(domain: str, allow: list[str]) -> bool:
    d = domain.lower().strip(".")
    return any(d == a or d.endswith("." + a) for a in allow)


def build_blocklists(iocs: list[dict], allow: list[str]) -> dict:
    FEEDS.mkdir(parents=True, exist_ok=True)
    ips, domains, urls = set(), set(), set()
    for x in iocs:
        v, t, s = x["v"], x["t"], x["s"]
        if s == "Feodo Tracker" and x.get("st") not in ("online", ""):
            continue  # Feodo: yalnızca aktif C2
        if s == "URLhaus" and x.get("st") != "online":
            continue
        if t == "ip" and is_public_ip(v):
            ips.add(v)
        elif t == "domain":
            d = v.lower().strip(".")
            if d and "." in d and not allowed(d, allow) and not IPV4_RE.match(d):
                domains.add(d)
        elif t == "url":
            urls.add(v)
            h = host_of(v)
            if h and IPV4_RE.match(h) and is_public_ip(h):
                ips.add(h)
            elif h and s != "URLhaus" and not allowed(h, allow):
                domains.add(h)
    stamp = NOW.strftime("%Y-%m-%d %H:%M UTC")
    hdr = lambda title: (f"# KOBİ CTI Portalı - {title}\n# Üretildi: {stamp}\n"
                         "# Kaynaklar: abuse.ch (Feodo/URLhaus/ThreatFox), USOM\n"
                         "# UYARI: Üretime almadan önce izleme (log) modunda test edin.\n")
    ip_sorted = sorted(ips, key=lambda i: tuple(int(p) for p in i.split(".")))
    (FEEDS / "ip-blocklist.txt").write_text(hdr("IP engelleme listesi") + "\n".join(ip_sorted) + "\n", encoding="utf-8")
    (FEEDS / "domain-blocklist.txt").write_text(hdr("Alan adı engelleme listesi") + "\n".join(sorted(domains)) + "\n", encoding="utf-8")
    (FEEDS / "url-blocklist.txt").write_text(hdr("URL engelleme listesi") + "\n".join(sorted(urls)) + "\n", encoding="utf-8")
    rsc = ["# KOBİ CTI Portalı - MikroTik RouterOS adres listesi", f"# Üretildi: {stamp}",
           "# Kullanım: /tool fetch url=... dst-path=kobi-cti.rsc ; /import file-name=kobi-cti.rsc",
           "/ip firewall address-list"]
    for ip in ip_sorted:
        rsc.append(f':do {{ add list=kobi-cti address={ip} timeout=2d comment="kobi-cti" }} on-error={{}}')
    (FEEDS / "mikrotik-blocklist.rsc").write_text("\n".join(rsc) + "\n", encoding="utf-8")
    log(f"  → feeds/: {len(ips)} IP, {len(domains)} alan adı, {len(urls)} URL")
    return {"ip": len(ips), "domain": len(domains), "url": len(urls)}


# --------------------------------------------------------------------------- #
# Demo veri (internet erişimi olmadan arayüzü denemek için)
# --------------------------------------------------------------------------- #
def demo(cfg):
    rnd = random.Random(42)
    d = lambda n: (NOW - dt.timedelta(days=n)).strftime("%Y-%m-%d")
    seeds = [
        ("CVE-2024-21762", "Fortinet", "FortiOS", "Fortinet FortiOS Out-of-Bound Write Vulnerability", True),
        ("CVE-2024-3400", "Palo Alto Networks", "PAN-OS", "Palo Alto Networks PAN-OS Command Injection Vulnerability", False),
        ("CVE-2023-4966", "Citrix", "NetScaler ADC and NetScaler Gateway", "Citrix NetScaler Buffer Overflow Vulnerability", True),
        ("CVE-2023-27997", "Fortinet", "FortiOS and FortiProxy SSL-VPN", "Fortinet FortiOS Heap-Based Buffer Overflow Vulnerability", False),
        ("CVE-2018-14847", "MikroTik", "RouterOS", "MikroTik RouterOS Directory Traversal Vulnerability", False),
        ("CVE-2024-1709", "ConnectWise", "ScreenConnect", "ConnectWise ScreenConnect Authentication Bypass Vulnerability", True),
        ("CVE-2023-20198", "Cisco", "IOS XE Web UI", "Cisco IOS XE Web UI Privilege Escalation Vulnerability", False),
        ("CVE-2021-34473", "Microsoft", "Exchange Server", "Microsoft Exchange Server Remote Code Execution Vulnerability", True),
        ("CVE-2023-46805", "Ivanti", "Connect Secure and Policy Secure", "Ivanti Connect Secure Authentication Bypass Vulnerability", False),
        ("CVE-2024-40766", "SonicWall", "SonicOS", "SonicWall SonicOS Improper Access Control Vulnerability", True),
        ("CVE-2023-28252", "Microsoft", "Windows", "Microsoft Windows Common Log File System (CLFS) Privilege Escalation Vulnerability", True),
        ("CVE-2021-44228", "Apache", "Log4j2", "Apache Log4j2 Remote Code Execution Vulnerability", True),
        ("CVE-2023-34362", "Progress", "MOVEit Transfer", "Progress MOVEit Transfer SQL Injection Vulnerability", True),
        ("CVE-2024-27198", "JetBrains", "TeamCity", "JetBrains TeamCity Authentication Bypass Vulnerability", False),
        ("CVE-2022-41040", "Microsoft", "Exchange Server", "Microsoft Exchange Server Server-Side Request Forgery Vulnerability", True),
    ]
    kev, epss = [], {}
    for i, (cve, ven, prod, name, rw) in enumerate(seeds):
        age = [1, 3, 5, 8, 11, 16, 22, 30, 41, 55, 63, 80, 95, 120, 150][i]
        kev.append({"cve": cve, "vendor": ven, "product": prod, "name": name,
                    "desc": f"[DEMO] {name}. Gerçek açıklama Actions çalıştığında CISA KEV'den gelir.",
                    "action": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
                    "added": d(age), "due": d(age - 21), "ransomware": rw, "cwes": [], "notes": []})
        epss[cve] = [round(rnd.uniform(0.2, 0.97), 4), round(rnd.uniform(0.9, 0.999), 4)]
    kev.sort(key=lambda x: x["added"], reverse=True)
    iocs = []
    fams = ["QakBot", "Emotet", "Pikabot", "AsyncRAT", "Lumma Stealer", "Remcos", "AgentTesla", "DarkGate"]
    for i in range(40):
        ip = f"{rnd.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rnd.randint(1, 254)}"
        iocs.append({"v": ip, "t": "ip", "s": rnd.choice(["Feodo Tracker", "ThreatFox"]), "m": rnd.choice(fams),
                     "d": d(rnd.randint(0, 20)), "st": "online", "x": "DEMO", "ref": ""})
    for i in range(30):
        dom = f"{rnd.choice(['update', 'secure', 'login', 'cdn', 'fatura', 'kargo', 'edevlet-destek'])}-{rnd.randint(100, 999)}.example"
        iocs.append({"v": dom, "t": "domain", "s": rnd.choice(["ThreatFox", "USOM"]), "m": rnd.choice(fams + ["Oltalama"]),
                     "d": d(rnd.randint(0, 20)), "x": "DEMO", "ref": ""})
        iocs.append({"v": f"http://{dom}/{rnd.choice(['invoice', 'dekont', 'setup'])}.zip", "t": "url", "s": "URLhaus",
                     "m": "malware_download", "d": d(rnd.randint(0, 20)), "st": "online", "x": "DEMO", "ref": ""})
    iocs.append({"v": "44d88612fea8a8f36de82e1278abb02f", "t": "hash", "s": "ThreatFox", "m": "EICAR test dosyası",
                 "d": d(1), "x": "DEMO", "ref": ""})
    news = []
    for i, (t, src) in enumerate([
        ("[DEMO] SSL-VPN cihazlarını hedefleyen yeni istismar dalgası", "BleepingComputer"),
        ("[DEMO] CISA bilinen istismar edilen zafiyetler kataloğuna 2 yeni kayıt ekledi", "CISA Advisories"),
        ("[DEMO] Fidye yazılımı grupları KOBİ'lerin uzak masaüstü erişimini kullanıyor", "The Hacker News"),
        ("[DEMO] Microsoft aylık güvenlik güncellemeleri yayımlandı", "Microsoft MSRC"),
        ("[DEMO] Kargo temalı oltalama SMS kampanyası", "SANS ISC"),
        ("[DEMO] MikroTik yönlendiricilerde Winbox erişimi hakkında uyarı", "SANS ISC"),
    ]):
        news.append({"title": t, "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                     "date": iso(NOW - dt.timedelta(hours=8 * i + 2)), "source": src,
                     "summary": "Demo içerik. Gerçek haberler GitHub Actions ile RSS kaynaklarından toplanır.",
                     "cves": ["CVE-2024-21762"] if i == 0 else []})
    groups = ["LockBit", "Akira", "Play", "RansomHub", "Medusa", "8Base", "BianLian", "Qilin"]
    sectors = ["Üretim", "İnşaat", "Sağlık", "Lojistik", "Teknoloji", "Perakende", "Eğitim", "Finans"]
    rw = []
    for i in range(60):
        rw.append({"victim": f"Örnek Firma {i + 1} [DEMO]", "group": rnd.choice(groups), "date": d(rnd.randint(0, 45)),
                   "country": "TR" if i % 4 == 0 else rnd.choice(["US", "DE", "IT", "FR", "GB", "ES"]),
                   "sector": rnd.choice(sectors), "site": ""})
    rw.sort(key=lambda x: x["date"], reverse=True)
    return kev, epss, iocs, news, rw


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="KOBİ CTI Portalı veri toplayıcı")
    ap.add_argument("--demo", action="store_true", help="internet olmadan demo veri üret")
    args = ap.parse_args()

    cfg = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    ret, src = cfg["retention"], cfg["sources"]
    st = Status()

    if args.demo:
        log("DEMO modu: örnek veri üretiliyor")
        kev, epss, iocs, news, rw = demo(cfg)
        for k in ("kev", "epss", "feodo", "urlhaus", "threatfox", "usom", "ransomware"):
            st.ok(k, k, "", 0, "demo")
    else:
        kev = read_previous("kev.json", {}).get("items", [])
        epss = {}
        if src.get("cisa_kev"):
            log("CISA KEV indiriliyor")
            try:
                kev = fetch_kev(st)
            except Exception as e:  # noqa: BLE001
                st.fail("kev", "CISA KEV", KEV_URL, e)
                log(f"  KEV hatası, önceki veri korunuyor: {e}")
        if src.get("epss") and kev:
            log("EPSS skorları indiriliyor")
            epss = fetch_epss([k["cve"] for k in kev], st)
        if not epss:
            epss = read_previous("kev.json", {}).get("epss", {})

        iocs = []
        prev_iocs = read_previous("iocs.json", {}).get("items", [])
        cap = ret["ioc_max_per_source"]
        jobs = [("feodo", "Feodo Tracker", lambda: fetch_feodo(st, cap)),
                ("urlhaus", "URLhaus", lambda: fetch_urlhaus(st, cap)),
                ("threatfox", "ThreatFox", lambda: fetch_threatfox(st, cap)),
                ("usom", "USOM", lambda: fetch_usom(st, ret["usom_api_pages"], cap))]
        for key, label, fn in jobs:
            if not src.get(key):
                continue
            log(f"{label} indiriliyor")
            try:
                iocs.extend(fn())
            except Exception as e:  # noqa: BLE001
                st.fail(key, label, "", e)
                kept = [x for x in prev_iocs if x.get("s") == label]
                iocs.extend(kept)
                log(f"  {label} hatası, önceki {len(kept)} kayıt korunuyor: {e}")

        news = read_previous("news.json", {}).get("items", [])
        if src.get("rss"):
            log("RSS haber kaynakları indiriliyor")
            fresh = fetch_rss(cfg.get("rss", []), st, ret["news_days"], ret["news_max"])
            if fresh:
                news = fresh

        rw = read_previous("ransomware.json", {}).get("items", [])
        if src.get("ransomware_live"):
            log("ransomware.live indiriliyor")
            try:
                rw = fetch_ransomware(st, cfg.get("ransomware_country", "TR"))
            except Exception as e:  # noqa: BLE001
                st.fail("ransomware", "ransomware.live", RWL_FREE, e)
                log(f"  ransomware.live hatası: {e}")

    log("Dosyalar yazılıyor")
    write_json("kev.json", {"items": kev, "epss": epss})
    write_json("iocs.json", {"items": iocs})
    write_json("news.json", {"items": news})
    write_json("ransomware.json", {"items": rw})
    counts = build_blocklists(iocs, cfg.get("blocklist_allow", []))
    write_json("meta.json", {
        "generated": iso(NOW),
        "demo": bool(args.demo),
        "site": cfg["site"],
        "kev_new_days": ret["kev_new_days"],
        "ransomware_country": cfg.get("ransomware_country", "TR"),
        "blocklists": counts,
        "sources": st.items,
    })
    bad = [s for s in st.items if not s["ok"]]
    log(f"Tamamlandı. {len(st.items) - len(bad)} kaynak başarılı, {len(bad)} hatalı.")
    # Tüm kaynaklar başarısızsa iş akışı kırmızı görünsün
    if st.items and len(bad) == len(st.items):
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
