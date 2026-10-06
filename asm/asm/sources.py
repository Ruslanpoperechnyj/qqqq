"""
Мульти-источниковый пассивный поиск имён и адресов.

Основано на живой разведке 04.10.2026 (документ «ИСТОЧНИКИ-ПОИСКА.md»):

  * crt.sh часто падает (502) — поэтому имена из сертификатов берём в первую очередь
    из CertSpotter, а crt.sh подключаем как второй источник и никогда не даём ему
    «завалить» анализ;
  * без ключей из нашей среды работают: CertSpotter, Mnemonic pDNS, OTX (url_list),
    urlscan.io, HackerTarget, ip.thc.org (обратный DNS), InternetDB, GreyNoise;
  * мёртвые/закрытые: AnubisDB (403), ThreatMiner (522), OTX passive_dns (429) —
    не подключаем;
  * RapidDNS и Wayback — рабочие, но нестабильные/медленные: включаются отдельно.

Принципы:
  * каждый источник изолирован: ошибка одного не мешает остальным;
  * общий кэш и ретраи — из collect._http (кэш в SQLite, повторный анализ мгновенный);
  * имена нормализуются и дедуплицируются, ведётся счёт вклада каждого источника;
  * только пассивный сбор: к чужой инфраструктуре никаких запросов, кроме публичных
    API-справочников и ip.thc.org (который отдаёт агрегаты, а не сканирует).

Платные/ключевые источники (Netlas, Shodan, VirusTotal, SecurityTrails, Validin,
Silent Push, Chaos, Censys, FOFA, ZoomEye) предусмотрены в CATALOG: включаются,
когда в переменных окружения появится ключ (см. _key).
"""
from __future__ import annotations

import inspect
import json
import os
import re
import time
import urllib.parse
from typing import Any

from . import collect, stealth as _stealth, store
from .settings import current_settings

# ----------------------------------------------------------------- справочник
# status: live = проверено живьём 04.10.2026;  dead = проверено, не работает;
#         key  = нужно бесплатное/платное подключение ключом.

CATALOG: list[dict] = [
    {"id": "certspotter", "name": "CertSpotter", "url": "https://api.certspotter.com/v1/issuances",
     "what": "имена из логов сертификатов (CT)", "key": "-", "limits": "неофициальный лимит",
     "status": "live", "enabled": True, "note": "основной источник имён (crt.sh часто 502)"},
    {"id": "crtsh", "name": "crt.sh", "url": "https://crt.sh/?q=%.{d}&output=json",
     "what": "CT-логи, история, полный список SAN", "key": "-", "limits": "часто падает/перегружен",
     "status": "live", "enabled": True, "note": "второй источник; фолбэк — CertSpotter"},
    {"id": "mnemonic", "name": "Mnemonic pDNS", "url": "https://api.mnemonic.no/pdns/v3/{d}",
     "what": "passive DNS: история связок имя↔IP", "key": "-", "limits": "малый объём без ключа",
     "status": "live", "enabled": True},
    {"id": "otx", "name": "AlienVault OTX", "url": "https://otx.alienvault.com/api/v1/indicators/domain/{d}/url_list",
     "what": "URL и хосты, замеченные сообществом", "key": "-", "limits": "limit=500",
     "status": "live", "enabled": True, "note": "старый passive_dns закрыт (429)"},
    {"id": "urlscan", "name": "urlscan.io", "url": "https://urlscan.io/api/v1/search/?q=domain:{d}",
     "what": "сохранённые сканы страниц: хосты, IP, пути", "key": "-", "limits": "без ключа урезано",
     "status": "live", "enabled": True},
    {"id": "hackertarget", "name": "HackerTarget", "url": "https://api.hackertarget.com/hostsearch/?q={d}",
     "what": "имена сразу с IP-адресами", "key": "-", "limits": "100 запросов/день",
     "status": "live", "enabled": True},
    {"id": "ripestat", "name": "RIPEstat", "url": "https://stat.ripe.net/data/prefix-overview",
     "what": "префиксы сетей, ASN, организация", "key": "-", "limits": "без лимитов",
     "status": "live", "enabled": True, "note": "уже используется в collect.py"},
    {"id": "internetdb", "name": "InternetDB (Shodan)", "url": "https://internetdb.shodan.io/{ip}",
     "what": "порты, CPE, CVE, имена по IP", "key": "-", "limits": "без лимитов",
     "status": "live", "enabled": True, "note": "уже используется в collect.py"},
    {"id": "greynoise", "name": "GreyNoise Community", "url": "https://api.greynoise.io/v3/community/{ip}",
     "what": "шумовой сканер или адресная атака", "key": "-", "limits": "50 запросов/день",
     "status": "live", "enabled": True, "note": "подключается к триажу IP"},
    {"id": "thcsubs", "name": "ip.thc.org (поддомены)", "url": "https://ip.thc.org/api/v1/lookup/subdomains",
     "what": "поддомены из базы 6 млрд имён + дата последней активности", "key": "-",
     "limits": "~250 запросов запас, +0,5/с", "status": "live", "enabled": True,
     "note": "проверено живьём: nmap.org → 14 доменов с датами"},
    {"id": "ipthc", "name": "ip.thc.org (обратный DNS)", "url": "https://ip.thc.org/{ip}",
     "what": "обратный поиск: какие домены живут на IP (6 млрд имён)", "key": "-",
     "limits": "~250 запросов запас, +0,5/с", "status": "live", "enabled": True},
    {"id": "rapiddns", "name": "RapidDNS", "url": "https://rapiddns.io/subdomain/{d}?full=1",
     "what": "passive DNS (веб-страница)", "key": "-", "limits": "HTML-парсинг",
     "status": "live", "enabled": False, "note": "вкл. ASM_SOURCES_EXTRA=1"},
    {"id": "wayback", "name": "Wayback CDX", "url": "https://web.archive.org/cdx/search/cdx",
     "what": "исторические URL и забытые поддомены", "key": "-", "limits": "медленный",
     "status": "live", "enabled": False, "note": "вкл. ASM_SOURCES_EXTRA=1"},
    {"id": "netlas", "name": "Netlas", "url": "https://app.netlas.io/api/",
     "what": "домены+IP+HTTP-тела (второй сканер)", "key": "нужен бесплатный ключ",
     "limits": "50 поисков/день", "status": "key", "enabled": False, "note": "лучший free-tier"},
    {"id": "shodan", "name": "Shodan", "url": "https://api.shodan.io/",
     "what": "индекс устройств и сервисов", "key": "нужен ключ", "limits": "100 запросов разово",
     "status": "key", "enabled": False},
    {"id": "virustotal", "name": "VirusTotal", "url": "https://www.virustotal.com/api/v3/",
     "what": "passive DNS и репутация", "key": "нужен ключ", "limits": "4 запроса/мин, 500/день",
     "status": "key", "enabled": False},
    {"id": "securitytrails", "name": "SecurityTrails", "url": "https://api.securitytrails.com/v1/",
     "what": "DNS-история (10+ трлн записей)", "key": "платный", "limits": "-",
     "status": "key", "enabled": False},
    {"id": "validin", "name": "Validin", "url": "https://app.validin.com/api/",
     "what": "пивот по инфраструктуре", "key": "community-ключ", "limits": "-",
     "status": "key", "enabled": False},
    {"id": "chaos", "name": "Chaos (ProjectDiscovery)", "url": "https://dns.projectdiscovery.io/",
     "what": "датасет поддоменов", "key": "бесплатный ключ", "limits": "-",
     "status": "key", "enabled": False},
]

# мёртвые/закрытые источники — держим в справочнике, чтобы не подключать снова
DEAD: list[dict] = [
    {"name": "AnubisDB (jldc.me)", "status": "dead", "reason": "403 Cloudflare (проверено 04.10.2026)"},
    {"name": "ThreatMiner", "url": "https://api.threatminer.org", "status": "dead", "reason": "522 (проверено)"},
    {"name": "OTX passive_dns", "status": "dead", "reason": "429 «Please authenticate» — использовать url_list"},
    {"name": "BufferOver / ThreatCrowd / SiteDossier / Riddler", "status": "dead",
     "reason": "домены/сервисы закрыты"},
    {"name": "subdomain.center", "status": "dead", "reason": "генерирует искусственные имена — не использовать"},
]

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# невидимые символы и управляющие коды — вычищаем из имён (источник может прислать мусор)
JUNK = re.compile(r"[\u200b-\u200f\u2028\u2029\ufeff\x00-\x1f\x7f]")
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_PAUSE = float(os.environ.get("ASM_SOURCES_PAUSE", "0.35"))


def _enabled_ids(settings=None) -> set[str]:
    ids = {c["id"] for c in CATALOG if c["enabled"]}
    extra = str(_setting(settings, "ASM_SOURCES_EXTRA", os.environ.get("ASM_SOURCES_EXTRA", "")) or "") not in ("", "0", "false", "no")
    if extra:
        ids |= {c["id"] for c in CATALOG if c["status"] == "live"}
    only = str(_setting(settings, "ASM_SOURCES", os.environ.get("ASM_SOURCES", "")) or "").strip()
    if only:
        ids = {s.strip() for s in only.split(",") if s.strip()}
    off_value = _setting(settings, "ASM_SOURCES_OFF", os.environ.get("ASM_SOURCES_OFF", ""))
    off = {s.strip() for s in str(off_value or "").split(",") if s.strip()}
    return ids - off


def source_enabled(sid: str, *, settings=None) -> bool:
    """Включён ли источник — по тем же правилам, что и реестр.

    Нужно вызывающему коду, который идёт мимо реестра (например, обогащение по
    адресу зовёт `collect.internetdb` напрямую). Без этой проверки настройка
    `ASM_SOURCES_OFF` выглядела бы рабочей, а источник — нет: так и было с
    InternetDB, у которого лицензия free только для некоммерческого
    использования.
    """
    return (sid or "").strip().lower() in _enabled_ids(settings=settings)


def _key() -> str | None:
    """Ключи платных источников берём из окружения; без ключа источник не запускается."""
    return None


def label(sid: str) -> str:
    """Человеческое имя источника по его идентификатору."""
    return _NAMES.get(sid, sid)


def sources_catalog(*, settings=None) -> dict:
    """Справочник для интерфейса и документации."""
    on = _enabled_ids(settings=settings)
    items = []
    for c in CATALOG:
        c2 = dict(c)
        c2["enabled"] = c["id"] in on
        items.append(c2)
    return {"sources": items, "dead": DEAD,
            "enabled_count": sum(1 for i in items if i["enabled"])}


# ----------------------------------------------------------------- утилиты
def _setting(settings, name: str, default):
    if settings is None:
        settings = current_settings()
    if settings is None:
        return os.environ.get(name, default)
    getter = getattr(settings, "get", None)
    return getter(name, default) if callable(getter) else default


def _call_collector(fn, domain: str, ttl: int, settings=None):
    """Pass snapshots to migrated collectors without breaking legacy plugins."""
    if settings is None:
        return fn(domain, ttl)
    try:
        parameters = inspect.signature(fn).parameters.values()
        accepts_settings = any(
            item.name == "settings" or item.kind is inspect.Parameter.VAR_KEYWORD
            for item in parameters
        )
    except (TypeError, ValueError):
        accepts_settings = True
    if accepts_settings:
        return fn(domain, ttl, settings=settings)
    return fn(domain, ttl)


def _norm(name: str, domain: str) -> str | None:
    """Нормализация имени: нижний регистр, без маски и ANSI, строгая проверка меток."""
    name = JUNK.sub("", ANSI.sub("", str(name or ""))).strip().lower().rstrip(".")
    name = name.lstrip("*.")
    if not name or len(name) > 253 or " " in name or "/" in name:
        return None
    if "@" in name:  # из адресов почты вида admin@host
        name = name.split("@", 1)[1]
    if not (name == domain or name.endswith("." + domain)):
        return None
    for lab in name.split("."):
        if not lab or not _LABEL.match(lab):
            return None
    return None if name == domain else name


def _host_from_url(u: str) -> str:
    try:
        h = urllib.parse.urlsplit(u if "://" in u else "http://" + u).hostname or ""
        return h.lower().rstrip(".")
    except Exception:
        return ""


# ----------------------------------------------------------------- источники
def src_certspotter(domain: str, ttl: int, *, settings=None) -> list[str]:
    url = ("https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(domain) +
           "&include_subdomains=true&expand=dns_names")
    data = collect._http(url, ttl, settings=settings)
    out: list[str] = []
    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict):
                out += [str(n) for n in (row.get("dns_names") or [])]
                out.append(str(row.get("common_name") or ""))
    return out


def src_crtsh(domain: str, ttl: int, *, settings=None) -> list[str]:
    return collect.crtsh_subdomains(domain, ttl, settings=settings)


def src_mnemonic(domain: str, ttl: int, *, settings=None) -> list[str]:
    url = f"https://api.mnemonic.no/pdns/v3/{urllib.parse.quote(domain)}?limit=500&aggregateResult=false"
    data = collect._http(url, ttl, settings=settings)
    out: list[str] = []
    if isinstance(data, dict):
        for row in data.get("data") or []:
            if isinstance(row, dict):
                out.append(str(row.get("query") or ""))
                out.append(str(row.get("answer") or ""))
    return out


def src_otx(domain: str, ttl: int, *, settings=None) -> list[str]:
    url = ("https://otx.alienvault.com/api/v1/indicators/domain/" + urllib.parse.quote(domain) +
           "/url_list?limit=500&page=1")
    data = collect._http(url, ttl, settings=settings)
    out: list[str] = []
    if isinstance(data, dict):
        for row in data.get("url_list") or []:
            if isinstance(row, dict):
                out.append(_host_from_url(str(row.get("url") or "")))
                out.append(str(row.get("hostname") or ""))
    return out


def src_urlscan(domain: str, ttl: int, *, settings=None) -> list[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain%3A{urllib.parse.quote(domain)}&size=100"
    data = collect._http(url, ttl, settings=settings)
    out: list[str] = []
    if isinstance(data, dict):
        for row in data.get("results") or []:
            if not isinstance(row, dict):
                continue
            page = row.get("page") or {}
            task = row.get("task") or {}
            out.append(str(page.get("domain") or ""))
            out.append(_host_from_url(str(page.get("url") or "")))
            out.append(_host_from_url(str(task.get("url") or "")))
    return out


def src_hackertarget(domain: str, ttl: int, *, settings=None) -> list[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    data = collect._http(url, ttl, settings=settings)
    out: list[str] = []
    text = ""
    if isinstance(data, dict):
        text = str(data.get("_raw") or data.get("_error") or "")
    elif isinstance(data, str):
        text = data
    for line in text.splitlines():
        if "," in line:
            out.append(line.split(",", 1)[0])
    return out


def src_thcsubs(domain: str, ttl: int, *, settings=None) -> list[str]:
    """ip.thc.org: поддомены из их базы (6 млрд имён), с датами последней активности."""
    ck = "thc:subdomains:" + domain
    if ttl > 0:
        hit = store.cache_get(ck, ttl)
        if hit is not None:
            return [str(x) for x in hit]
    data = collect._http("https://ip.thc.org/api/v1/lookup/subdomains", 0, method="POST",
                         data=json.dumps({"domain": domain}).encode(),
                         headers={"Content-Type": "application/json"}, settings=settings)
    out: list[str] = []
    if isinstance(data, dict):
        for row in data.get("domains") or []:
            out.append(str(row.get("domain") or "") if isinstance(row, dict) else str(row))
    if ttl > 0:
        store.cache_put(ck, out)
    return out


def src_rapiddns(domain: str, ttl: int, *, settings=None) -> list[str]:
    url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1"
    data = collect._http(url, ttl, settings=settings)
    text = str(data.get("_raw") or "") if isinstance(data, dict) else ""
    return re.findall(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*\." + re.escape(domain), text)[:2000]


def src_wayback(domain: str, ttl: int, *, settings=None) -> list[str]:
    url = ("https://web.archive.org/cdx/search/cdx?url=*." + urllib.parse.quote(domain) +
           "&output=json&fl=original&collapse=urlkey&limit=2000")
    data = collect._http(url, ttl, settings=settings)
    out: list[str] = []
    if isinstance(data, list):
        for row in data[1:] if data and isinstance(data[0], list) else data:
            if isinstance(row, list) and row:
                out.append(_host_from_url(str(row[0])))
    return out


_COLLECTORS = {
    "certspotter": src_certspotter,
    "crtsh": src_crtsh,
    "mnemonic": src_mnemonic,
    "otx": src_otx,
    "urlscan": src_urlscan,
    "hackertarget": src_hackertarget,
    "thcsubs": src_thcsubs,
    "rapiddns": src_rapiddns,
    "wayback": src_wayback,
}

_NAMES = {c["id"]: c["name"] for c in CATALOG}


def collect_domain(domain: str, log=print, ttl: int = 86400 * 3,
                   sources: set[str] | None = None, *, settings=None) -> dict[str, Any]:
    """Собрать имена домена со всех включённых источников.

    Возвращает {"names": {имя: [источники]}, "counts": {источник: сколько},
               "errors": {источник: ошибка}, "found": {источник: сырых имён}}.
    """
    on = sources if sources is not None else _enabled_ids(settings=settings)
    names: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    found: dict[str, int] = {}
    errors: dict[str, str] = {}
    for sid, fn in _COLLECTORS.items():
        if sid not in on:
            continue
        label = _NAMES.get(sid, sid)
        try:
            raw = _call_collector(fn, domain, ttl, settings=settings)
        except Exception as e:  # noqa: BLE001 — источник не должен ломать анализ
            errors[sid] = str(e)[:200]
            log(f"Источник {label}: сбой ({str(e)[:120]}) — продолжаем без него")
            continue
        if not raw:
            errors[sid] = "пусто"
            log(f"Источник {label}: ничего не отдал")
            continue
        got = 0
        for n in raw:
            norm = _norm(n, domain)
            if not norm:
                continue
            got += 1
            names.setdefault(norm, [])
            if sid not in names[norm]:
                names[norm].append(sid)
        counts[sid] = len({n for n, ss in names.items() if sid in ss})
        found[sid] = got
        log(f"Источник {label}: имён {counts[sid]}")
        # Пауза с разбросом: источники опрашиваются последовательно, и ровный
        # шаг между запросами сам себя выдаёт.
        pause = float(_setting(settings, "ASM_SOURCES_PAUSE", _PAUSE))
        time.sleep(_stealth.jitter(pause, 0.25, settings=settings))
    return {"names": names, "counts": counts, "errors": errors, "found": found}


# ----------------------------------------------------------------- обратный DNS
def domains_on_ip(ip: str, ttl: int = 86400 * 3, limit: int = 50, *, settings=None) -> list[str]:
    """ip.thc.org: какие домены ещё живут на этом IP (пассивно, из их базы 6 млрд имён)."""
    url = f"https://ip.thc.org/{urllib.parse.quote(ip)}?l={int(limit)}&noheader=1"
    data = collect._http(url, ttl, settings=settings)
    text = ""
    if isinstance(data, dict):
        text = str(data.get("_raw") or "")
    elif isinstance(data, str):
        text = data
    out: list[str] = []
    for line in ANSI.sub("", text).splitlines():
        line = line.strip().strip(",").lower().rstrip(".")
        if not line or " " in line or len(line) > 253 or "." not in line:
            continue
        if line.count(".") >= 1 and re.match(r"^[a-z0-9][a-z0-9_.-]*[a-z0-9]$", line):
            out.append(line)
    return out[:limit]
