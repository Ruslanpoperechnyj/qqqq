"""
Пассивные сборщики «цифровых следов».

ВАЖНО (отличие «анализа» от «сканирования», как в оригинале):
  * crt.sh            — Certificate Transparency: публичные логи выданных сертификатов
  * dns.google (DoH)  — публичные DNS-записи
  * rdap.org / RDAP   — регистрационные данные владельца и сети
  * RIPEstat          — маршрутизация, ASN, организация, страна
  * InternetDB (Shodan) — публичный индекс баннеров: открытые порты, CPE, теги, CVE
  * HTTP/TLS-проба     — один лёгкий запрос к своему же таргету (это уже активное
                        действие, но в рамках авторизованного периметра заказчика)

Всё кэшируется в SQLite: повторный анализ того же таргета идёт за секунды.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import logging
import os

# Заглушим инспекцию SSL-сертификатов на уровне ssl (не убираем совсем) —
# нам нужен именно сертификат таргета, включая самоподписанные.
import warnings

from . import stealth, store
from .settings import current_settings

TIMEOUT = int(os.environ.get("ASM_HTTP_TIMEOUT", "15"))


def _setting(settings, name: str, default):
    if settings is None:
        settings = current_settings()
    if settings is None:
        return os.environ.get(name, default)
    getter = getattr(settings, "get", None)
    return getter(name, default) if callable(getter) else default

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE
warnings.filterwarnings("ignore")


def _http(url: str, ttl: int, *, headers: dict | None = None, method: str = "GET",
          data: bytes | None = None, raw: bool = False, retries: int = 2,
          purpose: str = "outward", settings=None) -> Any:
    """GET с кэшем. raw=True -> возвращает (status, headers, body_bytes).

    purpose="outward" по умолчанию: почти все вызовы отсюда — сторонние
    сервисы (crt.sh, RDAP, InternetDB). Именно они видят наш адрес, и именно
    их запросы связывают личность с объектом. Исключения передают
    purpose="inward" явно.
    """
    ck = "http:" + method + ":" + url + (":" + str(len(data)) if data else "")
    if ttl > 0 and method == "GET":
        hit = store.cache_get(ck, ttl)
        if hit is not None:
            return hit
    hdrs = {"User-Agent": stealth.ua(purpose, settings=settings), "Accept": "application/json, */*"}
    timeout = float(_setting(settings, "ASM_HTTP_TIMEOUT", TIMEOUT))
    if headers:
        hdrs.update(headers)
    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with stealth.open_url(req, purpose=purpose, timeout=timeout,
                                  context=_ssl_ctx, settings=settings) as r:
                body = r.read()
                status = r.status
                rh = dict(r.headers)
            if raw:
                out = {"status": status, "headers": rh, "body": body.decode("utf-8", "replace")}
            else:
                try:
                    out = json.loads(body.decode("utf-8", "replace"))
                except Exception:
                    out = {"_raw": body.decode("utf-8", "replace")[:5000], "_status": status}
            if ttl > 0:
                store.cache_put(ck, out)
            return out
        except stealth.BlockedByStealth:
            # Отказ по политике скрытности — не сбой сети. Повторять его
            # бессмысленно (запрос всё равно не уйдёт), а как «сетевую ошибку»
            # он ещё и прячет причину. Пусть поднимается наверх: вызывающий
            # обязан записать причину, а не показать пустой результат.
            raise
        except urllib.error.HTTPError as e:
            # 404/400 для crt.sh и RDAP — нормальные ответы, кэшируем пустышку
            if e.code in (400, 403, 404, 429):
                out = {"_error": f"HTTP {e.code}", "_status": e.code}
                if ttl > 0:
                    store.cache_put(ck, out)
                return out
            last_err = e
        except Exception as e:  # таймаут, DNS, TLS
            last_err = e
        # Пауза между повторами со случайным разбросом: ровные интервалы —
        # такой же признак автоматизации, как одинаковый User-Agent.
        time.sleep(stealth.jitter(1.2 * (attempt + 1), 0.6, settings=settings))
    return {"_error": str(last_err)}


# ------------------------------------------------------------------ 1. CT-логи
def crtsh_subdomains(domain: str, ttl: int = 86400 * 3, *, settings=None) -> list[str]:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    data = _http(url, ttl, settings=settings)
    if not isinstance(data, list):
        return []
    subs: set[str] = set()
    for row in data:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if name and " " not in name and name.endswith(domain) and "*" not in name:
                subs.add(name)
    return sorted(subs)


def crtsh_certs(domain: str, ttl: int = 86400 * 3, *, settings=None) -> list[dict]:
    """Сертификаты на домен — для графа связей (issuer / SAN / срок)."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    data = _http(url, ttl, settings=settings)
    if not isinstance(data, list):
        return []
    seen: dict[str, dict] = {}
    for row in data:
        key = str(row.get("serial_number") or row.get("id"))
        if key in seen:
            continue
        seen[key] = {
            "issuer": row.get("issuer_name", ""),
            "common_name": row.get("common_name", ""),
            "not_before": row.get("not_before", ""),
            "not_after": row.get("not_after", ""),
            "names": [n.strip() for n in str(row.get("name_value", "")).split("\n") if n.strip()],
        }
    return list(seen.values())[:60]


# ------------------------------------------------------------------ 2. DNS (DoH)
DOH = "https://dns.google/resolve?name={name}&type={rtype}"


def dns(name: str, rtype: str = "A", ttl: int = 3600, *, settings=None) -> list[str]:
    url = DOH.format(name=urllib.parse.quote(name), rtype=rtype)
    data = _http(url, ttl, headers={"Accept": "application/dns-json"}, settings=settings)
    if not isinstance(data, dict) or "Answer" not in data:
        return []
    out = []
    for a in data["Answer"]:
        v = str(a.get("data", "")).strip().strip('"')
        if v:
            out.append(v)
    return out


def dns_all(name: str, ttl: int = 3600, *, settings=None) -> dict[str, list[str]]:
    res = {}
    for rt in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"):
        vals = dns(name, rt, ttl, settings=settings)
        if vals:
            res[rt] = vals
    return res


def resolve_ips(host: str, *, settings=None) -> list[str]:
    ips = dns(host, "A", settings=settings) + dns(host, "AAAA", settings=settings)
    return [i for i in ips if i and i[0].isdigit() or ":" in i]


# ------------------------------------------------------------------ 3. RDAP / WHOIS
def rdap_domain(domain: str, ttl: int = 86400 * 7, *, settings=None) -> dict:
    parts = domain.split(".")
    # RDAP-бутстрап: rdap.org сам редиректит к нужному реестру
    data = _http(f"https://rdap.org/domain/{urllib.parse.quote(domain)}", ttl, settings=settings)
    if not isinstance(data, dict) or "_error" in data:
        return {}
    out: dict[str, Any] = {"handle": data.get("handle"), "ldhName": data.get("ldhName")}
    for ev in data.get("events", []) or []:
        out.setdefault("events", {})[ev.get("eventAction", "?")] = ev.get("eventDate")
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", [])
        name = None
        for v in (ent.get("vcardArray") or [[], []])[1]:
            if v and v[0] == "fn":
                name = v[3]
        if name and ("registrant" in roles or "registrar" in roles or not out.get("org")):
            out.setdefault("entities", []).append({"roles": roles, "name": name})
            if "registrant" in roles:
                out["org"] = name
    out["status"] = data.get("status", [])
    return out


def ripe_prefix(ip: str, ttl: int = 86400 * 7, *, settings=None) -> dict:
    d = _http(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={urllib.parse.quote(ip)}",
              ttl, settings=settings)
    if not isinstance(d, dict) or not d.get("data"):
        return {}
    dd = d["data"]
    asns = dd.get("asns") or [{}]
    country = asns[0].get("country") or ""
    # RIPEstat иногда отдаёт в поле country длинное описание блока — это не страна
    if len(str(country)) > 40:
        country = ""
    return {
        "prefix": dd.get("resource"),
        "asn": asns[0].get("asn"),
        "holder": asns[0].get("holder"),
        "country": country,
        "announced": dd.get("announced"),
        "name": dd.get("name"),
    }


# ------------------------------------------------------------------ 4. InternetDB
def internetdb(ip: str, ttl: int = 86400, *, settings=None) -> dict:
    """Открытые порты и уязвимости по адресу из публичного индекса.

    Источник можно выключить настройкой, а не только не вызывать его: вызовов
    два (реестр источников и обогащение по адресу), и раньше проверка стояла
    только в первом — при `ASM_SOURCES_OFF=internetdb` обогащение продолжало
    ходить в Shodan. Лицензия InternetDB разрешает свободное использование
    только некоммерчески, поэтому выключатель обязан работать честно.
    """
    from . import sources as _sources
    if not _sources.source_enabled("internetdb", settings=settings):
        return {}
    d = _http(f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}", ttl, settings=settings)
    if not isinstance(d, dict) or "_error" in d:
        return {}
    return {
        "ports": sorted(d.get("ports") or []),
        "hostnames": d.get("hostnames") or [],
        "cpes": d.get("cpes") or [],
        "tags": d.get("tags") or [],
        "vulns": sorted(d.get("vulns") or []),
        "cpes_raw": d.get("cpes") or [],
    }


# ------------------------------------------------------------------ 5. HTTP/TLS-проба
def http_probe(host: str, port: int = 443, scheme: str | None = None, timeout: int | None = None,
               *, settings=None) -> dict:
    """Один лёгкий запрос к своему таргету. Без брутфорса, без эксплуатации."""
    timeout = timeout or float(_setting(settings, "ASM_HTTP_TIMEOUT", TIMEOUT))
    scheme = scheme or ("https" if port in (443, 8443, 9443) else "http")
    url = f"{scheme}://{host}:{port}/"
    out: dict[str, Any] = {"url": url, "scheme": scheme, "port": port}
    try:
        ctx = _ssl_ctx
        req = urllib.request.Request(url, headers={"User-Agent": stealth.ua("inward", settings=settings)})
        t0 = time.time()
        with stealth.open_url(req, purpose="inward", timeout=timeout,
                              context=ctx, settings=settings) as r:
            body = r.read(200000)
            out["status"] = r.status
            out["headers"] = {k.lower(): v for k, v in r.headers.items()}
            out["server"] = r.headers.get("Server", "")
            out["title"] = _title(body.decode("utf-8", "replace"))
            out["size"] = len(body)
            try:
                cert = r.getpeercert()
                out["tls"] = _cert_summary(cert)
            except Exception:
                pass
        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        return out
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        out["headers"] = {k.lower(): v for k, v in (e.headers or {}).items()}
        out["server"] = (e.headers or {}).get("Server", "")
        return out
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        # пробуем без TLS-контекста (http) для 80
        return out


def _title(html: str) -> str:
    low = html.lower()
    i, j = low.find("<title"), low.find("</title>")
    if i >= 0 and j > i:
        return html[low.find(">", i) + 1:j].strip()[:200]
    return ""


def _cert_summary(cert: dict | None) -> dict:
    if not cert:
        return {}
    issuer = {k: v for tup in cert.get("issuer", ()) for k, v in tup}
    subject = {k: v for tup in cert.get("subject", ()) for k, v in tup}
    return {
        "issuer_cn": issuer.get("commonName", ""),
        "issuer_o": issuer.get("organizationName", ""),
        "subject_cn": subject.get("commonName", ""),
        "not_after": cert.get("notAfter", ""),
        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:20],
        "version": cert.get("version"),
    }


def tcp_open(host: str, port: int, timeout: float = 3.0, *, settings=None) -> bool:
    """Мягкая проверка живости порта (только по своим/авторизованным таргетам).

    Через stealth.raw_connect, а не напрямую: иначе проверка живости порта
    идёт с домашнего адреса даже тогда, когда всё остальное прикрыто.
    """
    try:
        with stealth.raw_connect(host, port, timeout=timeout):
            return True
    except Exception:
        return False


def asn_intel(ip: str, *, settings=None) -> dict:
    """Ещё один срез по сети: префикс + ASN (для «инфраструктурного профиля»)."""
    return ripe_prefix(ip, settings=settings)
