"""
Пайплайн «продукт+версия -> CPE -> CVE -> CVSS/EPSS/KEV».

Это тот самый «предиктор» из видео. Разница с оригиналом только в том,
что он у нас честно ходит в публичные базы (NVD, CISA KEV, FIRST EPSS),
а не «предсказывает» уязвимости магией.

Ключевые оптимизации:
  * SQLite-кэш на все ответы NVD (7 дней) — повторный анализ мгновенный
  * токен-бакет 5 запросов / 30 сек (лимит NVD без API-ключа)
  * пакетная докачка KEV и EPSS одним запросом на CVE-id
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
from typing import Iterable

from . import collect, store

NVD = "https://services.nvd.nist.gov/rest/json"
NVD_KEY = os.environ.get("NVD_API_KEY", "").strip()
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={ids}"

_last_call = [0.0]


def _nvd_rate_limit() -> None:
    """5 запросов / 30 сек без ключа; с ключом — 50/30 сек."""
    window = 30.0
    max_calls = 50 if NVD_KEY else 5
    min_gap = window / max_calls
    dt = time.time() - _last_call[0]
    if dt < min_gap:
        time.sleep(min_gap - dt)
    _last_call[0] = time.time()


def nvd_url(path: str, params: dict) -> str:
    """URL запроса к NVD — один на добычу и на сверку.

    Слой сверки (`facts`) читает ответ NVD из кэша по тому же ключу, под каким
    его положил запрос. Разойдись эти два места хоть в порядке параметров — и
    сверка молча не нашла бы ничего, показывая «не подтверждено» там, где
    данные лежат.
    """
    return f"{NVD}/{path}?{urllib.parse.urlencode(params)}"


def _nvd_get(path: str, params: dict, ttl: int = 86400 * 7) -> dict:
    url = nvd_url(path, params)
    hit = store.cache_get("nvd:" + url, ttl)
    if hit is not None:
        return hit
    _nvd_rate_limit()
    headers = {"Accept": "application/json"}
    if NVD_KEY:
        headers["apiKey"] = NVD_KEY
    data = collect._http(url, 0, headers=headers)
    if isinstance(data, dict) and "_error" not in data:
        store.cache_put("nvd:" + url, data)
    return data if isinstance(data, dict) else {}


# ------------------------------------------------------------------ версии
def _vparts(v: str) -> list:
    parts = re.findall(r"\d+|[a-zA-Z]+", str(v or ""))
    out = []
    for p in parts:
        out.append(int(p) if p.isdigit() else p.lower())
    return out


def compare_versions(a: str, b: str) -> int:
    """Сравнение версий по частям: 9.4.51 > 9.4.50, 2.4.1 < 2.10, 8.3p1 < 9.3p2.

    Числовые части сравниваются как числа, буквенные — как строки, «p1» из
    «8.3p1» — отдельная часть. Версия из большего числа частей считается
    большей: 9.4.51.1 > 9.4.51. Возвращает -1, 0, 1.

    Раньше этот же код жил двумя вложенными функциями в `version_in_range` и в
    `_refine_one`, а третий такой же понадобился слою сверки — то есть три
    копии одного правила, которое обязано быть одним: расхождение между
    «применимо по NVD» и «применимо по нашему уточнению» читалось бы как
    противоречие в отчёте.
    """
    x, y = _vparts(a), _vparts(b)
    for i, j in zip(x, y):
        if isinstance(i, int) and isinstance(j, int):
            if i != j:
                return -1 if i < j else 1
        else:
            si, sj = str(i), str(j)
            if si != sj:
                return -1 if si < sj else 1
    return (len(x) > len(y)) - (len(x) < len(y))


def version_in_range(version: str, m: dict) -> bool:
    """Проверка попадания версии в диапазон versionStart/End из конфигурации CVE."""
    if not version:
        return True  # версия неизвестна -> считаем «возможно уязвимо»
    checks = [
        ("versionStartIncluding", lambda c: c >= 0),
        ("versionStartExcluding", lambda c: c > 0),
        ("versionEndIncluding", lambda c: c <= 0),
        ("versionEndExcluding", lambda c: c < 0),
    ]
    for key, pred in checks:
        if m.get(key):
            try:
                c = compare_versions(version, m[key])
            except Exception:
                continue
            if not pred(c):
                return False
    return True


# ------------------------------------------------------------------ CPE -> CVE
def cpe_candidates(vendor: str, product: str) -> list[str]:
    """Находим точные CPE-имена в словаре NVD (это ключ к корректному матчингу)."""
    if not vendor or not product:
        return []
    key = f"cpe:{vendor}:{product}"
    hit = store.cache_get(key, 86400 * 30)
    if hit is not None:
        return hit
    data = _nvd_get("cpes/2.0", {"keywordSearch": product, "resultsPerPage": 200}, ttl=86400 * 30)
    names: list[str] = []
    for item in (data.get("products") or []):
        cpe = (item.get("cpe") or {}).get("cpeName", "")
        parts = cpe.split(":")
        if len(parts) > 5 and parts[3] == vendor and parts[4] == product:
            names.append(cpe)
    store.cache_put(key, names)
    return names


def cvss_from(item: dict) -> tuple[float | None, str, str]:
    metrics = item.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            d = arr[0].get("cvssData") or {}
            score = d.get("baseScore")
            sev = d.get("baseSeverity") or (arr[0].get("baseSeverity") if arr[0].get("baseSeverity") else "")
            vector = d.get("vectorString", "")
            if score:
                sev = sev or ("CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW")
                return float(score), sev.upper(), vector
    return None, "", ""


def _cpe_matches(item: dict, cpes: Iterable[str], version: str) -> bool:
    cpes = list(cpes)
    for conf in item.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for cm in node.get("cpeMatch", []) or []:
                if not cm.get("vulnerable", True):
                    continue
                crit = cm.get("criteria", "")
                for cpe in cpes:
                    prefix = ":".join(cpe.split(":")[:5])  # cpe:2.3:a:vendor:product
                    if crit.startswith(prefix) and version_in_range(version, cm):
                        return True
    # Некоторые записи без configurations — не отбрасываем молча
    return False


CURATED: dict[tuple[str, str], list[dict]] = {
    ("apache", "2.4.49"): [{"cve": "CVE-2021-41773", "cvss": 9.8, "note": "Path traversal -> RCE, эксплуатируется в дикой природе"}],
    ("apache", "2.4.50"): [{"cve": "CVE-2021-42013", "cvss": 9.8, "note": "Обход патча CVE-2021-41773: path traversal -> RCE"}],
    ("apache", "2.4.51"): [{"cve": "CVE-2021-42013", "cvss": 9.8, "note": "Обход патча, исправлено в 2.4.51"}],
    ("apache", "2.4.48"): [{"cve": "CVE-2021-41773", "cvss": 9.8, "note": "Path traversal в mod_proxy"}],
    ("drupal", "7"): [{"cve": "CVE-2018-7600", "cvss": 9.8, "note": "Drupalgeddon2: RCE без аутентификации"}],
}


def curated_for(vendor: str, product: str, version: str) -> list[dict]:
    key = (product.lower(), version)
    if key in CURATED:
        return CURATED[key]
    # по мажорной версии
    major = str(version).split(".")[0]
    return CURATED.get((product.lower(), major), [])


def cpe23_from_cpe_uri(uri: str) -> str | None:
    """
    'cpe:/a:apache:http_server:2.4.7' -> 'cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*'
    (формат InternetDB/Shodan -> формат NVD 2.0). Без версии не конвертируем:
    иначе запрос вернёт все версии продукта и превратится в шум.
    """
    if not uri or not uri.startswith("cpe:/"):
        return None
    parts = uri[5:].split(":")
    if len(parts) < 4 or not parts[3]:
        return None
    kind, vendor, product, version = parts[0], parts[1], parts[2], parts[3]
    version = version.replace("%2f", "/")
    rest = parts[4:] if len(parts) > 4 else []
    fields = [kind, vendor, product, version] + rest
    fields += ["*"] * (11 - len(fields))
    return "cpe:2.3:" + ":".join(fields[:11])


def _version_of_cpe23(cpe23: str) -> str:
    """
    Версия из CPE. Формат 2.3: cpe:2.3:<part>:<vendor>:<product>:<version>:...
                                            ^3      ^4       ^5
    Формат URI:   cpe:/<part>:<vendor>:<product>:<version>  (индексы 0..3 после 'cpe:/')
    """
    if cpe23.startswith("cpe:/"):
        parts = cpe23[5:].split(":")
        v = parts[3] if len(parts) > 3 else ""
    else:
        parts = cpe23.split(":")
        v = parts[5] if len(parts) > 5 else ""
    return "" if v in ("", "*", "-") else v


# Ручные уточнения диапазонов: NVD иногда задаёт слишком широкий интервал
# (например, «все версии до 9.3»), тогда как производитель указывает точный.
# Для клиентского отчёта важнее точность, поэтому такие случаи поправляем руками.
REFINED_RANGES: dict[str, tuple[str, str, str, str]] = {
    # cve_id: (part, vendor, product, versionStartIncluding, versionEndExcluding)
    "CVE-2023-38408": ("a", "openbsd", "openssh", "8.3p1", "9.3p2"),
    "CVE-2021-41773": ("a", "apache", "http_server", "2.4.49", "2.4.50"),
    "CVE-2021-42013": ("a", "apache", "http_server", "2.4.50", "2.4.51"),
}


def _rule_applies(rule: tuple, parts: list[str]) -> bool:
    """Совпадает ли правило с этим CPE по продукту, поставщику и классу."""
    part, vendor, product, _vs, _ve = rule
    if len(parts) < 5 or parts[4] != product:
        return False
    # Пустой vendor — это «любой», а не «ничей». Уточнение, накопленное с
    # trivy/osv, поставщика не знает вовсе, и без этого условия оно
    # отфильтровывало бы каждую версию продукта, пряча в том числе настоящие
    # находки — то есть вело бы себя ровно наоборот.
    if vendor and parts[3] != vendor:
        return False
    if part and parts[2] != part:
        return False
    return True


def _refine(cve_id: str, cpe23: str, version: str) -> bool:
    """True — запись согласуется с уточнённым диапазоном (или уточнений нет).

    Правил на одну CVE может быть несколько: одна и та же CVE приходит на разные
    продукты, и каждое уточнение описывает свой. Применяются только правила,
    подходящие к этому CPE; не подходит ни одно — запись остаётся.

    Если подходящих правил несколько и они расходятся по диапазону, находка
    остаётся, когда попадает хотя бы в один из них. Спор между правилами
    решается в пользу показа, а не подавления: пропущенная настоящая уязвимость
    стоит дороже лишней строки в отчёте.
    """
    # Правила берутся из базы знаний: встроенный словарь плюс то, что оператор
    # накопил на объектах. Импорт отложенный — knowledge ссылается на cve.
    try:
        from . import knowledge
        rules = knowledge.refinements().get(str(cve_id).upper()) or []
    except Exception:
        rules = [tuple(r) for r in (REFINED_RANGES.get(cve_id) or [])]
    if not rules or not version:
        return True
    parts = cpe23.split(":")
    mine = [r for r in rules if _rule_applies(r, parts)]
    if not mine:
        return True  # уточнения есть, но все про другой продукт
    if len(mine) > 1:
        return any(_refine_one(r, version) for r in mine)
    return _refine_one(mine[0], version)


def _refine_one(rule: tuple, version: str) -> bool:
    """Проверка версии по одному правилу: [v_start, v_end) — уязвимый диапазон."""
    _part, _vendor, _product, v_start, v_end = rule
    if v_start and compare_versions(version, v_start) < 0:
        return False
    if v_end and compare_versions(version, v_end) >= 0:
        return False
    return True


def cves_for_cpe23(cpe23: str, limit: int = 2000, verify: bool = True) -> list[dict]:
    """
    Точный запрос к NVD по CPE версии: NVD сам учитывает диапазоны
    versionStart/End. Один HTTP-запрос на продукт-версию (кэш 7 дней).

    verify=True включает вторую проверку на нашей стороне: часть записей NVD
    содержит широкие диапазоны, из-за которых в выдачу попадают версии,
    которых уязвимость не касается. Для клиентского отчёта точность важнее полноты.
    """
    key = "nvd:cpe23:" + cpe23
    data = store.cache_get(key, 86400 * 7)
    if data is None:
        data = _nvd_get("cves/2.0", {"cpeName": cpe23, "noRejected": "",
                                     "resultsPerPage": min(limit, 2000)}, ttl=86400 * 7) or {}
        store.cache_put(key, data)
    version = _version_of_cpe23(cpe23)
    dropped = 0
    out: list[dict] = []
    for v in (data.get("vulnerabilities") or []):
        rec = v.get("cve") or {}
        cid = rec.get("id")
        if not cid:
            continue
        if verify and version:
            if not _refine(cid, cpe23, version):
                dropped += 1
                continue
            if rec.get("configurations") and not _cpe_matches(rec, [cpe23], version):
                dropped += 1
                continue
        sv, sev, vector = cvss_from(rec)
        desc = ""
        for d in rec.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        out.append({"cve_id": cid, "cvss": sv, "severity": sev, "vector": vector,
                    "description": desc, "published": rec.get("published", ""),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}", "source": "nvd-cpe"})
    return out


def cves_for_product(vendor: str, product: str, version: str, limit: int = 400) -> list[dict]:
    """Возвращает список {cve_id, cvss, severity, vector, description, url}."""
    if version:
        direct = cves_for_cpe23(f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*")
        if direct:
            return direct
    cpes = cpe_candidates(vendor, product)
    if not cpes:
        return []
    # запрос по virtualMatchString = cpe:2.3:a:vendor:product (одна ветка, все версии)
    vms = f"cpe:2.3:a:{vendor}:{product}"
    out: list[dict] = []
    seen: set[str] = set()
    start = 0
    while start < limit:
        data = _nvd_get("cves/2.0", {
            "virtualMatchString": vms,
            "noRejected": "",
            "resultsPerPage": 200,
            "startIndex": start,
        })
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            break
        for v in vulns:
            cve = v.get("cve") or {}
            cid = cve.get("id")
            if not cid or cid in seen:
                continue
            if not _cpe_matches(cve, cpes, version):
                continue
            score, sev, vector = cvss_from(cve)
            desc = ""
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            seen.add(cid)
            out.append({"cve_id": cid, "cvss": score, "severity": sev, "vector": vector,
                        "description": desc,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                        "published": cve.get("published", ""),
                        "source": "nvd"})
        start += 200
        total = data.get("totalResults", 0)
        if start >= total:
            break
    return out


# ------------------------------------------------------------------ KEV / EPSS
def kev_set(ttl: int = 86400) -> dict[str, dict]:
    data = collect._http(KEV_URL, ttl)
    out: dict[str, dict] = {}
    if isinstance(data, dict):
        for v in data.get("vulnerabilities", []) or []:
            out[v.get("cveID", "")] = {
                "vendor": v.get("vendorProject"), "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "dateAdded": v.get("dateAdded"),
                "dueDate": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse"),
            }
    store.cache_put("kev:index", out)
    return out


def kev_lookup(cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}
    idx = store.cache_get("kev:index", 86400)
    if idx is None:
        idx = kev_set()
    return {c: idx[c] for c in cve_ids if c in idx}


def epss_lookup(cve_ids: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    todo = []
    for c in cve_ids:
        hit = store.cache_get("epss:" + c, 86400 * 3)
        if hit is not None:
            if hit:
                out[c] = float(hit)
        else:
            todo.append(c)
    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        data = collect._http(EPSS_URL.format(ids=",".join(chunk)), 86400 * 3)
        got = {}
        if isinstance(data, dict):
            for row in data.get("data", []) or []:
                got[row.get("cve")] = float(row.get("epss", 0) or 0)
        for c in chunk:
            val = got.get(c, 0.0)
            store.cache_put("epss:" + c, val)
            if val:
                out[c] = val
    return out


def enrich(cves: list[dict]) -> list[dict]:
    ids = [c["cve_id"] for c in cves]
    kev = kev_lookup(ids)
    epss = epss_lookup(ids)
    for c in cves:
        c["kev"] = c["cve_id"] in kev
        c["kev_info"] = kev.get(c["cve_id"], {})
        c["epss"] = epss.get(c["cve_id"], 0.0)
    return cves


def nvd_text_summary(cve: dict) -> str:
    """Короткое русскоязычное описание класса уязвимости по CVSS-вектору/описанию."""
    vec = (cve.get("vector") or "").upper()
    desc = (cve.get("description") or "").lower()
    tags = []
    if "RCE" in vec or re.search(r"remote code execution|arbitrary code|command execution", desc):
        tags.append("выполнение произвольного кода (RCE)")
    if re.search(r"path traversal|directory traversal|\.\./", desc) or "AV:N/AC:L" in vec:
        pass
    if re.search(r"sql injection", desc):
        tags.append("SQL-инъекция")
    if re.search(r"denial of service|dos ", desc):
        tags.append("отказ в обслуживании (DoS)")
    if re.search(r"authentication bypass|bypass authentication", desc):
        tags.append("обход аутентификации")
    if re.search(r"privilege escalation", desc):
        tags.append("повышение привилегий")
    if re.search(r"information disclosure|disclos\w+ information", desc):
        tags.append("утечка информации")
    if re.search(r"ssrf|server-side request forgery", desc):
        tags.append("SSRF")
    if re.search(r"cross-site scripting|xss", desc):
        tags.append("XSS")
    if re.search(r"deserialization", desc):
        tags.append("десериализация (потенциальный RCE)")
    return ", ".join(tags) if tags else "по данным NVD"
