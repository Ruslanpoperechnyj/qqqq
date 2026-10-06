# -*- coding: utf-8 -*-
"""Слой сверки сведений: факт — это значение вместе с источником и датой.

Урок живого прогона сложной задачи (§31.9). Модель рассуждала верно, но не
сверялась с тем, что перед ней лежало: назвала применимой уязвимость, закрытую
в предыдущей версии (так сказал отчёт сканера), не заметила счётчик блокировки
3 из 5 в журнале и не потребовала перепроверить версию по скану трёхнедельной
давности. Это не работа для модели — рассуждение о задаче и сверка чисел
требуют разного. Здесь и живёт сверка: то, что можно посчитать, считает код.

Что делает слой:

* **применимость по диапазону.** Запись NVD разбирается до `cpeMatch`, и
  вердикт получает причину словами: «уязвимы <= 9.4.50, у нас 9.4.51». Не
  «применимо», не оценка модели, а диапазон и место в нём;
* **наше уточнение сильнее NVD.** Если по версии есть правило проекта
  (`knowledge.refinements`), оно проверяется первым: у вендора данные точнее,
  чем широкий интервал в записи;
* **источник и дата у каждого значения.** «NVD, кэш 4 дня» — иначе через
  неделю никто не вспомнит, сверялись мы или догадались;
* **свежесть.** У данных объекта есть возраст, и устаревшее не молчит:
  «скан 22 дня — версии перепроверить»;
* **«не подтверждено» вместо догадки.** Где данных нет, там именно это и
  написано. Модель, увидевшая «не подтверждено», спросит или пометит шаг как
  гипотезу; модель, увидевшая ложное «применимо», пойдёт бить по дырке,
  которой нет.

Почему отдельно от `cve.py`. Там — добыча: NVD, KEV, EPSS, лимиты и кэш, то
есть долгая сетевая работа конвейера. Здесь — сверка того, что уже добыто.
Поэтому слой по умолчанию в сеть НЕ ходит: читает кэш.

Доступ к сети — режимом (по умолчанию самый тихий):

* `off`   — не читаем даже кэш, ничего не подтверждено;
* `cache` — читаем кэш, в сеть не ходим (по умолчанию);
* `allow` — можно спросить источник из списка по коду и пополнить кэш.

Источники перечислены в коде (`NVD_HOSTS`), а не в настройке: слой сверки ходит
только туда, где лежат сведения. Общий доступ агента в интернет этим не
разрешается — это отдельное решение оператора (§32).
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from . import cve, store
from .settings import current_settings

# --------------------------------------------------------------------------- вердикты
CONFIRM, REFUTE, UNKNOWN = "confirm", "refute", "unknown"
VERDICT_TITLE = {CONFIRM: "применима", REFUTE: "НЕ применима",
                 UNKNOWN: "не подтверждена"}
VERDICT_MARK = {CONFIRM: "✓", REFUTE: "✗", UNKNOWN: "?"}

# --------------------------------------------------------------------------- режим
MODES = ("off", "cache", "allow")
MODE_ENV = "ASM_FACTS_NET"
MAX_AGE_ENV = "ASM_FACTS_MAX_AGE"
DEFAULT_MAX_AGE = 7
# Список по коду: куда слой сверки имеет право постучаться. Расширяется правкой
# здесь, а не настройкой на объекте.
NVD_HOSTS = ("services.nvd.nist.gov",)

FRESH, AGING, STALE, UNDATED = "fresh", "aging", "stale", "unknown"
SHEET_LIMIT = 12

# Возраст данных объекта считается строже, чем возраст сведений из базы. Список
# открытых портов и версия сервиса живут часами: обновление, перезапуск, перенос
# — и скан трёхнедельной давности описывает уже другой объект. Данные NVD, на
# которых стоит вердикт по уязвимости, живут дольше (там срок — ASM_FACTS_MAX_AGE).
SCAN_WARN_DAYS = 2
SCAN_STALE_DAYS = 14


def mode(explicit: str = "", settings=None) -> str:
    """Режим доступа из явного запроса или snapshot текущей операции."""
    snapshot = settings if settings is not None else current_settings()
    configured = (snapshot.get(MODE_ENV, "cache") if snapshot is not None
                  else os.environ.get(MODE_ENV, "cache"))
    m = (explicit or configured or "cache").strip().lower()
    return m if m in MODES else "cache"


def max_age_days(settings=None) -> int:
    """С какого возраста сведения считаются устаревшими."""
    snapshot = settings if settings is not None else current_settings()
    configured = (snapshot.get(MAX_AGE_ENV, DEFAULT_MAX_AGE) if snapshot is not None
                  else os.environ.get(MAX_AGE_ENV, DEFAULT_MAX_AGE))
    try:
        return max(1, int(configured or DEFAULT_MAX_AGE))
    except (TypeError, ValueError):
        return DEFAULT_MAX_AGE


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dt(ts) -> datetime | None:
    """Дата из строки. Наивные даты NVD (без пояса) трактуются как UTC:
    иначе вычитание осведомлённой даты из наивной падает, а исключение в
    сверке означало бы «возраст неизвестен» на каждом втором источнике.
    """
    try:
        dt = datetime.fromisoformat(str(ts or "").replace("Z", "+00:00"))
    except Exception:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def age_days(ts, now: datetime | None = None) -> float | None:
    dt = _dt(ts)
    if not dt:
        return None
    return ((now or _now()) - dt).total_seconds() / 86400.0


def freshness(ts, *, warn_days: int = 7, stale_days: int = 30,
              now: datetime | None = None, what: str = "данные") -> dict:
    """Возраст сведений и что с ним делать.

    Возраст — не украшение отчёта, а решение: свежие данные можно не
    перепроверять, старые обязаны быть перепроверены перед воздействием.
    Разница между «7 дней» и «22 дня» — это разница между «беру как есть» и
    «поднимаю версию заново».
    """
    days = age_days(ts, now)
    if days is None:
        return {"tier": UNDATED, "days": None,
                "line": f"{what}: дата неизвестна — свежесть не подтверждена"}
    if days < warn_days:
        tier = FRESH
    elif days < stale_days:
        tier = AGING
    else:
        tier = STALE
    dt = _dt(ts)
    when = dt.strftime("%d.%m.%Y") if dt else ""
    tail = {"fresh": "данные свежие",
            "aging": "данные не свежие: версии и порты могли измениться",
            "stale": "данные устарели: перед воздействием перепроверить версию"}[tier]
    return {"tier": tier, "days": round(days, 1),
            "line": f"{what} от {when} ({int(days)} дн.) — {tail}"}


# --------------------------------------------------------------------------- отрицания
# Разбор фразы для сверки чужих ответов (§31.9): окно вокруг совпадения не
# работает ни в одну сторону, границы фразы работают. Живёт здесь, а не в
# `plancheck`, потому что сверка нужна обоим, а `plancheck` — надстройка.
_BOUNDARY = re.compile(r"\n|[.;!?](?=\s|$)|(?:^|\s)—(?=\s)")
_NEGATIONS = ("не ", "нет ", "нельзя", "запрещ", "вместо", "кроме", "исключен",
              "исключён", "никак", "отказ", "недопустим", "без ")


def clause(text: str, pos: int) -> tuple[int, int]:
    """Границы фразы вокруг позиции: от предыдущей границы до следующей."""
    start = 0
    for m in _BOUNDARY.finditer(text or ""):
        if m.end() <= pos:
            start = m.end()
        else:
            return start, m.start()
    return start, len(text or "")


def negated(text: str, match: str) -> bool:
    """Все упоминания стоят в отрицании? («не используем hydra» — да)

    Отрицание ищется до совпадения и после: «перебор (hydra) не используем» —
    запрет стоит после слова. Если хоть одно упоминание идёт без отрицания в
    своей фразе, находка считается настоящей: показать лишнее оператору дешевле,
    чем принять совет за разрешение.
    """
    if not match:
        return False
    low = (text or "").lower()
    needle = match.lower()
    pos, found = low.find(needle), False
    while pos >= 0:
        found = True
        start, end = clause(text, pos)
        before = (text or "")[start:pos].lower()
        after = (text or "")[pos + len(needle):end].lower()
        if not any(n in before for n in _NEGATIONS) and \
                not any(n in after for n in _NEGATIONS):
            return False
        pos = low.find(needle, pos + 1)
    return found


# --------------------------------------------------------------------------- версии
def _row(row) -> dict:
    """Строка sqlite3.Row или None — привести к словарю (как `planner._row`)."""
    if row is None:
        return {}
    if isinstance(row, dict):
        return row
    try:
        return {k: row[k] for k in row.keys()}
    except Exception:
        return {}


def cpe23(vendor: str, product: str, version: str) -> str:
    """CPE 2.3 из частей. Пустой поставщик — «любой»: в находках вендора нет,
    а гадать его нельзя, иначе матчинг по NVD молча ничего не найдёт.
    """
    return (f"cpe:2.3:a:{vendor or '*'}:{product or '*'}:{version or '*'}"
            f":*:*:*:*:*:*:*")


def cpe23_parts(s: str) -> dict:
    p = str(s or "").split(":")
    return {"vendor": p[3] if len(p) > 3 else "",
            "product": p[4] if len(p) > 4 else "",
            "version": p[5] if len(p) > 5 and p[5] not in ("*", "-") else ""}


def range_text(cm: dict) -> str:
    """Диапазон из `cpeMatch` словами: «>= 2.0 и <= 9.4.50»."""
    bits = []
    for key, sign in (("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
                      ("versionEndIncluding", "<="), ("versionEndExcluding", "<")):
        if cm.get(key):
            bits.append(f"{sign} {cm[key]}")
    return " и ".join(bits) if bits else "любая версия"


def _cpe_match_entries(rec: dict, *, product: str, vendor: str = "") -> list[dict]:
    """Записи `cpeMatch`, относящиеся к этому продукту.

    Продукт обязателен, поставщик — нет: в находках его нет вовсе. Поэтому
    совпадение по продукту, а вендор сужает, если известен.
    """
    out = []
    for conf in rec.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                if cm.get("vulnerable") is False:
                    continue
                parts = str(cm.get("criteria") or "").split(":")
                if len(parts) < 6 or parts[4] != product:
                    continue
                if vendor and parts[3] not in (vendor, "*", "-"):
                    continue
                out.append(cm)
    return out


def record_applicability(rec: dict, *, product: str, version: str,
                         vendor: str = "") -> dict:
    """Применима ли запись NVD к этой версии продукта — с причиной.

    Порядок важнее полноты: сначала наше уточнение (у вендора точнее), затем
    диапазоны NVD, затем честное «не подтверждено». Вердикт никогда не
    выводится из наличия CVE в отчёте сканера — за это и заплатили ошибкой в
    прогоне №1.
    """
    cid = str(rec.get("id") or rec.get("cve_id") or "").upper()
    if not str(version or "").strip():
        # Без версии «применимо» — не вывод, а догадка. В `cve.version_in_range`
        # пустая версия трактуется как «возможно уязвимо» (это верно для отчёта
        # сканера: показать подозрение), но сверке нужен факт: здесь отвечаем
        # «не подтверждена», чтобы модель пошла проверять версию, а не бить.
        return {"cve": cid, "verdict": UNKNOWN, "ranges": [],
                "why": "версия продукта не подтверждена", "source": "nvd"}
    if cid and not cve._refine(cid, cpe23(vendor, product, version), version):  # noqa: SLF001
        return {"cve": cid, "verdict": REFUTE, "ranges": [],
                "why": f"по нашему уточнению диапазона версия {version} вне уязвимых",
                "source": "уточнение проекта"}
    matched = _cpe_match_entries(rec, product=product, vendor=vendor)
    if not matched:
        return {"cve": cid, "verdict": UNKNOWN, "ranges": [],
                "why": (f"в записи NVD нет диапазона для продукта «{product}» — "
                        f"уязвимость про другое изделие"
                        if rec.get("configurations") else
                        "в записи NVD нет данных о конфигурациях"),
                "source": "nvd"}
    ranges = []
    for cm in matched:
        txt = range_text(cm)
        if txt not in ranges:
            ranges.append(txt)
    sure = [cm for cm in matched if cve.version_in_range(version, cm)]
    if sure:
        return {"cve": cid, "verdict": CONFIRM, "ranges": ranges,
                "why": f"уязвимы версии {range_text(sure[0])}; у нас {version}",
                "source": "nvd"}
    return {"cve": cid, "verdict": REFUTE, "ranges": ranges,
            "why": f"уязвимы версии {' или '.join(ranges)}; у нас {version}",
            "source": "nvd"}


# --------------------------------------------------------------------------- добытое
def _payload(cpe23_str: str) -> dict:
    """Ответ NVD по этому CPE из кэша — без сети и без срока годности.

    Два ключа, потому что их два и в конвейере: `cves_for_cpe23` кладёт ответ
    под своим именем, а сырой HTTP-кэш — под ключом запроса. Второй нужен,
    когда скан этот CPE не спрашивал, а мы — да.
    """
    key = "nvd:cpe23:" + cpe23_str
    peek = store.cache_peek(key)
    if peek is None:
        url = cve.nvd_url("cves/2.0", {"cpeName": cpe23_str, "noRejected": "",
                                       "resultsPerPage": 2000})
        peek = store.cache_peek("nvd:" + url)
    if not peek or not isinstance(peek.get("payload"), dict):
        return {}
    data = peek["payload"]
    records = []
    for v in data.get("vulnerabilities") or []:
        rec = v.get("cve") or {}
        if rec.get("id"):
            records.append(rec)
    return {"records": records, "fetched_at": peek.get("fetched_at") or "",
            "cached": True}


def cves_for(cpe23_str: str, *, allow_net: bool | None = None) -> dict:
    """Что известно про эту связку продукт-версия: из кэша, а в сеть — по режиму.

    `allow_net=False` — жёсткий «только кэш» независимо от режима: так ходит
    проверка чужого ответа, которая не имеет права сходить в сеть за тем,
    чего ей не хватает.
    """
    m = mode()
    if m == "off":
        return {"records": [], "fetched_at": "", "origin": "сверка отключена",
                "cached": False}
    got = _payload(cpe23_str)
    age = age_days(got.get("fetched_at")) if got else None
    fresh_enough = got and age is not None and age <= max_age_days()
    if fresh_enough:
        return {**got, "age_days": round(age, 1), "origin": "кэш"}
    can_fetch = (m == "allow") if allow_net is None else bool(allow_net)
    if can_fetch:
        try:
            cve.cves_for_cpe23(cpe23_str)  # пополняет кэш; результат берём из него же
        except Exception as e:  # noqa: BLE001 — сеть не должна ронять сверку
            got2 = _payload(cpe23_str)
            return {**got2, "age_days": age, "origin": f"кэш (запрос не удался: {e})"
                    if got2 else f"нет данных (запрос не удался: {e})", "cached": bool(got2)}
        got2 = _payload(cpe23_str)
        if got2:
            return {**got2, "age_days": round(age_days(got2.get("fetched_at")) or 0, 1),
                    "origin": "запрос к NVD"}
    if got:
        return {**got, "age_days": age, "origin": f"кэш устарел ({int(age or 0)} дн.)"}
    return {"records": [], "fetched_at": "", "origin": "нет данных", "cached": False}


def kev_and_epss(cve_ids: list[str]) -> dict:
    """KEV и EPSS из кэша: пополняет их конвейер скана, здесь только чтение."""
    kev, epss = set(), {}
    idx = store.cache_peek("kev:index")
    table = (idx or {}).get("payload") or {}
    if isinstance(table, dict):
        kev = {c for c in cve_ids if c in table}
    for c in cve_ids:
        peek = store.cache_peek("epss:" + c)
        if peek and peek.get("payload"):
            try:
                epss[c] = float(peek["payload"])
            except (TypeError, ValueError):
                pass
    return {"kev": kev, "epss": epss}


def _cvss_of(rec: dict) -> tuple:
    return cve.cvss_from(rec)


# --------------------------------------------------------------------------- объект
def object_cpes(scan_id: int) -> dict:
    """Связки «продукт-версия» по объекту и что про них уже спрошено у NVD.

    Версии берём из находок и активов скана, CPE — из кэша запросов: только
    так связка получает настоящего вендора, которого в таблице находок нет.
    Версия, по которой CPE не запрашивали, попадает в «не подтверждено» —
    это и есть честный ответ на вопрос «а применима ли тут та уязвимость».
    """
    versions: dict[str, str] = {}
    for f in store.scan_findings(scan_id):
        ver = str(f.get("version") or "").strip()
        if ver:
            versions.setdefault(ver, str(f.get("product") or "").strip() or ver)
    for a in store.scan_assets(scan_id):
        meta = a.get("meta") or {}
        ver = str(meta.get("version") or "").strip()
        if ver:
            versions.setdefault(ver, str(meta.get("product") or ver).strip())
    cpes, seen = [], set()
    for row in store.q("SELECT key FROM cache WHERE key LIKE 'nvd:cpe23:%'"):
        s = str(row["key"])[len("nvd:cpe23:"):]
        parts = cpe23_parts(s)
        ver = parts.get("version") or ""
        if not ver or ver not in versions or s in seen:
            continue
        seen.add(s)
        cpes.append({"cpe23": s, "vendor": parts["vendor"], "product": parts["product"],
                     "version": ver, "display": versions.get(ver) or f"{parts['product']} {ver}"})
    unknown = [{"product": disp, "version": ver}
               for ver, disp in versions.items()
               if not any(c["version"] == ver for c in cpes)]
    return {"cpes": cpes, "unverified": unknown}


def sheet(*, scan_id: int = 0, allow_net: bool | None = None) -> dict:
    """Лист фактов по объекту: что проверено, чем подтверждено и насколько свежо.

    Это то, что кладётся модели в подсказку и то, по чему сверяется её ответ.
    Один сборщик на оба применения: разойдись они — модель считала бы законным
    то, что сверка объявляет выдумкой.
    """
    out: dict = {"scan": {}, "products": [], "index": {}, "lines": [],
                 "unverified": [], "mode": mode(), "scan_id": scan_id}
    if not scan_id:
        return out
    sc = store.scan(scan_id)
    if sc:
        ts = sc["finished_at"] or sc["started_at"]
        fr = freshness(ts, what=f"скан №{sc['id']}",
                       warn_days=SCAN_WARN_DAYS, stale_days=SCAN_STALE_DAYS)
        out["scan"] = {"id": sc["id"], "finished_at": ts, **fr}
    oc = object_cpes(scan_id)
    ids: list[str] = []
    for item in oc["cpes"]:
        got = cves_for(item["cpe23"], allow_net=allow_net)
        rows = []
        for rec in got["records"]:
            v = record_applicability(rec, product=item["product"],
                                     version=item["version"], vendor=item["vendor"])
            cvss, sev, _vec = _cvss_of(rec)
            rows.append({**v, "cvss": cvss, "severity": sev,
                         "published": rec.get("published", ""),
                         "fetched_at": got.get("fetched_at") or "",
                         "age_days": got.get("age_days"),
                         "origin": got.get("origin") or ""})
            ids.append(v["cve"])
        rows.sort(key=lambda r: (r["verdict"] != CONFIRM, -(r["cvss"] or 0)))
        out["products"].append({**item, "cves": rows, "origin": got.get("origin") or "",
                                "age_days": got.get("age_days"),
                                "fetched_at": got.get("fetched_at") or ""})
    extra = kev_and_epss(sorted(set(ids)))
    for p in out["products"]:
        for c in p["cves"]:
            c["kev"] = c["cve"] in extra["kev"]
            c["epss"] = extra["epss"].get(c["cve"])
            prev = out["index"].get(c["cve"])
            # одна CVE может прийти на разные продукты: в индексе держим
            # сильнейший вердикт — «подтверждена» важнее «не применима», иначе
            # сверка чужих ответов замолчала бы там, где опасность настоящая.
            rank = {CONFIRM: 0, UNKNOWN: 1, REFUTE: 2}
            if prev is None or rank[c["verdict"]] < rank[prev["verdict"]]:
                out["index"][c["cve"]] = {**c, "product": p["product"],
                                          "version": p["version"],
                                          "display": p["display"]}
    for u in oc["unverified"]:
        out["unverified"].append(
            f"{u['product']} {u['version']}: версия известна, но CVE по ней мы "
            f"не спрашивали — применимость уязвимостей не подтверждена")
    if out["mode"] == "off":
        out["unverified"].append(
            "сверка отключена (ASM_FACTS_NET=off): ни один факт не подтверждён")
    out["lines"] = lines(out)
    return out


def sheet_for_session(session_id: int) -> dict:
    """Лист фактов по последнему завершённому скану объекта этой сессии.

    Только кэш: проверка чужого ответа не имеет права ходить в сеть за тем,
    чего ей не хватает, — иначе прогон с внешним чатом превратился бы в серию
    запросов, о которых оператор не знает.
    """
    sess = _row(store.agent_session(session_id))
    tid = sess.get("target_id")
    if not tid:
        return {}
    sc = store.last_done_scan(int(tid))
    if not sc:
        return {}
    return sheet(scan_id=int(sc["id"]), allow_net=False)


def lines(sh: dict) -> list[str]:
    """Строки фактов — то, что идёт в подсказку модели и в отчёт о проверке."""
    out: list[str] = []
    sc = sh.get("scan") or {}
    if sc.get("line"):
        out.append(sc["line"] + (" → заказать свежую идентификацию"
                                 if sc.get("tier") in (AGING, STALE) else ""))
    for p in sh.get("products") or []:
        for c in p["cves"]:
            if c["verdict"] == UNKNOWN:
                continue  # «не подтверждено» — в отдельный список, не в факты
            mark = "NVD" if c["source"] == "nvd" else c["source"]
            age = f", кэш {int(c['age_days'])} дн." if c.get("age_days") is not None else ""
            tail = ""
            if c.get("kev"):
                tail = " | CISA KEV: эксплуатация в реальных атаках"
            elif c.get("epss"):
                tail = f" | EPSS {c['epss']:.0%}"
            out.append(f"{p['display']}: {c['cve']} {VERDICT_TITLE[c['verdict']]} — "
                       f"{c['why']} [{mark}{age}{tail}]")
    if len(out) > SHEET_LIMIT:
        out = out[:SHEET_LIMIT] + [f"…и ещё {len(out) - SHEET_LIMIT} фактов в кэше"]
    return out


def render_sheet(sh: dict, *, limit: int = 24) -> str:
    """Лист фактов человеку: то же, что уходит модели, плюс режим сверки."""
    if not sh or not sh.get("scan_id"):
        return ("Лист фактов пуст: по объекту не выбрано ни одного скана.\n"
                "Показать по сессии:  python3 app.py agent facts <сессия>")
    out = [f"Факты по объекту (сверка: режим {sh.get('mode')}, скан {sh['scan_id']})"]
    if sh.get("scan", {}).get("line"):
        out.append("  " + sh["scan"]["line"])
    shown = 0
    for p in sh.get("products") or []:
        if not p["cves"]:
            out.append(f"  {p['display']}: данных NVD в кэше нет ({p['origin']})")
            continue
        out.append(f"  {p['display']} [{p['vendor']}:{p['product']}] — {p['origin']}:")
        for c in p["cves"]:
            if shown >= limit:
                break
            shown += 1
            extra = []
            if c.get("cvss"):
                extra.append(f"CVSS {c['cvss']}")
            if c.get("kev"):
                extra.append("KEV")
            elif c.get("epss"):
                extra.append(f"EPSS {c['epss']:.0%}")
            tail = ("  (" + ", ".join(extra) + ")") if extra else ""
            out.append(f"    {VERDICT_MARK[c['verdict']]} {c['cve']} — "
                       f"{VERDICT_TITLE[c['verdict']]}: {c['why']}{tail}")
    for u in sh.get("unverified") or []:
        out.append("  ? " + u)
    out.append("")
    out.append("Сверка — это код, а не модель: вердикт по диапазону версий, "
               "источник и дата у каждого значения.")
    return "\n".join(out)


# --------------------------------------------------------------------------- сверка ответа
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def cves_in(text: str) -> list[str]:
    """Идентификаторы уязвимостей из текста — в порядке появления, без повторов."""
    out: list[str] = []
    for m in CVE_RE.finditer(text or ""):
        cid = m.group(0).upper()
        if cid not in out:
            out.append(cid)
    return out


def verify(text: str, sh: dict) -> list[dict]:
    """Сверить названные в тексте уязвимости с тем, что мы о них знаем.

    Вердикт даётся не «верит ли модель», а тому, есть ли у нас данные. Три
    случая, и они не равны: подтверждена нашим списком, опровергнута (в ответе
    её используют, а она закрыта или не про этот продукт) и «у нас нет данных»
    — последнее не ошибка ответа, а дыра в наших сведениях, и она называется.
    """
    idx = (sh or {}).get("index") or {}
    out = []
    for cid in cves_in(text):
        used = not negated(text, cid)
        item = idx.get(cid)
        if item is None:
            out.append({"cve": cid, "verdict": UNKNOWN, "used": used,
                        "why": "по этому объекту данных у нас нет",
                        "source": "", "contradiction": False})
            continue
        out.append({**item, "used": used,
                    "contradiction": bool(used and item["verdict"] == REFUTE)})
    return out


def render_verify(claims: list[dict], sh: dict | None = None) -> list[str]:
    """Строки сверки для отчёта о проверке ответа.

    `sh` — лист фактов: из него добавляется строка о свежести данных объекта.
    Возраст скана — такая же сверяемая конкретика, как диапазон версий: по
    нему решается, можно ли вообще опираться на названные версии.
    """
    if not claims:
        return []
    out = ["СВЕРКА СВЕДЕНИЙ (по базе и кэшу, а не по словам модели):"]
    sc = (sh or {}).get("scan") or {}
    if sc.get("tier") in (AGING, STALE):
        out.append("  ! " + sc["line"])
    for c in claims:
        src = f" [{c['source']}]" if c.get("source") else ""
        if c.get("contradiction"):
            out.append(f"  ✗ {c['cve']} — в ответе используется как применимая, "
                       f"а у нас {VERDICT_TITLE[c['verdict']].lower()}: {c['why']}{src}")
        elif not c.get("used"):
            out.append(f"  · {c['cve']} — упомянута в отрицании; у нас "
                       f"{VERDICT_TITLE[c['verdict']].lower()} ({c['why']}){src}")
        elif c["verdict"] == CONFIRM:
            out.append(f"  ✓ {c['cve']} — подтверждена: {c['why']}{src}")
        elif c["verdict"] == REFUTE:
            out.append(f"  · {c['cve']} — {VERDICT_TITLE[c['verdict']]} "
                       f"({c['why']}){src}")
        else:
            out.append(f"  ? {c['cve']} — {c['why']}: прежде чем опираться, "
                       f"проверить версию на объекте")
    bad = [c for c in claims if c.get("contradiction")]
    if bad:
        out.append(f"  Итог сверки: расхождений с базой — {len(bad)}. Такой шаг "
                   f"до воздействия не дойдёт: сначала новая идентификация версии.")
    return out
