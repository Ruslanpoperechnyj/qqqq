"""Экспорт отчёта: Markdown (для заказчика), JSON (для интеграций), CSV (для трекера)."""
from __future__ import annotations

import re

import csv
import io
import json
from datetime import datetime, timezone

from . import remediate, score, store


def _target_block(t: dict) -> str:
    return (f"| Параметр | Значение |\n|---|---|\n"
            f"| Объект анализа | `{t['value']}` |\n"
            f"| Заказчик | {t['client']} |\n"
            f"| Основание (договор/письмо) | {t['auth_ref']} |\n"
            f"| Дата разрешения | {t.get('auth_date') or '—'} |\n"
            f"| Дата анализа (UTC) | {t.get('created_at','')[:19]} |\n")


def markdown(scan_id: int) -> str:
    sc = store.scan(scan_id)
    t = dict(store.target(sc["target_id"]))
    stats = json.loads(sc["stats"] or "{}")
    rep = stats.get("report", {})
    # записи приводим к словарям и сразу чистим служебные пути: в отчёт заказчику они
    # не должны попадать ни из свежих находок, ни из сохранённых прежними версиями
    findings = []
    for row in store.scan_findings(scan_id):
        f = dict(row)
        for key in ("title", "asset"):
            if f.get(key):
                f[key] = _clean_paths(str(f[key]))
        findings.append(f)
    assets = store.scan_assets(scan_id)
    diffs = stats.get("diffs", {})
    s = score.summarize(findings)

    L = []
    L.append(f"# Отчёт о внешнем периметре: {t['value']}")
    L.append("")
    L.append(_target_block(t))
    L.append("")
    act = (json.loads(sc["stats"] or "{}").get("active") or {}) if sc else {}
    method = ("пассивный анализ открытых источников (Certificate Transparency, DNS, RDAP, RIPEstat, "
              "публичные индексы баннеров)")
    failed = _source_failures(sc)
    if act:
        parts_m = []
        if act.get("ports"):
            parts_m.append("сканирование портов (naabu)")
        if act.get("nuclei"):
            parts_m.append(f"активные проверки уязвимостей по шаблонам (nuclei, адресов: {act.get('urls', 0)})")
        if parts_m:
            method += " + " + " + ".join(parts_m)
    method += (". Эксплуатация уязвимостей не производилась, перебор паролей не выполнялся, "
               "содержимое баз данных не читалось; агрессивные категории проверок исключены.")
    L.append(f"**Метод:** {method}")
    L.append("")
    if failed:
        # Отчёт не должен выглядеть полным, когда часть источников не ответила.
        # «Ничего не найдено» и «источник не опрошен» — разные утверждения.
        L.append(f"**Оговорка по полноте.** Из перечисленных источников "
                 f"{len(failed)} не дали данных в этом анализе:")
        L.append("")
        for name, why in failed[:8]:
            L.append(f"- {name} — {why}")
        L.append("")
        L.append("Выводы по этим направлениям следует считать неполными. Причина "
                 "указана для каждого источника; повторный анализ возможен после "
                 "её устранения.")
        L.append("")
    L.append(f"## 1. Резюме для руководителя")
    L.append("")
    L.append(rep.get("summary", ""))
    L.append("")
    if rep.get("llm_report"):
        L.append(f"> Режим аналитики: {rep.get('mode')}")
        L.append("")
        L.append(rep["llm_report"])
        L.append("")
    L.append("## 2. Инфраструктурный профиль")
    L.append("")
    L.append("```")
    L.append(rep.get("infra_profile", "").strip())
    L.append("```")
    L.append("")
    L.append(f"Собрано активов: **{len(assets)}**; открытых сервисов: **{stats.get('services', 0)}**; "
             f"находок: **{s['total']}** "
             f"(P0 — {s['counts']['P0']}, P1 — {s['counts']['P1']}, P2 — {s['counts']['P2']}, P3 — {s['counts']['P3']}).")
    L.append("")
    L.append("## 3. Приоритет защиты")
    L.append("")
    L.append("```")
    L.append(rep.get("protection_priority", "").strip())
    L.append("```")
    L.append("")
    L.append("## 4. Сводка по продуктам (с чего начинать обновление)")
    L.append("")
    prods = score.by_product(findings)
    if prods:
        L.append("| Продукт | Версия | Объектов | Всего | P0 | P1 | P2 | P3 | Худшая оценка |")
        L.append("|---|---|---|---|---|---|---|---|---|")
        for p in prods[:25]:
            L.append(f"| {p['product']} | {p['version'] or '—'} | {p['assets']} | {p['total']} | "
                     f"{p['P0']} | {p['P1']} | {p['P2']} | {p['P3']} | {p['worst']} |")
        L.append("")
    L.append("## 5. Находки")
    L.append("")
    if findings:
        L.append("| # | Приоритет | Оценка | CVE | Объект | Порт | CVSS | EPSS | KEV |")
        L.append("|---|---|---|---|---|---|---|---|---|")
        for i, f in enumerate(findings[:80], 1):
            L.append("| {i} | {p} | {sc} | {cve} | {asset} | {port} | {cvss} | {epss} | {kev} |".format(
                i=i, p=f.get("priority"), sc=f.get("score"), cve=f.get("cve_id") or f.get("title", "")[:60],
                asset=_clean_paths(f.get("asset") or f.get("ip") or "")[:40], port=f.get("port") or "",
                cvss=f.get("cvss") or "", epss=(f"{f['epss']:.1%}" if f.get("epss") else ""),
                kev="да" if f.get("kev") else ""))
        if len(findings) > 80:
            L.append("")
            L.append(f"*В таблице первые 80 находок из {len(findings)} — полный перечень в CSV-выгрузке.*")
        L.append("")
        detail = [f for f in findings if f.get("priority") in ("P0", "P1")][:12]
        if detail:
            L.append("### Разбор приоритетных находок")
            L.append("")
        for i, f in enumerate(detail, 1):
            L.append(f"#### {i}. {f.get('title')}")
            L.append("")
            _lbl = score.PRIORITY_LABELS.get(f.get("priority"), "")
            _lbl = _lbl.split("—", 1)[-1].strip() if "—" in _lbl else _lbl
            L.append(f"* **Приоритет:** **{f.get('priority')}** — {_lbl}")
            L.append(f"* **Объект:** `{_clean_paths(str(f.get('asset') or f.get('ip') or ''))}`" +
                     (f" (порт {f['port']})" if f.get("port") else ""))
            L.append(f"* **Оценка риска:** {f.get('score')}")
            _kind = store.KIND_LABELS.get(f.get("kind") or "other", "")
            if _kind:
                L.append(f"* **Что это:** {_kind}")
            L.append(f"* **Почему так оценено:** {f.get('rationale')}")
            ev = f.get("evidence") or {}
            if ev.get("описание (NVD)"):
                L.append(f"* **Суть:** {ev['описание (NVD)'][:500]}")
            if ev.get("признак обнаружения"):
                L.append(f"* **Признак обнаружения:** {ev['признак обнаружения']}")
            if ev.get("затронутые объекты"):
                L.append(f"* **Затронуто:** {ev['затронутые объекты']}")
            if ev.get("ссылка"):
                L.append(f"* **Первоисточник:** {ev['ссылка']}")
            fix = f.get("fix") or {}
            if fix.get("пункты"):
                L.append("")
                L.append(f"**Как закрыть** ({fix.get('класс','')}):")
                L.append("")
                for pt in fix["пункты"]:
                    L.append(f"  * {pt}")
                if fix.get("команды"):
                    L.append("")
                    L.append("  ```bash")
                    for c in fix["команды"]:
                        L.append("  " + c.replace("\n", "\n  "))
                    L.append("  ```")
            L.append("")
        rest = [f for f in findings if f.get("priority") in ("P0", "P1")][12:]
        if rest:
            L.append(f"Остальные находки уровня P0/P1 ({len(rest)} шт.) — в таблице выше и в CSV.")
            L.append("")
    else:
        L.append("Находок не выявлено.")
        L.append("")
    L.append("## 6. Сценарий атаки (что будет, если не закрывать)")
    L.append("")
    L.append(rep.get("attack_scenario", ""))
    L.append("")
    if diffs and not diffs.get("first_scan"):
        L.append("## 7. Изменения с прошлого анализа")
        L.append("")
        L.append(f"Сравнение со сканом №{diffs.get('previous_scan_id')}.")
        L.append("")
        for key, title in (("new_assets", "Новые активы"), ("removed_assets", "Исчезли активы"),
                           ("new_findings", "Новые находки"), ("fixed_findings", "Закрытые находки")):
            raw = list(diffs.get(key) or [])
            texts = [_change_text(x) for x in raw]
            probes = []
            if key in ("new_assets", "removed_assets"):
                # адреса вида «…/nosuchurl/><script>alert» — это следы проверок путей,
                # а не новые сервисы заказчика: в списке инфраструктуры им не место
                probes = [t for t in texts if _is_probe_url(t)]
                texts = [t for t in texts if not _is_probe_url(t)]
            if not texts:
                L.append(f"* **{title}:** нет изменений"
                         + (f" (плюс {len(probes)} адресов, найденных проверками путей)" if probes else ""))
                continue
            L.append(f"* **{title}** — {len(texts)} шт.:")
            for t in texts[:12]:
                L.append(f"    * {t}")
            if len(texts) > 12:
                L.append(f"    * …и ещё {len(texts) - 12}")
            if probes:
                L.append(f"    * (не показано ещё {len(probes)} адресов, найденных проверками путей: "
                         f"это не новые сервисы, а результаты перебора имён файлов)")
        L.append("")
    L.append("## 8. Что делать на этой неделе")
    L.append("")
    for line in _todo(findings):
        L.append(f"1. {line}")
    plan = remediate.plan_new_week(findings)
    if plan:
        L.append("")
        L.append("### Сводный план устранения по типам работ")
        L.append("")
        for line in plan:
            L.append(f"* {line}")
    L.append("")
    L.append("## 9. Ограничения метода (прочитать перед выводами)")
    L.append("")
    L.append("* Анализ **пассивный**: объект не сканировался перебором портов, уязвимости не эксплуатировались, "
             "содержимое баз данных не читалось.")
    L.append("* Факт наличия CVE определяется сопоставлением версии компонента с базой NVD. "
             "В дистрибутивах Linux часть уязвимостей закрывается backport-патчами без смены версии — "
             "такие записи требуют ручной проверки.")
    L.append("* Часть записей NVD относится к отдельным модулям продукта, которых у заказчика может не быть "
             "включёнными. Каждую находку уровня P0/P1 следует подтвердить до начала работ.")
    L.append("* Оценка вероятности эксплуатации (EPSS) и факт эксплуатации (CISA KEV) — данные на дату анализа "
             f"({datetime.now(timezone.utc).strftime('%d.%m.%Y')} UTC) и меняются со временем.")
    L.append("* Данные об открытых портах получены из публичных индексов и могут быть устаревшими; "
             "для подтверждения выполняется лёгкая проба только по веб-портам.")
    L.append("")
    L.append("---")
    L.append("")
    L.append("*Отчёт подготовлен автоматизированной платформой анализа внешнего периметра. "
             "Оценки риска рассчитаны по публичным источникам (NVD, FIRST EPSS, CISA KEV) и "
             "подлежат проверке специалистом перед принятием решений.*")
    return "\n".join(L)


def _source_failures(sc) -> list[tuple[str, str]]:
    """Источники, которые не дали данных, и почему.

    Берётся из журнала анализа: строки вида
    «Источник crt.sh: сбой (…) — продолжаем без него» и
    «Источник CertSpotter: ничего не отдал».

    Зачем: в отчёте перечислены источники, которые в принципе используются.
    Если часть из них не ответила или была пропущена (например, режимом
    скрытности), отчёт обязан это сказать — иначе он утверждает больше, чем
    было сделано, а заказчик принимает решения по неполным данным.
    """
    log = (sc["log"] if sc and "log" in sc.keys() else "") or ""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in log.splitlines():
        line = line.strip()
        if not line.startswith("Источник "):
            continue
        body = line[len("Источник "):]
        if ": " not in body:
            continue
        name, why = body.split(": ", 1)
        name = name.strip()
        if name in seen:
            continue
        if why.startswith("сбой"):
            seen.add(name)
            reason = why[len("сбой"):].strip().strip("()").split(") —")[0]
            out.append((name, reason or "причина не указана"))
        elif why.startswith("ничего не отдал"):
            seen.add(name)
            out.append((name, "ответ пустой"))
    return out


def _clean_paths(text: str) -> str:
    """Служебные каталоги копий репозитория не должны попадать в отчёт заказчику
    даже из записей прошлых анализов (там они могли сохраниться до исправления)."""
    text = re.sub(r"/tmp/asm-repo-[^/\s]*/", "", text)
    # «repo/» — имя служебной копии репозитория; после «код: », «(» или пробела оно лишнее
    return re.sub(r"(?<=[(:\s])repo/", "", text)


def _change_text(x) -> str:
    """Строка для списка изменений: без словарей Python и без «None»."""
    if isinstance(x, dict):
        what = str(x.get("what") or x.get("title") or "—")
        asset = str(x.get("asset") or "")
        port = x.get("port")
        if asset and asset not in what:
            what = f"{what} — {asset}" + (f":{port}" if port else "")
        return _clean_paths(what)
    return _clean_paths(str(x))


def _is_probe_url(text: str) -> bool:
    """Адрес, найденный перебором имён файлов (а не новый сервис заказчика)."""
    low = text.lower()
    for mark in ("url:", "адрес:"):
        if low.startswith(mark):
            low = low[len(mark):].strip()
    if not low.startswith(("http://", "https://")):
        return False
    return any(m in low for m in ("<", ">", "script", "nosuchurl", "/etc/passwd", ".exe",
                                  ".cgi", "_vti_", "administrator.", "?alert"))


def _todo(findings: list[dict]) -> list[str]:
    out = []
    p0 = [f for f in findings if f.get("priority") == "P0"]
    p1 = [f for f in findings if f.get("priority") == "P1"]
    risky = [f for f in findings if f.get("is_risky_port")]
    if p0:
        uniq = []
        for f in p0:
            k = f.get("cve_id") or f.get("title")
            if k not in uniq:
                uniq.append(k)
        out.append("Закрыть немедленно (24–72 ч): " + "; ".join(str(x) for x in uniq[:6]) +
                   ". Порядок — обновить компонент либо временно ограничить доступ по IP.")
    if p1:
        uniq = []
        for f in p1:
            k = f.get("cve_id") or f.get("title")
            if k not in uniq:
                uniq.append(k)
        out.append("Запланировать на 1–2 недели: " + "; ".join(str(x) for x in uniq[:8]) + ".")
    if risky:
        out.append("Убрать из интернета сервисы, которым там не место: " +
                   ", ".join(sorted({(f.get('title') or '') for f in risky}))[:400] +
                   ". Доступ — только через VPN с двухфакторной аутентификацией.")
    out.append("Сузить периметр: служебные и тестовые поддомены (dev/test/stage/admin) "
               "закрыть аутентификацией на уровне обратного прокси или убрать из публикации.")
    out.append("Включить регулярный контроль изменений: анализ раз в 2 недели, "
               "чтобы новые сервисы не появлялись «вслепую».")
    out.append("Проверить резервные копии на возможность восстановления после шифровальщика "
               "(оффлайн-копия, проверка восстановления раз в квартал).")
    return out


def json_report(scan_id: int) -> str:
    sc = store.scan(scan_id)
    t = dict(store.target(sc["target_id"]))
    return json.dumps({
        "scan": {"id": scan_id, "started_at": sc["started_at"], "finished_at": sc["finished_at"],
                 "status": sc["status"]},
        "target": t,
        "stats": json.loads(sc["stats"] or "{}"),
        "assets": store.scan_assets(scan_id),
        "findings": store.scan_findings(scan_id),
    }, ensure_ascii=False, indent=2)


def csv_report(scan_id: int) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["priority", "score", "kind", "cve", "title", "asset", "ip", "port", "product",
                "version", "cvss", "severity", "epss", "kev", "rationale"])
    for f in store.scan_findings(scan_id):
        w.writerow([f.get("priority"), f.get("score"),
                    store.KIND_LABELS.get(f.get("kind") or "other", f.get("kind")),
                    f.get("cve_id"), f.get("title"),
                    f.get("asset"), f.get("ip"), f.get("port"), f.get("product"), f.get("version"),
                    f.get("cvss"), f.get("severity"), f.get("epss"), "1" if f.get("kev") else "0",
                    f.get("rationale")])
    return buf.getvalue()
