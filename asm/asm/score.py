"""
Скоринг находок: «приоритет защиты», как в оригинале.

Формула честная и объяснимая (в отличие от «ИИ предсказал»):

    score = CVSS*10
            × множитель экспозиции (сервис наружу / опасный сервис)
            × множитель вероятности эксплуатации (EPSS)
            + бонус за технологический долг (возраст CVE)
    если CVE в CISA KEV  ->  P0 безусловно (эксплуатация уже фиксируется)

Каждое число имеет источник: NVD (CVSS), FIRST (EPSS), CISA (KEV),
InternetDB/наша проба (экспозиция).
"""
from __future__ import annotations

from datetime import datetime, timezone

P0, P1, P2, P3 = "P0", "P1", "P2", "P3"
PRIORITY_LABELS = {
    P0: "P0 — закрыть в течение 24–72 часов",
    P1: "P1 — закрыть в течение 1–2 недель",
    P2: "P2 — плановое обновление",
    P3: "P3 — низкий риск / к сведению",
}
PRIORITY_ORDER = {P0: 0, P1: 1, P2: 2, P3: 3}


def _age_years(published: str) -> float:
    """Возраст уязвимости в годах.

    Даты NVD приходят без часового пояса («2015-01-01»), реже — со смещением.
    Отнимать наивную дату от осведомлённой нельзя: выходило исключение, оно
    глушилось, и технологический долг молча считался нулевым — то есть не
    работал вообще, кроме редких дат с поясом.
    """
    try:
        dt = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
    except Exception:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days / 365.25


# база для находок nuclei (когда CVSS нет, но есть критичность шаблона)
NUCLEI_BASE = {"critical": 90.0, "high": 68.0, "medium": 42.0, "low": 18.0, "info": 8.0,
               "unknown": 25.0}


def score_finding(f: dict) -> dict:
    """Принимает находку с полями cvss/severity/epss/kev/published/port/service."""
    cvss = f.get("cvss")
    reasons: list[str] = []
    if f.get("source_kind") == "nuclei":
        base = NUCLEI_BASE.get((f.get("severity") or "unknown").lower(), 25.0)
        reasons.append(f"шаблонная проверка nuclei, критичность {(f.get('severity') or 'н/д').upper()} "
                       f"(база {base:.0f})")
    elif f.get("source_kind") in ("tls", "exposure", "engine", "secret", "code", "image",
                                  "sast", "deps", "iac", "wapiti") and f.get("severity"):
        base = NUCLEI_BASE.get(str(f["severity"]).lower(), 25.0)
        reasons.append(f"проверка движком арсенала, критичность {str(f['severity']).upper()} "
                       f"(база {base:.0f})")
    elif isinstance(cvss, (int, float)):
        # нелинейная база: CVSS 9.8 -> 96, 7.5 -> 56, 5.9 -> 35, 4.3 -> 18
        base = float(cvss) ** 2
        reasons.append(f"CVSS {cvss} — {f.get('severity') or 'n/a'} (база {base:.0f})")
    else:
        base = 30.0
        reasons.append("CVSS неизвестен — консервативная оценка")

    # --- экспозиция
    mult = 1.0
    port = f.get("port")
    if port in (443, 8443, 9443):
        mult *= 1.10
        reasons.append("сервис опубликован в интернет по TLS (×1.10)")
    elif port in (80, 8080, 8000, 8888, 9090, 5000):
        mult *= 1.15
        reasons.append("сервис опубликован в интернет по HTTP (×1.15)")
    elif port:
        mult *= 1.20
        reasons.append(f"небанальный сервис наружу, порт {port} (×1.20)")

    # --- вероятность эксплуатации
    # Ступени разнесены по существу: раньше «высокая» и «заметная» отличались
    # всего на 1.15 → 1.30, и разница между вероятностью 12% и 60% в итоговом
    # балле почти терялась. Верхняя ступень теперь ×1.45.
    epss = f.get("epss") or 0.0
    if epss >= 0.5:
        mult *= 1.45
        reasons.append(f"EPSS {epss:.0%} — эксплойт с высокой вероятностью (×1.45)")
    elif epss >= 0.1:
        mult *= 1.20
        reasons.append(f"EPSS {epss:.0%} — заметная вероятность эксплуатации (×1.20)")
    elif epss >= 0.01:
        mult *= 1.05
        reasons.append(f"EPSS {epss:.0%} (×1.05)")

    # --- технологический долг
    # Множителем, а не слагаемым. Раньше к произведению прибавлялось +4/+8, и
    # на большой базе это не значило ничего (96 против 96.4), а на маленькой
    # перевешивало всё остальное: база 18 с долгом давала 27 — выше базы 25 без
    # долга. Теперь долг соразмерен находке, как и остальные поправки.
    years = _age_years(f.get("published", ""))
    if years >= 5:
        mult *= 1.12
        reasons.append(f"уязвимости {years:.0f} лет — технологический долг (×1.12)")
    elif years >= 2:
        mult *= 1.06
        reasons.append(f"уязвимости {years:.0f} года — не закрыта (×1.06)")

    score = base * mult
    kev = bool(f.get("kev"))

    if kev:
        priority = P0
        score = max(score, 95.0)
        reasons.append("CISA KEV: эксплуатация фиксируется в реальных атаках → P0")
        if (f.get("kev_info") or {}).get("ransomware") == "Known":
            reasons.append("используется в кампаниях шифровальщиков")
    elif f.get("source_kind") == "nuclei" and (f.get("severity") or "").lower() == "critical":
        priority = P0
        score = max(score, 88.0)
        reasons.append("подтверждено активной проверкой + критичная критичность → P0")
    elif f.get("source_kind") in ("tls", "exposure", "engine") and (f.get("severity") or "").lower() in ("critical", "high"):
        priority = P1
        score = max(score, 74.0)
        reasons.append("проверка движком арсенала подтвердила проблему высокой критичности → P1")
    elif f.get("is_risky_port"):
        priority = P1 if (f.get("score_raw") or 70) >= 60 else P2
        score = max(score, 70.0)
        reasons.append("сервис, которому не место в интернете: нужна проверка аутентификации → P1")
    elif score >= 85:
        priority = P0
    elif score >= 55:
        priority = P1
    elif score >= 28:
        priority = P2
    else:
        priority = P3

    f["score"] = round(score, 1)
    f["priority"] = priority
    f["priority_label"] = PRIORITY_LABELS[priority]
    f["rationale"] = "; ".join(reasons) if reasons else "нет данных для оценки"
    return f


def summarize(findings: list[dict]) -> dict:
    counts = {P0: 0, P1: 0, P2: 0, P3: 0}
    for f in findings:
        counts[f.get("priority", P3)] += 1
    top = sorted(findings, key=lambda x: (-(x.get("score") or 0)))[:5]
    return {
        "counts": counts,
        "total": len(findings),
        "kev": sum(1 for f in findings if f.get("kev")),
        "top": [{"cve": f.get("cve_id"), "title": f.get("title"), "asset": f.get("asset"),
                 "score": f.get("score"), "priority": f.get("priority")} for f in top],
    }


def by_product(findings: list[dict]) -> list[dict]:
    """Сводка «сколько проблем в каком продукте» — то, что нужно для плана работ."""
    agg: dict[str, dict] = {}
    for f in findings:
        key = f.get("product") or "продукт не определён (публичный индекс)"
        a = agg.setdefault(key, {"product": key, "version": f.get("version") or "",
                                 "total": 0, P0: 0, P1: 0, P2: 0, P3: 0,
                                 "assets": set(), "worst": 0.0})
        a["total"] += 1
        a[f.get("priority", P3)] += 1
        if f.get("asset"):
            a["assets"].add(f["asset"])
        a["worst"] = max(a["worst"], f.get("score") or 0)
    out = []
    for a in agg.values():
        a["assets"] = len(a["assets"])
        out.append(a)
    return sorted(out, key=lambda x: (-x[P0], -x[P1], -x["worst"]))


def apply_criticality(f: dict, crit: str) -> dict:
    """Критичность актива из реестра заказчика смещает приоритет на один шаг.

    Критичный актив: P3->P2, P2->P1, P1->P0 (и обоснование в балле).
    Некритичный/внутренний: наоборот, на шаг вниз (но не ниже P3).
    """
    order = [P0, P1, P2, P3]
    pr = f.get("priority")
    if pr not in order or not crit:
        return f
    i = order.index(pr)
    if crit == "critical":
        new_i = max(0, i - 1)
        why = "актив в реестре заказчика помечен как критичный — приоритет поднят"
    elif crit in ("low", "internal"):
        new_i = min(3, i + 1)
        why = "актив помечен как некритичный/внутренний — приоритет снижен"
    else:
        return f
    if new_i != i:
        f["priority_before_registry"] = pr
        f["priority"] = order[new_i]
        f["rationale"] = (f.get("rationale") or "") + " · " + why
    f["registry_criticality"] = crit
    return f
