"""
Аналитический слой «Oracle»: превращает структурированные данные в текст.

Честная реализация того, что в видео показано как «ИИ объясняет простыми словами»:
  1) offline-режим — детерминированные шаблоны + правила (работает без ключей);
  2) LLM-режим    — если заданы ASM_LLM_BASE / ASM_LLM_KEY (любой OpenAI-совместимый
                    эндпоинт: OpenAI, Ollama http://localhost:11434/v1, vLLM, GigaChat-прокси),
                    тот же срез данных уходит в модель и возвращается текстом.

Модель НЕ ищет уязвимости. Она объясняет то, что уже нашли инструменты —
именно так это и устроено в оригинале.
"""
from __future__ import annotations

import json
import os

from . import collect, score
from .settings import current_settings


def _llm(messages: list[dict], max_tokens: int = 1200) -> str | None:
    settings = current_settings()
    base = str(settings.get("ASM_LLM_BASE", "") if settings else
               os.environ.get("ASM_LLM_BASE", "")).rstrip("/")
    key = os.environ.get("ASM_LLM_KEY", "")
    model = (settings.get("ASM_LLM_MODEL", "gpt-4o-mini") if settings else
             os.environ.get("ASM_LLM_MODEL", "gpt-4o-mini"))
    if not base:
        return None
    payload = json.dumps({"model": model, "messages": messages, "temperature": 0.2,
                          "max_tokens": max_tokens}).encode()
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = collect._http(base + "/chat/completions", 0, headers=headers,
                         method="POST", data=payload, retries=1, settings=settings)
    try:
        return data["choices"][0]["message"]["content"]
    except Exception:
        return None


# ------------------------------------------------------------------ 1. профиль инфраструктуры
def infra_profile(assets: list[dict], ip_meta: dict, target: str) -> str:
    kinds: dict[str, int] = {}
    for a in assets:
        kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1
    subs = [a["value"] for a in assets if a["kind"] == "subdomain"]
    ips = [a["value"] for a in assets if a["kind"] == "ip"]
    certs = [a for a in assets if a["kind"] == "cert"]

    lines = [f"Инфраструктурный профиль «{target}»", ""]
    lines.append(f"Собрано цифровых следов: {len(assets)} — из них поддоменов {len(subs)}, "
                 f"IP-адресов {len(ips)}, сертификатов {len(certs)}.")
    if certs:
        issuers = {}
        for c in certs:
            iss = (c.get("meta", {}).get("issuer") or "неизвестен").split(",")[0][:60]
            issuers[iss] = issuers.get(iss, 0) + 1
        top = sorted(issuers.items(), key=lambda x: -x[1])[:4]
        lines.append("Удостоверяющие центры: " + "; ".join(f"{k} — {v}" for k, v in top) + ".")
    if ip_meta:
        countries = {}
        orgs = {}
        asns = {}
        for ip, m in ip_meta.items():
            if m.get("country"):
                countries[m["country"]] = countries.get(m["country"], 0) + 1
            if m.get("holder"):
                orgs[m["holder"]] = orgs.get(m["holder"], 0) + 1
            if m.get("asn"):
                asns[m["asn"]] = asns.get(m["asn"], 0) + 1
        if countries:
            lines.append("Размещение по странам: " + ", ".join(
                f"{k} — {v} IP" for k, v in sorted(countries.items(), key=lambda x: -x[1])[:6]) + ".")
        if orgs:
            lines.append("Операторы/провайдеры: " + "; ".join(
                list(orgs.keys())[:5]) + ".")
        if asns:
            lines.append("Автономные системы: " + ", ".join(f"AS{k} ({v} IP)" for k, v in
                                                             sorted(asns.items(), key=lambda x: -x[1])[:6]) + ".")

    risky = [s for s in subs if any(t in s.split(".")[0] for t in
                                    ("dev", "test", "stage", "staging", "qa", "admin", "panel",
                                     "vpn", "mail", "api", "old", "backup", "beta", "demo", "1c", "sso"))]
    if risky:
        lines.append("")
        lines.append("Внимание — «тени инфраструктуры» (поддомены, которые обычно "
                     "остаются без присмотра после запуска проекта): " + ", ".join(risky[:15]) + ".")
    return "\n".join(lines)


# ------------------------------------------------------------------ 2. приоритет защиты
def protection_priority(findings: list[dict]) -> str:
    s = score.summarize(findings)
    lines = ["Приоритет защиты", ""]
    if not findings:
        lines.append("Уязвимостей по публичным данным не выявлено. Рекомендуется повторный "
                     "контроль через 14 дней — базы CVE пополняются ежедневно.")
        return "\n".join(lines)
    lines.append(f"Всего находок: {s['total']}. "
                 f"P0 — {s['counts']['P0']}, P1 — {s['counts']['P1']}, "
                 f"P2 — {s['counts']['P2']}, P3 — {s['counts']['P3']}. "
                 f"Из них подтверждённо эксплуатируются в реальных атаках (CISA KEV): {s['kev']}.")
    lines.append("")
    lines.append("Порядок закрытия:")
    seen = set()
    n = 0
    for f in sorted(findings, key=lambda x: (score.PRIORITY_ORDER.get(x.get("priority"), 9),
                                             -(x.get("score") or 0))):
        key = (f.get("cve_id") or f.get("title"))
        if key in seen:
            continue
        seen.add(key)
        n += 1
        if n > 10:
            break
        local = f.get("cve_id") or f.get("title")
        where = f.get("asset") or f.get("ip") or "?"
        extra = f" на {where}" if where != "?" else ""
        lines.append(f"{n}. {f.get('priority')} · {local}{extra} — {f.get('rationale','')}")
    lines.append("")
    lines.append("Пояснение уровней: " + score.PRIORITY_LABELS["P0"] + "; " +
                 score.PRIORITY_LABELS["P1"] + "; " + score.PRIORITY_LABELS["P2"] + ".")
    return "\n".join(lines)


# ------------------------------------------------------------------ 3. сценарий атаки
def attack_scenario(findings: list[dict], assets: list[dict]) -> str:
    if not findings:
        return "Сценарий атаки не строится: зацепок в открытых данных не найдено."
    subs = [a["value"] for a in assets if a["kind"] == "subdomain"]
    RUISKY_DB_PORTS = (3306, 5432, 27017, 6379, 9200, 11211, 1433, 2181, 2379, 5984, 1521)
    RUISKY_REMOTE_PORTS = (3389, 5900, 445, 23, 21, 111)
    RUISKY_PANEL_PORTS = (5601, 15672, 10000, 3000, 2375)
    classes = {
        "rce": [f for f in findings if "RCE" in (f.get("title") or "").upper()
                or "произвольного кода" in (f.get("title") or "")],
        "db": [f for f in findings if f.get("port") in RUISKY_DB_PORTS],
        "panel": [f for f in findings if f.get("port") in RUISKY_PANEL_PORTS],
        "remote": [f for f in findings if f.get("port") in RUISKY_REMOTE_PORTS],
    }
    raw = []
    if subs:
        raw.append("Разведка без касания объекта: по логам выдачи сертификатов "
                     f"собираются поддомены ({len(subs)} шт.), включая тестовые и служебные среды. "
                     f"Дальше по открытым индексам определяются их IP и опубликованные сервисы.")
    if classes["remote"]:
        raw.append("Подбор учётных данных к удалённому доступу "
                     f"({classes['remote'][0].get('title')}, порт {classes['remote'][0].get('port')}). "
                     "Делается автоматическими средствами, быстро и без «взлома» как такового; "
                     "при слабом пароле — доступ во внутреннюю сеть и развитие атаки.")
    if classes["db"]:
        raw.append("Прямое подключение к СУБД наружу: при отсутствии авторизации "
                     "данные читаются целиком, включая персональные данные клиентов и сотрудников; "
                     "это же основание для уведомления Роскомнадзора об утечке (ст. 19 152-ФЗ).")
    if classes["panel"]:
        raw.append("Панель управления — точка входа без эксплойта: подбор пароля, "
                     "проверка дефолтных учётных данных, эксплуатация известных уязвимостей панели.")
    if classes["rce"]:
        raw.append("Если в стеке есть RCE-уязвимость, она даёт выполнение команд "
                     "на сервере: закрепление, доступ к внутренней сети, развёртывание "
                     "шифровальщика или тихий вывод данных месяцами.")
    raw.append("Ущерб. По статистике инцидентов: кража данных клиентов, простой "
                 "сервисов, требования выкупа, репутационные потери и штрафные риски.")
    # нумерация по факту: пропусков вида «Шаг 1 -> Шаг 4» в отчёте заказчика быть не должно
    return "\n".join(f"Шаг {i}. {t}" for i, t in enumerate(raw, 1))


# ------------------------------------------------------------------ 4. резюме для руководителя
def executive_summary(target: str, findings: list[dict], ip_meta: dict, assets: list[dict]) -> str:
    s = score.summarize(findings)
    crit = s["counts"]["P0"] + s["counts"]["P1"]
    parts = [f"По результатам пассивного анализа внешнего периметра «{target}» "
             f"собрано {len(assets)} цифровых следов и выявлено {s['total']} находок."]
    if crit:
        parts.append(f"{crit} из них требуют вмешательства в первую очередь"
                     f"{' — включая уязвимости, эксплуатация которых уже фиксируется в реальных атаках' if s['kev'] else ''}.")
    else:
        parts.append("Критических проблем на внешнем контуре не выявлено.")
    risky = [f for f in findings if f.get("is_risky_port")]
    if risky:
        parts.append("Отдельно отмечены сервисы, которых не должно быть в публичном доступе: "
                     + ", ".join(sorted({(f.get('title') or '') for f in risky}))[:400] + ".")
    parts.append("Рекомендация: закрыть P0/P1 в указанные сроки, сузить публичный периметр "
                 "(всё, что не обязано быть в интернете — за VPN), включить регулярный "
                 "контроль изменений — новые сервисы появляются быстрее, чем их успевают учитывать.")
    return " ".join(parts)


# ------------------------------------------------------------------ 5. сборка
def build(scan: dict, target: dict, assets: list[dict], findings: list[dict],
          ip_meta: dict, diffs: dict) -> dict:
    tname = target["value"]
    profile = infra_profile(assets, ip_meta, tname)
    priority = protection_priority(findings)
    scenario = attack_scenario(findings, assets)
    summary = executive_summary(tname, findings, ip_meta, assets)

    result = {
        "mode": "offline (правила)",
        "summary": summary,
        "infra_profile": profile,
        "protection_priority": priority,
        "attack_scenario": scenario,
    }

    # LLM-режим: тот же срез данных -> живой текст
    brief = {
        "target": tname,
        "findings": [{"priority": f.get("priority"), "cve": f.get("cve_id"), "title": f.get("title"),
                      "asset": f.get("asset"), "cvss": f.get("cvss"), "epss": f.get("epss"),
                      "kev": f.get("kev"), "port": f.get("port")} for f in findings[:40]],
        "assets_count": len(assets),
        "asn": {k: v.get("asn") for k, v in list(ip_meta.items())[:20]},
        "changes_since_previous": diffs,
    }
    text = _llm([
        {"role": "system", "content": (
            "Ты — старший аналитик кибербезопасности. Пишешь отчёт для владельца небольшой компании. "
            "Строго по фактам из JSON, без выдумывания CVE и адресов. Русский язык, деловой тон, "
            "без паники и без терминов без расшифровки. Структура ответа в Markdown: "
            "«Резюме для руководителя», «Приоритет защиты», «Сценарий атаки», «Что делать на этой неделе».")},
        {"role": "user", "content": "Данные пассивного анализа периметра:\n" + json.dumps(brief, ensure_ascii=False)[:12000]},
    ], max_tokens=1500)
    if text:
        settings = current_settings()
        model = (settings.get("ASM_LLM_MODEL", "модель") if settings else
                 os.environ.get("ASM_LLM_MODEL", "модель"))
        result["mode"] = f"LLM ({model})"
        result["llm_report"] = text
    return result
