# -*- coding: utf-8 -*-
"""Карта объекта: что известно о цели — одним сбором, для человека и модели.

Зачем отдельный модуль. Сведения об объекте лежат в разных местах: цель и
основание — в `targets`, поверхность — в сканах, «где мы стоим» — в записи
доступа, порядок работ — в шагах сессии, запреты — в заметках, сверка — в
`facts`. Модель видит их по частям и потому пересказывает то, чего нет.
Карта собирает всё это **кодом** и в одном виде, который можно положить и в
подсказку планировщика (текст), и в документ передачи (схема mermaid), и в
панель. Модель карту читает, но не строит: источники у неё и у проверки одни.

Чего в карте нет и почему. Секретов нет по построению: есть имена учёток и
хостов, паролей и ключей — нет. Их место в записи доступа (`handover`) и в
личной передаче заказчику, а не в подсказке модели. Внутренние данные
(учётки AD, сессии) в карту попадают только тем, что уже собрано шагами.
"""

from __future__ import annotations

from . import store

# Стадии работ по объекту: по ним видно, где мы стоим и что ещё не собрано.
STAGES = ("recon", "entry", "inside", "access", "handover")
STAGE_TITLE = {
    "recon": "разведка снаружи",
    "entry": "первый вход выполнен",
    "inside": "работа внутри объекта",
    "access": "доступ получен",
    "handover": "передача заказчику",
}

DONE_STATUS = ("done", "ok", "completed", "success")


def _row(obj) -> dict:
    """Строка базы (или что-то похожее) — в обычный словарь."""
    try:
        return {k: obj[k] for k in obj.keys()}
    except Exception:  # noqa: BLE001 — это может быть и пустой None
        return dict(obj or {})


def _stage(sess: dict, access_row: dict, steps: list[dict]) -> str:
    """Где мы стоим по этому объекту. Правила простые и объяснимые."""
    if sess.get("closed_at") or (sess.get("status") and sess["status"] != "open"):
        return "handover"
    if access_row:
        return "access"
    if any(str(s.get("cls") or "") == "internal" for s in steps):
        return "inside"
    if any(str(s.get("status") or "") in DONE_STATUS for s in steps):
        return "entry"
    return "recon"


def _surface(scan_id: int, limit: int) -> dict:
    """Поверхность по последнему скану: порты, сервисы, продукты, хосты."""
    out: dict = {"scan_id": scan_id, "finished_at": "", "ports": [], "services": [],
                 "products": [], "hosts": []}
    if not scan_id:
        return out
    sc = _row(store.scan(scan_id))
    out["finished_at"] = str(sc.get("finished_at") or sc.get("started_at") or "")
    try:
        from . import agent as agent_mod
        sig = agent_mod.scan_signals(scan_id)
        out["ports"] = sorted(sig.get("ports") or [])
        out["services"] = sorted(sig.get("services") or [])
        out["products"] = sorted(sig.get("products") or [])
    except Exception:  # noqa: BLE001 — карта обязана собраться и без сигналов
        pass
    by_host: dict[str, dict] = {}
    for f in store.scan_findings(scan_id):
        asset = str(f.get("asset") or f.get("ip") or "—")
        h = by_host.setdefault(asset, {"asset": asset, "findings": [], "ports": set()})
        if f.get("port"):
            h["ports"].add(int(f["port"]))
        h["findings"].append({"title": str(f.get("title") or "")[:80],
                              "severity": f.get("severity") or "",
                              "priority": f.get("priority") or ""})
    hosts = []
    for h in by_host.values():
        h["ports"] = sorted(h["ports"])
        h["findings"] = h["findings"][:3]
        hosts.append(h)
    hosts.sort(key=lambda x: (-len(x["findings"]), x["asset"]))
    out["hosts"] = hosts[:limit]
    return out


def build(*, session_id: int = 0, scan_id: int = 0, target_id: int = 0,
          limit: int = 60) -> dict:
    """Собрать карту объекта. Ничего не доказывает и не ходит в сеть.

    `session_id` — из какой сессии взять шаги, доступ и заметки; без него
    карта собирается по объекту и его последнему скану.
    """
    m: dict = {"ok": False, "target": {}, "session": {}, "scope": [],
               "stage": "recon", "stage_title": STAGE_TITLE["recon"],
               "surface": _surface(0, limit), "position": {}, "steps": [],
               "limits": [], "verified": [], "unverified": [], "unknowns": []}
    sess = _row(store.agent_session(session_id)) if session_id else {}
    tid = int(target_id or sess.get("target_id") or 0)
    if not tid and not scan_id:
        return m
    tgt = _row(store.target(tid)) if tid else {}
    value = str(tgt.get("value") or "")
    reg = store.registry_get(value) if value else {}
    m["target"] = {
        "id": tid, "value": value, "client": tgt.get("client") or "",
        "auth_ref": tgt.get("auth_ref") or "", "auth_date": tgt.get("auth_date") or "",
        "kind": reg.get("kind") or "", "criticality": reg.get("criticality") or "",
        "exposure": reg.get("exposure") or "",
    }
    m["session"] = {"id": session_id, "status": sess.get("status") or "",
                    "operator": sess.get("operator") or "",
                    "created_at": sess.get("created_at") or "",
                    "deadline": sess.get("deadline") or ""}
    # Область работ: то, что назвал человек. Для карты это рамка, а не приговор.
    try:
        from . import agent as agent_mod
        sess_row = store.agent_session(session_id) if session_id else None
        m["scope"] = list(agent_mod.agreed_scope(sess_row))
    except Exception:  # noqa: BLE001
        m["scope"] = []

    steps = store.agent_steps(session_id) if session_id else []
    m["position"] = _row(_access_for(session_id)) if session_id else {}
    m["stage"] = _stage(sess, m["position"], steps)
    m["stage_title"] = STAGE_TITLE[m["stage"]]
    m["steps"] = [{"id": s.get("id"), "action_id": s.get("action_id"),
                   "title": s.get("title") or "", "cls": s.get("cls") or "",
                   "status": s.get("status") or ""} for s in steps[-limit:]]

    sc = int(scan_id or 0)
    if not sc and tid:
        last = store.last_done_scan(tid)
        sc = int(_row(last).get("id") or 0) if last else 0
    m["surface"] = _surface(sc, limit)

    # Заметки сессии: запреты и решения. В карту идут текстом — модель обязана
    # их видеть, в отличие от секретов, которых здесь нет и быть не может.
    for n in (store.agent_notes(session_id, limit=40) if session_id else []):
        text = str(n.get("text") or "")[:200]
        if not text:
            continue
        if n.get("kind") == "ban":
            m["limits"].append("ЗАПРЕТ: " + text)
        elif n.get("kind") == "decision":
            m["limits"].append("РЕШЕНИЕ: " + text)

    # Сверка §32: строки берём из того же сборщика, что идёт в подсказку и в
    # проверку ответа. Карта их не пересчитывает — она их показывает.
    if session_id:
        try:
            from . import facts
            sh = facts.sheet_for_session(session_id)
            if sh.get("scan_id"):
                m["verified"] = list(facts.lines(sh))
                m["unverified"] = [str(u)[:200] for u in (sh.get("unverified") or [])][:6]
        except Exception:  # noqa: BLE001 — сверка не обязана быть всегда
            pass

    m["unknowns"] = _unknowns(m)
    m["ok"] = bool(tid)
    return m


def _access_for(session_id: int) -> dict:
    """Запись доступа без секретов (в ней их и нет по построению)."""
    if not session_id:
        return {}
    try:
        from . import handover
        return handover.access(session_id)
    except Exception:  # noqa: BLE001
        return {}


def _unknowns(m: dict) -> list[str]:
    """Что в карте ещё пусто — честно, чтобы модель не додумывала за код."""
    out: list[str] = []
    if not m["surface"]["scan_id"]:
        out.append("сканов по объекту нет: поверхность не наблюдалась")
    if m["stage"] in ("recon", "entry"):
        out.append("внутри объекта не работали: учётки, сессии и связи AD не собраны")
    if m["stage"] == "inside" and not m["position"]:
        out.append("внутри работаем, но полученный доступ ещё не записан "
                   "(handover access)")
    if m["stage"] == "access" and not m["position"].get("verify"):
        out.append("доступ записан, но не отмечено, чем он проверен")
    if m["surface"]["scan_id"] and not m["verified"]:
        out.append("сверенных сведений нет: версии продуктов не подтверждены (§32)")
    return out


# ------------------------------------------------------------------ текстом

def text(m: dict, limit: int = 3000) -> str:
    """Карта текстом: в подсказку планировщика и в отчёт человеку."""
    if not m.get("ok"):
        return "Карта объекта: данных нет (не выбрана цель и нет сканов)"
    t = m["target"]
    s = m["surface"]
    out: list[str] = ["КАРТА ОБЪЕКТА (собрана кодом; секретов в карте нет)"]
    head = t["value"] or "—"
    if t["client"]:
        head += f" ({t['client']})"
    out.append(f"  объект: {head}")
    if t["auth_ref"]:
        out.append(f"  основание: {t['auth_ref']}"
                   + (f" от {t['auth_date']}" if t["auth_date"] else ""))
    cls = ", ".join(x for x in (t["kind"], t["criticality"], t["exposure"]) if x)
    if cls:
        out.append(f"  класс: {cls}")
    if m["scope"]:
        out.append(f"  область работ: {', '.join(str(x) for x in m['scope'][:12])}")
    out.append(f"  стадия: {m['stage_title']}"
               + (f" (сессия {m['session']['id']})" if m["session"]["id"] else ""))
    if s["scan_id"]:
        out.append(f"  поверхность (скан №{s['scan_id']}, {s['finished_at'] or '—'}):")
        out.append(f"    порты: {', '.join(str(p) for p in s['ports'][:24]) or 'нет'}")
        out.append(f"    сервисы: {', '.join(s['services'][:12]) or 'нет'}")
        out.append(f"    продукты: {', '.join(s['products'][:12]) or 'нет'}")
        for h in s["hosts"][:8]:
            ports = ", ".join(str(p) for p in h["ports"][:8]) or "—"
            sev = ", ".join(x["severity"] for x in h["findings"] if x["severity"])
            out.append(f"    {h['asset']}: порты {ports}; находок {len(h['findings'])}"
                       + (f"; важность: {sev}" if sev else ""))
    if m["position"]:
        p = m["position"]
        who = "@".join(x for x in (p.get("account"), p.get("host")) if x) or "—"
        out.append("  где стоим: " + who
                   + (f" ({p['privilege']})" if p.get("privilege") else "")
                   + (f", способ: {p['method']}" if p.get("method") else "")
                   + (f", проверено: {p['verify']}" if p.get("verify") else ""))
    elif m["stage"] in ("inside", "access"):
        out.append("  где стоим: доступ ещё не записан (handover access)")
    if m["steps"]:
        out.append("  ход работ (последние шаги):")
        for st in m["steps"][-6:]:
            out.append(f"    {st['action_id']} [{st['status']}] {st['title'][:60]}")
    for lim in m["limits"][:6]:
        out.append("  " + lim)
    if m["verified"]:
        out.append("  СВЕРЕННЫЕ СВЕДЕНИЯ (§32, опираться на них, не противоречить):")
        for ln in m["verified"][:8]:
            out.append("    " + str(ln)[:200])
    for u in m["unverified"][:4]:
        out.append("  НЕ ПРОВЕРЕНО: " + str(u)[:180])
    for u in m["unknowns"]:
        out.append("  НЕИЗВЕСТНО: " + u)
    res = "\n".join(out)
    if limit and len(res) > limit:
        res = res[:limit].rsplit("\n", 1)[0] + "\n  … (карта обрезана по длине)"
    return res


def brief(m: dict, limit: int = 1500) -> str:
    """Краткая карта для подсказки: контекст без того, что уже сказано рядом.

    Запреты, сверка и находки в подсказке идут отдельными блоками, поэтому
    здесь их нет — иначе один и тот же текст занимал бы контекст дважды.
    """
    if not m.get("ok"):
        return "Карта объекта: данных нет"
    t = m["target"]
    s = m["surface"]
    out: list[str] = ["КАРТА ОБЪЕКТА (собрана кодом, менять её нельзя — она про"
                      " наблюдённое; секретов в ней нет):"]
    head = t["value"] or "—"
    if t["client"]:
        head += f" ({t['client']})"
    out.append(f"  объект: {head}"
               + (f"; основание: {t['auth_ref']}" if t["auth_ref"] else ""))
    cls = ", ".join(x for x in (t["kind"], t["criticality"], t["exposure"]) if x)
    if cls:
        out.append(f"  класс: {cls}")
    if m["scope"]:
        out.append(f"  область работ: {', '.join(str(x) for x in m['scope'][:10])}")
    out.append(f"  стадия: {m['stage_title']}")
    if s["scan_id"]:
        out.append(f"  поверхность (скан №{s['scan_id']}, {s['finished_at'] or '—'}):"
                   f" порты {', '.join(str(p) for p in s['ports'][:16]) or 'нет'};"
                   f" продукты {', '.join(s['products'][:8]) or 'нет'}")
        for h in s["hosts"][:6]:
            out.append(f"    {h['asset']}: порты "
                       + (", ".join(str(p) for p in h["ports"][:6]) or "—")
                       + f"; находок {len(h['findings'])}")
    if m["position"]:
        p = m["position"]
        out.append("  где стоим: "
                   + "@".join(x for x in (p.get("account"), p.get("host")) if x)
                   + (f" ({p['privilege']})" if p.get("privilege") else ""))
    if m["steps"]:
        out.append("  ход работ: " + "; ".join(
            f"{st['action_id']} [{st['status']}]" for st in m["steps"][-5:]))
    for u in m["unknowns"][:4]:
        out.append("  НЕИЗВЕСТНО: " + u)
    res = "\n".join(out)
    if limit and len(res) > limit:
        res = res[:limit].rsplit("\n", 1)[0] + "\n  … (карта обрезана)"
    return res


# ------------------------------------------------------------------- схемой

def _node(label: str, limit: int = 48) -> str:
    """Безопасная подпись узла mermaid: кавычек и скобок в ней быть не должно."""
    s = str(label or "—").replace('"', "'").replace("[", " ").replace("]", " ")
    s = s.replace("(", " ").replace(")", " ")
    if len(s) > limit:
        s = s[:limit - 1] + "…"
    return s


def mermaid(m: dict) -> str:
    """Схема объекта для отчёта и панели. Только то, что уже известно."""
    if not m.get("ok"):
        return "flowchart LR\n  none[\"данных пока нет\"]"
    t = m["target"]
    s = m["surface"]
    lines = ["flowchart LR"]
    root = _node(t["value"] or "объект")
    if t["client"]:
        root += "<br/>" + _node(t["client"], 32)
    lines.append(f'  tgt["{root}"]')
    if m["stage"] in ("recon", "entry"):
        lines.append(f'  us["мы: {_node(m["stage_title"], 32)}"]')
        lines.append("  us --> tgt")
    if m["position"]:
        p = m["position"]
        who = _node("@".join(x for x in (p.get("account"), p.get("host")) if x) or "доступ")
        priv = _node(p.get("privilege"), 24)
        lines.append(f'  us["мы: {_node(m["stage_title"], 32)}"]')
        lines.append(f'  acc["доступ: {who}'
                     + (f" ({priv})" if priv and priv != "—" else "") + '"]')
        lines.append("  us --> acc")
    host_ids: list[str] = []
    for i, h in enumerate(s["hosts"][:8], 1):
        hid = f"h{i}"
        host_ids.append(hid)
        label = _node(h["asset"], 40)
        extra = []
        if h["ports"]:
            extra.append(", ".join(str(p) for p in h["ports"][:4]))
        if h["findings"]:
            extra.append(f"находок {len(h['findings'])}")
        if extra:
            label += "<br/>" + _node(" · ".join(extra), 44)
        lines.append(f'  {hid}["{label}"]')
        lines.append(f"  tgt --- {hid}")
    if m["position"] and host_ids:
        lines.append(f"  acc --- {host_ids[0]}")
    if m["verified"] or m["unverified"]:
        v = _node(f"сверено §32: {len(m['verified'])}"
                  + (f", не проверено: {len(m['unverified'])}" if m["unverified"] else ""), 52)
        lines.append(f'  facts["{v}"]')
        lines.append("  tgt --- facts")
    if not (m["steps"] or m["position"] or s["hosts"]):
        lines.append('  empty["работы по объекту ещё не начаты"]')
        lines.append("  tgt --- empty")
    return "\n".join(lines)
