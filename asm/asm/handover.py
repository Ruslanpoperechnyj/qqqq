# -*- coding: utf-8 -*-
"""Пакет передачи доступа заказчику.

Работа по договору заканчивается не отчётом, а демонстрацией: инструмент
доводит до доступа, дальше человек. Этот модуль собирает документ, который
сопровождает демонстрацию и остаётся у заказчика.

Три требования, из которых выведено всё остальное:

1. **Секрета здесь нет и быть не может.** Пароль, ключ и хеш передаются лично
   и в демонстрации, а документ у заказчика остаётся на годы. Поэтому в схеме
   нет ни одного поля под секрет, а весь свободный текст проходит проверку на
   похожее на секрет — с отказом, а не с предупреждением.

2. **Цепочка со временем берётся из базы, а не набирается руками.** Смысл
   документа в том, что он подтверждает: доступ получен в границах работ.
   Составленный человеком «список того, что делалось» этого не доказывает.

3. **Границы работ перечисляются явно.** Сказать, что доступ получен, мало:
   надо сказать, чего мы НЕ делали — не читали данные, не закреплялись, не
   ходили дальше одобренного. Заказчик ищет следы и должен знать, что искать.

Про инфраструктуру. Адресов и узлов, через которые шла работа, в документе нет:
заказчик знает, что была проверка, но связать её с конкретным человеком нельзя
даже при разборе после неё. Это условие договора, поэтому решение принято в коде,
а не оставлено на аккуратность составителя.
"""
from __future__ import annotations

import json
import re

from . import store

# --------------------------------------------------------------- проверка на секрет

# Здесь важно не «поймать всё», а не пропустить очевидное. Ложное срабатывание
# стоит одной переформулировки, пропуск стоит пароля в документе, который
# заказчик будет хранить годами. Поэтому отказ, а не предупреждение.
_SECRET_RULES: tuple[tuple[str, str, re.Pattern], ...] = (
    # «пара хешей» идёт первой: она точнее описывает выгрузку из базы домена,
    # а общее правило на 32 знака иначе сработало бы раньше и сказало меньше.
    ("пара хешей", "два NT-хеша через двоеточие — выгрузка из базы домена",
     re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:[0-9a-fA-F]{32}(?![0-9a-fA-F])")),
    ("NT-хеш", "32 шестнадцатеричных знака — так выглядит NT-хеш пароля",
     re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")),
    ("пустой LM-хеш", "aad3b435… — признак скопированного хеша из базы",
     re.compile(r"aad3b435b51404eeaad3b435b51404ee", re.I)),
    ("хеш Kerberos", "так выглядит перехваченный запрос проверки подлинности",
     re.compile(r"\$(?:NT|NETNTLMv?2?|krb5[a-z]*)\$", re.I)),
    ("хеш пароля", "так выглядят хеши паролей в файлах теней",
     re.compile(r"\$(?:1|2[aby]?|5|6|y|argon2\w*)\$[!-~]{8,}")),
    ("закрытый ключ", "это начало файла закрытого ключа",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("ключ доступа", "похоже на токен или ключ доступа, а не на пометку",
     re.compile(r"(?i)\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
                r"client[_-]?secret|token)\b\s*[:=]\s*\S{8,}")),
    ("ключ в заголовке", "так выглядит ключ доступа в заголовке запроса",
     re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}")),
    ("пароль", "похоже на сам пароль, а не на пометку о нём",
     re.compile(r"(?i)\b(?:пароль|password|passwd|pwd)\b\s*[:=]\s*\S{8,}")),
)

# Разделители, после которых значение не считается секретом: «см. сейф»,
# «устно», «передано лично» — это пометки, а не секреты.
_PLACEHOLDER = re.compile(
    r"(?i)\s*(см\.|смотри|устно|лично|передан\w*|отдельн\w*|сейф|"
    r"tbd|вручн\w*|ручн\w*|n/?a)\b")


def secret_reason(text: str) -> str:
    """Похож ли текст на секрет. Пустая строка — не похож.

    Возвращает «что это» и «почему так решено» — чтобы ложное срабатывание
    было легко опознать и переформулировать.
    """
    if not text:
        return ""
    if _PLACEHOLDER.match(text) or _PLACEHOLDER.match(text.strip()):
        return ""
    for name, why, rx in _SECRET_RULES:
        m = rx.search(text)
        if not m:
            continue
        # После «:] знака =» может стоять пометка вместо секрета
        if name in ("пароль", "ключ доступа") and _PLACEHOLDER.match(m.group(0).split("=")[-1].split(":")[-1]):
            continue
        return f"«{name}»: {why}"
    return ""


def _guard(text: str, field: str) -> None:
    r = secret_reason(text)
    if r:
        raise ValueError(
            f"в поле «{field}» найдено похожее на секрет — {r}.\n"
            f"    Значение поля: {text[:60]}{'…' if len(text) > 60 else ''}\n"
            "    Секреты не хранятся и не попадают в документ: он остаётся\n"
            "    у заказчика. Укажите, где секрет передан (например,\n"
            "    «выдано лично»), а само значение — нет.")


# ------------------------------------------------------------------ доступ

# Ни одного поля под секрет: не «мы не сохраняем», а «сохранить некуда».
ACCESS_FIELDS = ("account", "privilege", "host", "method", "verify", "note")


def set_access(session_id: int, *, account: str = "", privilege: str = "",
               host: str = "", method: str = "", verify: str = "",
               note: str = "") -> None:
    """Записать, какой доступ получен. Секрет сюда передать нельзя."""
    for field, value in (("учётная запись", account), ("уровень доступа", privilege),
                         ("объект", host), ("способ", method),
                         ("команда проверки", verify), ("пометка", note)):
        _guard(value, field)
    old = access(session_id)
    if old:
        store.ex(
            "UPDATE handover_access SET account=?, privilege=?, host=?, method=?,"
            " verify=?, note=?, updated_at=? WHERE session_id=?",
            (account, privilege, host, method, verify, note, store.now(), session_id))
    else:
        store.ex(
            "INSERT INTO handover_access(session_id, account, privilege, host,"
            " method, verify, note, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (session_id, account, privilege, host, method, verify, note,
             store.now(), store.now()))
    store.audit("handover_access_set",
                {"session_id": session_id, "account": account,
                 "privilege": privilege, "host": host, "method": method})


def access(session_id: int) -> dict:
    row = store.one("SELECT * FROM handover_access WHERE session_id=?", (session_id,))
    return dict(row) if row else {}


# ------------------------------------------------- что осталось на объекте

def add_placed(session_id: int, *, file: str, host: str = "", path: str = "",
               note: str = "") -> int:
    """Отметить файл, перенесённый на объект.

    Без этого списка уборка после работ держится на памяти, а память через
    два месяца работы по объекту подводит. Незакрытые записи попадают
    в документ как незавершённая уборка и в код возврата.
    """
    _guard(file, "файл")
    _guard(host, "объект")
    _guard(path, "путь")
    _guard(note, "пометка")
    pid = store.ex(
        "INSERT INTO handover_placed(session_id, file, host, path, note,"
        " placed_at, removed) VALUES(?,?,?,?,?,?,0)",
        (session_id, file, host, path, note, store.now()))
    store.audit("handover_placed",
                {"session_id": session_id, "file": file, "host": host, "path": path})
    return pid


def mark_removed(placed_id: int, note: str = "") -> bool:
    row = store.one("SELECT * FROM handover_placed WHERE id=?", (placed_id,))
    if not row:
        return False
    store.ex("UPDATE handover_placed SET removed=1, removed_at=?, note=?"
             " WHERE id=?", (store.now(), note or row["note"], placed_id))
    store.audit("handover_placed_removed", {"id": placed_id, "file": row["file"],
                                            "host": row["host"]})
    return True


def placed(session_id: int) -> list[dict]:
    return [dict(r) for r in store.q(
        "SELECT * FROM handover_placed WHERE session_id=? ORDER BY id", (session_id,))]


def outstanding(session_id: int) -> list[dict]:
    return [p for p in placed(session_id) if not p["removed"]]


# ------------------------------------------------------------------ цепочка

_STEP_RU = {
    "proposed": "предложен",
    "approved": "одобрен",
    "rejected": "отклонён",
    "executed": "выполнен",
    "failed": "сбой",
    "handoff": "передано человеку",
}


def chain(session_id: int) -> list[dict]:
    """Что происходило, по времени, из журнала — а не по памяти составителя."""
    out = []
    for st in store.agent_steps(session_id):
        out.append({
            "seq": st.get("seq"),
            "action_id": st.get("action_id"),
            "title": st.get("title") or "",
            "cls": st.get("cls") or "",
            "status": st.get("status") or "",
            "status_ru": _STEP_RU.get(st.get("status") or "", st.get("status") or ""),
            "decided_by": st.get("decided_by") or "",
            "decided_at": st.get("decided_at") or "",
            "started_at": st.get("started_at") or "",
            "finished_at": st.get("finished_at") or "",
            "decision_note": st.get("decision_note") or "",
        })
    return out


# --------------------------------------------------------------- документ

# Что НЕ делалось — не выводится из журнала, потому что это обещания о
# несовершённом. Список задан здесь и должен меняться вместе с правилами
# работы, а не с данными.
BOUNDARIES = (
    "данные заказчика не читались, не выгружались и не изменялись; содержимое "
    "баз данных не просматривалось",
    "не создавалось ничего, что переживёт работы: учётные записи, службы, "
    "задания по расписанию, ключи",
    "перемещение по сети выполнялось только по отдельно одобренным шагам, "
    "каждый — с подтверждением человеком",
    "журналы событий на объекте не изменялись и не удалялись",
    "за пределами объекта работ активность не велась, сторонние сервисы "
    "не затрагивались",
    "люди не использовались: ни переписки, ни звонков, ни убеждения",
)

CLS_RU = {"observe": "наблюдение", "probe": "проба", "impact": "воздействие",
          "handoff": "передача"}


def _fmt(t: str) -> str:
    return (t or "").replace("T", " ")[:19] or "—"


def _findings_for_target(target_id: int, limit: int = 25) -> list[dict]:
    """Наиболее значимые находки по объекту — что заказчику исправлять."""
    seen: dict[str, dict] = {}
    for sc in store.scans(target_id):
        for f in store.scan_findings(sc["id"]):
            key = (f.get("title") or "")[:120]
            if key in seen:
                continue
            if (f.get("priority") or "") not in ("P0", "P1"):
                continue
            seen[key] = f
    rows = sorted(seen.values(), key=lambda f: (f.get("priority") or "P9",
                                                -(f.get("score") or 0)))
    return rows[:limit]


def build(session_id: int, *, show_infra: bool = False) -> str:
    """Собрать документ передачи.

    show_infra оставлен для внутреннего пользования и по умолчанию выключен:
    адреса и узлы, через которые шла работа, в документе заказчику не нужны,
    а связать по ним работу с человеком — можно.
    """
    sess = store.agent_session(session_id)
    if sess is None:
        raise ValueError(f"сессии {session_id} нет")
    # sqlite3.Row: у него есть индексация по имени, но нет .get() — нужен dict
    sess = dict(sess)
    t = store.target(sess["target_id"])
    t = dict(t) if t is not None else {"value": "?", "client": "?", "auth_ref": "?"}
    acc = access(session_id)
    steps = chain(session_id)
    items = placed(session_id)
    left = [p for p in items if not p["removed"]]

    L: list[str] = []
    L.append(f"# Передача доступа: {t['value']}")
    L.append("")
    L.append(f"| | |")
    L.append(f"|---|---|")
    L.append(f"| Объект | {t['value']} |")
    L.append(f"| Заказчик | {t['client']} |")
    L.append(f"| Основание | {t['auth_ref']} |")
    L.append(f"| Сессия | {session_id} |")
    L.append(f"| Работы начаты | {_fmt(sess['created_at'])} |")
    status_ru = {"open": "идут", "closed": "окончены",
                 "stopped_by_operator": "ОСТАНОВЛЕНЫ ОПЕРАТОРОМ",
                 "expired": "ПРЕРВАНЫ по сроку"}.get(sess.get("status") or "",
                                                      sess.get("status") or "?")
    L.append(f"| Работы окончены | {_fmt(sess['closed_at'])} |")
    L.append(f"| Состояние сессии | {status_ru} |")
    if sess.get("operator"):
        L.append(f"| Исполнитель | {sess['operator']} |")
    L.append("")
    L.append("> **Обязательство по договору: доступ передаётся заказчику лично и до "
             "окончания срока работ.** Документ фиксирует передачу, но не заменяет её.")
    L.append("")
    if (sess.get("status") or "") in ("stopped_by_operator", "expired"):
        # Остановленные работы — не оконченные работы. Выдавать одно за другое
        # в документе, который заказчик принимает по акту, нельзя.
        why = (sess.get("stop_note") or "").strip()
        L.append("> **Внимание: эти работы были остановлены, а не доведены до "
                 "конца обычным порядком.**")
        L.append(f"> Состояние: {status_ru}."
                 + (f" Причина: {why}" if why else ""))
        L.append("> Раздел «Что передаётся» описывает доступ на момент остановки.")
        L.append("")

    # ---- 1
    L.append("## 1. Что передаётся")
    L.append("")
    if acc:
        L.append("| | |")
        L.append("|---|---|")
        for label, key in (("Учётная запись", "account"), ("Уровень доступа", "privilege"),
                           ("Объект", "host"), ("Способ подключения", "method")):
            if acc.get(key):
                L.append(f"| {label} | {acc[key]} |")
        L.append("")
        if acc.get("verify"):
            L.append("Проверка доступа выполняется заказчиком самостоятельно:")
            L.append("")
            L.append("```")
            L.append(acc["verify"])
            L.append("```")
            L.append("")
    else:
        L.append("Данные о доступе не заполнены: `python3 app.py handover access "
                 f"{session_id} --account … --privilege … --host … --method …`")
        L.append("")
    L.append("**Секрет (пароль, ключ или хеш) в этом документе отсутствует "
             "намеренно.**")
    L.append("Он передаётся лично при демонстрации и не хранится ни в базе, "
             "ни в отчётах:")
    L.append("этот документ остаётся у заказчика, и секрет в нём жил бы годами.")
    L.append("")
    if acc.get("note"):
        L.append(f"Пометка: {acc['note']}")
        L.append("")

    # ---- 2
    L.append("## 2. Что выполнялось, со временем")
    L.append("")
    if not steps:
        L.append("Шагов в этой сессии нет.")
        L.append("")
    else:
        cnt: dict[str, int] = {}
        for s in steps:
            cnt[s["status_ru"]] = cnt.get(s["status_ru"], 0) + 1
        L.append("Итог по шагам: " + ", ".join(f"{k} — {v}" for k, v in cnt.items()) + ".")
        L.append("")
        L.append("| # | Время решения | Шаг | Класс | Решение | Кем | Чем закончилось |")
        L.append("|---|---|---|---|---|---|---|")
        for s in steps:
            when = _fmt(s["decided_at"] or s["started_at"] or s["finished_at"])
            who = s["decided_by"] or "—"
            L.append(f"| {s['seq']} | {when} | {s['title'] or s['action_id']} | "
                     f"{CLS_RU.get(s['cls'], s['cls'])} | {s['status_ru']} | {who} | "
                     f"{s['decision_note'] or '—'} |")
        L.append("")
    # ---- 3
    L.append("## 3. Границы работ")
    L.append("")
    L.append("Ниже — что в ходе работ **не** выполнялось. Это утверждение о "
             "несовершённом,")
    L.append("и оно проверяемо: перечисленные действия оставляют следы, "
             "которых на объекте нет.")
    L.append("")
    for b in BOUNDARIES:
        L.append(f"- {b}")
    L.append("")
    rej = [x for x in steps if x["status"] == "rejected"]
    if rej:
        L.append(f"Отдельно: {len(rej)} предложенных шаг(ов) были отклонены "
                 "человеком до выполнения.")
        L.append("Это и есть работа границ — они не декларированы, а видны "
                 "в журнале:")
        L.append("")
        for x in rej:
            L.append(f"- {x['title'] or x['action_id']}"
                     + (f" — {x['decision_note']}" if x["decision_note"] else ""))
        L.append("")
    if show_infra:
        L.append("_В документ включены сведения об инфраструктуре: "
                 "он помечен как внутренний._")
        L.append("")

    # ---- 4
    L.append("## 4. Уборка после работ")
    L.append("")
    if not items:
        L.append("На объект ничего не переносилось — убирать нечего.")
        L.append("")
    else:
        L.append("| Файл | Где | Когда | Состояние |")
        L.append("|---|---|---|---|")
        for p in items:
            where = f"{p['host']}:{p['path']}" if p["host"] or p["path"] else "—"
            state = ("удалён " + _fmt(p["removed_at"])) if p["removed"] else "**НА ОБЪЕКТЕ**"
            L.append(f"| {p['file']} | {where} | {_fmt(p['placed_at'])} | {state} |")
        L.append("")
        if left:
            L.append(f"**Уборка не завершена: {len(left)} файл(ов) остались на объекте.**")
            L.append("Отметьте удаление: `python3 app.py handover removed "
                     f"{session_id} --id <номер>`")
            L.append("")
        else:
            L.append("Все перенесённые файлы удалены.")
            L.append("")

    # ---- 5
    L.append("## 5. Что рекомендуется исправить")
    L.append("")
    fs = _findings_for_target(sess["target_id"])
    if not fs:
        L.append("Значимых находок по этому объекту не зафиксировано.")
        L.append("")
    else:
        L.append("Точки, через которые получен доступ, и связанные с ними находки:")
        L.append("")
        L.append("| Приоритет | Находка | Где |")
        L.append("|---|---|---|")
        for f in fs:
            L.append(f"| {f.get('priority') or '—'} | {(f.get('title') or '')[:110]} | "
                     f"{(f.get('asset') or '')[:60]} |")
        L.append("")
        L.append("Подробности с доказательствами — в отчёте по анализу.")
        L.append("")

    # ---- 6
    L.append("## 6. Что заказчику следует учесть")
    L.append("")
    L.append(f"- Наши действия **отражены в журналах** объекта за период "
             f"{_fmt(sess['created_at'])} — {_fmt(sess['closed_at'])}. "
             "Журналы не изменялись;")
    L.append("  если система обнаружения срабатывала, это ожидаемо и не является "
             "инцидентом.")
    L.append("- Сведения об узлах и адресах, с которых велась работа, в этот "
             "документ не включены.")
    L.append("  При необходимости они передаются через согласованный канал "
             "деконфликта.")
    L.append("- Доступ, описанный в разделе 1, следует отозвать после "
             "демонстрации.")
    L.append("")

    # ---- 7
    # Карта объекта: схема того, что наблюдали и где стоим. Собирается тем же
    # кодом, что идёт модели в подсказку и в панель, — расхождению взяться
    # неоткуда. Секретов в карте нет по построению (asm/objmap.py).
    try:
        from . import objmap
        om = objmap.build(session_id=session_id)
        if om.get("ok"):
            L.append("## 7. Карта объекта")
            L.append("")
            L.append("Схема собрана по нашим наблюдениям: объект, узлы, находки "
                     "и место, где остановились. Секретов в ней нет.")
            L.append("")
            L.append("```mermaid")
            L.append(objmap.mermaid(om))
            L.append("```")
            L.append("")
    except Exception:  # noqa: BLE001 — документ важнее приложения к нему
        pass

    L.append("---")
    L.append("")
    L.append(f"_Документ составлен автоматически по журналу работ "
             f"(сессия {session_id}). Время — в UTC._")
    return "\n".join(L)


def status(session_id: int) -> dict:
    """Сводка для CLI: чего не хватает до готового пакета."""
    acc = access(session_id)
    items = placed(session_id)
    left = [p for p in items if not p["removed"]]
    missing = [k for k in ("account", "privilege", "host", "method") if not acc.get(k)]
    return {"session": session_id, "access": acc, "placed": len(items),
            "outstanding": len(left), "missing": missing,
            "ready": not missing and not left}
