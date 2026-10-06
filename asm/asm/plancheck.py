# -*- coding: utf-8 -*-
"""Проверка ответа модели: что из написанного ею прошло бы наш конвейер.

Зачем это отдельно от планировщика. Планировщик проверяет ответ **внутри**
работы: он же его и заказывает. А здесь проверяется ответ, полученный снаружи —
из чата LM Studio, из чужого прогона, из вставленного текста. Это нужно в двух
случаях:

* **живой прогон сложной задачи**: видно не «понравилось или нет», а что именно
  принято, что отброшено и почему;
* **спор с моделью задним числом**: если её план написан словами, а не шагами
  каталога, ворота всё равно найдут в этом тексте запрещённые приёмы.

Проверка отвечает на четыре разных вопроса, и путать их нельзя:

1. **Шаги.** Действие из каталога? не повтор? не выдумано? — то же, что делает
   `planner.validate`.
2. **Ворота на шагах.** Пройдёт ли шаг с такими условиями — то же, что делает
   `gate.check_step_with`.
3. **Текст ответа.** Есть ли в написанном приёмы, которых мы не делаем вовсе
   (перебор, чистка журналов, выгрузка данных). Команды в тексте не выполняются,
   но именно так модель и советует — значит, смотреть надо на текст.
4. **Сверка сведений.** То, что в ответе сказано про конкретику — версии,
   применимость уязвимостей, свежесть данных, — сверяется с базой (`facts`).
   Форма может быть безупречной, а применимость — выдуманной: в прогоне №1
   ответ был дисциплинированным и при этом опирался на отчёт сканера вместо
   диапазона версий.

Текст — свободная форма, поэтому находка в тексте помечается как «упоминание»,
если рядом стоит отрицание («не использовать hydra», «перебор запрещён»), и как
настоящая, если отрицания рядом нет. Это не отменяет решения оператора, но
убирает шум: правило, процитированное в ответе, — не нарушение правила.
"""
from __future__ import annotations

from . import facts, gate, planner, store

# Отрицание ищется НЕ окном вокруг совпадения, а по границам фразы.
#
# Проверено на живых ответах: окно не работает ни в одну сторону. Широкое
# («не» где-то рядом) помечает цитатой правила настоящий план — «Если не
# выйдет — пойду через сегмент подрядчика 10.20.7.5». Узкое пропускает честный
# отказ — «Нельзя проводить полный перебор паролей (Brute-force)»: «нельзя»
# стоит на 38 знаков раньше и в окно не попадает.
#
# Фраза — единица смысла: внутри неё отрицание относится к тому, что рядом.
# Границы: перевод строки, конец предложения (точка, ;, !, ? с пробелом или
# концом строки) и тире, отделённое пробелами. Двоеточие границей НЕ считается:
# «Запрещено договором: любые действия в сегменте …» — это одна мысль.
#
# Сам разбор живёт в `facts`: им пользуется и сверка сведений (там отрицание
# отделяет «в ответе совет» от «в ответе цитата правила»). Дублировать его
# нельзя — две копии одного правила разойдутся, и вердикты начнут спорить.
_clause = facts.clause


def _negated(text: str, match: str) -> bool:
    """Все упоминания стоят в отрицании? — см. `facts.negated`."""
    return facts.negated(text, match)


def gate_scope_for(session_id: int) -> tuple:
    """Согласованная область этой сессии — чтобы вызывающий не гадал."""
    return planner.agent.agreed_scope(store.agent_session(session_id))


def check_text(session_id: int, text: str, *, scope: tuple = (), limit: int = 8,
               sheet: dict | None = None, facts_on: bool = True) -> dict:
    """Проверить ответ модели целиком. Ничего не выполняет и не пишет в базу.

    Четвёртый вопрос проверки — **сверка сведений**. Первые три спрашивают про
    форму ответа (шаги, ворота, запрещённые приёмы в тексте). Форма была в
    прогоне №1 хороша, а провал случился ровно там, где модель опиралась на
    выдуманные или непроверенные данные: назвала применимой уязвимость,
    закрытую в предыдущей версии, и не переспросила версию по скану
    трёхнедельной давности. Поэтому здесь к ответу прикладывается лист фактов
    (`facts.sheet`) и каждое упоминание CVE сверяется с ним.

    Лист берётся из кэша и никуда не ходит: проверка чужого ответа не должна
    превращаться в сетевую работу, о которой оператор не знает. `sheet=…` —
    готовый лист от вызывающего, `facts_on=False` — совсем без сверки.
    """
    text = text or ""
    if not scope:
        scope = gate_scope_for(session_id)
    if sheet is None and facts_on:
        try:
            sheet = facts.sheet_for_session(session_id)
        except Exception:  # noqa: BLE001 — сверка не обязана быть, проверка обязана
            sheet = {}
    sheet = sheet or {}

    # 1) Текст: то, что в ответе написано словами.
    raw = gate.check(text, kind="ответ модели", scope=scope)
    mentions = []
    for f in raw["findings"]:
        item = dict(f)
        item["negated"] = _negated(text, str(f["match"]))
        mentions.append(item)

    # 2) Шаги: то, что модель предложила как действия каталога.
    steps, parse_error = planner.parse(text)
    good, rejected = planner.validate(steps, session_id, limit=limit)
    access = bool(planner.agent._access_for(session_id))  # noqa: SLF001
    checked = []
    for st in good:
        g = gate.check_step_with(
            {"action_id": st["action"], "places": bool(_places(st["action"])),
             "params": {"target": planner._target_of(session_id)}},  # noqa: SLF001
            scope=scope)
        # Ворота — не единственное условие. Те же правила очереди, что и в
        # конвейере: внутренний шаг без записи доступа в план не пойдёт, каким
        # бы законным он ни выглядел.
        can, why = planner.can_queue(st, access_recorded=access)
        checked.append({**st, "gate": g["action"], "gate_note": g["note"],
                        "queue": can, "queue_note": why})
    return {"raw": raw, "mentions": mentions, "steps": checked,
            "rejected": rejected, "parse_error": parse_error,
            "parsed": len(steps), "scope": tuple(scope),
            "named_cves": facts.cves_in(text),
            "sheet": sheet, "claims": facts.verify(text, sheet) if sheet else []}


def _places(action_id: str) -> bool:
    a = (planner.agent.BY_ID.get(action_id) or {})
    return bool(a.get("places"))


def render(res: dict, *, session_id: int = 0) -> str:
    """Отчёт о проверке: что принято, что отброшено, что не так в тексте."""
    out: list[str] = []
    if session_id:
        out.append(f"Проверка ответа для сессии {session_id}"
                   + (f" (область: {', '.join(res['scope'])})" if res.get("scope") else ""))
    steps = res.get("steps") or []
    if steps:
        out.append("")
        out.append("Шаги, которые прошли бы в план:")
        for st in steps:
            mark = {"allow": "✓", "warn": "!", "block": "✗"}.get(st["gate"], "?")
            out.append(f"  {mark} {st['action']} [{st['cls']}] — {st.get('why') or ''}")
            if st["gate"] != "allow":
                out.append(f"      ворота: {st['gate_note']}")
            if not st.get("queue", True):
                out.append(f"      в очередь не пойдёт: {st['queue_note']}")
    else:
        out.append("")
        out.append("Шагов каталога в ответе нет: план написан словами. "
                   "Проверяется только текст ниже.")

    if res.get("parse_error"):
        out.append("")
        out.append("Ответ разобран не полностью: " + str(res["parse_error"]))
    if res.get("rejected"):
        out.append("")
        out.append("Предложено, но не принято:")
        for x in res["rejected"]:
            out.append(f"  {x.get('action')}: {x.get('reason')}")

    mentions = res.get("mentions") or []
    hard = [m for m in mentions if not m.get("negated")]
    soft = [m for m in mentions if m.get("negated")]
    if hard:
        out.append("")
        out.append("В ТЕКСТЕ ОТВЕТА есть то, чего мы не делаем:")
        for m in hard:
            out.append(f"  ✗ [{m['category']}] {m['match']}")
        out.append("  (текст сам по себе ничего не выполняет — но именно так "
                   "модель и советует; смотреть глазами)")
    if soft:
        out.append("")
        out.append("Упоминания в отрицании (правило процитировано, не нарушение):")
        for m in soft:
            out.append(f"  · [{m['category']}] {m['match']}")

    claims = res.get("claims") or []
    sh = res.get("sheet") or {}
    if claims:
        out.append("")
        out.extend(facts.render_verify(claims, sh))
    elif res.get("named_cves") and not sh.get("scan_id"):
        # Уязвимости названы, а сверить их не с чем: по объекту нет ни скана,
        # ни данных NVD в кэше. Это дыра в наших сведениях, и она называется
        # вслух — иначе отсутствие раздела читалось бы как «всё сошлось».
        out.append("")
        out.append("Сверка сведений: уязвимости в ответе названы, но по объекту нет "
                   "ни скана, ни данных NVD в кэше — проверить нечем.")

    out.append("")
    bad = [c for c in claims if c.get("contradiction")]
    if not steps and not hard and not bad:
        out.append("Итог: ни шагов каталога, ни запрещённых приёмов — проверять нечего.")
    elif hard:
        out.append("Итог: в ответе есть запрещённый приём — такой план до выполнения "
                   "не дойдёт.")
    elif bad:
        out.append(f"Итог: форма ответа в порядке, но {len(bad)} расхождений со "
                   "сведениями: пока это не перепроверено на объекте, шаг до "
                   "воздействия не дойдёт.")
    else:
        out.append("Итог: шаги законны; исполнение всё равно ждёт решения оператора.")
    return "\n".join(out)


def check_file(session_id: int, path: str, *, limit: int = 8,
               facts_on: bool = True) -> dict:
    """Проверить ответ, сохранённый в файле (то, что модель отдала текстом)."""
    with open(path, encoding="utf-8") as f:
        return check_text(session_id, f.read(), limit=limit, facts_on=facts_on)
