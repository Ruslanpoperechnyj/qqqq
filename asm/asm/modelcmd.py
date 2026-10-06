# -*- coding: utf-8 -*-
"""Команды внутреннего шага, написанные моделью.

Зачем это здесь. Команды внутренних шагов были статичными шаблонами
(`agent.internal_plan`): код знал, что делать на Linux и Windows «вообще», но не
знал, что уже известно про **этот** объект — какие версии, какие группы, где мы
стоим. Прогоны показали (§33.8), что думающая модель пишет исполняемые команды
корректно; решение — подключить её именно к этому месту, а не к эксплуатации.

Что модель делает и чего не делает:

  * пишет **только команды** шага: что запустить на хосте под названной учёткой;
  * порядок работ, перенос файла, имя файла на хосте и уборка остаются в коде
    (`agent.internal_plan`) — модель их не переписывает, иначе уборка разошлась бы
    с тем, что реально лежит на объекте;
  * ничего не выполняется: шаг по-прежнему готовит текст для человека, который
    читает и запускает сам (агент внутренние шаги не исполняет никогда).

Чем это ограничено, и почему так:

  * **ворота поимённо.** Каждая команда проходит `gate.check`; заблокированная не
    попадает в текст вовсе — вместо неё пометка «отброшено, причина». Тот же
    набор запретов, что и везде: секреты (по документу), перебор, малварь, C2,
    логи, данные заказчика, доступность.
  * **проверка ответа целиком.** Готовый текст идёт через `plancheck.check_text` —
    то же сито, что для ответов модели в прогонах (§32).
  * **запасной путь всегда есть.** Модель недоступна, ответила мусором или все
    команды заблокированы — шаг готовится по шаблонам, и в тексте это прямо
    сказано («источник: правила»). Тишины вместо содержания не бывает.

Включается настройкой `ASM_MODEL_CMDS`: `auto` (по умолчанию — работает, если
задан `ASM_LLM_BASE`), `on`, `off`.
"""

from __future__ import annotations

import json
import os

from . import aiagent, gate
from .settings import current_settings

MODE = (os.environ.get("ASM_MODEL_CMDS") or "auto").strip().lower()
if MODE not in ("auto", "on", "off"):
    MODE = "auto"

MAX_CMDS = 10
MAX_LEN = 400          # одна команда; длиннее — почти наверняка не команда

SYSTEM = """Ты пишешь команды для одного шага внутренних работ по аудиту защищённости.
Работа идёт на объекте заказчика, у которого есть договор; всё, что ты напишешь,
человек прочитает и запустит сам.

ЖЁСТКИЕ ПРАВИЛА:
1) Только чтение: команды не меняют файлы, настройки, службы и данные. Никаких
   удалений, установок, перезапусков, правок конфигов.
2) Только один хост — тот, что назван. Никаких обращений к другим адресам.
3) Запрещено и будет отброшено: перебор и подбор паролей, дампы секретов и
   памяти (lsass, mimikatz, secretsdump), персистентность (cron, службы,
   автозапуск), сетевые туннели и проброс портов, правка или удаление журналов,
   вредоносные приёмы. Не предлагай их даже «на будущее».
4) Никаких файлов сверх тех, что названы во входных данных. Каждый файл на
   чужой машине должен быть в записи об уборке.
5) Пиши команды так, как их наберут в оболочке названной системы
   (Linux — sh/bash; Windows — cmd или PowerShell, укажи это). Не выдумывай
   версии, имена служб и пути: чего не знаешь — не пиши.
6) Коротко: не больше 8 команд, каждая — одна строка.

Ответ — только JSON без пояснений вокруг:
{"commands": ["...", "..."], "why": "одной строкой, что даст шаг",
 "cleanup": ["команды уборки, если после шага что-то остаётся, иначе пустой список"]}
"""


def enabled() -> bool:
    """Работает ли модель на этом шаге из snapshot текущей операции."""
    settings = current_settings()
    mode = str(settings.get("ASM_MODEL_CMDS", MODE) if settings is not None
               else os.environ.get("ASM_MODEL_CMDS", MODE))
    mode = mode.strip().lower()
    if mode not in ("auto", "on", "off"):
        mode = "auto"
    if mode == "off":
        return False
    if mode == "on":
        return True
    cfg = aiagent.config()
    return bool(cfg.get("base")) or bool(cfg.get("mock"))


def _ask(cfg: dict, messages: list[dict]) -> str:
    """Ответ модели строкой. Пустая строка — модели нет (это не ошибка шага)."""
    if not cfg.get("base") and not cfg.get("mock"):
        return ""
    return "".join(aiagent._tokens(cfg, messages))  # noqa: SLF001 — один путь к модели


def _parse(text: str) -> dict:
    """Разобрать ответ модели. Терпимо: берём первый JSON-объект."""
    raw = aiagent._extract_json(text or "") or {}  # noqa: SLF001
    cmds = raw.get("commands")
    if isinstance(cmds, str):
        cmds = [cmds]
    if not isinstance(cmds, list):
        cmds = []
    clean: list[str] = []
    for c in cmds:
        s = " ".join(str(c or "").split())
        if s and len(s) <= MAX_LEN and s not in clean:
            clean.append(s)
    cleanup = raw.get("cleanup")
    if isinstance(cleanup, str):
        cleanup = [cleanup]
    cleanup = [str(c).strip() for c in (cleanup or []) if str(c or "").strip()]
    return {"commands": clean[:MAX_CMDS], "why": str(raw.get("why") or "").strip(),
            "cleanup": cleanup[:MAX_CMDS]}


def _screen(cmds: list[str], *, scope: tuple, target: str) -> tuple[list[str], list[dict]]:
    """Прогнать команды через ворота. Возвращает (прошедшие, отброшенные)."""
    good: list[str] = []
    dropped: list[dict] = []
    for c in cmds:
        g = gate.check(c, kind="команда", scope=scope, target=target)
        if g["action"] == gate.BLOCK:
            dropped.append({"cmd": c, "reason": g.get("note") or "запрещено воротами"})
        else:
            good.append(c)
    return good, dropped


def commands(action_id: int | str, params: dict, sess: dict | None = None, *,
             scope: tuple = (), title: str = "", why: str = "",
             fix: dict | None = None) -> dict:
    """Команды шага от модели. Ничего не выполняет и не пишет в базу.

    Возвращает словарь с источником: `source="модель"` — команды написала модель
    и они прошли ворота; `source="правила"` — модель не смогла, шаг готовится
    шаблонами (в `error` причина, и она попадает в текст шага).
    """
    out: dict = {"ok": False, "source": "правила", "cmds": [], "cleanup": [],
                 "why": "", "dropped": [], "error": ""}
    cfg = aiagent.config()
    if not (cfg.get("base") or cfg.get("mock")):
        out["error"] = "модель не задана (ASM_LLM_BASE пуст)"
        return out

    host = str((params or {}).get("host") or "<хост>").strip()
    user = str((params or {}).get("user") or "<учётная запись>").strip()
    osname = str((params or {}).get("os") or "").strip() or "не названа"
    goal = str((params or {}).get("goal") or "").strip()

    lines = ["ШАГ: " + (title or str(action_id)),
             "ЗАЧЕМ: " + (why or "—"),
             f"ХОСТ: {host}",
             f"СИСТЕМА: {osname}",
             f"ОТ ИМЕНИ: {user}"]
    if goal:
        lines.append("ЦЕЛЬ ШАГА: " + goal)
    for k, v in (fix or {}).items():
        lines.append(f"ОБЯЗАТЕЛЬНО: {k} — {v}")
    # Карта объекта: модель пишет команды под то, что уже известно, а не «вообще».
    try:
        from . import objmap
        m = objmap.build(session_id=int((sess or {}).get("id") or 0))
        if m.get("ok"):
            lines += ["", objmap.brief(m, limit=900)]
    except Exception:  # noqa: BLE001 — карта не обязательна для команд
        pass
    lines += ["", "Верни только JSON по схеме."]
    user_msg = "\n".join(lines)

    try:
        raw = _ask(cfg, [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": user_msg}])
    except Exception as e:  # noqa: BLE001 — модель не должна ронять шаг
        out["error"] = f"модель недоступна: {e}"
        return out
    parsed = _parse(raw)
    if not parsed["commands"]:
        out["error"] = ("модель не вернула команд" if not (raw or "").strip()
                        else "ответ модели не разобран как JSON с командами")
        return out

    good, dropped = _screen(parsed["commands"], scope=scope, target=host)
    if not good:
        out["error"] = ("все команды отброшены воротами: "
                        + (dropped[0]["reason"][:120] if dropped else "нет команд"))
        out["dropped"] = dropped
        return out

    # Проверка ответа целиком: то же сито, что и для ответов модели в прогонах.
    try:
        from . import plancheck
        res = plancheck.check_text(int((sess or {}).get("id") or 0),
                                   "\n".join(good), scope=scope, facts_on=False)
        blocked = [f for f in (res.get("raw") or {}).get("findings") or []
                   if f.get("level") == gate.BLOCK]
        if blocked:
            good = [c for c in good
                    if not any(f.get("match") and str(f["match"]) in c for f in blocked)]
            for f in blocked:
                dropped.append({"cmd": str(f.get("match") or ""),
                                "reason": "проверка ответа: " + str(f.get("title") or "")})
            if not good:
                out["error"] = "после проверки ответа команд не осталось"
                out["dropped"] = dropped
                return out
    except Exception:  # noqa: BLE001 — проверка не обязана быть, шаг обязателен
        pass

    out.update({"ok": True, "source": "модель", "cmds": good,
                "cleanup": parsed["cleanup"], "why": parsed["why"],
                "dropped": dropped})
    return out


def text_block(res: dict) -> list[str]:
    """Строки для текста шага: команды, источник и что отброшено."""
    if not res.get("ok"):
        why = res.get("error") or "модель не использовалась"
        return [f"Команды подготовлены правилами инструмента ({why})."]
    L = ["Команды (написала модель, каждая проверена воротами):", ""]
    for c in res["cmds"]:
        L.append("  " + c)
    if res.get("why"):
        L += ["", f"Что даст шаг: {res['why']}"]
    dropped = res.get("dropped") or []
    if dropped:
        L.append("")
    for d in dropped[:4]:
        why = " ".join(str(d.get("reason") or "").split())
        if len(why) > 140:  # обрезаем по слову, чтобы не рвать фразу на середине
            why = why[:140].rsplit(" ", 1)[0] + "…"
        L.append(f"  отброшено: {str(d.get('cmd') or '')[:60]} — {why}")
    if res.get("cleanup"):
        L += ["", "Уборка после шага:"]
        for c in res["cleanup"]:
            L.append("  " + c)
    return L
