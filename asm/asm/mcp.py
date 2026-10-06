# -*- coding: utf-8 -*-
"""MCP: наши инструменты снаружи — и только те, которые ничего не запускают.

Зачем. Интерфейс работы с агентом у нас свой (панель и терминал), но рядом живут
удобные редакторы вроде OpenCode, которые умеют подключать чужие инструменты по
протоколу MCP. Отдавать им **свои** инструменты чтения — это бесплатное удобство:
человек работает в привычном окне, а читает при этом наша база, а не чужой
пересказ.

Чего здесь принципиально нет:

1. **Ничего, что выполняется на объекте.** Отдаются только инструменты чтения
   (карта, находки, сверка, память, знания, состояние, арсенал, стелс, бюджет,
   транспорт, вложения). «Команда», внутренние шаги и отправка транспортом
   снаружи недоступны: шаг ставит человек в чате или терминале, там же он видит
   карточку и говорит «да». Причина не в недоверии к редактору, а в устройстве
   правил: решение по шагу принимает оператор, а не интерфейс.

2. **Ничего, что ходит в интернет.** Инструмент «интернет» тоже не отдаётся:
   выход наружу — это след, а след должен быть решением человека, а не побочным
   эффектом нажатия в редакторе.

Почему stdio. MCP-сервер по стандарту общается по stdio; сюда нельзя писать
ничего, кроме протокола, поэтому все сообщения о работе идут в stderr.

Запуск:

    python3 app.py mcp --session 3        # сервер для сессии 3

и в настройках редактора (пример для OpenCode):

    {"mcp": {"asm": {"type": "local",
                     "command": ["python3", "app.py", "mcp", "--session", "3"]}}}
"""
from __future__ import annotations

import json
import sys
from typing import Any

from . import agent, chat, store

# Версия протокола, которую мы понимаем. Если клиент просит другую — отвечаем
# своей: он либо согласится, либо честно откажется, но молча не сломается.
PROTOCOL = "2024-11-05"
SERVER_NAME = "asm-agent"

# Что отдаём наружу. Список именно такой, а не «всё, кроме»: новый инструмент
# должен попасть сюда осознанно, а не оказаться снаружи по недосмотру.
EXPOSED = ("карта", "находки", "сверка", "память", "знания", "состояние",
           "арсенал", "стелс", "бюджет", "транспорт", "вложения")

# Что не отдаём и почему — чтобы отказ был объяснением, а не пустотой.
NOT_EXPOSED = {
    "команда": "свободный шаг ставит человек: решение по шагу принимает оператор, "
               "а не редактор. Откройте чат: python3 app.py chat <сессия>",
    "интернет": "выход наружу — это след; он должен быть решением человека, "
                "а не нажатием в редакторе",
}


def _text(s: Any) -> str:
    return s if isinstance(s, str) else json.dumps(s, ensure_ascii=False)


def tool_list() -> list[dict]:
    """Список инструментов в форме MCP: имя, описание, схема аргументов."""
    out = []
    for name in EXPOSED:
        meta = chat.TOOLS.get(name)
        if not meta:
            continue
        props = {}
        for key, descr in (meta.get("args") or {}).items():
            props[key] = {"type": "string", "description": str(descr)}
        out.append({
            "name": name,
            "description": str(meta.get("about") or ""),
            "inputSchema": {"type": "object", "properties": props},
        })
    return out


def call_tool(name: str, args: dict, *, session: int) -> dict:
    """Вызвать инструмент и вернуть ответ в форме MCP."""
    name = str(name or "").strip().lower()
    if name in NOT_EXPOSED:
        return _err(name + ": " + NOT_EXPOSED[name])
    if name not in EXPOSED:
        known = ", ".join(EXPOSED)
        return _err(f"инструмента «{name}» здесь нет. Доступны: {known}")
    sess = store.agent_session(session)
    if sess is None:
        return _err(f"сессии {session} нет: укажите существующую (agent start)")
    if chat.AUTO == "strict" and name not in ("состояние",):
        # Строгий режим чата — про решения. Здесь шагов нет вовсе, поэтому
        # ограничение не мешает: чтение остаётся чтением.
        pass
    meta = chat.TOOLS.get(name) or {}
    run = meta.get("run")
    if not callable(run):
        return _err(f"инструмент «{name}» доступен только внутри сессии")
    try:
        res = run(int(session), int(sess["target_id"]), dict(args or {}))
    except Exception as e:  # noqa: BLE001 — отказ должен быть словами, не трассировкой
        return _err(f"инструмент «{name}» не сработал: {type(e).__name__}: {str(e)[:200]}")
    return {"content": [{"type": "text", "text": _text(res)}], "isError": False}


def _err(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def handle(msg: dict, *, session: int) -> dict | None:
    """Обработать одно сообщение JSON-RPC. None — отвечать не нужно (уведомление)."""
    method = str(msg.get("method") or "")
    mid = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": "1.0"},
        }}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": tool_list()}}
    if method == "tools/call":
        params = msg.get("params") or {}
        got = call_tool(params.get("name"), params.get("arguments") or {}, session=session)
        return {"jsonrpc": "2.0", "id": mid, "result": got}
    if mid is None:
        return None
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"метод «{method}» не поддерживается"}}


def serve(session: int, stdin=None, stdout=None) -> int:
    """Цикл stdio. В stdout — только протокол, всё остальное в stderr."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    store.connect()
    if store.agent_session(session) is None:
        print(f"MCP: сессии {session} нет — укажите существующую "
              f"(python3 app.py agent start <цель>)", file=sys.stderr)
        return 2
    print(f"MCP asm-agent: сессия {session}, инструментов {len(tool_list())} "
          f"(только чтение; шаги — в чате и терминале)", file=sys.stderr)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:  # noqa: BLE001 — мусор в протоколе не должен ронять сервер
            print("MCP: не разобрал строку как JSON", file=sys.stderr)
            continue
        if isinstance(msg, list):            # пакетный режим: обрабатываем по одному
            msgs = msg
        else:
            msgs = [msg]
        for m in msgs:
            try:
                answer = handle(m, session=session)
            except Exception as e:  # noqa: BLE001
                answer = {"jsonrpc": "2.0", "id": m.get("id"),
                          "error": {"code": -32603,
                                    "message": f"внутренняя ошибка: {type(e).__name__}"}}
            if answer is None:
                continue
            stdout.write(json.dumps(answer, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0


def status() -> dict:
    """Сводка для доклада: что отдаём снаружи и что нет."""
    return {"server": SERVER_NAME, "protocol": PROTOCOL,
            "exposed": list(EXPOSED), "closed": dict(NOT_EXPOSED),
            "session_required": True}
