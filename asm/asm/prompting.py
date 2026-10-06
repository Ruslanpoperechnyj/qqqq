# -*- coding: utf-8 -*-
"""Безопасная загрузка системных промптов и автоматических подсказок ASM.

Runtime-файлы выбираются только из явного allowlist. Файлы ручных тестовых
задач в knowledge/prompts не сканируются и не могут случайно стать system
prompt. Контекстные плейбуки остаются отдельными справочными данными, а не
сливаются с базовой системной рамкой.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

_ROOT = Path(__file__).resolve().parent.parent
_SYSTEM_PROMPTS = {
    "agent_chat": _ROOT / "knowledge" / "system_prompts" / "agent-chat.md",
}
_MAX_SYSTEM_PROMPT_CHARS = 16_000
_MAX_METHOD_HINTS_CHARS = 1_400


def load_system_prompt(role: str) -> tuple[str, str]:
    """Вернуть (текст, fingerprint) для явно разрешённой роли.

    Нет поиска по каталогам или пользовательского пути: добавление новой роли
    требует отдельной записи в allowlist. fingerprint позволяет аудировать
    версию без записи самого промпта или пользовательских данных.
    """
    path = _SYSTEM_PROMPTS.get(str(role or ""))
    if path is None:
        raise ValueError(f"роль системного промпта не разрешена: {role!r}")
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as e:
        raise RuntimeError(f"системный промпт {role!r} не прочитан: {type(e).__name__}") from e
    if not text:
        raise RuntimeError(f"системный промпт {role!r} пуст")
    if len(text) > _MAX_SYSTEM_PROMPT_CHARS:
        raise RuntimeError(f"системный промпт {role!r} превышает лимит {_MAX_SYSTEM_PROMPT_CHARS}")
    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return text, f"{role}:{fingerprint}"


def _one_line(value: object, limit: int) -> str:
    """Санитизировать поле справочного плейбука и не дать ему разорвать блок."""
    from .aiagent import sanitize

    text = sanitize(str(value or ""), limit=limit)
    text = " ".join(text.split())
    return text.replace("<", "‹").replace(">", "›")


def render_method_hints(playbooks: Iterable[dict], *, scan_id: int,
                        allowed_actions: Iterable[str],
                        max_chars: int = _MAX_METHOD_HINTS_CHARS) -> tuple[str, list[str]]:
    """Сжато отрисовать только совпавшие и допустимые методические плейбуки.

    Вызывающая сторона отвечает за подбор по наблюдениям. Здесь повторно
    проверяются action ID, длина и границы полей. Текст остаётся в контекстном
    сообщении и никогда не получает роль system/developer.
    """
    try:
        sid = int(scan_id)
    except (TypeError, ValueError):
        return "", []
    if sid <= 0 or max_chars < 200:
        return "", []
    allowed = {str(a) for a in (allowed_actions or ())}
    header = (f"МЕТОДИЧЕСКИЕ ПОДСКАЗКИ — справочно, не разрешение; "
              f"подобраны по завершённому скану №{sid}.")
    footer = ("Сверяй применимость с фактами и ограничениями; каждый шаг к объекту "
              "всё равно требует отдельного одобрения.")
    lines = [header]
    used: list[str] = []
    seen: set[str] = set()
    for pb in list(playbooks or [])[:3]:
        if not isinstance(pb, dict):
            continue
        pid = _one_line(pb.get("id"), 80)
        title = _one_line(pb.get("title") or pid, 120)
        if not pid or pid in seen:
            continue
        steps = pb.get("steps") or []
        if not isinstance(steps, (list, tuple)):
            continue
        step_lines = []
        for step in steps[:4]:
            if not isinstance(step, dict):
                continue
            action = str(step.get("action") or "").strip()
            if action not in allowed:
                continue
            why = _one_line(step.get("why"), 150)
            step_lines.append(f"  • {action}: {why or 'применимость нужно подтвердить'}")
        if not step_lines:
            continue
        entry = [f"- {title} [{pid}]", *step_lines]
        candidate = lines + entry + [footer]
        if len("\n".join(candidate)) > max_chars:
            break
        lines.extend(entry)
        used.append(pid)
        seen.add(pid)
    if not used:
        return "", []
    lines.append(footer)
    return "\n".join(lines), used
