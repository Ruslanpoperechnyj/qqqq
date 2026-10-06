#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сборка файлов «только для вставки в модель» из файлов задач.

Зачем: в файлах задач в конце лежит раздел «Ключ к проверке» — список ловушек и
правильных ответов. Показывать его модели нельзя, а вручную обрезать легко
ошибкой (один раз уехал файл-шаблон с метками-заглушками). Поэтому текст для
модели собирается кодом и проверяется: без ключа, без меток, с данными внутри.

Запуск:  python3 tools/build-prompts.py
Пишет:   knowledge/prompts/<имя>-for-model.md
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "knowledge" / "prompts"

SOURCES = ("hard-task.md", "hard-task-with-facts.md", "hard-task-2.md")

BANNER = (
    "<!-- ЭТО ФАЙЛ ДЛЯ ВСТАВКИ В МОДЕЛЬ. Копировать целиком, ничего не обрезать\n"
    "     и не добавлять. Разбора ловушек и ответов здесь нет — он для оператора.\n"
     "Незаполненных меток-заглушек здесь быть не должно. -->\n\n"
)


def build(name: str) -> tuple[Path, int]:
    src = (PROMPTS / name).read_text(encoding="utf-8")
    try:
        a = src.index("\n## Задача\n") + 1
    except ValueError:
        raise SystemExit(f"{name}: не найден раздел «## Задача»")
    try:
        b = src.index("\n## Ключ к проверке")
    except ValueError:
        raise SystemExit(f"{name}: не найден раздел «## Ключ к проверке» — "
                         "проверьте, что ключ в файле есть и назван так же")
    part = src[a:b].rstrip()
    while part.endswith("-"):
        part = part[:-1].rstrip()

    # Проверки, из-за которых однажды уехал шаблон:
    if "{{" in part or "}}" in part:
        raise SystemExit(f"{name}: в тексте для модели остались метки-заглушки")
    if "Ключ к проверке" in part:
        raise SystemExit(f"{name}: в текст для модели попал ключ")
    if "## Задача" not in part.splitlines()[0]:
        raise SystemExit(f"{name}: текст должен начинаться с «## Задача»")
    if name == "hard-task-2.md" and part.count("```csv") != 3:
        raise SystemExit(f"{name}: ожидалось три таблицы csv — данные не подставлены?")

    out = PROMPTS / (name[:-3] + "-for-model.md")
    out.write_text(BANNER + part + "\n", encoding="utf-8")
    return out, len(part)


def main() -> None:
    for name in SOURCES:
        path, size = build(name)
        print(f"{name:28s} -> {path.name:34s} {size:6d} знаков")
    print("готово. Модели вставлять только файлы -for-model.md")


if __name__ == "__main__":
    sys.exit(main())
