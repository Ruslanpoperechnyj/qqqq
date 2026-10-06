#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Диагностика: почему app.py engines видит не все движки.

Нужна потому, что установщик рапортует «установлено всё», а engines показывает
«5 из 19».

Проверено на практике (2026-10-03, Windows, Python 3.14.7): причиной оказалось
отставание asm/engines.py на рабочей машине — в нём не было _candidates(),
поэтому .exe не подставлялись к именам при поиске. Снаружи картина совпадала
с другими гипотезами, и обе оказались неверными: os.name был 'nt', а X_OK
ничего не отбраковывал.

Поэтому скрипт проверяет, по порядку:

  1) есть ли в asm/engines.py _candidates()   <- реальная причина;
  2) существует ли вообще bin/ внутри TOOLS_DIR;
  3) совпадает ли os.name с 'nt' на Windows;
  4) отбраковывает ли что-нибудь os.access(файл, os.X_OK).

И по каждому движку показывает, на каком именно шаге обрывается поиск.

Запуск из корня проекта:
    python bin/diag-engines.py
"""
from __future__ import annotations

import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm import engines  # noqa: E402

TOOLS = ["nuclei", "naabu", "subfinder", "httpx", "dnsx", "tlsx", "katana",
         "gau", "ffuf", "amass", "nmap", "trivy", "gitleaks", "trufflehog",
         "osv-scanner", "semgrep", "wapiti", "nikto.pl", "testssl.sh"]


def _cands(name: str) -> list:
    """Варианты имени файла. Если engines.py старый — только само имя."""
    fn = getattr(engines, "_candidates", None)
    return fn(name) if fn else [name]


def main() -> int:
    print("=" * 68)
    print("1. СРЕДА")
    print("=" * 68)
    print(f"  os.name       = {os.name!r}     <- если не 'nt', причина A")
    print(f"  sys.platform  = {sys.platform!r}")
    print(f"  python        = {sys.version.split()[0]}  ({sys.executable})")
    # Диагностика обязана переживать отсутствие того, что она проверяет:
    # первая версия падала с AttributeError именно на старом engines.py,
    # то есть на том самом случае, который должна была обнаружить.
    cand = getattr(engines, "_candidates", None)
    if cand is None:
        print("  _candidates   = ОТСУТСТВУЕТ")
        print("                  -> asm/engines.py старше правки с перебором .exe.")
        print("                     Это и есть причина «5 из 19»: поиск идёт по")
        print("                     имени без расширения, а в bin/ лежит nuclei.exe.")
    else:
        print(f"  _candidates('nuclei') = {cand('nuclei')}")
    print()

    print("=" * 68)
    print("2. КАТАЛОГ АРСЕНАЛА")
    print("=" * 68)
    print(f"  ASM_TOOLS_DIR = {os.environ.get('ASM_TOOLS_DIR') or '(не задан)'}")
    print(f"  TOOLS_DIR     = {engines.TOOLS_DIR}")
    print(f"  существует    = {os.path.isdir(engines.TOOLS_DIR)}")
    bin_dir = os.path.join(engines.TOOLS_DIR, "bin")
    print(f"  bin/          = {bin_dir}")
    print(f"  bin/ есть     = {os.path.isdir(bin_dir)}")
    if os.path.isdir(bin_dir):
        items = sorted(os.listdir(bin_dir))
        print(f"  файлов в bin/ = {len(items)}")
        for name in items[:25]:
            print(f"      {name}")
        if len(items) > 25:
            print(f"      ... и ещё {len(items) - 25}")
    print()

    print("=" * 68)
    print("3. ПОШАГОВО ПО КАЖДОМУ ДВИЖКУ")
    print("=" * 68)
    print(f"  {'движок':13} {'кандидат':18} {'есть':5} {'X_OK':5} {'итог'}")
    print("  " + "-" * 64)
    найдено = 0
    for name in TOOLS:
        путь = engines.tool_path(name)
        if путь:
            найдено += 1
        # показываем, что именно отбраковано: перебираем те же каталоги, что tool_path
        показан = False
        for base in [engines.TOOLS_DIR] + engines.LEGACY_DIRS:
            for под in (os.path.join(base, "pylibs", "bin"), os.path.join(base, "bin")):
                for c in _cands(name):
                    cand = os.path.join(под, c)
                    if os.path.exists(cand):
                        ok = os.access(cand, os.X_OK)
                        метка = "OK" if ok else "ОТБРОСАН по X_OK"
                        print(f"  {name:13} {os.path.basename(cand):18} "
                              f"{'да':5} {str(ok):5} {метка}")
                        показан = True
                        break
                if показан:
                    break
            if показан:
                break
        if not показан:
            via = shutil.which(name)
            print(f"  {name:13} {'(в bin/ нет)':18} {'-':5} {'-':5} "
                  f"{'PATH: ' + via if via else 'не найден нигде'}")
    print()
    print(f"  tool_path() вернул путь для {найдено} из {len(TOOLS)}")
    print()

    print("=" * 68)
    print("4. ВЫВОД")
    print("=" * 68)
    # Проверка версии кода идёт первой: на практике именно отставание
    # asm/engines.py от рабочей копии и дало «5 из 19».
    if getattr(engines, "_candidates", None) is None:
        print("  ПРИЧИНА НАЙДЕНА: в asm/engines.py нет _candidates().")
        print("  Это файл отставшей версии — без перебора .exe поиск идёт по")
        print("  имени без расширения, а в bin/ лежат nuclei.exe, naabu.exe и т.д.")
        print("  Видны только testssl.sh и nikto (отдельная ветка с одним")
        print("  os.path.exists) и то, что найдётся через PATH.")
        print("  Лечение: взять свежий asm/engines.py из рабочей копии.")
        return 0

    if not os.path.isdir(os.path.join(engines.TOOLS_DIR, "bin")):
        print("  ФАЙЛОВ НЕТ ВОВСЕ: bin/ внутри TOOLS_DIR не существует.")
        print(f"  TOOLS_DIR = {engines.TOOLS_DIR}")
        print("  Смотрите раздел 2 — ASM_TOOLS_DIR, возможно, указывает не туда.")
        return 0

    if os.name != "nt":
        print("  os.name не 'nt' — на Windows это значит, что python запускается")
        print("  не как обычный Windows-Python, и .exe не подставляются.")
        print("  Проверьте:  python -c \"import os; print(os.name)\"  и")
        print("             py -c \"import os; print(os.name)\"")
        return 0

    отброшено = 0
    for name in TOOLS:
        for base in [engines.TOOLS_DIR] + engines.LEGACY_DIRS:
            for под in (os.path.join(base, "pylibs", "bin"),
                        os.path.join(base, "bin")):
                for c in _cands(name):
                    cand = os.path.join(под, c)
                    if os.path.exists(cand) and not os.access(cand, os.X_OK):
                        отброшено += 1
    if отброшено:
        print(f"  {отброшено} найденных файлов отброшены проверкой")
        print("  os.access(файл, os.X_OK) в tool_path().")
    else:
        print("  Явных причин не найдено: каталог на месте, расширение")
        print("  подставляется, X_OK не отсекает. Сопоставьте раздел 3 с")
        print("  фактическим содержимым bin/ — возможно, движки не")
        print("  доустановились и в bin/ их действительно нет.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
