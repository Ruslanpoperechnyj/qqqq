#!/usr/bin/env python3
"""
ASM — прототип платформы анализа внешнего периметра.

Запуск:
    python3 app.py serve                      # дашборд на http://localhost:8000
    python3 app.py add client.ru --client "ООО Ромашка" --ref "Договор 14-А"
    python3 app.py scan client.ru             # анализ (в фоне)
    python3 app.py scan client.ru --wait      # анализ с ожиданием
    python3 app.py report 1 --fmt md          # отчёт в stdout
    python3 app.py findings 1                 # находки в таблицу
    python3 app.py list                       # цели и сканы

Переменные окружения:
    NVD_API_KEY     — ключ NVD (без него лимит 5 запросов/30 сек)
    ASM_LLM_BASE    — OpenAI-совместимый эндпоинт для ИИ-заключения (напр. http://localhost:11434/v1)
    ASM_LLM_KEY     — ключ, если нужен
    ASM_LLM_MODEL   — модель (по умолчанию gpt-4o-mini)
    ASM_PORT        — порт дашборда (по умолчанию 8000)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time


def _apply_inline_settings(argv: list[str]) -> list[str]:
    """Разобрать --set ASM_KEY=VALUE до импорта asm.

    Зачем это нужно именно здесь, а не в argparse: больше сотни настроек
    читаются один раз на импорте модуля (asm/active.py, asm/aiagent.py,
    asm/engines.py). Если выставить их после импорта, они не подействуют,
    и пользователь получит молча проигнорированную настройку.

    Заодно это единственный способ задать настройку из PowerShell одной
    строкой: там не работает привычная форма «ASM_KEY=значение команда»,
    а ставить переменную окружения на всю сессию ради одного запуска неудобно.

    Возвращает argv без разобранных пар, чтобы argparse их не увидел.
    """
    rest: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--set" and i + 1 < len(argv):
            pair = argv[i + 1]
            i += 2
        elif a.startswith("--set="):
            pair = a[len("--set="):]
            i += 1
        else:
            rest.append(a)
            i += 1
            continue
        if "=" not in pair:
            print(f"--set: ожидалось ASM_КЛЮЧ=значение, получено «{pair}»",
                  file=sys.stderr)
            continue
        k, v = pair.split("=", 1)
        k = k.strip()
        if not k.startswith("ASM_"):
            print(f"--set: ключ «{k}» не начинается с ASM_ — пропущен, "
                  f"иначе можно перекрыть произвольную переменную окружения",
                  file=sys.stderr)
            continue
        os.environ[k] = v
    return rest


sys.argv = [sys.argv[0]] + _apply_inline_settings(sys.argv[1:])

# Preserve only explicit scan and mode overrides before the legacy adapter adds
# preset values to process env. The private payload is used by --no-wait child
# processes; it contains no secret/model/transport values.
from asm.mode import PRESETS as _MODE_PRESETS  # pure constant table; no DB connect
from asm.settings import project_explicit_environment as _project_explicit_environment

_INTERNAL_EXPLICIT_CONFIG_ENV = "_ASM_EXPLICIT_CONFIG_SNAPSHOT"
_INTERNAL_SCAN_SETTINGS_ENV = "_ASM_SCAN_SETTINGS_SNAPSHOT"
_MODE_ENV_KEYS = frozenset(key for preset in _MODE_PRESETS.values() for key in preset)


def _capture_explicit_config_environment() -> dict[str, object]:
    values = os.environ
    payload = os.environ.get(_INTERNAL_EXPLICIT_CONFIG_ENV)
    if payload:
        try:
            decoded = json.loads(payload)
            if isinstance(decoded, dict):
                values = decoded
        except (TypeError, ValueError):
            # Malformed private child-process metadata is ignored without
            # echoing its contents; explicit values fall back to current env.
            pass
    return _project_explicit_environment(values, additional_keys=_MODE_ENV_KEYS)


_EXPLICIT_CONFIG_ENVIRONMENT = _capture_explicit_config_environment()


def _apply_mode_before_imports() -> None:
    """Режим работ (mode.py) — в окружение до импорта рабочих модулей.

    asm/engines.py, asm/stealth.py и asm/scan.py читают свои настройки один
    раз при импорте. Режим, выставленный после импорта, молча не подействовал
    бы — ровно тот класс ошибок, из-за которого и появился `--set` до импорта.
    Явная настройка (--set, переменная в шелле) сильнее режима.
    """
    try:
        from asm import store as _st
        from asm import mode as _md
        _st.connect()
        _md.load_into_env(_st)
    except Exception as e:  # noqa: BLE001 — режим не должен мешать работе
        print(f"[режим] применить не удалось: {e}", file=sys.stderr)


_apply_mode_before_imports()

from asm import mode as modemod, report, scan as scanmod, store, web
from asm.settings import Settings, SettingsError, use_settings


def _scan_settings_snapshot() -> Settings:
    """Собрать scan snapshot из child payload либо mode + явных env keys."""
    child_payload = os.environ.get(_INTERNAL_SCAN_SETTINGS_ENV)
    if child_payload is not None:
        try:
            decoded = json.loads(child_payload)
        except (TypeError, ValueError):
            raise SettingsError("внутренний scan snapshot некорректен") from None
        if not isinstance(decoded, dict):
            raise SettingsError("внутренний scan snapshot должен быть таблицей")
        if "scan" in decoded or "config" in decoded:
            scan_values = decoded.get("scan") or {}
            config_values = decoded.get("config") or {}
            if not isinstance(scan_values, dict) or not isinstance(config_values, dict):
                raise SettingsError("внутренний scan snapshot некорректен")
            return Settings.from_sources(
                environment=scan_values, cli_overrides=config_values,
            )
        return Settings.from_sources(environment=decoded)

    _, mode_values = modemod.stored_preset(store)
    return Settings.from_environment_snapshot(
        _EXPLICIT_CONFIG_ENVIRONMENT, mode_values=mode_values
    )

try:  # бесплатный арсенал ИБ (nuclei, nmap, nikto, trivy, gitleaks, ...)
    from asm import engines
except Exception:  # noqa: BLE001
    engines = None  # type: ignore


def _discover_settings() -> dict:
    """Найти все настройки ASM_* прямо в исходниках.

    Отдельный справочник настроек вести бессмысленно: их больше сотни, и он
    разошёлся бы с кодом в первый же месяц. Вместо этого имена и значения по
    умолчанию читаются из самих вызовов os.environ.get(...).
    """
    import ast
    import pathlib as _pl
    root = os.path.dirname(os.path.abspath(__file__))
    out: dict = {}
    files = [os.path.join(root, "app.py")]
    asm_dir = os.path.join(root, "asm")
    if os.path.isdir(asm_dir):
        files += [os.path.join(asm_dir, n) for n in sorted(os.listdir(asm_dir))
                  if n.endswith(".py")]
    for path in files:
        try:
            src = _pl.Path(path).read_text(encoding="utf-8")
            tree = ast.parse(src)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"):
                continue
            if not node.args:
                continue
            try:
                name = ast.literal_eval(node.args[0])
            except Exception:
                continue
            if not isinstance(name, str) or not name.startswith("ASM_"):
                continue
            default = ""
            if len(node.args) > 1:
                try:
                    default = ast.literal_eval(node.args[1])
                except Exception:
                    default = "<вычисляется>"
            rec = out.setdefault(name, {"модули": set(), "по умолчанию": default})
            rec["модули"].add(os.path.basename(path))
    return out


def _print_settings() -> None:
    found = _discover_settings()
    if not found:
        print("настроек не найдено — проверьте, что каталог asm/ на месте")
        return
    print(f"Найдено настроек в коде: {len(found)}")
    print("Любую можно задать одной строкой:  python3 app.py --set КЛЮЧ=значение <команда>")
    print()
    for name in sorted(found):
        rec = found[name]
        cur = os.environ.get(name)
        mods = ", ".join(sorted(rec["модули"]))
        dflt = rec["по умолчанию"]
        if cur is not None:
            state = f"= {cur}  (по умолчанию {dflt!r})"
        else:
            state = f"по умолчанию {dflt!r}"
        print(f"  {name:26} {state:40} [{mods}]")
    # Скорость запросов — единственная группа, где пустое значение по умолчанию
    # осмысленно: оно означает «взять из профиля». Показать это надо явно,
    # иначе строка «по умолчанию ''» выглядит как потерянное значение.
    rates = [k for k in found if k.endswith("_RATE") and not found[k]["по умолчанию"]]
    if rates:
        print()
        if engines is not None:
            print(f"  Пустое значение у {', '.join(sorted(rates))}")
            print("  означает «взять из профиля». Профиль сейчас: "
                  f"{engines.PROFILE}")
            print("    " + "   ".join(f"{e}={engines.rate_for(e)}" for e in
                                      ("naabu", "nuclei", "httpx", "katana")))
            print(f"  Профили: safe — щадящий (по умолчанию), pentest, full.")
            print(f"  Разброс скорости: ASM_RATE_SPREAD="
                  f"{engines.RATE_SPREAD} (доля, 0 выключает)")
        else:
            print(f"  Пустое значение у {', '.join(sorted(rates))} означает "
                  "«взять из профиля».")

    extra = sorted(k for k in os.environ if k.startswith("ASM_") and k not in found)
    if extra:
        print("\n  заданы, но в коде не встречаются (возможно, опечатка):")
        for name in extra:
            print(f"    {name} = {os.environ[name]}")


def _find_target(value: str):
    value = value.strip().lower()
    for t in store.targets():
        if str(t["value"]) == value:
            return t
    return None


def _setup_console() -> None:
    """Русский текст в консоли Windows: без этого вывод — «кракозябры».

    PowerShell и Git Bash дают Python кодировку cp866/cp1251, и кириллица
    превращается в мусор: команда отрабатывает, но результат нечитаем, а при
    перенаправлении вывода дело доходит до UnicodeEncodeError. Переводим
    консоль в UTF-8 (то же, что «chcp 65001») и просим utf-8 у потоков.
    Замена непечатаемых символов, а не ошибка: падать из-за вывода CLI нельзя.
    """
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:  # noqa: BLE001 — нет консоли (pythonw) или старая система
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — поток может быть подменён (тесты, IDE)
            pass


def params_of(step) -> dict:
    """Параметры шага словарём. Мелочь, но понадобилась в трёх местах сразу."""
    try:
        raw = step["params"] if "params" in step.keys() else "{}"
        return json.loads(raw or "{}")
    except Exception:  # noqa: BLE001
        return {}


def main() -> int:
    _setup_console()
    ap = argparse.ArgumentParser(description="ASM: анализ внешнего периметра (прототип)")
    # --set разбирается до импорта asm (см. _apply_inline_settings), поэтому
    # здесь он объявлен только ради --help: до argparse эти пары не доходят.
    ap.add_argument("--set", action="append", default=[], metavar="ASM_КЛЮЧ=ЗНАЧЕНИЕ",
                    help="задать настройку одной строкой, можно несколько раз. "
                         "Работает из PowerShell, где нельзя написать "
                         "«ASM_КЛЮЧ=значение команда». Пример: "
                         "--set ASM_NMAP_TOP=1000")
    ap.add_argument("--settings", action="store_true",
                    help="показать все поддерживаемые настройки ASM_* и их значения")
    sub = ap.add_subparsers(dest="cmd", required=False)

    s = sub.add_parser("serve", help="запустить веб-дашборд")
    s.add_argument("--port", type=int, default=None)
    s.add_argument("--host", default="0.0.0.0")

    a = sub.add_parser("add", help="добавить цель")
    a.add_argument("target")
    a.add_argument("--client", required=True)
    a.add_argument("--ref", dest="ref", required=True, help="основание: договор/письмо-разрешение")
    a.add_argument("--date", default="")
    a.add_argument("--note", default="")

    sc = sub.add_parser("scan", help="запустить анализ")
    sc.add_argument("target_or_id")
    sc.add_argument("--wait", action="store_true", default=True,
                    help="ждать окончания анализа (по умолчанию)")
    sc.add_argument("--run-scan-id", type=int, default=0, help=argparse.SUPPRESS)
    sc.add_argument("--no-wait", action="store_true",
                    help="отделить анализ в фоновый процесс и сразу вернуть управление")
    sc.add_argument("--max-subdomains", type=int, default=None)
    sc.add_argument("--max-ips", type=int, default=None)
    sc.add_argument("--repo", default=None, help="git-репозиторий заказчика для проверки кода (запоминается у цели)")
    sc.add_argument("--code", dest="code_path", default=None, help="каталог с кодом заказчика на этой машине")
    sc.add_argument("--image", default=None, help="образ контейнера заказчика (например nginx:1.25)")

    r = sub.add_parser("report", help="выгрузить отчёт")
    r.add_argument("scan_id", type=int)
    r.add_argument("--fmt", default="md", choices=["md", "json", "csv"])
    r.add_argument("--out", default=None)

    f = sub.add_parser("findings", help="показать находки")
    f.add_argument("scan_id", type=int)
    f.add_argument("--all", action="store_true", help="показать и низкоприоритетные")

    vf = sub.add_parser("verify", help="перепроверить находки: какие порты ещё открыты")
    vf.add_argument("scan_id", type=int)
    vf.add_argument("--timeout", type=float, default=3.0,
                    help="таймаут проверки порта в секундах (по умолчанию 3)")
    vf.add_argument("--mark-fixed", action="store_true",
                    help="пометить закрытыми находки на закрывшихся портах")
    vf.add_argument("--operator", default=os.environ.get("USER", ""))

    lg = sub.add_parser("log", help="журнал скана: что запускалось, что пропущено и почему")
    lg.add_argument("scan_id", type=int)
    lg.add_argument("--tail", type=int, default=0,
                    help="только последние N строк (по умолчанию весь журнал)")
    lg.add_argument("--only", default="",
                    help="показывать только строки, содержащие подстроку "
                         "(например --only пропущен или --only ОШИБКА)")

    sub.add_parser("list", help="список целей и сканов")

    sub.add_parser("engines", help="состояние бесплатного арсенала ИБ (что установлено и чем закрывается)")

    md = sub.add_parser("mode",
                        help="режим работ: показать, проверить готовность, включить "
                             "тихий или боевой")
    md.add_argument("what", nargs="?", default="",
                    help="пусто — показать; check — проверить готовность машины; "
                         "safe — тихий; combat — боевой (боевой)")
    md.add_argument("--force", action="store_true",
                    help="включить боевой режим несмотря на блокеры (пишется в журнал)")
    md.add_argument("--operator", default=os.environ.get("USER", ""))

    ch = sub.add_parser("chat", help="чат с агентом по сессии: разговор, инструменты — её, решения — ваши")
    ch.add_argument("session", nargs="?", default="", help="номер сессии (agent start)")
    ch.add_argument("--ask", default="", help="одна реплика без интерактивного режима")

    at = sub.add_parser("attach", help="приложить файл или фото к объекту (уйдёт в чат)")
    at.add_argument("target", help="номер цели")
    at.add_argument("path", help="файл или изображение")
    at.add_argument("--note", default="", help="пометка")
    at.add_argument("--session", type=int, default=0, help="привязать к сессии")

    dr = sub.add_parser("drafts", help="черновики проверок nuclei по находкам анализа")
    dr.add_argument("scan_id", type=int)
    dr.add_argument("--limit", type=int, default=40)

    se = sub.add_parser("search", help="поиск по находкам по смыслу (локальная модель, без интернета)")
    se.add_argument("scan_id", type=int)
    se.add_argument("query")

    mm = sub.add_parser("memory",
                        help="память между объектами: что похожего уже встречалось и чем кончилось")
    mm.add_argument("query", nargs="?", default="",
                    help="что ищем своими словами")
    mm.add_argument("--finding", type=int, default=0,
                    help="номер находки: чем она похожа на прошлые объекты")
    mm.add_argument("--index", action="store_true",
                    help="пересобрать индекс по всем анализам")
    mm.add_argument("--k", type=int, default=10, help="сколько совпадений показать")
    mm.add_argument("--target", type=int, default=0,
                    help="искать только по этому заказчику")

    mp = sub.add_parser("map", help="карта объекта: что известно о цели (собрано кодом)")
    mp.add_argument("session", nargs="?", default="", help="номер сессии агента")
    mp.add_argument("--target", type=int, default=0,
                    help="собрать по объекту, без сессии (номер цели)")
    mp.add_argument("--mermaid", action="store_true",
                    help="показать схему (mermaid) — её место в отчёте и панели")
    mp.add_argument("--out", default="", help="записать карту в файл")

    mc = sub.add_parser("mcp",
                        help="отдать инструменты чтения наружу по MCP (для OpenCode и подобных)")
    mc.add_argument("--session", type=int, default=0, help="номер сессии агента")
    mc.add_argument("--status", action="store_true",
                    help="показать, что отдаётся наружу, и выйти")

    ho = sub.add_parser("handover", help="пакет передачи доступа заказчику")
    ho.add_argument("action", nargs="?", default="show",
                    choices=["show", "access", "placed", "removed", "write"],
                    help="show — показать и проверить готовность; access — записать, "
                         "какой доступ получен; placed — что перенесено на объект; "
                         "removed — отметить убранным; write — сохранить в файл")
    ho.add_argument("session", nargs="?", type=int, default=0, help="номер сессии агента")
    ho.add_argument("--account", default="", help="учётная запись, к которой получен доступ")
    ho.add_argument("--privilege", default="", help="уровень доступа словами")
    ho.add_argument("--method", default="", help="способ подключения")
    ho.add_argument("--target-host", default="", help="объект, на котором доступ")
    ho.add_argument("--verify", default="", help="команда, которой заказчик проверит доступ")
    ho.add_argument("--note", default="", help="пометка")
    ho.add_argument("--file", default="", help="имя файла, перенесённого на объект")
    ho.add_argument("--where-host", default="", help="на каком объекте он лежит")
    ho.add_argument("--path", default="", help="куда именно положен")
    ho.add_argument("--id", type=int, default=0, help="номер записи о перенесённом файле")
    ho.add_argument("--out", default="", help="куда записать документ (по умолчанию — на экран)")

    sl = sub.add_parser("stealth", help="скрытность: чем выходим наружу и чем выглядим")
    sl.add_argument("action", nargs="?", default="status",
                    choices=["status", "check", "cover", "env"],
                    help="status — состояние и инвентарь (по умолчанию); "
                         "check — проверить выход на самом деле; "
                         "cover — прикрытие вне процесса (VPN): туннель, адрес "
                         "выхода, резолвер DNS; env — готовые строки export")

    sr = sub.add_parser("sources", help="пассивная разведка домена по всем источникам (без сканирования)")

    kb = sub.add_parser("kb", help="база знаний: плейбуки, уточнения CVE, шаблоны доказательств")
    kb.add_argument("action", nargs="?", default="status",
                    choices=["status", "playbooks", "match", "refine", "evidence",
                             "learn", "list", "forget"],
                    help="status — сводка; playbooks — список; match <скан> — что подходит "
                         "к результатам анализа; refine <находка> — запомнить ложное "
                         "срабатывание как уточнение; evidence <класс> — шаблон доказательств; "
                         "learn <скан> — запомнить уточнения по всем ложным "
                         "срабатываниям скана сразу; list — накопленные уточнения с номерами; "
                         "forget <номер> — убрать уточнение")
    kb.add_argument("arg", nargs="?", default="",
                    help="match — номер скана; refine — номер находки; "
                         "evidence — observe/probe/impact/handoff_access; "
                         "forget — номер уточнения из kb list")
    kb.add_argument("--operator", default=os.environ.get("USER", ""))
    kb.add_argument("--note", default="")
    kb.add_argument("--dry-run", action="store_true",
                    help="для learn: только показать, что было бы запомнено")

    ag = sub.add_parser("agent", help="агент: предлагает шаги и ничего не делает без подтверждения")
    ag.add_argument("action", choices=["actions", "start", "plan", "approve", "deny",
                                       "run", "status", "stop", "deadline", "close",
                                       "resume", "extend", "selftest", "inside",
                                       "step", "plans", "gate", "notes", "say",
                                       "autopilot", "check", "facts", "free", "budget"])
    ag.add_argument("arg", nargs="?", default="",
                    help="actions, resume, selftest — без аргумента; start — цель или её ID; "
                         "plan/run/status/stop/close/extend — номер сессии; "
                         "approve/deny — номер шага")
    ag.add_argument("arg2", nargs="?", default="",
                    help="для inside: номер сессии вторым аргументом")
    ag.add_argument("--operator", default=os.environ.get("USER", ""),
                    help="кто принимает решения (пишется в журнал аудита)")
    ag.add_argument("--note", default="", help="пометка к решению")
    ag.add_argument("--limit", type=int, default=4, help="сколько шагов предложить")
    ag.add_argument("--inside-host", default="",
                    help="для inside: хост, на котором выполняется внутренний шаг")
    ag.add_argument("--inside-user", default="",
                    help="для inside: от чьей учётной записи")
    ag.add_argument("--inside-os", default="", help="для inside: windows или linux")
    ag.add_argument("--goal", default="", help="для inside_next_host: что нужно на хосте")
    ag.add_argument("--scan", type=int, default=0,
                    help="для extend: номер скана, по результатам которого "
                         "подбираются плейбуки")
    ag.add_argument("--planner", default="",
                    help="для extend: rules (по умолчанию), model или both; "
                         "model — план строит локальная модель из готового "
                         "каталога, both — модель плюс остаток правилами")
    ag.add_argument("--approve-what", dest="approve_what", default="none",
                    choices=["none", "recon"],
                    help="для autopilot: none — только выполнять одобренное и "
                         "планировать; recon — самому одобрять наблюдение и чтение")
    ag.add_argument("--rounds", type=int, default=3,
                    help="для autopilot: сколько кругов пройти")
    ag.add_argument("--file", default="",
                    help="для check: файл с ответом модели (то, что она выдала текстом)")
    # Внимание: dest не "cmd" — это имя занято подкомандой (agent/scan/…).
    # Первая версия задала --cmd без dest, и argparse затирал имя подкоманды
    # пустой строкой: любая команда «agent …» печатала справку.
    ag.add_argument("--cmd", dest="free_cmd", default="",
                    help="для free: команда, которую предлагает агент")
    ag.add_argument("--intent", default="", help="для free: зачем она нужна, одной строкой")
    ag.add_argument("--tool", default="", help="для free: чем работаем (для отчёта и журнала)")
    ag.add_argument("--target-host", dest="target_host", default="",
                    help="для free: хост, к которому относится шаг (если он к объекту)")
    # По умолчанию None (не «0»): иначе явное «--hosts 0» не отличить от «флаг не
    # назван», и просьба оператора молча пропадала.
    ag.add_argument("--steps", type=int, default=None, help="для budget: шагов в час")
    ag.add_argument("--noise", type=int, default=None, help="для budget: единиц шума в час")
    ag.add_argument("--hosts", type=int, default=None, help="для budget: хостов на сессию")
    ag.add_argument("--files", type=int, default=None,
                    help="для budget: сколько файлов может лежать на объекте одновременно")
    ag.add_argument("--secret-prompt", dest="secret_prompt", action="store_true",
                    help="для run: спросить пароль доступа скрытым вводом (в базу и журнал "
                         "не пишется; иначе берётся из ASM_INWARD_SECRET)")
    ag.add_argument("--net", action="store_true",
                    help="для facts: разово разрешить запрос к источнику сведений "
                         "(NVD) и пополнить кэш; без флага читается только кэш")
    ag.add_argument("--no-facts", dest="no_facts", action="store_true",
                    help="для check: не сверять сведения, только форма ответа")
    ag.add_argument("--kind", default="",
                    choices=["", "goal", "ban", "decision", "question", "event"],
                    help="для say/notes: вид записи (по умолчанию определяется словами)")
    ag.add_argument("--deadline", default="",
                    help="жёсткий срок в ISO-формате, например 2026-12-31T18:00:00+00:00; "
                         "работает и с start (задать сразу), и с deadline (изменить)")
    sr.add_argument("domain")
    sr.add_argument("--ip", action="append", default=[], help="дополнительно: обратный поиск по IP")
    sr.add_argument("--extra", action="store_true", help="включить нестабильные (RapidDNS, Wayback)")

    args = ap.parse_args()
    store.connect()

    if getattr(args, "settings", False):
        _print_settings()
        return 0
    if not args.cmd:
        ap.print_help()
        print("\nвсе настройки:  python3 app.py --settings")
        return 0

    if args.cmd == "serve":
        stale = store.mark_stale_scans()
        if stale:
            print(f"помечено прерванными (процесс скана не пережил перезапуск): {stale}")
        web.serve(host=args.host, port=args.port,
                  explicit_environment=_EXPLICIT_CONFIG_ENVIRONMENT)
        return 0

    if args.cmd == "add":
        tid = store.add_target(args.target, args.client, args.ref, args.date, args.note)
        print(f"цель #{tid} добавлена: {args.target} (заказчик: {args.client}, основание: {args.ref})")
        return 0

    if args.cmd == "scan":
        try:
            # Snapshot before creating a scan or handing work to a child process.
            scan_settings = _scan_settings_snapshot()
        except SettingsError as e:
            print(f"ошибка настроек scan: {e}", file=sys.stderr)
            return 2
        t = None
        if args.target_or_id.isdigit():
            # число — это ID ЦЕЛИ. ID скана здесь не принимаем: путаница между «цель 2»
            # и «скан 2» приводила к запуску не того, что просили
            t = store.target(int(args.target_or_id))
            if t is None:
                row = store.one("SELECT id, target_id FROM scans WHERE id=?", (int(args.target_or_id),))
                if row:
                    print(f"#{args.target_or_id} — это ID скана, а не цели. "
                          f"Анализ запускается по цели: python3 app.py scan {row['target_id']}",
                          file=sys.stderr)
                    return 1
        if t is None:
            t = _find_target(args.target_or_id)
        if t is None:
            print(f"цель «{args.target_or_id}» не найдена. Добавьте: python3 app.py add ...", file=sys.stderr)
            return 1
        # --run-scan-id: служебный ключ фонового процесса — продолжает уже созданную запись,
        # а не заводит вторую (иначе один запуск давал два номера скана)
        sid = int(getattr(args, "run_scan_id", 0) or 0) or store.new_scan(t["id"])
        store.audit("scan_started", {"target": t["value"], "scan_id": sid, "client": t["client"],
                                     "auth_ref": t["auth_ref"], "source": "cli"})
        mats = {}
        if getattr(args, "repo", None):
            mats["repo"] = args.repo
        if getattr(args, "code_path", None):
            mats["code_path"] = args.code_path
        if getattr(args, "image", None):
            mats["image"] = args.image
        if mats:
            cur = store.target_materials(t["id"])
            cur.update(mats)
            store.set_materials(t["id"], cur)
            print("материалы заказчика сохранены у цели:", ", ".join(f"{k}={v}" for k, v in mats.items()))
        limits = {}
        if args.max_subdomains is not None:
            limits["max_subdomains"] = args.max_subdomains
        if args.max_ips is not None:
            limits["max_ips"] = args.max_ips
        print(f"анализ №{sid} по «{t['value']}» запущен (основание: {t['auth_ref']})")
        if args.no_wait:
            # по-настоящему фоновый процесс: прежде здесь оставалась нить внутри этой команды,
            # и скан «висел вечно», едва термин���л закрывался
            import subprocess
            argv = [sys.executable, "-u", os.path.abspath(__file__), "scan", str(t["value"]), "--wait",
                    "--run-scan-id", str(sid)]
            # Per-run CLI limits must survive the detached-process boundary too.
            if args.max_subdomains is not None:
                argv.extend(("--max-subdomains", str(args.max_subdomains)))
            if args.max_ips is not None:
                argv.extend(("--max-ips", str(args.max_ips)))
            log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"scan-{sid}.log")
            fh = open(log_path, "w", encoding="utf-8")
            child_env = os.environ.copy()
            child_env[_INTERNAL_EXPLICIT_CONFIG_ENV] = json.dumps(
                _EXPLICIT_CONFIG_ENVIRONMENT, separators=(",", ":")
            )
            child_env[_INTERNAL_SCAN_SETTINGS_ENV] = json.dumps(
                {"scan": scan_settings.scan.to_legacy_dict(),
                 "config": scan_settings.to_legacy_config()}, separators=(",", ":")
            )
            # Legacy import-time readers in the child see the exact operation
            # snapshot too; secrets and DB bootstrap variables are not projected.
            child_env.update(scan_settings.to_legacy_environment())
            subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                             start_new_session=True, cwd=os.path.dirname(os.path.abspath(__file__)),
                             env=child_env)
            print(f"скан идёт в фоне (процесс отделён от команды). Журнал: {log_path}")
            print("следите за прогрессом в дашборде: python3 app.py serve")
        else:
            scanmod.run(sid, limits, settings=scan_settings)
            sc = store.scan(sid)
            print(sc["log"])
            print("статус:", sc["status"])
            print(report.markdown(sid))
        return 0

    if args.cmd == "attach":
        from asm import chat as chatmod
        tid = int(args.target) if str(args.target).isdigit() else 0
        if tid and not store.target(tid):
            tid = 0
        if not tid:
            t = _find_target(args.target)
            tid = t["id"] if t else 0
        if not tid:
            print(f"цель «{args.target}» не найдена", file=sys.stderr)
            return 1
        r = chatmod.save_attachment(tid, args.path, session_id=int(args.session or 0),
                                    note=args.note)
        if not r["ok"]:
            print("не вышло: " + r["error"], file=sys.stderr)
            return 1
        print(f"вложение #{r['id']} «{r['name']}» ({r['kind']}, {r['size']} б) — "
              f"лежит у объекта #{tid}")
        return 0

    if args.cmd == "chat":
        from asm import chat as chatmod
        sid = int(args.session) if str(args.session).isdigit() else 0
        if not sid:
            print("нужен номер сессии: python3 app.py chat <сессия>\n"
                  "сессии: python3 app.py agent status <номер>  или agent start <цель>",
                  file=sys.stderr)
            return 1
        if args.ask:
            # Одна реплика без интерактивного режима: удобно для скриптов и проверок.
            def _show(ev: dict) -> None:
                t = ev.get("type")
                if t == "tool":
                    print(f"  · инструмент: {ev.get('name')}"
                          + (f" — {ev['why']}" if ev.get("why") else ""))
                elif t == "step":
                    print(f"  ● шаг #{ev.get('id')} [{ev.get('cls')}] {ev.get('title')} — "
                          f"{ev.get('status')}")
                elif t == "warning":
                    print(f"  ! {ev.get('text')}")
            r = chatmod.ask(sid, args.ask, emit=_show)
            print(r.get("answer") or "")
            return 0 if r.get("ok") else 1
        return chatmod.repl(sid)

    if args.cmd == "mode":
        from asm import mode as md
        what = (args.what or "").strip().lower()
        if not what:
            cur = md.current()
            print(f"режим работ: {cur['mode'] or '(не задан)'}")
            print(f"  {cur['title']}")
            print("  ключи режима:")
            for k in cur["keys"]:
                print(f"    {k:20} {cur['env'][k] or '(пусто)'}")
            print("\nвключить: python3 app.py mode combat | safe")
            print("проверить: python3 app.py mode check")
            return 0
        if what == "check":
            ch = md.check()
            print("Проверка готовности машины к боевому режиму")
            for it in ch["items"]:
                mark = {"ok": "V", "warn": "!", "blocker": "X"}[it["state"]]
                print(f"  {mark} {it['item']:18} {it['text']}")
            if ch["blockers"]:
                print("\nБЛОКЕРЫ (без их снятия боевой режим не включится):")
                for b in ch["blockers"]:
                    print("  X " + b)
            if ch["warnings"]:
                print("\nПринято осознанно, если вы согласны:")
                for w in ch["warnings"]:
                    print("  ! " + w)
            if not ch["blockers"]:
                print("\nблокеров нет — можно включать: python3 app.py mode combat")
            return 0
        res = md.apply(what, force=args.force, operator=args.operator)
        if not res.get("ok"):
            print(f"режим не включён: {res.get('error') or ''}", file=sys.stderr)
            for b in res.get("blockers") or []:
                print("  X " + b, file=sys.stderr)
            for w in res.get("warnings") or []:
                print("  ! " + w, file=sys.stderr)
            print(f"\nосознанно, поверх блокеров: python3 app.py mode {what} --force",
                  file=sys.stderr)
            return 2
        print(f"режим включён: {res['mode']} — {res['title']}")
        if res.get("forced"):
            print("  ВНИМАНИЕ: включено поверх блокеров, это записано в журнал аудита:")
            for b in res.get("blockers") or []:
                print("    X " + b)
        for w in res.get("warnings") or []:
            print("  ! " + w)
        print("  действует на каждую следующую команду; посмотреть — python3 app.py mode")
        print("  разово перекрыть: python3 app.py --set ASM_PROFILE=full <команда>")
        return 0
    if args.cmd == "engines":
        if engines is None:
            print("модуль арсенала недоступен")
            return 1
        st = engines.available()
        rows = [v for v in st.values() if isinstance(v, dict) and v.get("id")]
        print("Бесплатный арсенал ИБ (всё без ключей и без прав root):")
        for e in rows:
            mark = "✓" if e["installed"] else "·"
            ver = ("  " + str(e["version"])) if e["installed"] and e.get("version") else ""
            name = f"{e['name']} ({e['bin']})"
            print(f"  {mark} {name:24} {str(e.get('role'))[:20]:20} {str(e.get('what',''))[:44]}{ver}")
        inst = sum(1 for e in rows if e["installed"])
        print(f"  установлено: {inst} из {len(rows)}")
        if isinstance(st.get("nuclei"), dict) and st["nuclei"].get("templates"):
            print(f"  шаблонов проверок nuclei: {st['nuclei']['templates']}")
        prof = st.get("profile") or {}
        pname = prof.get("name", "safe")
        hint = {"safe": "аудит периметра", "pentest": "тестирование на проникновение",
                "full": "полный режим, включая DoS"}.get(pname, "")
        print(f"  профиль: {pname}" + (f" ({hint})" if hint else ""))
        banned = prof.get("banned_tags")
        if banned is None:
            banned = sorted(engines.BANNED_TAGS)
        print("  отключено (категории nuclei): " + (", ".join(banned) if banned else "ничего"))
        if prof:
            print(f"  nuclei: теги {prof.get('nuclei_tags')}, критичность {prof.get('nuclei_severity')}, "
                  f"interactsh {'вкл' if prof.get('interactsh') else 'выкл'}")
            print(f"  nikto tuning {prof.get('nikto_tuning')}  ·  wapiti: {prof.get('wapiti_modules')}"
                  f"  ·  trufflehog: проверка ключей {'вкл' if prof.get('trufflehog_verify') else 'выкл'}")
        wl = (st.get("wordlists") or {}).get("files") or []
        if wl:
            print("  словари:", ", ".join(f"{w['file']} ({w['lines']})" for w in wl))
        return 0

    if args.cmd == "drafts":
        from asm import drafts as dmod
        fs = store.scan_findings(args.scan_id)
        made = dmod.drafts_for_scan(fs, limit=args.limit)
        if not made:
            print("По этому анализу нет находок с адресом — черновиков не будет.")
            return 0
        folder = dmod.write_drafts(args.scan_id, made)
        tpl = len([d for d in made if d["kind"] == "template"])
        print(f"Черновики: {len(made)} (шаблонов {tpl}, команд повторной проверки {len(made) - tpl})")
        for d in made[:20]:
            print("  ", d["filename"], "—", str(d.get("title"))[:60])
        print("каталог:", folder)
        print("проверить: nuclei -validate -t " + folder + "/*.yaml")
        return 0

    if args.cmd == "map":
        from asm import objmap
        sess_id = int(args.session) if str(args.session).isdigit() else 0
        if not sess_id and not args.target:
            print("нужно: python3 app.py map <сессия>  или  map --target <номер цели>",
                  file=sys.stderr)
            return 2
        if sess_id and store.agent_session(sess_id) is None:
            print(f"сессии {sess_id} нет", file=sys.stderr)
            return 2
        m = objmap.build(session_id=sess_id, target_id=args.target)
        body = objmap.mermaid(m) if args.mermaid else objmap.text(m)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(body + "\n")
            print(f"записано: {args.out}")
        else:
            print(body)
        return 0

    if args.cmd == "mcp":
        from asm import mcp as mmod
        if args.status:
            st = mmod.status()
            print("MCP: наши инструменты для внешнего редактора")
            print("  отдаём (только чтение, ничего не запускают):")
            for name in st["exposed"]:
                print("   -", name)
            print("  не отдаём:")
            for name, why in st["closed"].items():
                print(f"   - {name}: {why}")
            print("  запуск: python3 app.py mcp --session <номер сессии>")
            return 0
        if not args.session:
            print("нужен номер сессии: python3 app.py mcp --session 3\n"
                  "  список сессий: python3 app.py agent sessions", file=sys.stderr)
            return 2
        return mmod.serve(args.session)

    if args.cmd == "handover":
        from asm import handover as hmod
        if not args.session:
            print("нужен номер сессии агента: python3 app.py handover show <сессия>",
                  file=sys.stderr)
            return 2
        sid = args.session
        sess = store.agent_session(sid)
        if sess is None:
            print(f"сессии {sid} нет", file=sys.stderr)
            return 2

        if args.action == "access":
            try:
                hmod.set_access(sid, account=args.account, privilege=args.privilege,
                                host=args.target_host, method=args.method,
                                verify=args.verify, note=args.note)
            except ValueError as e:
                # Отказ, а не предупреждение: документ остаётся у заказчика.
                print("НЕ ЗАПИСАНО.", file=sys.stderr)
                print(f"  {e}", file=sys.stderr)
                return 2
            print(f"сессия {sid}: данные о доступе записаны")
            for label, val in (("учётная запись", args.account),
                               ("уровень доступа", args.privilege),
                               ("объект", args.target_host),
                               ("способ", args.method)):
                if val:
                    print(f"  {label}: {val}")
            print("  секрет не спрашивался и не сохранён — это устройство схемы,")
            print("  а не обещание: колонки под него в базе нет")
            return 0

        if args.action == "placed":
            if not args.file:
                print("нужно --file <имя>: что перенесено на объект", file=sys.stderr)
                return 2
            try:
                pid = hmod.add_placed(sid, file=args.file, host=args.where_host,
                                      path=args.path, note=args.note)
            except ValueError as e:
                print("НЕ ЗАПИСАНО.", file=sys.stderr)
                print(f"  {e}", file=sys.stderr)
                return 2
            print(f"запись {pid}: {args.file} → "
                  f"{args.where_host or 'объект не указан'}:{args.path or '?'}")
            print("  попадает в раздел уборки пакета передачи")
            print(f"  отметить убранным: python3 app.py handover removed {sid} --id {pid}")
            return 0

        if args.action == "removed":
            if not args.id:
                print("нужен --id <номер записи>", file=sys.stderr)
                return 2
            if not hmod.mark_removed(args.id, args.note):
                print(f"записи {args.id} нет", file=sys.stderr)
                return 2
            left = hmod.outstanding(sid)
            print(f"запись {args.id}: отмечена убранной")
            print(f"  осталось на объекте: {len(left)}")
            return 0

        doc = hmod.build(sid)
        if args.action == "write":
            out = args.out or f"передача-{sid}.md"
            with open(out, "w", encoding="utf-8") as f:
                f.write(doc)
            print(f"документ записан: {out}")
        else:
            print(doc)

        st = hmod.status(sid)
        print()
        if st["ready"]:
            print("ПАКЕТ ГОТОВ: доступ описан, уборка закрыта.")
            if not dict(sess).get("closed_at"):
                print("  ОДНАКО сессия ещё не закрыта — работы по ней считаются идущими.")
                print(f"  python3 app.py agent close {sid}")
                return 1
            return 0
        print("ПАКЕТ НЕ ГОТОВ:")
        if st["missing"]:
            ru = {"account": "учётная запись", "privilege": "уровень доступа",
                  "host": "объект", "method": "способ подключения"}
            print("  не заполнено: " + ", ".join(ru.get(m, m) for m in st["missing"]))
            print(f"  python3 app.py handover access {sid} --account … --privilege … "
                  f"--target-host … --method …")
        if st["outstanding"]:
            print(f"  на объекте осталось файлов: {st['outstanding']}")
            print(f"  python3 app.py handover show {sid}   — покажет, какие именно")
        return 1

    if args.cmd == "stealth":
        from asm import stealth as smod
        if args.action == "env":
            st = smod.status()
            print("# Строки для Git Bash. Можно и одной командой с --set:")
            print("#   python3 app.py --set ASM_STEALTH=require "
                  "--set ASM_PROXY_OUTWARD=http://адрес:порт scan 19")
            print()
            print(f"export ASM_STEALTH={smod.MODE}")
            if st["proxy_inward"]:
                print(f"export ASM_PROXY_INWARD={st['proxy_inward']}")
            if st["proxy_outward"]:
                print(f"export ASM_PROXY_OUTWARD={st['proxy_outward']}")
            if smod.SOCKS:
                print(f"export ASM_SOCKS={smod.SOCKS}")
            print("# ASM_SOCKS — SOCKS5 для перебора портов: HTTP-прокси их не берёт.")
            print("# Чаще всего это туннель на своём VPS:  ssh -N -D 1080 user@vps")
            fp = smod.impersonate_state()
            if fp["on"]:
                print(f"export ASM_TLS_FINGERPRINT={fp['target']}")
                print("# Отпечаток TLS под браузером: UA мало, JA3 обычного Python "
                      "узнаётся сразу.")
            else:
                print("# ASM_TLS_FINGERPRINT: " + fp["why"])
            return 0

        if args.action == "check":
            print("Проверка выхода — запросом, а не чтением настройки.")
            print("«Прокси прописан» и «прокси скрывает адрес» — разные утверждения.")
            print()
            fp = smod.impersonate_state()
            print("  отпечаток TLS:       " + (
                f"браузерный ({fp['target']}) — JA3 как у Chrome"
                if fp["on"] else fp["why"]))
            print()
            res = smod.compare_exits()
            print(f"  напрямую:            {res['direct'] or 'не удалось'}"
                  + (f"  ({res['direct_err'][:50]})" if res["direct_err"] else ""))
            print(f"  на объект:           {res['via_inward'] or 'прямой выход'}")
            print(f"  к внешним сервисам:  {res['via_outward'] or 'прямой выход'}")
            print()
            printed = False
            for key, label in (("via_inward", "для объекта"), ("via_outward", "для внешних")):
                if not res[key]:
                    continue
                printed = True
                if res["direct"] and res[key] != res["direct"]:
                    print(f"  ВЫХОД {label}: подменён — адрес отличается от домашнего")
                else:
                    print(f"  ВЫХОД {label}: НЕ ПОДМЕНЁН — виден домашний адрес")
            if not printed:
                print("  ВЫХОД: прокси не задан, весь трафик идёт с домашнего адреса")
            print()
            print("  " + res["note"])
            bad = (not smod.has_proxy("outward")) or (
                res["direct"] and res["via_outward"] == res["direct"])
            if bad:
                print()
                print("  ИТОГ: работа в таком виде оставляет домашний адрес")
                print("        в журналах сервисов, через которые идёт разведка.")
                return 1
            print()
            print("  ИТОГ: внешний выход подменён. Сырые соединения (перебор портов)")
            print("        прикрыты отдельно — проверьте строку target_raw ниже.")
            return 0

        if args.action == "cover":
            # Покров вне процесса: VPN. Инструмент не может проверить чужой
            # туннель работой, поэтому показывает то, что видно: адаптер,
            # фактический адрес выхода и резолвер DNS (утечка DNS — самая
            # частая беда VPN: домены объекта уходят провайдеру).
            cover = smod.cover_state()
            print("Прикрытие вне процесса (VPN)")
            print(f"  настройка ASM_COVER: {cover['mode']}")
            if cover["tunnels"]:
                print("  туннели в системе:")
                for t in cover["tunnels"][:5]:
                    print(f"    - {t}")
            else:
                print("  туннелей в системе не видно")
            print()
            ip, where = smod.my_ip(purpose="inward")
            print(f"  адрес выхода:        {ip or 'не удалось узнать'}"
                  + (f"  (источник: {where})" if ip else ""))
            try:
                import json as _json
                req = urllib.request.Request("https://edns.ip-api.com/json",
                                             headers={"User-Agent": smod.ua("outward")})
                with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
                    dns = (_json.loads(r.read(400).decode("utf-8", "replace")) or {}).get("dns") or {}
                if dns.get("ip"):
                    print(f"  резолвер DNS:        {dns['ip']}"
                          + (f"  ({dns.get('geo')})" if dns.get("geo") else ""))
            except Exception:  # noqa: BLE001 — проверка DNS не обязательна
                print("  резолвер DNS:        узнать не удалось (проверьте утечку "
                      "вручную: dnsleaktest.com)")
            print()
            if cover["mode"] == "vpn" and cover["tunnels"]:
                print("  ИТОГ: прикрытие подтверждено настройкой и видимым туннелем.")
                print("        Убедитесь глазами: адрес выхода и резолвер — не домашние.")
                return 0
            if cover["mode"] == "vpn":
                print("  ИТОГ: ASM_COVER=vpn задан, но туннеля не видно — "
                      "включите VPN или уберите настройку.")
                return 1
            print("  ИТОГ: прикрытие вне процесса не настроено. Для VPN: "
                  "ASM_COVER=vpn;")
            print("        для прокси: ASM_PROXY_OUTWARD=http://адрес:порт")
            return 1

        st = smod.status()
        print("Скрытность")
        if st.get("cover", {}).get("mode") not in ("", "off"):
            cov = st["cover"]
            print(f"  прикрытие вне процесса: ASM_COVER={cov['mode']}"
                  + (f" — туннель виден: {cov['tunnels'][0]}" if cov["tunnels"]
                     else " — туннель НЕ виден"))
        print(f"  режим:  {st['mode']}", end="")
        if st["mode"] == "off":
            print("  — ничего не проверяется, трафик идёт как есть")
        elif st["mode"] == "warn":
            print("  — выход наружу разрешён, но о каждом сообщается")
        else:
            print("  — прямой выход наружу запрещён")
        print(f"  выход на объект:        {st['proxy_inward'] or 'не задан (идём напрямую)'}")
        print(f"  выход к внешним:        {st['proxy_outward'] or 'не задан (идём напрямую)'}")
        print(f"  SOCKS5 для сырых:       {st['socks'] or 'не задан'}")
        if st["proxy_inward"] or st["proxy_outward"]:
            print(f"  выходы раздельные:      "
                  f"{'да' if st['separate_exits'] else 'НЕТ — оба через один узел'}")
        print(f"  UA на объект:           {st['ua_inward']}")
        print(f"  UA к внешним:           {st['ua_outward']}")
        if st["ua_override"]:
            print("  UA задан вручную настройкой ASM_UA")
        print(f"  подмена UA движкам:     {'включена' if st['engine_ua_patched'] else 'выключена'}")
        fp = st.get("fingerprint") or {}
        if fp.get("on"):
            print(f"  отпечаток TLS:          браузерный ({fp['target']}) — "
                  "отпечаток клиента как у Chrome, а не как у скрипта")
        else:
            print(f"  отпечаток TLS:          обычный Python — {fp.get('why') or 'не задан'}")
        print()
        print("Куда инструмент ходит наружу")
        for r in st["inventory"]:
            mark = "✓" if r["proxied"] else "·"
            note = ""
            if not r["proxied"]:
                note = ("  ← сырое соединение, нужен SOCKS5" if r.get("socks")
                        else "  ← идёт с домашнего адреса")
            print(f"  {mark} {r['id']:14} {r['what']}{note}")
        print()
        print("  ✓ — через подменённый выход, · — напрямую")
        hid = st["uncovered"]
        if hid:
            print()
            print(f"  НЕ ПРИКРЫТО ({len(hid)}): {', '.join(hid)}")
            print("  В режиме off это ожидаемо. Для работы по договору поднимите")
            print("  режим и выходы:  python3 app.py stealth env")
        return 0

    if args.cmd == "memory":
        from asm import vector as vmod
        if args.index:
            res = vmod.index_all(force=True)
            print(f"переиндексировано сканов: {res['scans']} из {res['scans_total']}, "
                  f"находок: {res['indexed']}")
            print("способ:", res["backend"])
            return 0
        if args.finding:
            res = vmod.similar(args.finding, k=args.k)
            f = res.get("finding") or {}
            if not f:
                print(f"находки {args.finding} нет")
                return 2
            print(f"находка {args.finding}: {f.get('title') or ''}")
            print(f"  {f.get('asset') or ''} · {f.get('cve_id') or 'без CVE'}")
            print()
            items = res.get("results") or []
            if not items:
                print("похожего на других объектах не найдено")
                print("режим:", res.get("mode") or "—")
                return 0
            print(f"что похожего было раньше · {res.get('mode', '')}")
            for it in items:
                print(f"  {it['score']:>6} | скан {it['scan_id']:>3} | "
                      f"{(it['client'] or '?'):<14} | {it['status_ru']:<22} | "
                      f"{str(it['title'])[:46]}")
                print(f"         {it['target']} · вывод: {it['note'] or 'решения не было'}")
            print()
            print("это подсказка, а не вердикт: на другом объекте контекст другой")
            return 0
        if not args.query.strip():
            print("нужен запрос:  python3 app.py memory «открытый каталог»")
            print("или:          python3 app.py memory --finding 42")
            print("или:          python3 app.py memory --index")
            return 2
        res = vmod.search_all(args.query, k=args.k, target_id=args.target)
        items = res.get("results") or []
        print(f"Поиск по всем объектам: «{args.query}» · {res.get('mode', '')}")
        if not items:
            print("ничего не найдено")
            return 0
        for it in items:
            print(f"  {it['score']:>6} | скан {it['scan_id']:>3} | "
                  f"{(it['client'] or '?'):<14} | {it['status_ru']:<22} | "
                  f"{str(it['title'])[:46]}")
            print(f"         {it['why']} · {it['target']}")
        return 0

    if args.cmd == "search":
        from asm import vector as vmod
        res = vmod.search(args.scan_id, args.query, k=10)
        print(f"Поиск: «{args.query}» · {res.get('mode', '')} · {res.get('backend', '')}")
        for it in res["results"]:
            print(f"  {it['score']:>6} | {it['priority'] or '—':>3} | {str(it['title'])[:78]}")
            print(f"         {it['why']} · {it['finding'].get('asset') or ''}")
        return 0

    if args.cmd == "report":
        out = {"md": report.markdown, "json": report.json_report, "csv": report.csv_report}[args.fmt](args.scan_id)
        if args.out:
            open(args.out, "w", encoding="utf-8").write("\ufeff" + out if args.fmt == "csv" else out)
            print("сохранено:", args.out)
        else:
            print(out)
        return 0

    if args.cmd == "findings":
        for fi in store.scan_findings(args.scan_id):
            if not args.all and fi.get("priority") in ("P2", "P3"):
                continue
            print(f"{fi.get('priority')} {fi.get('score'):>5} {fi.get('cve_id') or '':<16} "
                  f"{(fi.get('asset') or fi.get('ip') or '')[:34]:<34} порт {fi.get('port') or '-':<6} "
                  f"{(fi.get('title') or '')[:70]}")
        return 0

    if args.cmd == "verify":
        from asm import collect
        findings = store.scan_findings(args.scan_id)
        if not findings:
            print(f"в скане {args.scan_id} нет находок")
            return 0
        # проверяем по уникальным парам адрес:порт, а не по каждой находке —
        # на одном порту может висеть несколько CVE, и долбить его лишний раз
        # незачем
        pairs: dict[tuple, list[dict]] = {}
        no_addr: list[dict] = []
        for f in findings:
            ip, port = f.get("ip"), f.get("port")
            if not ip or not port:
                no_addr.append(f)
                continue
            try:
                pairs.setdefault((str(ip), int(port)), []).append(f)
            except (TypeError, ValueError):
                no_addr.append(f)
        print(f"скан {args.scan_id}: находок {len(findings)}, "
              f"уникальных адрес:порт {len(pairs)}, без адреса {len(no_addr)}")
        open_now, closed = [], []
        for (ip, port), fs in sorted(pairs.items()):
            alive = collect.tcp_open(ip, port, timeout=args.timeout)
            (open_now if alive else closed).append((ip, port, fs))
            mark = "открыт" if alive else "ЗАКРЫТ"
            print(f"  {ip}:{port:<6} {mark:8} находок: {len(fs)}")
        print(f"\nоткрыто: {len(open_now)}, закрылось: {len(closed)}")
        if no_addr:
            print(f"без адреса (проверить нельзя): {len(no_addr)} — это находки "
                  f"по коду, образам и публичным индексам")
        if not closed:
            print("всё воспроизводится")
            return 0
        if not args.mark_fixed:
            n = sum(len(fs) for _, _, fs in closed)
            print(f"\n{n} находок на закрывшихся портах. Пометить закрытыми: "
                  f"python3 app.py verify {args.scan_id} --mark-fixed")
            return 0
        n = 0
        for ip, port, fs in closed:
            for f in fs:
                if f.get("status") in ("fixed", "false"):
                    continue
                store.set_finding_status(f["id"], "fixed",
                                         f"порт {ip}:{port} закрыт при перепроверке",
                                         args.operator)
                store.audit("finding_verified_closed",
                            {"finding": f["id"], "ip": ip, "port": port,
                             "operator": args.operator})
                n += 1
        print(f"помечено закрытыми: {n}")
        return 0

    if args.cmd == "log":
        row = store.one("""SELECT s.*, t.value AS host, t.client AS client
                           FROM scans s LEFT JOIN targets t ON t.id = s.target_id
                           WHERE s.id=?""", (args.scan_id,))
        if row is None:
            print(f"скана {args.scan_id} нет; список: python3 app.py list", file=sys.stderr)
            return 1
        lines = [ln for ln in (row["log"] or "").splitlines() if ln.strip()]
        total = len(lines)
        shown = lines
        if args.only:
            shown = [ln for ln in shown if args.only in ln]
        if args.tail > 0:
            shown = shown[-args.tail:]
        print(f"скан {args.scan_id}  цель: {row['host'] or '?'}  "
              f"заказчик: {row['client'] or '-'}  статус: {row['status']}")
        print(f"начат: {row['started_at'] or '-'}   закончен: {row['finished_at'] or '-'}")
        note = f", показано {len(shown)}" if (args.only or args.tail) else ""
        print(f"строк в журнале: {total}{note}")
        print("-" * 68)
        for ln in shown:
            print(ln)
        if not shown:
            print("(в журнале пусто — скан, вероятно, не запускался)")
        if row["error"]:
            print("-" * 68)
            print("ОШИБКА СКАНА:")
            print(row["error"])
        return 0

    if args.cmd == "sources":
        import os as _os
        from asm import sources as src
        if args.extra:
            _os.environ["ASM_SOURCES_EXTRA"] = "1"
        catalog = src.sources_catalog()
        print(f"Включённых источников: {catalog['enabled_count']} "
              f"(без ключей — {sum(1 for x in catalog['sources'] if x['enabled'])})\n")
        res = src.collect_domain(args.domain, log=lambda m: print("  " + m))
        print("\nИМЕНА ({}):".format(len(res["names"])))
        for n in sorted(res["names"]):
            print(f"  {n:<48} {', '.join(src.label(s) for s in res['names'][n])}")
        if res["errors"]:
            print("\nИсточники без данных: " + ", ".join(f"{src.label(k)} ({v})" for k, v in res["errors"].items()))
        for ip in args.ip:
            print(f"\nОбратный поиск по IP {ip}:")
            for d in src.domains_on_ip(ip):
                print("  " + d)
        return 0

    if args.cmd == "kb":
        from asm import knowledge
        if args.action == "status":
            st = knowledge.status()
            print(f"каталог: {st['каталог']}")
            print(f"  плейбуков загружено : {st['плейбуков загружено']}")
            print(f"  PyYAML доступен     : {'да' if st['yaml доступен'] else 'нет (нужны .json)'}")
            print(f"  уточнений в базе    : {st['уточнений в базе']}")
            print(f"  уточнений всего     : {st['уточнений всего (с встроенными)']}")
            print(f"  шаблонов доказательств: {st['классов доказательств']}")
            if st["предупреждений"]:
                print("\n  ПРЕДУПРЕЖДЕНИЯ:")
                for w in st["предупреждений"]:
                    print("   -", w)
            else:
                print("\n  предупреждений нет")
            return 0
        try:
            from asm import agent as _ag
            actions = [a["id"] for a in _ag.catalog()]
        except Exception:
            actions = []
        if args.action == "playbooks":
            pbs, warns = knowledge.load_playbooks(known_actions=actions)
            for w in warns:
                print("ПРЕДУПРЕЖДЕНИЕ:", w, file=sys.stderr)
            if not pbs:
                print("плейбуков нет")
                return 1
            for pb in pbs:
                m = pb.get("match") or {}
                cond = ", ".join(f"{k}={v}" for k, v in m.items())
                print(f"\n{pb['id']}  —  {pb['title']}")
                print(f"  когда срабатывает: {cond}")
                if pb.get("note"):
                    print(f"  примечание: {pb['note']}")
                for i, st in enumerate(pb.get("steps") or [], 1):
                    print(f"  {i}. {st.get('action')}"
                          + (f"  — {st['why']}" if st.get("why") else ""))
            return 0
        if args.action == "match":
            if not args.arg.isdigit():
                print("нужен номер скана", file=sys.stderr)
                return 2
            sid = int(args.arg)
            ports, services, products, banners = set(), set(), set(), []
            for a in store.scan_assets(sid):
                v = str(a.get("value") or "")
                if ":" in v:
                    try:
                        ports.add(int(v.rsplit(":", 1)[1]))
                    except ValueError:
                        pass
                svc = (a.get("meta") or {}).get("service")
                if svc:
                    services.add(svc)
                    # строка сервиса берётся из баннера, поэтому в поиске по
                    # banner она участвует наравне с product
                    banners.append(str(svc))
                prod = (a.get("meta") or {}).get("product")
                if prod:
                    products.add(prod)
                    banners.append(str(prod))
            for f in store.scan_findings(sid):
                if f.get("port"):
                    ports.add(int(f["port"]))
                if f.get("service"):
                    services.add(f["service"])
                    banners.append(str(f["service"]))
                if f.get("product"):
                    products.add(f["product"])
                    banners.append(str(f["product"]))
            pbs, warns = knowledge.match_playbooks(
                ports=ports, services=services, products=products,
                banners=banners, known_actions=actions)
            for w in warns:
                print("ПРЕДУПРЕЖДЕНИЕ:", w, file=sys.stderr)
            print(f"скан {sid}: портов {len(ports)}, сервисов {len(services)}, "
                  f"продуктов {len(products)}")
            if not pbs:
                print("подходящих плейбуков нет")
                return 0
            print(f"подходит плейбуков: {len(pbs)}\n")
            for pb in pbs:
                print(f"  {pb['id']}  —  {pb['title']}")
                print(f"    цепочка: " + " -> ".join(
                    str(st.get("action")) for st in pb.get("steps") or []))
            print("\nПлейбук предлагает последовательность; выполняет оператор "
                  "по одному шагу с подтверждением.")
            return 0
        if args.action == "refine":
            if not args.arg.isdigit():
                print("нужен номер находки", file=sys.stderr)
                return 2
            fid = int(args.arg)
            f = store.finding(fid)
            if not f:
                print(f"находки {fid} нет", file=sys.stderr)
                return 1
            if f.get("status") != "false":
                print("сначала пометьте находку как ложное срабатывание "
                      "(статус «false») — иначе уточнение запоминать не с чего")
                return 2
            ok = knowledge.refinement_from_finding(fid, note=args.note,
                                                   operator=args.operator)
            if not ok:
                # говорим конкретно, чего не хватает: «не хватило данных»
                # заставляет перебирать вслепую
                ev = f.get("evidence") or {}
                if isinstance(ev, str):
                    try:
                        ev = json.loads(ev)
                    except Exception:
                        ev = {}
                missing = []
                if not f.get("cve_id"):
                    missing.append("CVE-идентификатор")
                if not (f.get("product") or ev.get("пакет") or ev.get("cpe_product")):
                    missing.append("продукт")
                if not (f.get("version") or ev.get("установлено")):
                    missing.append("версия")
                print("уточнение не создано: не хватает "
                      + ", ".join(missing or ["данных"])
                      + ". Без версии диапазон уточнить нечем.")
                return 1
            print(f"уточнение запомнено для {f.get('cve_id')} "
                  f"({f.get('product')} {f.get('version')})")
            print("  в следующих аудитах эта связка CVE+продукт+версия "
                  "не будет всплывать")
            return 0
        if args.action == "learn":
            if not args.arg.isdigit():
                print("нужен номер скана", file=sys.stderr)
                return 2
            res = knowledge.learn_from_scan(int(args.arg), operator=args.operator,
                                            dry_run=args.dry_run)
            made, skipped = res["запомнено"], res["пропущено"]
            verb = "было бы запомнено" if args.dry_run else "запомнено"
            print(f"скан {args.arg}: {verb} уточнений {len(made)}, "
                  f"пропущено {len(skipped)}")
            for m in made:
                print(f"  + {m.get('cve_id'):18} {m.get('product')} {m.get('version')}")
            for sk in skipped:
                print(f"  - находка {sk.get('находка')}: {sk.get('причина')}")
            if args.dry_run and made:
                print("\nэто был предварительный просмотр; чтобы записать: "
                      f"python3 app.py kb learn {args.arg} --operator <кто>")
            if not made and not skipped:
                print("в скане нет находок, помеченных как ложное срабатывание")
            return 0
        if args.action == "list":
            rows = knowledge.refinement_rows()
            if not rows:
                print("уточнений нет — память пуста")
                print("они появляются сами, когда находка помечается как ложное "
                      "срабатывание,")
                print("или через  python3 app.py kb learn <скан>")
                return 0
            print(f"уточнений: {len(rows)}")
            print()
            print(f"{'№':>4}  {'CVE':<18} {'продукт':<20} {'диапазон':<22} "
                  f"{'автор':<12} когда")
            for r in rows:
                rng = f"{r.get('v_start') or '…'} .. {r.get('v_end') or '…'}"
                print(f"{r['id']:>4}  {(r.get('cve_id') or ''):<18} "
                      f"{(r.get('product') or ''):<20} {rng:<22} "
                      f"{(r.get('operator') or ''):<12} "
                      f"{(r.get('created_at') or '')[:16]}")
                note = (r.get("note") or "").strip()
                if note:
                    print(f"      примечание: {note}")
            print()
            print("убрать:  python3 app.py kb forget <номер>")
            print("уточнение прячет находку во всех следующих аудитах — "
                  "убирайте ошибочные")
            return 0

        if args.action == "forget":
            try:
                rid = int(args.arg)
            except (TypeError, ValueError):
                print("нужен номер уточнения из  python3 app.py kb list")
                return 2
            if not knowledge.forget_refinement(rid, operator=args.operator):
                print(f"уточнения {rid} нет — смотрите  python3 app.py kb list")
                return 2
            print(f"уточнение {rid} убрано")
            print("находки, которые оно прятало, снова попадут в следующие аудиты")
            return 0

        if args.action == "evidence":
            cls = args.arg.strip() or "probe"
            t = knowledge.evidence_template(cls)
            print(f"{cls}: {t['название']}")
            if t.get("предупреждение"):
                print("  ВНИМАНИЕ:", t["предупреждение"])
            print(f"  объект затронут: {'нет' if t.get('объект не затронут') else 'ДА'}")
            print("\n  что приложить:")
            for it in t.get("что приложить") or []:
                print("   -", it)
            if t.get("что НЕ делать"):
                print("\n  чего не делать:")
                for it in t["что НЕ делать"]:
                    print("   -", it)
            return 0

    if args.cmd == "agent":
        from asm import agent
        if args.action == "actions":
            print("Что агент умеет предлагать  ·  " + agent.profile_note())
            print()
            print("Снаружи — то, что делается до входа:")
            for a in agent.catalog():
                if a.get("internal"):
                    continue
                mark = {"observe": "·", "probe": "△", "impact": "⚠"}[a["cls"]]
                got = "" if a.get("installed") else "  [движок не установлен]"
                print(f"  {mark} {a['id']:16} {a['cls_title']:34} {a['title']}{got}")
            print()
            print("Внутри — то, что делается после входа (готовятся, не выполняются):")
            for a in agent.catalog():
                if not a.get("internal"):
                    continue
                mark = {"observe": "·", "probe": "△", "impact": "⚠"}[a["cls"]]
                stay = "  [оставляет файл на хосте]" if a.get("places") else ""
                print(f"  {mark} {a['id']:18} {a['title']}{stay}")
            print()
            print("  ⚠ — воздействие: необратимо, всегда требует подтверждения")
            print("  Внутренние шаги агент не выполняет: у него нет канала внутрь,")
            print("  и строить его он не должен. Шаг выдаёт команды и уборку.")
            return 0

        if args.action == "inside":
            if not args.arg:
                print("Внутренняя работа: что делать ПОСЛЕ входа.")
                print("Агент внутрь не ходит — он готовит точные команды и уборку.")
                print()
                for a in agent.INTERNAL:
                    stay = ("оставляет файл на хосте" if a.get("places")
                            else "ничего не оставляет")
                    print(f"  {a['id']:18} {a['title']}")
                    print(f"  {'':18} зачем: {a['why']}")
                    print(f"  {'':18} след:  {stay}")
                print()
                print("Поставить шаг (нужны сессия и ОДИН хост):")
                print("  python3 app.py agent inside <шаг> <сессия> --inside-host <хост> "
                      "[--inside-os windows|linux] [--inside-user <кто>] [--goal <что нужно>]")
                print("  например:  python3 app.py agent inside inside_privileges 1 "
                      "--inside-host srv-01 --inside-os linux --inside-user www-data")
                print()
                print("Посмотреть, что получилось:  python3 app.py agent plan <сессия>")
                return 0

            aid = args.arg.strip()
            if aid not in agent.INTERNAL_BY_ID:
                print(f"нет внутреннего шага «{aid}»", file=sys.stderr)
                print("список: python3 app.py agent inside", file=sys.stderr)
                return 2
            if not args.arg2.isdigit():
                print(f"нужен номер сессии: python3 app.py agent inside {aid} <сессия> "
                      f"--inside-host <хост>", file=sys.stderr)
                return 2
            sid = int(args.arg2)
            sess = store.agent_session(sid)
            if sess is None:
                print(f"сессии {sid} нет", file=sys.stderr)
                return 2
            if not args.inside_host:
                print("нужен --inside-host <хост>: внутренний шаг готовится под "
                      "конкретный хост", file=sys.stderr)
                return 2

            a = agent.INTERNAL_BY_ID[aid]
            if a.get("places"):
                # Не формальность: файл окажется на хосте заказчика, а пакет
                # передачи без записи о доступе не соберётся.
                from asm import handover as hmod_i
                if not hmod_i.access(sid):
                    print("СНАЧАЛА ЗАПИШИТЕ ДОСТУП.", file=sys.stderr)
                    print("  Шаг оставит файл на хосте заказчика. Пока доступ не "
                          "записан,", file=sys.stderr)
                    print("  пакет передачи собрать нельзя, а файл уже появится.",
                          file=sys.stderr)
                    print(f"  python3 app.py handover access {sid} --account … "
                          f"--privilege … --target-host … --method …", file=sys.stderr)
                    return 2

            params = {"target": "", "host": args.inside_host,
                      "user": args.inside_user, "os": args.inside_os,
                      "goal": args.goal}
            step = agent.propose(sid, aid, params=params,
                                 rationale=f"{a['why']} (подготовка, не выполнение)")
            if step is None:
                # Причина отказа должна быть названа: «проверьте хост» на
                # самом деле не говорит, что именно не так.
                why = ""
                if not params["host"]:
                    why = "нужен --inside-host <хост>"
                else:
                    _h, _w = agent._one_host(params)
                    if _w:
                        why = _w
                if not why and a.get("places") and a.get("payload"):
                    o_s = params["os"].strip().lower()
                    if not (o_s.startswith("win") or o_s.startswith("lin")):
                        why = "нужен --inside-os windows|linux: от системы зависит, какой файл класть"
                    else:
                        # Берём строку по признаку, а не по номеру: номер
                        # зависел от числа строк в шапке и дал пустое сообщение.
                        lines = agent.internal_plan(aid, params, {"id": sid}).split("\n")
                        for k, ln in enumerate(lines):
                            if ("файла для этого шага нет" in ln
                                    or "Не указана система" in ln):
                                tail = [x.strip() for x in lines[k:k + 2] if x.strip()]
                                why = " ".join(tail)
                                break
                print("шаг не поставлен: " + (why or "проверьте условия шага"),
                      file=sys.stderr)
                return 2
            print(f"сессия {sid}: поставлен шаг {step} — {a['title']}")
            print(f"  хост: {args.inside_host}")
            if a.get("places"):
                print("  ВНИМАНИЕ: шаг оставит файл на хосте заказчика. "
                      "Команды уборки будут в выводе шага.")
            print("  ничего не выполнено, ждёт решения")
            print(f"  посмотреть:  python3 app.py agent plan {sid}")
            print(f"  одобрить:    python3 app.py agent approve {step} "
                  f"--operator {args.operator or 'кто-то'}")
            # run принимает НОМЕР СЕССИИ и проходит по всем одобренным шагам,
            # а не номер шага. Подсказка с номером шага вела в пустоту.
            print(f"  подготовить: python3 app.py agent run {sid}")
            return 0
        if args.action == "start":
            t = None
            if args.arg.isdigit():
                t = store.target(int(args.arg))
            if t is None:
                row = store.one("SELECT * FROM targets WHERE value=?", (args.arg.strip().lower(),))
                t = dict(row) if row else None
            if t is None:
                print(f"цель «{args.arg}» не найдена; сначала: python3 app.py add {args.arg} "
                      f"--client ... --ref ...", file=sys.stderr)
                return 1
            sid = agent.open_session(t["id"], args.operator, args.note,
                                     (args.deadline or "").strip())
            made = agent.propose_opening(sid, t["value"], limit=args.limit)
            print(f"сессия {sid} открыта: цель {t['value']} (заказчик: {t['client']})")
            dl = store.agent_session(sid)["deadline"]
            if args.deadline and not dl:
                print("  ВНИМАНИЕ: срок не записан — проверьте формат --deadline",
                      file=sys.stderr)
            elif dl:
                print(f"  жёсткий срок: {dl} — после него агент не выполнит ничего")
            print(agent.profile_note())
            print(f"предложено шагов: {len(made)} — ничего не выполнено, ждут решения")
            print(f"далее:  python3 app.py agent plan {sid}")
            return 0
        if args.action == "resume":
            if engines is None:
                print("движки недоступны — снимать нечего", file=sys.stderr)
                return 1
            was = engines.halt_state()
            engines.resume()
            store.audit("agent_resume", {"operator": args.operator, "note": args.note})
            print("флаг остановки снят" if was else "флага остановки не было")
            print("  ВАЖНО: снятие флага само по себе ничего не возобновляет —")
            print("  закрытая сессия остаётся закрытой, шаги надо предлагать заново")
            return 0
        if args.action == "selftest":
            if engines is None:
                print("движки недоступны — проверять нечего", file=sys.stderr)
                return 1
            print("Проверка кнопки СТОП на этой машине.")
            print("Запускается настоящее дерево процессов (родитель и потомок),")
            print("затем по нему бьёт та же stop_all(), что и по кнопке. Секунды.")
            print()
            r = engines.selftest()
            print(f"  система:            {r['platform']}  ({r['mechanism']})")
            if r.get("pids"):
                print(f"  фикстура:           родитель {r['pids'][0]}, "
                      f"потомок {r['pids'][1]}")
                print(f"  были живы до стопа: {r['alive_before']}")
            print(f"  подтверждено убито: {r['killed_confirmed']}")
            print(f"  выжили:             {r['survivors'] or 'никто'}")
            for idx, note in enumerate(r["notes"], 1):
                print(f"  примечание {idx}:     {note}")
            if r.get("exc"):
                print(f"  сбой запуска:       {r['exc']}")
            print()
            if r["ok"]:
                print("ИТОГ: кнопка СТОП работает — дерево процессов прекратило")
                print("      работу целиком, ни родитель, ни потомок не выжили.")
                return 0
            print("ИТОГ: ПРОВЕРКА НЕ ПРОЙДЕНА.")
            print("      Именно от этой кнопки зависит, прекратится ли воздействие")
            print("      на объект. Пока она не проходит — работу не начинать.")
            return 1
        if not args.arg.isdigit() and args.action != "inside":
            print("нужен номер сессии или шага", file=sys.stderr)
            return 2
        n = int(args.arg)
        if args.action == "plan":
            steps = agent.pending(n)
            if not steps:
                print(f"в сессии {n} нет шагов, ожидающих решения")
                return 0
            print(f"Ждут решения ({len(steps)}). Ничего не выполнится без подтверждения.")
            from asm import gate as gate_mod
            for st in steps:
                print(f"\n  шаг {st['id']}")
                print("  " + agent.describe(st).replace("\n", "\n  "))
                g = agent.gate_step(st["id"])
                for line in gate_mod.describe(g).splitlines():
                    print("  " + line)
            print(f"\nодобрить:  python3 app.py agent approve <номер шага> --operator <кто>")
            print(f"отклонить: python3 app.py agent deny <номер шага> --operator <кто>")
            return 0
        if args.action == "step":
            # Команды подготовленного шага хранятся в базе, но перечитать их
            # после agent run было нечем: он их печатает один раз, и если
            # вывод ушёл за край экрана, взять команды негде. А копировать их
            # руками — единственный способ выполнить внутреннюю работу.
            if not args.arg.isdigit():
                print("нужен номер шага: python3 app.py agent step <номер>",
                      file=sys.stderr)
                return 2
            st = store.agent_step(int(args.arg))
            if st is None:
                print(f"шага {args.arg} нет", file=sys.stderr)
                return 2
            print(f"Шаг {st['id']} · сессия {st['session_id']} · {st['action_id']}")
            print(f"  {st['title']}")
            print(f"  класс: {st['cls']}   статус: {st['status']}")
            if st["rationale"]:
                print(f"  зачем: {st['rationale']}")
            if st["risk"]:
                print(f"  риск : {st['risk']}")
            try:
                params = json.loads(st["params"] or "{}")
            except Exception:
                params = {}
            # Команды шага — отдельным блоком: их пишет модель, и читать их
            # надо глазами, а не как строку словаря.
            cmds = list(params.pop("cmds", []) or [])
            if cmds:
                src = params.pop("cmds_source", "") or "модель"
                print(f"  команды ({len(cmds)}, источник: {src}):")
                for c in cmds:
                    print("    " + str(c)[:160])
                why = params.pop("cmds_why", "")
                if why:
                    print("  зачем это: " + str(why)[:160])
                for d in (params.pop("cmds_dropped", []) or [])[:4]:
                    print("    отброшено: " + str(d.get("cmd") or "")[:60]
                          + " — " + str(d.get("reason") or "")[:100])
                for k in ("cmds_cleanup", "cmds_error"):
                    params.pop(k, None)
            elif params.get("cmds_error"):
                print("  команды: правилами — " + str(params.pop("cmds_error"))[:120])
            shown = {k: v for k, v in params.items() if v not in ("", None)}
            if shown:
                print("  условия: " + ", ".join(f"{k}={v}" for k, v in shown.items()))
            if st["decided_at"]:
                print(f"  решение: {st['status']} — {st['decided_by'] or 'не указан'}"
                      f" в {st['decided_at']}")
            if st["decision_note"]:
                print(f"  примечание: {st['decision_note']}")
            if st["error"]:
                print(f"\nОШИБКА: {st['error']}")
            if st["result"]:
                print()
                print(st["result"])
            elif st["status"] == "proposed":
                print(f"\nОдобрить: python3 app.py agent approve {st['id']} "
                      f"--operator <кто>")
            return 0

        if args.action == "check":
            # Проверка ответа модели, полученного снаружи (чат, чужой прогон):
            # что из него прошло бы наш конвейер. Ничего не выполняется.
            if not args.arg.isdigit() or not args.file:
                print('нужно: python3 app.py agent check <сессия> --file "<ответ.txt>"',
                      file=sys.stderr)
                return 2
            from asm import plancheck
            try:
                res = plancheck.check_file(int(args.arg), args.file, limit=args.limit + 4,
                                           facts_on=not args.no_facts)
            except OSError as e:
                print(f"файл не прочитан: {e}", file=sys.stderr)
                return 2
            print(plancheck.render(res, session_id=int(args.arg)))
            return 0

        if args.action == "facts":
            # Лист фактов по объекту: что код посчитал по базам и кэшу. По
            # умолчанию читается только кэш — сеть включается флагом на один
            # запуск, чтобы за объект никто не ходил без решения оператора.
            if not args.arg.isdigit():
                print("нужен номер сессии:  python3 app.py agent facts <сессия>",
                      file=sys.stderr)
                return 2
            from asm import facts as facts_mod
            sid = int(args.arg)
            sh = {}
            if args.scan:
                sh = facts_mod.sheet(scan_id=args.scan, allow_net=bool(args.net))
            else:
                sh = facts_mod.sheet_for_session(sid)
                if sh.get("scan_id") and args.net:
                    sh = facts_mod.sheet(scan_id=sh["scan_id"], allow_net=True)
            if not sh or not sh.get("scan_id"):
                print("по сессии нет завершённого скана: сверять нечего\n"
                      "  сначала скан:  python3 app.py scan <цель>\n"
                      "  или с явным сканом:  python3 app.py agent facts "
                      f"{sid} --scan <номер>", file=sys.stderr)
                return 1
            print(facts_mod.render_sheet(sh))
            print()
            print(f"режим сверки: {facts_mod.mode()} "
                  f"(ASM_FACTS_NET=off|cache|allow; срок годности "
                  f"{facts_mod.max_age_days()} дн. — ASM_FACTS_MAX_AGE)")
            return 0
        if args.action == "gate":
            # Показать проверку ДО решения: оператор должен видеть, чем платит.
            if not args.arg.isdigit():
                print("нужен номер шага: python3 app.py agent gate <номер>", file=sys.stderr)
                return 2
            from asm import gate as gate_mod
            g = agent.gate_step(int(args.arg))
            print(gate_mod.describe(g))
            return 0 if g["action"] != gate_mod.BLOCK else 1
        if args.action == "notes":
            if not args.arg.isdigit():
                print("нужен номер сессии: python3 app.py agent notes <сессия>",
                      file=sys.stderr)
                return 2
            rows = store.agent_notes(int(args.arg), limit=200,
                                     kinds=(args.kind,) if args.kind else None)
            if not rows:
                print(f"в памяти сессии {args.arg} записей нет")
                return 0
            print(f"Память сессии {args.arg} ({len(rows)} записей; свежие — внизу):")
            for r in rows:
                title = store.NOTE_KIND_TITLE.get(r["kind"], r["kind"])
                print(f"  {r['created_at'][:16]} [{title}] {r['text']}"
                      f"  ({r['source'] or '—'})")
            return 0
        if args.action == "say":
            if not args.arg.isdigit() or not args.arg2:
                print('нужно: python3 app.py agent say <сессия> "текст"', file=sys.stderr)
                return 2
            kind = store.agent_note(int(args.arg), args.kind or store.note_kind(args.arg2),
                                    args.arg2, source=args.operator or "оператор")
            rows = store.agent_notes(int(args.arg), limit=1)
            title = store.NOTE_KIND_TITLE.get(rows[-1]["kind"], "") if rows else ""
            print(f"записано в память сессии {args.arg} (№{kind}, вид: {title})")
            print("теперь это учитывается в каждом плане: агент видит запись "
                  "и не предлагает то, что запрещено")
            return 0
        if args.action == "autopilot":
            if not args.arg.isdigit():
                print("нужен номер сессии: python3 app.py agent autopilot <сессия>",
                      file=sys.stderr)
                return 2
            from asm import planner as pmod
            rec = pmod.autopilot(int(args.arg), rounds=args.rounds,
                                 approve=args.approve_what, scan_id=args.scan or None,
                                 limit=max(args.limit, 2),
                                 planner_mode=args.planner, operator=args.operator)
            print(pmod.render_autopilot(rec))
            return 0
        if args.action in ("approve", "deny"):
            ok = store.agent_decide(n, args.action == "approve", args.operator, args.note)
            if not ok:
                print(f"шаг {n} не в статусе «ожидает решения» — решение не принято", file=sys.stderr)
                return 1
            print(f"шаг {n}: {'ОДОБРЕНО' if args.action == 'approve' else 'отклонено'}"
                  f" (записал: {args.operator or 'не указан'})")
            return 0
        if args.action == "free":
            n = int(args.arg) if str(args.arg).isdigit() else 0
            if not n or store.agent_session(n) is None:
                print("нужен номер сессии: python3 app.py agent free <сессия> --cmd «…» "
                      "--intent «…»", file=sys.stderr)
                return 1
            res = agent.propose_free(n, args.free_cmd, intent=args.intent,
                                     target=args.target_host, tool=args.tool)
            if not res.get("ok"):
                print("шаг не поставлен: " + str(res.get("reason") or "причина не названа"),
                      file=sys.stderr)
                return 1
            st = store.agent_step(res["step"])
            pp = params_of(st)
            print(f"свободный шаг #{res['step']} поставлен, класс {res['cls']}:")
            print(f"  команда: {pp.get('cmd')}")
            if pp.get("intent"):
                print(f"  зачем  : {pp.get('intent')}")
            g = res.get("gate") or {}
            mark = {"allow": "можно", "warn": "можно, но обратите внимание"}.get(
                str(g.get("action")), str(g.get("action")))
            print(f"  ворота : {mark}" + (f" — {g.get('note')}" if g.get("note") else ""))
            need, why = agent.needs_operator(st)
            print("  решение: " + ("нужно ваше слово — " + why if need
                                   else "агент выполнит сам (чтение, объект не меняется)"))
            print(f"  одобрить: python3 app.py agent approve {res['step']} --operator <кто>")
            return 0

        if args.action == "budget":
            n = int(args.arg) if str(args.arg).isdigit() else 0
            if not n or store.agent_session(n) is None:
                print("нужен номер сессии: python3 app.py agent budget <сессия> "
                      "[--steps N --noise N --hosts N --files N]", file=sys.stderr)
                return 1
            from asm import budget as bmod
            asked = {"steps": args.steps, "noise": args.noise,
                     "hosts": args.hosts, "files": args.files}
            asked = {k: v for k, v in asked.items() if v is not None}
            if asked:
                # Ноль и минус названы осознанно — значит, о них и говорим, а не
                # молча оставляем прежнее число.
                floors = {"steps": bmod.FLOOR["steps_per_hour"], "noise": bmod.FLOOR["noise_per_hour"],
                          "hosts": bmod.FLOOR["hosts"], "files": bmod.FLOOR["files_at_once"]}
                low = {k: v for k, v in asked.items() if v < floors[k]}
                if low:
                    for k, v in low.items():
                        print(f"бюджет не изменён: --{k} {v} ниже предела ({floors[k]}). "
                              f"Совсем остановить работу — это не бюджет: для этого есть "
                              f"СТОП (панель) и закрытие сессии (agent close).", file=sys.stderr)
                    return 1
                got = bmod.set_budget(n, steps_per_hour=asked.get("steps"),
                                      noise_per_hour=asked.get("noise"),
                                      hosts=asked.get("hosts"),
                                      files_at_once=asked.get("files"),
                                      note=args.note, operator=args.operator)
                if not got.get("ok"):
                    print("бюджет не изменён: " + str(got.get("why")), file=sys.stderr)
                    return 1
                print("бюджет обновлён.")
            print(bmod.text(n))
            return 0

        if args.action == "run":
            if store.agent_session(n) is None:
                # Иначе «в сессии 5 нет одобренных шагов» звучит как «всё
                # выполнено», хотя сессии с таким номером не существует.
                print(f"сессии {n} нет — выполнять нечего", file=sys.stderr)
                return 2
            done = 0
            # Пароль доступа нужен транспорту внутрь. Он живёт только в памяти
            # этого запуска: скрытый ввод или переменная окружения — и ничего на диске.
            secret = os.environ.get("ASM_INWARD_SECRET", "")
            if getattr(args, "secret_prompt", False) and not secret:
                import getpass
                secret = getpass.getpass("пароль доступа (не сохраняется): ")
            for st in store.agent_steps(n):
                if st["status"] != store.AGENT_APPROVED:
                    continue
                res = agent.execute(st["id"], secret=secret)
                done += 1
                if res.get("inward"):
                    print(f"  шаг {st['id']} ({st['action_id']}): отправлено транспортом, "
                          f"команд {res.get('count')}")
                    print()
                    print(res["result"])
                    print()
                elif res.get("handoff"):
                    kind = ("подготовлены команды для внутренней работы"
                            if res.get("internal") else "передача человеку")
                    print(f"  шаг {st['id']}: {kind}")
                    print()
                    print(res["result"])
                    print()
                elif res.get("ok"):
                    print(f"  шаг {st['id']} ({st['action_id']}): готово, результатов {res.get('count')}")
                else:
                    print(f"  шаг {st['id']} ({st['action_id']}): {res.get('reason')}")
            if not done:
                print(f"в сессии {n} нет одобренных шагов — выполнять нечего")
            return 0
        if args.action == "status":
            if store.agent_session(n) is None:
                print(f"сессии {n} нет", file=sys.stderr)
                return 2
            for st in store.agent_steps(n):
                print(f"  {st['id']:4} {st['cls']:8} {st['action_id']:16} {st['status']:10} "
                      f"{st['title']}")
            return 0
        if args.action == "stop":
            # сначала убиваем процессы, потом пишем в базу: если убийство упадёт,
            # в базе не должно остаться состояния «остановлено», которого нет по факту
            if engines is None:
                alive, killed = 0, 0
            else:
                alive = len(engines.running())
                killed = engines.stop_all(f"оператор {args.operator or '(не указан)'}")
            store.agent_stop(n, args.operator, args.note, killed=killed)
            print(f"сессия {n} остановлена")
            print(f"  процессов было живо: {alive}, подтверждено убито: {killed}")
            left = engines.stop_survivors() if engines is not None else []
            if left:
                print(file=sys.stderr)
                print("  ВНИМАНИЕ: часть процессов пережила остановку и, возможно,",
                      file=sys.stderr)
                print("  продолжает работать на объекте:", file=sys.stderr)
                for it in left:
                    print(f"    pid {it['pid']}: {it['cmd']}", file=sys.stderr)
                print("  проверьте их вручную, прежде чем считать воздействие",
                      file=sys.stderr)
                print("  прекращённым.", file=sys.stderr)
            print("  новые шаги не выполняются, ожидавшие подтверждения — отменены")
            print("  чтобы продолжить работу: python3 app.py agent close "
                  f"{n} и начать новую сессию")
            return 0
        if args.action == "extend":
            if not args.scan:
                print("нужно --scan <номер скана>: по чему подбирать плейбуки",
                      file=sys.stderr)
                return 2
            from asm import planner as pmod
            _mode = pmod.mode(args.planner)
            print(f"планировщик: {_mode}"
                  + ("  (правила: как было до модели)" if _mode == "rules" else ""))
            res = pmod.plan_and_apply(n, args.scan, explicit_mode=_mode,
                                      limit=args.limit)
            for w in res["warnings"]:
                print("ПРЕДУПРЕЖДЕНИЕ:", w, file=sys.stderr)
            sig = agent.scan_signals(args.scan)
            print(f"скан {args.scan}: портов {len(sig['ports'])}, "
                  f"сервисов {len(sig['services'])}, продуктов {len(sig['products'])}")
            mp = res.get("model")
            if mp is not None:
                print()
                if mp["ok"]:
                    print(f"план модели ({len(mp['steps'])} шагов, "
                          f"{mp['raw_len']} знаков ответа):")
                    for st in mp["steps"]:
                        print(f"  {st['action']:<18} [{st['cls']:<7}] "
                              f"{str(st['why'])[:88]}")
                else:
                    print(f"план модели не принят: {mp['error']}")
                for d in mp.get("dropped") or []:
                    print(f"  отброшено: {d['action']} — {d['reason']}")
            if res["playbooks"]:
                print("сработали плейбуки: " + ", ".join(res["playbooks"]))
            try:
                from asm import vector as _v
                notes = _v.notes_for_scan(args.scan)
            except Exception:
                notes = []
            if notes:
                print()
                print("память: похожее уже встречалось на других объектах")
                for nt in notes:
                    print(f"  {nt['priority'] or '—'} {str(nt['title'])[:56]}")
                    for h in nt["hits"]:
                        print(f"      был на {h['client'] or '?'} ({h['target']}) — "
                              f"{h['status_ru']}"
                              + (f" · {h['note']}" if h["note"] else ""))
                print("  это подсказка, а не вердикт: контекст объекта другой")
                print()
            for sk in res["skipped"]:
                print(f"не поставлено (решает человек): {sk['action']} — {sk['reason']}")
            if res["queued"]:
                print(f"\nпредложено шагов: {len(res['queued'])} — ничего не выполнено, "
                      f"ждут решения")
                print("воздействие и внутренние шаги планировщиком не ставятся вообще")
                print(f"далее:  python3 app.py agent plan {n}")
            else:
                print("новых шагов нет: всё из цепочек уже предложено ранее")
            return 0
        if args.action == "plans":
            rows = store.agent_plan_rows(n, limit=6)
            if not rows:
                print(f"в сессии {n} планы ещё не записывались")
                return 0
            print(f"журнал планов сессии {n} (свежие сверху)")
            for r in rows:
                steps = (r["plan"] or {}).get("steps") or []
                print(f"\n  [{r['source']}] {r['created_at']} — {r['note']}")
                if not steps:
                    continue
                for st in steps:
                    aid = st.get("action") or st.get("action_id") or "?"
                    why = str(st.get("why") or "")[:80]
                    print(f"      {aid:<18} {why}")
                for d in (r["plan"] or {}).get("dropped") or []:
                    print(f"      отброшено: {d.get('action')} — {d.get('reason')}")
            print("\nэто след решений планировщика, а не выполненные действия")
            return 0
        if args.action == "deadline":
            if not args.deadline:
                print("нужно --deadline, например --deadline 2026-12-31T18:00:00+00:00")
                return 2
            store.agent_set_deadline(n, args.deadline)
            print(f"сессия {n}: срок {args.deadline}")
            print("  после этого времени агент откажется выполнять шаги сам")
            return 0
        if args.action == "close":
            store.agent_close(n)
            print(f"сессия {n} закрыта")
            return 0

    if args.cmd == "list":
        if not store.targets():
            # Пустой вывод читается как «команда не сработала». Это первая
            # команда на новой машине, и она должна объяснить, что делать.
            print("целей пока нет. Добавить: python3 app.py add <адрес> "
                  "--client \"<заказчик>\" --ref \"<основание>\"")
            print("или откройте панель: python3 app.py serve")
            return 0
        for t in store.targets():
            print(f"#{t['id']} {t['value']:<34} {t['client'][:26]:<26} основание: {t['auth_ref'][:24]}")
            for sc in store.scans(t["id"]):
                print(f"    скан #{sc['id']:<4} {sc['status']:<8} {sc['started_at'][:16]}  {sc['progress'] or ''}")
        return 0
    return 0


if __name__ == "__main__":
    _cli_args = sys.argv[1:]
    _cli_command = next((arg for arg in _cli_args if not arg.startswith("-")), "")
    # Preserve the legacy diagnostics/inspection surface (including its
    # explicitly waived secret display) and commands that do not consume
    # operation settings. Operational commands get one typed snapshot.
    _needs_operation_settings = (
        "--settings" not in _cli_args and "--help" not in _cli_args
        and _cli_command not in ("", "add", "list", "scan", "serve")
    )
    if _needs_operation_settings:
        _snapshot_builder = _scan_settings_snapshot
        with use_settings(_snapshot_builder()):
            sys.exit(main())
    sys.exit(main())
