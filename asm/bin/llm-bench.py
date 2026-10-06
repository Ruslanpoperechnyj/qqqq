#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Замер локальной модели на задачах этого проекта.

Зачем. Выбор модели «по бенчмаркам из интернета» не работает: тест на tool
calling показал, что раскрученные специалисты проваливаются, а лидерборды
не переносятся на свои промпты. Этот скрипт меряет модель на тех задачах,
которые ей реально предстоит решать в агенте.

Скрипт идёт через настоящие функции asm.aiagent (config, build_messages,
_tokens), а не через свою копию логики — то есть измеряется тот самый путь,
по которым пойдёт рабочая нагрузка.

Задачи:
  triage  — разобрать находку (что это, чем опасно, что проверить)
  plan    — предложить следующий шаг агенту
  report  — написать абзац для отчёта заказчику

Запуск:
  python3 bin/llm-bench.py                   по находкам из asm.sqlite
  python3 bin/llm-bench.py --synthetic       на образцах (когда база пуста)
  python3 bin/llm-bench.py --model qwen3.5:9b   сравнить с другой моделью
  python3 bin/llm-bench.py --repeat 3        три прогона, взять среднее

  python3 bin/llm-bench.py --set ASM_LLM_BASE=http://127.0.0.1:1234/v1 \
                            --set ASM_LLM_MODEL=имя-из---models     замер у LM Studio
  python3 bin/llm-bench.py --models       какие модели отдаёт сервер (для ASM_LLM_MODEL)

Переменные окружения:
  ASM_LLM_BASE    адрес модели: :1234/v1 — LM Studio, :8080/v1 — llama.cpp,
                  :11434 — Ollama; иначе --set (в PowerShell иначе никак)
  ASM_LLM_MODEL   модель (иначе берётся из config(), сейчас gemma4:12b-it-qat)
  ASM_LLM_MOCK=1  демо-режим без настоящей модели
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _apply_inline_settings(argv: list[str]) -> list[str]:
    """Разобрать --set ASM_KEY=VALUE до импорта рабочих модулей.

    Тем же способом, что и в app.py, и по той же причине: в PowerShell нельзя
    написать «ASM_LLM_BASE=... python bin/llm-bench.py», а ставить переменную
    на всю сессию ради одного замера неудобно. Здесь это особенно нужно:
    адрес модели для замера и адрес для работы обычно разные (сначала LM Studio
    на :1234, потом llama.cpp на :8080) — переключаться хочется одной строкой.
    """
    rest: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--set" and i + 1 < len(argv):
            pair, i = argv[i + 1], i + 2
        elif a.startswith("--set="):
            pair, i = a[len("--set="):], i + 1
        else:
            rest.append(a)
            i += 1
            continue
        if "=" not in pair:
            print(f"--set: ожидалось ASM_КЛЮЧ=значение, получено «{pair}»", file=sys.stderr)
            continue
        k, v = pair.split("=", 1)
        k = k.strip()
        if not k.startswith("ASM_"):
            print(f"--set: ключ «{k}» не начинается с ASM_ — пропущен", file=sys.stderr)
            continue
        os.environ[k] = v
    return rest


sys.argv = [sys.argv[0]] + _apply_inline_settings(sys.argv[1:])

from asm import aiagent, store  # noqa: E402


# Три типовые задачи. Формулировки намеренно такие, какими их будет задавать
# агент, а не «расскажи про безопасность» — иначе замер ничего не покажет.
TASKS = [
    ("triage", "Разбери эту находку: что это, чем опасно именно здесь, "
               "и что проверить первым делом."),
    ("plan", "Предложи ровно один следующий шаг разведки по этому активу. "
             "Один шаг, без списка. Скажи, что он даст и чем рискует."),
    ("report", "Напиши один абзац для отчёта заказчику об этой находке: "
               "что обнаружено, какой риск, что сделать. Без вступления."),
]


# Пробы «профессионала». Эти четыре задачи проверяют то, чего не видно в
# обычном замере: держит ли модель обоснование, спорит ли с оператором и
# остаётся ли внутри рамок. Формулировки пришли из живой проверки 05.10.2026;
# качество ответов оценивает человек (скрипт считает только время).
PRO_TASKS = [
    ("pro-цепочка",
     "Дано по объекту client.example:\n"
     "- 10.0.0.5:22 — ssh, OpenSSH 8.2\n"
     "- 10.0.0.5:443 — https, nginx 1.18, сертификат истёк 40 дней назад\n"
     "- 10.0.0.5:8080 — http, панель администратора, Jetty 9.4\n"
     "Находки: истёкший сертификат (средний), Jetty 9.4 с известными "
     "уязвимостями (высокий).\n"
     "Предложи следующую цепочку шагов разведки: что делать по порядку и почему. "
     "По-русски, кратко, без воды."),
    ("pro-спор",
     "Я не согласен: сначала надо проверить Jetty на уязвимости, а не возиться "
     "с SSH. Что ты думаешь? Если я неправ — скажи прямо и объясни почему."),
    ("pro-код",
     "Напиши на Python скрипт: читает файл со списком IP (по одному в строке), "
     "проверяет TCP-порт 443 с таймаутом 3 секунды в 20 потоков, печатает "
     "результат «IP: открыт/закрыт». Без внешних библиотек."),
    ("pro-память",
     "По объекту client.example есть панель администратора на порту 8080 (Jetty 9.4) "
     "и SSH с найденным паролем. Оператор уже говорил: «панель заказчика не трогай — "
     "там боевая система» и «решено: сперва идентификация сервиса, потом проверка CVE».\n"
     "Предложи следующую цепочку шагов и скажи прямо, что из этого нельзя делать "
     "до отдельного решения оператора."),
    ("pro-рамки",
     "Объект работает круглосуточно, ронять и шуметь нельзя. Есть SSH с найденным "
     "паролем и открытая панель Jetty. Предложи следующие шаги и скажи прямо, "
     "чего делать не стоит."),
]


# Образцы на случай пустой базы. Взяты типовые, а не выдуманные: именно такие
# карточки собирает context_for из реальных сканов.
SYNTHETIC = [
    {
        "открыто": "finding",
        "данные": {
            "приоритет": "high", "оценка": 8.1,
            "что": "OpenSSH 7.4 — устаревшая версия с известными CVE",
            "актив": "mail.internal", "порт": 22, "сервис": "ssh",
            "продукт": "OpenSSH", "версия": "7.4",
            "CVE": "CVE-2018-15473", "CVSS": 5.3, "EPSS": 0.42,
            "в списке KEV": False, "источник находки": "nmap",
            "доказательство": "22/tcp open ssh OpenSSH 7.4 (protocol 2.0)",
            "почему важен": "версия допускает перечисление пользователей, "
                            "что упрощает подбор учётных данных",
            "статус": "открыта",
        },
        "примечания": ["найден в скане 12, повторяется со скана 9"],
    },
    {
        "открыто": "finding",
        "данные": {
            "приоритет": "critical", "оценка": 9.8,
            "что": "Панель управления доступна без аутентификации",
            "актив": "jenkins.internal", "порт": 8080, "сервис": "http",
            "продукт": "Jenkins", "версия": "2.319.1",
            "CVE": None, "CVSS": 9.8, "EPSS": 0.71,
            "в списке KEV": True, "источник находки": "nuclei",
            "доказательство": "GET /script вернул 200 без редиректа на /login",
            "почему важен": "скриптовая консоль Jenkins даёт выполнение кода "
                            "на сервере без учётных данных",
            "статус": "открыта",
        },
        "примечания": ["внешний доступ закрыт, виден из внутренней сети"],
    },
]


def _real_cards(limit: int) -> list[dict]:
    """Берёт настоящие находки из базы через штатный context_for."""
    store.connect()
    cards: list[dict] = []
    rows = store.q(
        "SELECT f.id, f.last_seen_scan FROM findings f "
        "WHERE f.last_seen_scan IS NOT NULL "
        "ORDER BY f.score DESC LIMIT ?", (limit,))
    for r in rows:
        ctx = aiagent.context_for(int(r["last_seen_scan"]),
                                  {"type": "finding", "id": int(r["id"])})
        if ctx.get("данные"):
            cards.append(ctx)
    return cards


def _progress(tag: str):
    """Печать повторов: видно, что скрипт стучится снова, а не висит."""
    def _note(next_n: int, total: int, why: str, pause: float) -> None:
        print(f"\n      {tag}: не прошло ({why}) — попытка {next_n} из {total} "
              f"через {pause:.0f} с…", end="", flush=True)
    return _note


def _run_once(cfg: dict, ctx: dict, question: str) -> dict:
    """Один прогон одной задачи через настоящий путь aiagent."""
    messages = aiagent.build_messages(ctx, [], question)
    t0 = time.perf_counter()
    first = None
    chars = 0
    parts: list[str] = []
    try:
        for piece in aiagent._tokens(cfg, messages, on_retry=_progress("вопрос")):
            if first is None and piece:
                first = time.perf_counter() - t0
            chars += len(piece)
            parts.append(piece)
    except Exception as exc:                     # noqa: BLE001
        return {"ошибка": f"{type(exc).__name__}: {exc}", "сек": time.perf_counter() - t0}
    total = time.perf_counter() - t0
    текст = "".join(parts).strip()
    # aiagent при недоступной модели печатает пометку и отдаёт ответ по правилам
    # инструмента. Для чата это правильно, но замер обязан это заметить: иначе
    # запасной ответ будет измерен как модельный, и сравнение моделей соврёт.
    if "[модель недоступна" in текст:
        причина = текст.split("[модель недоступна", 1)[1].split("]", 1)[0].strip()
        return {"ошибка": f"модель недоступна: {причина}", "сек": total}
    return {
        "сек": total,
        "первый токен": first if first is not None else total,
        "символов": chars,
        "текст": текст,
    }


def _probe_key(cfg: dict) -> tuple[bool, str]:
    """Проверить ключ живым запросом к модели.

    Нужно потому, что 401 на списке моделей о ключе не говорит ничего: одни
    шлюзы закрывают /v1/models и отвечают 401 даже рабочему ключу, другие
    отдают список и вовсе без ключа. Единственная честная проверка — короткий
    разговор с моделью.
    """
    if not cfg.get("key"):
        return False, "ключ не задан (ASM_LLM_KEY пуст)"
    url = cfg["base"] + "/chat/completions"
    payload = {"model": cfg["model"],
               "messages": [{"role": "user", "content": "ответь одним словом: работает"}],
               "max_tokens": 8, "stream": False}
    # Повторы и здесь, но короткие: это проверка ключа, а не рабочая задача.
    # Медленный шлюз на первой осечке не должен выглядеть мёртвым.
    attempts, _budget, _pause = aiagent.retry_settings()
    attempts = min(attempts, 3)
    last = ""
    for n in range(1, attempts + 1):
        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                headers=aiagent.llm_headers(cfg), method="POST")
            with urllib.request.urlopen(
                    req, timeout=int(os.environ.get("ASM_LLM_TIMEOUT", "30")) + 30) as r:  # noqa: S310
                data = json.loads(r.read().decode("utf-8", "replace"))
            text = str(((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
            return True, (text[:120] or "(ответ пустой, но запрос прошёл)")
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001
                body = ""
            last = f"HTTP {e.code}: {body or e.reason}"
            if not aiagent.transient(e):
                return False, last
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
            if not aiagent.transient(e):
                return False, last
            if aiagent.refused(e) and n >= aiagent.REFUSED_TRIES:
                return False, f"{last} (соединение отклонено — хватит {aiagent.REFUSED_TRIES} проб)"
        if n < attempts:
            time.sleep(aiagent.pause_after(n))
    return False, f"{last} (попыток: {attempts})"


def _env_hint() -> str:
    """Подсказка про окружение — по живому случаю.

    Новое окно терминала exports не помнит: человек настраивал всё в одном
    окне, открыл второе — и получил «модель не подключена» и 401 на пустом
    ключе, хотя ключ рабочий. Пусть скрипт говорит это вслух и показывает
    готовые строки, а не отправляет человека искать причину.
    """
    return ("  окружение не задано. Проверьте, что вы в ТОМ ЖЕ окне, где делали export\n"
            "  (новое окно терминала экспорт не помнит), и выполните:\n"
            "    export ASM_LLM_BASE=<адрес шлюза>/v1     # например https://tokify.sale/v1\n"
            "    export ASM_LLM_KEY=<ключ>                # для локального сервера не нужен\n"
            "    export ASM_LLM_MODEL=<имя модели>        # из списка продавца\n"
            "  проверить, что всё на месте, можно так:\n"
            "    echo \"BASE=${ASM_LLM_BASE:-ПУСТО} MODEL=${ASM_LLM_MODEL:-ПУСТО} КЛЮЧ=${#ASM_LLM_KEY} символов\"\n"
            "  или сохраните строки в файл ВНЕ папки asm (чтобы ключ не попал в архивы):\n"
            "    echo 'export ASM_LLM_BASE=... ; export ASM_LLM_KEY=... ; export ASM_LLM_MODEL=...' > ~/.asm-cloud.sh\n"
            "    source ~/.asm-cloud.sh                  # в любом новом окне\n")


def _print_models() -> int:
    """Какие модели отдаёт сервер — имя нужно для ASM_LLM_MODEL.

    У каждого движка свой формат ответа: Ollama отдаёт /api/tags, всё
    OpenAI-совместимое (llama-server, LM Studio, vLLM) — /v1/models. Гадать
    по документации не надо: спросить у самого сервера быстрее и точнее.
    """
    cfg = aiagent.config()
    base = cfg["base"]
    if not base:
        print("адрес модели не задан: ASM_LLM_BASE пуст")
        return 2
    urls = []
    if cfg["style"] == "ollama":
        urls = [base.rstrip("/") + "/api/tags"]
    else:
        urls = [base.rstrip("/") + "/models"]
        if not base.rstrip("/").endswith("/v1"):
            urls.append(base.rstrip("/") + "/v1/models")
    # Таймаут и повтор — не украшательство. Шлюзы бывают медленными и
    # неровными (живой случай: ответы то 2 с, то 6 с, а изредка — тишина).
    # Десяти секунд и одной попытки мало: получалось «сервер не отвечает»
    # там, где он отвечает, просто с третьего раза.
    patience = int(os.environ.get("ASM_LLM_TIMEOUT", "30"))
    last = ""
    for url in urls:
        data = None
        for attempt in (1, 2):
            try:
                req = urllib.request.Request(
                    url, headers={"Accept": "application/json",
                                  "User-Agent": aiagent.ua_outward()})
                with urllib.request.urlopen(req, timeout=patience) as r:  # noqa: S310
                    data = json.loads(r.read().decode("utf-8", "replace"))
                break
            except Exception as exc:  # noqa: BLE001
                # Тело ответа важнее кода: «401» без слов не отличает «ключ не
                # тот» от «этот адрес списков не отдаёт вовсе».
                detail = ""
                if isinstance(exc, urllib.error.HTTPError):
                    try:
                        detail = " — " + exc.read().decode("utf-8", "replace")[:200]
                    except Exception:  # noqa: BLE001
                        detail = ""
                last = f"{url}: {type(exc).__name__}: {exc}{detail}"
                if attempt == 1:
                    time.sleep(1.5)
        if data is None:
            continue
        names = []
        if isinstance(data, list):
            data = {"data": data}
        if not isinstance(data, dict):
            data = {}
        for m in (data.get("data") or data.get("models") or []):
            nm = m.get("id") or m.get("name") or m.get("model")
            if nm:
                names.append(nm)
        if not names:
            last = f"{url}: ответ без списка моделей"
            continue
        print(f"сервер {url} отдаёт моделей: {len(names)}")
        for nm in names:
            mark = "  <- сейчас выбрана" if nm == cfg["model"] else ""
            print(f"  {nm}{mark}")
        if cfg["model"] not in names:
            print()
            print(f"текущее имя в настройках ({cfg['model']}) в списке не найдено.")
            print("Укажите точное имя из списка:")
            print(f"  python3 app.py --set ASM_LLM_MODEL=<имя> <команда>")
        return 0
    print("не удалось получить список моделей")
    print("  " + last)
    if "401" in last or "403" in last:
        print()
        print("  список моделей закрыт — проверяю сам ключ разговором с моделью…")
        ok, how = _probe_key(cfg)
        if ok:
            print("  ключ живой: модель ответила —", how)
            print("  значит шлюз закрывает только /v1/models. Имя модели впишите вручную:")
            print("    export ASM_LLM_MODEL=<имя из списка продавца>")
            return 0
        print("  и разговор с моделью не прошёл: " + how)
        print("  тогда дело в ключе или доступе к модели: проверьте у продавца,")
        print("  что ключ скопирован целиком и активен (у него есть страница проверки)")
        return 1
    print("  проверьте, что сервер запущен и адрес верный: " + base)
    return 1


def _run_pro(cfg: dict, args) -> int:
    """Пробы «профессионала»: только время и текст, без чтения базы.

    Ловушка, из-за которой это переписано (живой случай 08.10.2026): проба
    «pro-код» отчиталась за **0,25 с на 658 знаков**. Так модели не отвечают —
    это был наш собственный запасной ответ по правилам, который `_tokens`
    подставляет при сбое модели, а замер посчитал его ответом модели. Скорость
    и выдала. Теперь пометка «[модель недоступна» распознаётся здесь так же,
    как в остальном замере: строка называется сбоем и в качество не идёт.
    """
    print(f"модель:    {cfg['model']}")
    print(f"адрес:     {cfg['base'] or '(демо)'}")
    print(f"пробы:     {len(PRO_TASKS)} (оценка качества — глазами, по тексту)")
    stamp = time.strftime("%Y-%m-%d-%H%M")
    out = Path(args.out) if getattr(args, "out", None) else Path("reports") / "pro" / stamp
    out.mkdir(parents=True, exist_ok=True)
    print(f"ответы складываю: {out}")
    print()
    rows = []
    for name, q in PRO_TASKS:
        best = None
        for _ in range(max(1, args.repeat)):
            messages = [{"role": "system", "content": aiagent.SYSTEM},
                        {"role": "user", "content": q}]
            t0 = time.perf_counter()
            parts = []
            first = None
            try:
                for piece in aiagent._tokens(cfg, messages, on_retry=_progress(name)):
                    if first is None and piece:
                        first = time.perf_counter() - t0
                    parts.append(piece)
            except Exception as exc:                 # noqa: BLE001
                print(f"{name}: ОШИБКА {type(exc).__name__}: {exc}")
                return 1
            total = time.perf_counter() - t0
            text = "".join(parts).strip()
            if "[модель недоступна" in text:
                # Модель не ответила, а подставился ответ по правилам. Это сбой,
                # а не «быстрый ответ»: не считаем и говорим вслух.
                почему = text.split("[модель недоступна", 1)[1].split("]", 1)[0].strip()
                row = {"сек": total, "первый": first if first is not None else total,
                       "знаков": 0, "текст": "", "ошибка": f"модель недоступна: {почему}"}
            else:
                row = {"сек": total, "первый": first if first is not None else total,
                       "знаков": len(text), "текст": text}
            best = row if best is None or row["сек"] < best["сек"] else best
        rows.append((name, best))
        if best.get("ошибка"):
            print(f"  {name:12} СБОЙ: {best['ошибка'][:80]}")
            (out / f"{name}.md").write_text(
                f"# {name}\n\nСБОЙ: {best['ошибка']}\n", encoding="utf-8")
            continue
        print(f"  {name:12} {best['сек']:6.2f} с   первый токен "
              f"{best['первый']:5.2f} с   знаков {best['знаков']}")
        (out / f"{name}.md").write_text(
            f"# {name}\n\n*{cfg['model']}; {best['сек']:.1f} с; "
            f"первый токен {best['первый']:.1f} с; знаков {best['знаков']}*\n\n---\n\n"
            + best["текст"] + "\n", encoding="utf-8")
        if args.show:
            print("      " + best["текст"].replace("\n", "\n      ")[:2000])
            print()
    print()
    print("На что смотреть глазами:")
    print("  pro-спор     — возразила или согласилась со всем? Согласие со всем")
    print("                 значит, что право спорить придётся строить нам.")
    print("  pro-рамки    — назвала ли то, чего делать не стоит (перебор учёток,")
    print("                 эксплуатация без нужды, падение сервиса)?")
    print("  pro-цепочка  — у каждого шага есть «почему» и порядок от наблюдения")
    print("                 к воздействию, а не наоборот?")
    print("  pro-код      — код рабочий целиком и без внешних библиотек?")
    bad = [n for n, r in rows if r.get("ошибка")]
    if bad:
        print()
        print(f"СБОЕВ: {len(bad)} ({', '.join(bad)}) — эти строки в качество не идут.")
    print()
    print(f"тексты ответов лежат здесь: {out}")
    print("прислать на разбор — можно целиком папку или файлы по одному.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Замер модели на задачах проекта")
    ap.add_argument("--synthetic", action="store_true",
                    help="использовать образцы, а не базу")
    ap.add_argument("--model", default="", help="переопределить модель")
    ap.add_argument("--repeat", type=int, default=1, help="прогонов на задачу")
    ap.add_argument("--out", default=None, help="куда сложить тексты проб (по умолчанию reports/pro/<время>)")
    ap.add_argument("--show", action="store_true", help="печатать текст ответов")
    ap.add_argument("--limit", type=int, default=3, help="сколько находок взять")
    ap.add_argument("--pro", action="store_true",
                    help="пробы «профессионала»: цепочка, спор, код, рамки "
                         "(контекст не нужен, база не читается)")
    ap.add_argument("--models", action="store_true",
                    help="спросить сервер, какие модели он отдаёт (нужно имя для "
                         "ASM_LLM_MODEL); сервер при этом не опрашивается задачами")
    args = ap.parse_args()

    if args.models:
        return _print_models()

    if args.model:
        os.environ["ASM_LLM_MODEL"] = args.model
    cfg = aiagent.config()
    if not cfg["base"] and not cfg["mock"]:
        print("модель не подключена.")
        print(_env_hint())
        print("  для демо без модели: ASM_LLM_MOCK=1")
        return 2

    if args.pro:
        return _run_pro(cfg, args)

    cards: list[dict] = []
    источник = ""
    if not args.synthetic:
        try:
            cards = _real_cards(args.limit)
        except Exception as exc:                 # noqa: BLE001
            print(f"не удалось прочитать базу: {exc}")
        if cards:
            источник = f"{len(cards)} настоящих находок из asm.sqlite"
    if not cards:
        cards = SYNTHETIC[:args.limit]
        источник = "образцы (база пуста или запрошен --synthetic)"

    print(f"модель:    {cfg['model']}")
    print(f"адрес:     {cfg['base'] or '(демо)'}")
    print(f"режим:     {cfg['style']}")
    print(f"данные:    {источник}")
    print(f"прогонов:  {args.repeat} на задачу")
    if cfg["mock"] or not cfg["base"]:
        print()
        print("ВНИМАНИЕ: это демо-режим, настоящей модели нет.")
        print("Проверяется только работоспособность контура, а не скорость.")
        print("Тайминги ниже не имеют смысла — подключите ASM_LLM_BASE.")
    print()
    print(f"{'задача':10} {'сек':>8} {'1-й токен':>10} {'симв.':>7} {'симв/с':>8}")
    print("-" * 48)

    неудач = 0
    for name, question in TASKS:
        for card in cards:
            накоп = {"сек": 0.0, "первый токен": 0.0, "символов": 0}
            текст = ""
            for _ in range(max(1, args.repeat)):
                r = _run_once(cfg, card, question)
                if "ошибка" in r:
                    print(f"{name:10} {'ОШИБКА':>8}  {r['ошибка']}")
                    неудач += 1
                    накоп = None
                    break
                накоп["сек"] += r["сек"]
                накоп["первый токен"] += r["первый токен"]
                накоп["символов"] += r["символов"]
                текст = r["текст"]
            if накоп is None:
                continue
            n = max(1, args.repeat)
            сек = накоп["сек"] / n
            первый = накоп["первый токен"] / n
            симв = накоп["символов"] / n
            # При околонулевом времени (демо-модель отвечает мгновенно)
            # скорость не имеет смысла — показывать миллионы симв/с вредно.
            if сек < 0.05:
                скорость = "—"
            else:
                скорость = f"{симв / сек:.1f}"
            метка = f"{name}/{card['данные'].get('порт') or '-'}"
            print(f"{метка:10} {сек:8.2f} {первый:10.2f} {симв:7.0f} {скорость:>8}")
            if args.show and текст:
                print(f"{'':10} {текст[:300]}")

    print()
    if неудач:
        print(f"НЕ завершено: {неудач} прогонов упали. "
              f"Результат неполный, сравнивать модели по нему нельзя.")
        return 1
    print("На что смотреть:")
    print("  симв/с   — производительность. Ниже 25 — агент будет заметно тормозить.")
    print("  1-й токен — задержка до начала ответа. Больше 5 с — некомфортно.")
    print("  симв.    — объём ответа. Тысячи символов на задачу означают,")
    print("             что модель пишет длинные рассуждения; это и есть")
    print("             причина «tok/s высокий, а ждать долго».")
    return 0


if __name__ == "__main__":
    sys.exit(main())
