#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A/B-проба: несколько моделей на одних и тех же заданиях (08.10.2026).

Зачем. Замер одной модели мало что говорит: «ответила уверенно» — не факт.
Нужно сравнение на **наших** заданиях и рядом с **нашей** планкой (Gemma 12B:
4 ловушки из 8 на сложной задаче). Этот скрипт делает ровно это: кормит одну
и ту же подсказку нескольким моделям, складывает ответы в файлы и считает то,
что считается машинно.

Про медленные шлюзы. Прямые запросы к перекупщицким ключам отвечают неровно:
первый токен может идти минуту. Поэтому ответ читается **потоком**, а на экран
сыплются точки — видно, что работа идёт, а не что всё умерло. `Ctrl+C` больше
не роняет прогон: он аккуратно останавливает его, уже собранные ответы и сводка
остаются на месте.

Что считается машинно (и потому честно):
  * время до первого слова и общее — по факту;
  * токены (вход/выход) — из `usage`, если сервер его отдал; иначе **оценка**
    по символам, и в таблице это помечено;
  * признак отказа — по маркерам вежливого «не могу» (штука неровная, поэтому
    показываем цитату, а не вердикт);
  * блоки кода и следы Linux-команд (`apt-get`, `systemctl`) — чтобы помнить:
    наша среда Windows + Git Bash, а модель может советовать то, чего у нас нет.

Чего здесь НЕТ: автоматического счёта ловушек. Раскладка «4 из 8» делается
глазами по разбору в самом задании — машина тут соврёт. Для «солянки»
отдельно есть `tools/check-big.py`: он запускает присланный код на фикстурах
и сверяет цепочку.

Порядок работы:
    export ASM_LLM_BASE=... ASM_LLM_KEY=... ASM_LLM_MODEL=...
    python3 bin/llm-ab.py --models claude-opus-5.5,gpt-6-sol,claude-opus-5-thinking
    # ответы: reports/ab/<дата-время>/<модель>/<задание>.md
    # сводка:  reports/ab/<дата-время>/СВОДКА.md

Ключ берётся только из окружения и в файлы не пишется.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from asm import aiagent  # noqa: E402

# Маркеры отказа. Не «вердикт», а повод посмотреть: настоящий отказ и
# осторожная формулировка выглядят похоже, и решать должен человек.
REFUSAL = (
    "не могу помочь", "не могу выполнить", "не могу этого", "не стану", "не буду",
    "не имею права", "неэтично", "недопустимо", "нарушает", "отказываюсь",
    "i can't help", "i cannot help", "i'm unable", "i am unable", "i won't",
    "i will not", "against my", "не могу предоставить", "не могу дать",
)

LINUX_TRACES = ("apt-get", "apt install", "yum ", "dnf ", "pacman", "systemctl ")

# Наша планка: сложная задача на Gemma 12B — 4 ловушки из 8 (прогон 06.10.2026).
GEMMA_LINE = "Gemma 12B: 4 ловушки из 8, ошибка в CVE-2026-2044"


class Failed(Exception):
    """Проба не удалась после всех попыток. Несёт причину и число попыток."""

    def __init__(self, why: str, attempts: int, partial: str = ""):
        super().__init__(why)
        self.why = why
        self.attempts = attempts
        self.partial = partial


class Interrupted(Exception):
    """Ctrl+C посреди ответа. Несёт то, что уже успело прийти, — терять нельзя."""

    def __init__(self, partial: str, first: float | None, secs: float):
        super().__init__("остановлено оператором")
        self.partial = partial
        self.first = first
        self.secs = secs


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


def safe(name: str) -> str:
    return re.sub(r"[^0-9A-Za-zА-Яа-я._-]+", "_", name).strip("_") or "model"


def _estimate_tokens(text: str) -> int:
    """Оценка токенов по символам. Именно оценка — так и подписываем."""
    return max(1, len(text) // 3)


def _messages(task: str) -> list[dict]:
    return [{"role": "system", "content": aiagent.SYSTEM},
            {"role": "user", "content": task}]


def _stream(cfg: dict, messages: list[dict], *, t0: float, timeout: int,
            progress: bool) -> tuple[str, float | None]:
    """Читать ответ потоком. Возвращает текст и время до первого слова."""
    url = cfg["base"] + "/chat/completions"
    payload = {"model": cfg["model"], "messages": messages, "stream": True,
               "temperature": cfg.get("temperature", 0.2)}
    parts: list[str] = []
    first: float | None = None
    seen = 0
    with aiagent._post_stream(url, payload, timeout=timeout,
                              headers=aiagent.llm_headers(cfg)) as r:
        try:
            for raw in r:
                for line in raw.decode("utf-8", "replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    data = line[5:].strip() if line.startswith("data:") else line
                    if data == "[DONE]":
                        return "".join(parts), first
                    if not data.startswith("{"):
                        continue
                    try:
                        d = json.loads(data)
                        ch = (d.get("choices") or [{}])[0]
                        piece = (ch.get("delta") or {}).get("content") or ch.get("text") or ""
                    except Exception:  # noqa: BLE001 — мусор в потоке не должен рвать ответ
                        continue
                    if not piece:
                        continue
                    if first is None:
                        first = time.perf_counter() - t0
                    parts.append(piece)
                    seen += 1
                    if progress and seen % 20 == 0:
                        sys.stdout.write("·")
                        sys.stdout.flush()
        except KeyboardInterrupt:
            raise Interrupted("".join(parts), first, time.perf_counter() - t0)
    return "".join(parts), first


def _plain(cfg: dict, messages: list[dict], *, timeout: int, max_tokens: int) -> tuple[str, dict]:
    """Обычный запрос целиком — запасной путь, если поток не пошёл."""
    url = cfg["base"] + "/chat/completions"
    payload = {"model": cfg["model"], "messages": messages, "stream": False,
               "temperature": cfg.get("temperature", 0.2), "max_tokens": max_tokens}
    req = urllib.request.Request(
        url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=aiagent.llm_headers(cfg), method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        raw = r.read().decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Шлюз мог ответить потоком, хотя попросили целиком. Текст рядом.
        text = aiagent.text_from_any_answer(raw)
        if text:
            return text, {}
        raise aiagent.EmptyAnswer("ответ не разобрался: " + raw[:120])
    text = ((((data.get("choices") or [{}])[0].get("message") or {}).get("content")) or "").strip()
    return text, (data.get("usage") or {})


def ask(cfg: dict, task: str, *, timeout: int, max_tokens: int, progress: bool = True,
        retries: int | None = None) -> dict:
    """Один запрос к модели: сначала потоком, дальше — с повторами.

    Устроено так не случайно. Поток даёт видимый прогресс, но шлюзы умеют его
    не держать; поэтому первая осечка потока — не приговор, а повод спросить
    обычным запросом. А вот обычный запрос повторяется уже по общему правилу
    (`ASM_LLM_RETRIES`, по умолчанию 15, с паузами и бюджетом времени): у
    посреднических шлюзов отказ через раз — норма, и одна неудача ничего не
    значит. После всех попыток — честный СБОЙ с причиной и числом попыток.
    """
    messages = _messages(task)
    attempts, budget, _pause = aiagent.retry_settings()
    if retries:
        attempts = max(1, int(retries))
    started = time.monotonic()
    t0 = time.perf_counter()
    first: float | None = None
    usage: dict = {}
    partial = ""
    text = ""
    try:
        text, first = _stream(cfg, messages, t0=t0, timeout=timeout, progress=progress)
        if not text.strip():
            raise aiagent.EmptyAnswer("пустой поток")
        estimated = True
        return _row(cfg, task, text, first, t0, usage, estimated, attempts_used=1)
    except Interrupted:
        raise
    except Exception as stream_err:  # noqa: BLE001
        # Поток не пошёл — у кого-то он просто выключен. Причину говорим
        # вслух и дальше идём обычным запросом, но уже с повторами.
        why = aiagent.why_short(stream_err)
        if progress:
            sys.stdout.write(f" [поток не пошёл: {why} — спрашиваю целиком, повторов {attempts}] ")
            sys.stdout.flush()
        # Если поток успел отдать часть текста, сохраним её на случай полного провала.
        partial = getattr(stream_err, "partial", "") or ""
        if not aiagent.transient(stream_err) and not isinstance(stream_err, aiagent.EmptyAnswer):
            # Причина не сетевая (например, «модель не найдена») — повторять нечего.
            raise Failed(f"{why} (повторять бессмысленно)", 1, partial)

    last = why
    n = 0
    while n < attempts:
        n += 1
        try:
            text, usage = _plain(cfg, messages, timeout=timeout, max_tokens=max_tokens)
            if not text.strip():
                raise aiagent.EmptyAnswer("пустой ответ")
            break
        except Interrupted:
            raise
        except Exception as e:  # noqa: BLE001
            last = aiagent.why_short(e)
            if not aiagent.transient(e):
                raise Failed(f"{last} (повторять бессмысленно)", n, partial)
            if aiagent.refused(e) and n >= aiagent.REFUSED_TRIES:
                raise Failed(f"{last} (соединение отклонено — хватит "
                             f"{aiagent.REFUSED_TRIES} проб)", n, partial)
            if n >= attempts:
                break
            if time.monotonic() - started >= budget:
                raise Failed(f"{last} (бюджет времени на повторы исчерпан)", n, partial)
            pause = aiagent.pause_after(n)
            if progress:
                sys.stdout.write(f"\n    попытка {n + 1} из {attempts} ({last}) через {pause:.0f} с… ")
                sys.stdout.flush()
            time.sleep(pause)
    else:
        n = attempts
    if not text.strip():
        raise Failed(f"{last} (попыток: {n})", n, partial)
    estimated = not usage
    return _row(cfg, task, text, first, t0, usage, estimated, attempts_used=n)


def _row(cfg: dict, task: str, text: str, first, t0: float, usage: dict,
         estimated: bool, *, attempts_used: int) -> dict:
    """Собрать строку результата из полученного текста."""
    dt = time.perf_counter() - t0
    text = text.strip()
    tokens_in = int(usage.get("prompt_tokens") or 0) or _estimate_tokens(task)
    tokens_out = int(usage.get("completion_tokens") or 0) or _estimate_tokens(text)
    low = text.lower()
    return {"text": text, "secs": dt, "first": first,
            "tokens_in": tokens_in, "tokens_out": tokens_out,
            "estimated": bool(estimated), "attempts": attempts_used,
            "refusals": [m for m in REFUSAL if m in low],
            "linux": [t.strip() for t in LINUX_TRACES if t in low],
            "fences": text.count("```") // 2}


def verdict(row: dict) -> str:
    """Короткая строка для сводки. Без вранья: сомнение так и называется."""
    if row.get("error"):
        return "СБОЙ: " + row["error"][:60]
    bits = []
    if row["refusals"]:
        bits.append(f"отказ? ({row['refusals'][0]})")
    if row["fences"]:
        bits.append(f"код: {row['fences']} блок(ов)")
    if not bits:
        bits.append("ответ без явных признаков отказа")
    if row["linux"]:
        bits.append("Linux: " + ", ".join(row["linux"][:3]))
    return "; ".join(bits)


def _cell_tokens(row: dict) -> str:
    nums = f"{row['tokens_in']}+{row['tokens_out']}"
    return "≈" + nums if row.get("estimated") else nums


def _summary(rows: list[dict], tasks: list[Path], interrupted: bool) -> str:
    lines = ["# Сводка A/B-пробы", "",
             f"Когда: {time.strftime('%d.%m.%Y %H:%M')}",
             f"Задания: {', '.join(t.name for t in tasks)}",
             f"Планка: {GEMMA_LINE}", ""]
    if interrupted:
        lines += ["> Прогон остановлен оператором (Ctrl+C). Ниже — то, что успело собраться.", ""]
    lines += ["| модель | задание | до 1-го слова | всего | токены вх+вых | блоков кода | признаки отказа | Linux-команды |",
              "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if r.get("error"):
            short = r["error"].split("{")[0].strip().rstrip(":") or r["error"]
            lines.append(f"| {r['model']} | {r['task']} | — | — | — | — | СБОЙ: {short[:60]} | — |")
            continue
        first = f"{r['first']:.0f} с" if r.get("first") else "—"
        note = "прервано вами (часть ответа)" if r.get("partial") else \
            (", ".join(r["refusals"]) or "нет")
        lines.append("| {m} | {t} | {f} | {s:.0f} с | {tok} | {fc} | {r} | {l} |".format(
            m=r["model"], t=r["task"], f=first, s=r["secs"], tok=_cell_tokens(r),
            fc=r["fences"], r=note, l=", ".join(r["linux"][:3]) or "нет"))
    total_out = sum(r.get("tokens_out") or 0 for r in rows)
    total_in = sum(r.get("tokens_in") or 0 for r in rows)
    est = any(r.get("estimated") for r in rows if not r.get("error"))
    lines += ["",
              f"Токенов за прогон: вход {total_in}, выход {total_out}"
              + (" (знак ≈ — оценка по символам: сервер не отдал usage)." if est else "."),
              "Расход по ключу точнее видно на странице продавца.", "",
              "**Что дальше руками:** раскладка ловушек делается глазами по разбору в задании "
              "(машина здесь соврёт). Для «солянки» — `python3 tools/check-big.py --file <ответ>`."]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="A/B-проба моделей на наших заданиях")
    ap.add_argument("--models", default="claude-opus-5.5,gpt-6-sol,claude-opus-5-thinking",
                    help="через запятую; имена — как у продавца ключа")
    ap.add_argument("--task", action="append", default=None,
                    help="файл задания (можно несколько раз); по умолчанию два наших")
    ap.add_argument("--out", default=None, help="куда складывать (по умолчанию reports/ab/<время>)")
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("ASM_LLM_TIMEOUT", "60")) + 240,
                    help="терпение на один ответ, с (по умолчанию с запасом)")
    ap.add_argument("--max-tokens", type=int, default=int(os.environ.get("ASM_AB_MAX_TOKENS", "6000")))
    ap.add_argument("--repeat", type=int, default=1, help="прогонов на модель и задание")
    ap.add_argument("--retries", type=int, default=0,
                    help="попыток на ответ (по умолчанию из ASM_LLM_RETRIES, 15)")
    args = ap.parse_args()

    cfg0 = aiagent.config()
    if not cfg0["base"] or not cfg0["key"]:
        print("для пробы нужны адрес и ключ — задайте их в этом окне:")
        print(_env_hint())
        return 2

    tasks = args.task or [str(ROOT / "knowledge" / "prompts" / "hard-task-for-model.md"),
                          str(ROOT / "knowledge" / "prompts" / "hard-task-with-facts-for-model.md")]
    tasks = [Path(t) for t in tasks]
    for t in tasks:
        if not t.exists():
            print(f"нет файла задания: {t}")
            return 2
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    stamp = time.strftime("%Y-%m-%d-%H%M")
    out = Path(args.out) if args.out else ROOT / "reports" / "ab" / stamp
    out.mkdir(parents=True, exist_ok=True)

    print(f"задания: {', '.join(t.name for t in tasks)}")
    print(f"модели:  {', '.join(models)}")
    print(f"складываю: {out}")
    attempts, budget, _p = aiagent.retry_settings()
    if args.retries:
        attempts = max(1, args.retries)
    print(f"планка для сравнения — {GEMMA_LINE}")
    print(f"повторов на ответ: {attempts} (бюджет {budget:.0f} с, паузы с ростом). "
          f"Настроить: ASM_LLM_RETRIES, ASM_LLM_RETRY_BUDGET, ASM_LLM_RETRY_PAUSE")
    print("ответ читается потоком: точки = слова идут. Ctrl+C останавливает аккуратно.")
    print()

    rows: list[dict] = []
    interrupted = False
    try:
        for model in models:
            cfg = dict(cfg0, model=model)
            mdir = out / safe(model)
            mdir.mkdir(parents=True, exist_ok=True)
            for t in tasks:
                text = t.read_text(encoding="utf-8")
                for run in range(1, max(1, args.repeat) + 1):
                    name = t.stem + (f"-прогон{run}" if args.repeat > 1 else "")
                    print(f"→ {model} × {t.stem}"
                          + (f" (прогон {run})" if args.repeat > 1 else "") + " … ",
                          end="", flush=True)
                    row = {"model": model, "task": t.stem, "run": run}
                    try:
                        res = ask(cfg, text, timeout=args.timeout, max_tokens=args.max_tokens,
                                  retries=args.retries or None)
                        row.update(res)
                        first = f", первое слово {res['first']:.0f} с" if res.get("first") else ""
                        tries = "" if res.get("attempts", 1) == 1 else f"; попыток {res['attempts']}"
                        print(f" готово за {res['secs']:.0f} с{first}{tries}; токенов {_cell_tokens(res)}")
                        body = (f"# {model} × {t.stem}\n\n"
                                f"*{time.strftime('%d.%m.%Y %H:%M')}; ответ {res['secs']:.0f} с"
                                + (f", первое слово {res['first']:.0f} с" if res.get("first") else "")
                                + tries
                                + f"; токены вход/выход: {_cell_tokens(res)}"
                                + (" (оценка)" if res.get("estimated") else "")
                                + f"; маркеры отказа: {', '.join(res['refusals']) or 'нет'}*\n\n---\n\n"
                                + res["text"] + "\n")
                    except Failed as f:
                        short = f.why if "попыток:" in f.why else f"{f.why} (попыток: {f.attempts})"
                        row["error"] = short
                        row["attempts"] = f.attempts
                        print(short[:110])
                        body = f"# {model} × {t.stem}\n\nСБОЙ: {short}\n"
                        if f.partial.strip():
                            # Часть ответа всё-таки пришла — терять её незачем.
                            row["text"] = f.partial.strip()
                            body += ("\n*Поток успел отдать часть ответа до сбоя:*\n\n---\n\n"
                                     + f.partial.strip() + "\n")
                    except urllib.error.HTTPError as e:
                        detail = ""
                        try:
                            detail = e.read().decode("utf-8", "replace")[:300]
                        except Exception:  # noqa: BLE001
                            detail = ""
                        row["error"] = f"HTTP {e.code}: {detail or e.reason}"
                        print(row["error"][:90])
                        body = f"# {model} × {t.stem}\n\nСБОЙ: {row['error']}\n"
                    except Interrupted as stop:
                        # Прервали посреди ответа: часть слов уже пришла — сохраняем
                        # её отдельным файлом и только потом останавливаемся.
                        part = stop.partial.strip()
                        row.update({"partial": True, "text": part, "secs": stop.secs,
                                    "first": stop.first, "tokens_in": _estimate_tokens(text),
                                    "tokens_out": _estimate_tokens(part),
                                    "estimated": True, "refusals": [], "linux": [], "fences": 0})
                        (mdir / f"{name}.md").write_text(
                            f"# {model} × {t.stem}\n\n*Остановлено вами (Ctrl+C) через "
                            f"{stop.secs:.0f} с. Ниже — то, что успело прийти.*\n\n---\n\n"
                            + part + "\n", encoding="utf-8")
                        rows.append(row)
                        raise
                    except Exception as e:  # noqa: BLE001
                        row["error"] = f"{type(e).__name__}: {e}"
                        print(row["error"][:90])
                        body = f"# {model} × {t.stem}\n\nСБОЙ: {row['error']}\n"
                    (mdir / f"{name}.md").write_text(body, encoding="utf-8")
                    rows.append(row)
    except KeyboardInterrupt:
        interrupted = True
        print()
        print("остановлено вами (Ctrl+C). Собранное сохраню и посчитаю — ничего не потеряется.")

    summary = _summary(rows, tasks, interrupted)
    (out / "СВОДКА.md").write_text(summary, encoding="utf-8")
    print()
    print(summary)
    print(f"ответы и сводка: {out}")
    print("ключ никуда не записан — он был только в окружении.")
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
