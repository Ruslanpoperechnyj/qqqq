#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Пробы чужого шлюза: есть ли ручки (effort, fast) и что за начинка за вывеской.

Зачем. У Claude Opus 5.5 (Anthropic, 22.09.2026) есть ровно одна ручка —
`output_config.effort` (low/medium/high/xhigh/max, по умолчанию medium), и есть
«фаст мод» (`speed: "fast"`, только первый-партийный Claude API). Мы работаем
через OpenAI-совместимый шлюз перекупщика, и **доходят ли туда эти поля — не
написано нигде**. Здесь это проверяется, причём двумя разными способами.

Способ 1 — канарейка неверного значения. Посылаем заведомо недопустимое
(например `effort: "ultra"`). Если поле долетает до апстрима, тот отвечает 400
«не бывает такого»; если шлюз поле глотает — приходит 200. Это про **наличие
двери**, а не про то, что за ней.

Способ 2 — замер действенности. Одна и та же «думающая» задача с effort=low и
effort=max. Живая ручка меняет число выходных токенов (у Anthropic думание
оплачивается как выход) и время; проглоченная — не меняет ничего. Это про то,
что **дверь не бутафория**.

Двери бывают две. У OpenAI-совместимого фасада поля `output_config` обычно не
ходят — они не из его словаря (живой прогон 04.10.2026 это подтвердил: канарейки
вернули 200, а апстрим обязан ругаться). Но многие шлюзы держат и вторую,
Anthropic-совместимую дверь (`POST /v1/messages`), где эти поля родные. Группа
`anthropic` стучится именно туда — и туда же отдельно проверяет `thinking`.

Третий, побочный набор — из документации: у настоящего 5.5 часть полей ОБЯЗАНА
давать ошибку (thinking нельзя выключить, sampling — только дефолты, выход ≤128K).
Но это не «паспорт» модели, а термометр: сравнивать два замера между собой,
особенно в день серьёзной работы.

Порядок работы (ключ берётся из окружения и не печатается):
    source ~/.asm-cloud.sh
    python3 bin/llm-probe.py                      # все пробы
    python3 bin/llm-probe.py --group knobs        # только ручки (главное)
    python3 bin/llm-probe.py --only base,effort-max
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from asm import aiagent  # noqa: E402 — общий транспорт: UA и разбор потока
except Exception:  # noqa: BLE001 — проба должна работать и в отрыве от пакета
    aiagent = None

TINY = "Ответь ровно одним словом: ок"
# «Думающая» задача: маленькая, но с шагами — на ней effort либо виден, либо нет.
THINKY = ("Не спеша: сколько чисел от 1 до 100 делятся на 3 или на 5, но не "
          "делятся на 15? Ответь одним числом.")
WHO = ("Одной строкой, без пояснений: какая ты модель, какой у тебя размер "
       "контекста и какая дата отсечки знаний?")
CUTOFF = ("Что важного произошло 22 сентября 2026 года? Если не знаешь — так и "
          "скажи. Двумя предложениями.")

PROMPTS = {"tiny": TINY, "thinky": THINKY, "who": WHO, "cutoff": CUTOFF}

PROBES = [
    # --- группа «ручки»: долетают ли параметры и действуют ли они -----------
    {"group": "knobs", "name": "base", "what": "контроль: думающая задача, без полей",
     "extra": {}, "prompt": "thinky", "timeout": 180},
    {"group": "knobs", "name": "effort-low", "what": "output_config.effort=low",
     "extra": {"output_config": {"effort": "low"}}, "prompt": "thinky", "timeout": 180},
    {"group": "knobs", "name": "effort-max", "what": "output_config.effort=max",
     "extra": {"output_config": {"effort": "max"}}, "prompt": "thinky", "timeout": 300},
    {"group": "knobs", "name": "effort-bogus", "what": "effort=ultra: 400 = поле живое",
     "extra": {"output_config": {"effort": "ultra"}}, "prompt": "thinky", "timeout": 180},
    {"group": "knobs", "name": "reffort-high", "what": "reasoning_effort=high (стиль OpenAI)",
     "extra": {"reasoning_effort": "high"}, "prompt": "thinky", "timeout": 180},
    {"group": "knobs", "name": "reffort-bogus", "what": "reasoning_effort=ultra: канарейка",
     "extra": {"reasoning_effort": "ultra"}, "prompt": "thinky", "timeout": 180},
    {"group": "knobs", "name": "speed-fast", "what": "speed=fast + бета-заголовок",
     "extra": {"speed": "fast"}, "headers": {"anthropic-beta": "fast-mode-2026-02-01"},
     "prompt": "thinky", "timeout": 300},
    {"group": "knobs", "name": "think-off", "what": "thinking=disabled: у 5.5 это 400",
     "extra": {"thinking": {"type": "disabled"}}, "prompt": "tiny", "timeout": 120},
    {"group": "knobs", "name": "temperature", "what": "temperature=0.9: у 5.5 это 400",
     "extra": {"temperature": 0.9}, "prompt": "tiny", "timeout": 120},
    {"group": "knobs", "name": "maxout", "what": "max_tokens=200000: предел 128K",
     "extra": {"max_tokens": 200000}, "prompt": "tiny", "timeout": 120},
    # --- группа «паспорт»: термометр, не удостоверение ----------------------
    {"group": "id", "name": "who", "what": "самоназвание модели",
     "extra": {}, "prompt": "who", "timeout": 120},
    {"group": "id", "name": "cutoff", "what": "отсечка: знает ли про 22.09.2026",
     "extra": {}, "prompt": "cutoff", "timeout": 120},
    # --- вторая дверь: Anthropic-совместимый /messages ----------------------
    {"group": "anthropic", "name": "ant-base", "what": "/messages: контроль",
     "style": "anthropic", "extra": {}, "prompt": "thinky", "timeout": 180},
    {"group": "anthropic", "name": "ant-effort-low", "what": "/messages: effort=low",
     "style": "anthropic", "extra": {"output_config": {"effort": "low"}},
     "prompt": "thinky", "timeout": 180},
    {"group": "anthropic", "name": "ant-effort-max", "what": "/messages: effort=max",
     "style": "anthropic", "extra": {"output_config": {"effort": "max"}},
     "prompt": "thinky", "timeout": 300},
    {"group": "anthropic", "name": "ant-effort-bogus", "what": "/messages: effort=ultra (канарейка)",
     "style": "anthropic", "extra": {"output_config": {"effort": "ultra"}},
     "prompt": "thinky", "timeout": 180},
    {"group": "anthropic", "name": "ant-think-off", "what": "/messages: thinking=disabled",
     "style": "anthropic", "extra": {"thinking": {"type": "disabled"}},
     "prompt": "tiny", "timeout": 120},
]


def load_env() -> tuple[str, str, str]:
    """Адрес, ключ, модель — из окружения; если окно новое — из ~/.asm-cloud.sh."""
    base = (os.environ.get("ASM_LLM_BASE") or "").strip()
    key = (os.environ.get("ASM_LLM_KEY") or "").strip()
    model = (os.environ.get("ASM_LLM_MODEL") or "").strip()
    if base and key and model:
        return base.rstrip("/"), key, model
    f = Path.home() / ".asm-cloud.sh"
    if f.exists():
        vals: dict[str, str] = {}
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            n, v = line.split("=", 1)
            vals[n.strip()] = v.strip().strip('"').strip("'")
        base = base or vals.get("ASM_LLM_BASE", "") or vals.get("BASE", "")
        key = key or vals.get("ASM_LLM_KEY", "") or vals.get("KEY", "") or vals.get("TOKIFY_KEY", "")
        model = model or vals.get("ASM_LLM_MODEL", "") or vals.get("MODEL", "")
    return base.rstrip("/"), key, model


def build_request(base: str, key: str, model: str, probe: dict, prompt: str):
    """Адрес, тело и заголовки — под нужную дверь (OpenAI-фасад или Anthropic).

    Разница не косметическая: у Anthropic-двери поля `output_config` и
    `thinking` родные, у OpenAI-фасада — чужие, и он их, как правило, молча
    выкидывает. Поэтому одну и ту же ручку надо стучать в обе двери.
    """
    if probe.get("style") == "anthropic":
        url = base.rstrip("/") + "/messages"
        payload = {"model": model, "max_tokens": 64,
                   "messages": [{"role": "user", "content": prompt}]}
        hdrs = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
        if key:
            hdrs["x-api-key"] = key
    else:
        url = base.rstrip("/") + "/chat/completions"
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}],
                   "max_tokens": 64, "stream": False}
        hdrs = {"Content-Type": "application/json"}
        if key:
            hdrs["Authorization"] = "Bearer " + key
    hdrs["User-Agent"] = aiagent.ua_outward() if aiagent else (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    payload.update(probe.get("extra") or {})
    hdrs.update(probe.get("headers") or {})
    return url, payload, hdrs


def call(base: str, key: str, model: str, probe: dict, prompt: str, timeout: int):
    """Один запрос. Возвращает (код, сырой текст, ошибка транспорта, секунды)."""
    url, payload, hdrs = build_request(base, key, model, probe, prompt)
    t0 = time.time()
    status, raw, err = 0, "", ""
    try:
        req = urllib.request.Request(url,
                                     data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                     headers=hdrs, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status = int(r.status)
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = int(e.code)
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            raw = ""
    except Exception as e:  # noqa: BLE001 — наружу отдаём короткую причину
        err = f"{type(e).__name__}: {e}"
    return status, raw, err, time.time() - t0


def parse(raw: str):
    """(текст, токены_вход, токены_выход, ошибка сервера) — по возможности числа."""
    txt, tin, tout, errtxt = "", None, None, ""
    raw = (raw or "").strip()
    if not raw:
        return txt, tin, tout, errtxt
    try:
        data = json.loads(raw)
    except Exception:  # noqa: BLE001 — шлюз любит отвечать потоком
        if aiagent:
            txt = aiagent.text_from_any_answer(raw)
        return txt.replace("\n", " ")[:220], tin, tout, errtxt
    if isinstance(data, dict):
        if data.get("error"):
            e = data["error"]
            errtxt = str(e.get("message") if isinstance(e, dict) else e)[:240]
        u = data.get("usage") or {}
        if isinstance(u, dict):
            tin = u.get("prompt_tokens") or u.get("input_tokens")
            tout = u.get("completion_tokens") or u.get("output_tokens")
        if isinstance(data.get("content"), list):  # ответ Anthropic-двери
            txt = " ".join(b.get("text", "") for b in data["content"]
                           if isinstance(b, dict) and b.get("type") == "text")
        elif aiagent:
            txt = aiagent.text_from_any_answer(raw)
        else:
            try:
                txt = ((data.get("choices") or [{}])[0].get("message") or {}).get("content", "")
            except Exception:  # noqa: BLE001
                txt = ""
    return (txt or "").replace("\n", " ")[:220], tin, tout, errtxt


def _moved(got: dict, name: str):
    """Разница с контролем: (дельта токенов или None, дельта секунд)."""
    b = got.get("base") or {}
    r = got.get(name) or {}
    dth = None
    if r.get("tout") is not None and b.get("tout") is not None:
        dth = r["tout"] - b["tout"]
    return dth, ((r.get("dt") or 0) - (b.get("dt") or 0))


def verdicts(res: list[dict]) -> list[str]:
    got = {r["name"]: r for r in res}
    out: list[str] = []

    def st(n):
        return (got.get(n) or {}).get("status")

    # 1. Канарейка показывает только то, было ли значение отвергнуто.
    # 200 само по себе НЕ различает «проглочено», «нормализовано» и другую начинку.
    for name, human in (("effort-bogus", "output_config.effort"), ("reffort-bogus", "reasoning_effort")):
        if name in got:
            c = st(name)
            if c == 400:
                out.append(f"{human}: 400 на заведомо неверное значение — маршрут его отверг; "
                           "значение попало под валидацию, но по одному коду нельзя понять, шлюзом или апстримом.")
            elif c == 200:
                out.append(f"{human}: 200 на неверное значение — запрос принят, но канарейка не сработала. "
                           "Это не отличает проглатывание/нормализацию поля от другой или терпимой начинки.")
            else:
                out.append(f"{human}: код {c or '—'} — не дошли; повторить пробу.")

    # 2. Сравниваем low/max и, если есть, контроль без effort. Это наблюдение,
    # не доказательство причинности: ответы и маршрутизация могут быть недетерминированы.
    a, b = got.get("effort-low") or {}, got.get("effort-max") or {}
    base = got.get("base") or {}
    if a.get("status") == 200 and b.get("status") == 200:
        dth = None
        if a.get("tout") is not None and b.get("tout") is not None:
            dth = b["tout"] - a["tout"]
        dt = (b.get("dt") or 0) - (a.get("dt") or 0)

        if base.get("status") == 200:
            parts = []
            for name, row in (("low", a), ("max", b)):
                delta = (row["tout"] - base["tout"]
                         if row.get("tout") is not None and base.get("tout") is not None else None)
                elapsed = (row.get("dt") or 0) - (base.get("dt") or 0)
                detail = f"против base {delta:+d} выходных токенов" if delta is not None else "usage неизвестен"
                detail += f", {elapsed:+.1f} с"
                if row.get("txt") and base.get("txt"):
                    detail += ", текст отличается" if row["txt"].strip() != base["txt"].strip() else ", текст совпал"
                parts.append(f"{name}: {detail}")
            out.append("Сравнение с base: " + "; ".join(parts) +
                       ". Это сигнал для проверки, не доказательство действия effort (один замер на вариант).")

        if dth is not None and abs(dth) >= 25:
            out.append(f"effort max vs low: заметная разница в этом замере ({dth:+d} выходных токенов, "
                       f"{dt:+.1f} с); повторить на той же задаче, прежде чем считать ручку рабочей.")
        elif dt >= 10:
            out.append(f"effort max vs low: токены почти не различаются, но max шёл на {dt:+.1f} с дольше; "
                       "это слабый сигнал, нужен повтор.")
        else:
            out.append(f"effort max vs low: {dth if dth is not None else '?'} токенов, {dt:+.1f} с — "
                       "явного различия в этом замере нет; это не доказывает, что поле игнорируется.")
    elif "effort-low" in got or "effort-max" in got:
        out.append("effort: не обе пробы дали 200 — смотреть строки таблицы.")

    # 3. reasoning_effort (стиль OpenAI) против контроля.
    if st("reffort-high") == 200:
        dth, dt = _moved(got, "reffort-high")
        out.append(f"reasoning_effort: принят (200), против контроля "
                   f"{dth if dth is not None else '?'} токенов и {dt:+.1f} с — «принят» ещё не значит «применён».")

    # 4. Фаст мод.
    if st("speed-fast") == 200:
        dth, dt = _moved(got, "speed-fast")
        if dt <= -2:
            out.append(f"speed: быстрее контроля на {dt:+.1f} с — похоже, фаст мод живой; "
                       "для верности сверить повтором (это про время, а оно шумит).")
        else:
            out.append(f"speed: принят, но ускорения не видно ({dt:+.1f} с) — скорее всего "
                       "проглочен. Фаст мод вообще только у первого-партийного Claude API.")

    # 5. Поля, которые у настоящего 5.5 обязаны падать.
    for name, human in (("think-off", "thinking=disabled"), ("temperature", "temperature≠дефолт"),
                        ("maxout", "max_tokens>128K")):
        c = st(name)
        if c == 400:
            out.append(f"{name}: 400 на «{human}» — как у настоящего 5.5: поле долетает "
                       "до живого API и тот его отклоняет.")
        elif c == 200:
            out.append(f"{name}: 200 на «{human}» — запрос принят; это не доказывает, что поле применено "
                       "или отброшено: возможны нормализация или другая начинка.")
        elif name in got:
            out.append(f"{name}: код {c or '—'} — не дошли.")

    if any(r["name"] in ("who", "cutoff") for r in res):
        out.append("who / cutoff — словами в таблице: это термометр, а не паспорт. "
                   "Сверить с прошлым замером, а не с обещанием продавца.")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Пробы чужого шлюза: ручки и термометр")
    ap.add_argument("--group", default="all", choices=("all", "knobs", "id", "anthropic"),
                    help="knobs — ручки через OpenAI-фасад, anthropic — вторая дверь "
                         "/v1/messages, id — самоназвание/отсечка")
    ap.add_argument("--only", default="", help="имена проб через запятую")
    ap.add_argument("--model", default="", help="переопределить модель")
    ap.add_argument("--base", default="", help="переопределить адрес шлюза (…/v1)")
    ap.add_argument("--attempts", type=int, default=2, help="попыток на пробу (шлюз капризный)")
    args = ap.parse_args()

    base, key, model = load_env()
    base = (args.base or base).rstrip("/")
    model = args.model or model
    if not base or not model:
        print("  окружение не задано. Проверьте, что вы в том же окне, где делали export,")
        print("  и выполните:  source ~/.asm-cloud.sh   (или задайте ASM_LLM_BASE/KEY/MODEL).")
        return 2
    if key and not key.isascii():
        # Заголовки HTTP умеют только latin-1. Живой случай: ключ с кириллицей
        # давал UnicodeEncodeError на каждой пробе — выглядело как «шлюз лежит».
        print("  ключ содержит не-латинские символы — HTTP-заголовок так не умеет.")
        print("  похоже, в ASM_LLM_KEY попал не ключ (или он скопирован с лишним).")
        return 2

    todo = PROBES
    if args.group != "all":
        todo = [p for p in todo if p["group"] == args.group]
    if args.only:
        names = {n.strip() for n in args.only.split(",")}
        todo = [p for p in PROBES if p["name"] in names]
    if not todo:
        print("  нечего запускать: сверьте --group/--only")
        return 2

    print(f"== llm-probe · {base} · модель: {model}")
    print(f"   ключ: {len(key)} знаков (в вывод не попадает) · проб: {len(todo)} · "
          "только синтетика\n")
    res: list[dict] = []
    for p in todo:
        prompt = PROMPTS[p.get("prompt", "tiny")]
        attempt, status, raw, err, dt = 0, 0, "", "", 0.0
        while attempt < max(1, args.attempts):
            attempt += 1
            status, raw, err, dt = call(base, key, model, p, prompt, p.get("timeout", 120))
            if status == 200 or (400 <= status < 500):
                break
            if attempt < max(1, args.attempts):
                time.sleep(2.0)  # 5xx/обрыв — шлюз этим славится, одна повторная попытка
        txt, tin, tout, errtxt = parse(raw)
        res.append({"name": p["name"], "status": status, "dt": dt, "tin": tin, "tout": tout,
                    "txt": txt, "err": err, "errtxt": errtxt, "group": p["group"]})
        tok = f"{tin if tin is not None else '?'}/{tout if tout is not None else '?'}"
        shown = errtxt or txt or err or "—"
        note = f"  (попыток: {attempt})" if attempt > 1 else ""
        print(f"{p['name']:<17} {status or '—':>4}  {dt:6.1f} с  {tok:>9}  {shown[:100]}{note}")

    bad = [r for r in res if r["status"] not in (200, 400)]
    if bad:
        print("\n  вним.: не все пробы дошли (шлюз роняет поток — он этим известен).")
        print("  повторите:  python3 bin/llm-probe.py --only " + ",".join(r["name"] for r in bad))

    ant = [dict(r, name=r["name"][4:]) for r in res if r["name"].startswith("ant-")]
    plain = [r for r in res if not r["name"].startswith("ant-")]

    print("\n-- как читать " + "-" * 60)
    for v in verdicts(plain):
        print("  * " + v)

    if ant:
        print("\n-- вторая дверь (/v1/messages) " + "-" * 38)
        door = next((r["status"] for r in ant if r["name"] == "base"), 0)
        if door in (404, 405, 501, 0):
            print(f"  * двери нет: код {door or '—'}. Значит уровень рассуждений через "
                  "этот шлюз не выставить — остаётся просить продавца.")
        else:
            for v in verdicts(ant):
                print("  * " + v)
    print("\n  Проба стоит копейки и её не жалко повторить: (1) заведомо неверное значение —")
    print("  дверь есть или нет; (2) low против max на думающей задаче — дверь живая или")
    print("  бутафория; (3) повторить в день серьёзной работы — не сменилась ли начинка.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
