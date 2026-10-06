# -*- coding: utf-8 -*-
"""Бюджеты работ: рамка, которая считает себя сама и подстраивается под ситуацию.

Решение оператора (06.10.2026): бюджеты «нужно подстраивать под ситуацию», и
«оно само считает и подстраивается». Значит, это не форма с цифрами, которые
оператор вбивает руками и потом забывает, а живая оценка: сколько объект может
выдержать и сколько нужно нам, чтобы дойти до цели.

Из чего собирается предложение (при открытии сессии):

* **срок** — жёсткий дедлайн сессии: ближе срок — выше темп;
* **размер области** — сколько адресов в договоре: большой периметр не обойти
  на тихом темпе, но и «долбить» его нельзя;
* **критичность заказчика** — из реестра (если помечен как критичный, шум
  сжимается: простой у него дороже нашей скорости);
* **режим** — `safe` (тихий) или `combat` (боевой): тот же периметр, разный темп;
* **прошлые сессии по объекту** — если по нему уже работали, темп можно взять
  спокойнее: первое впечатление уже собрано, торопиться некуда.

Дальше бюджет живёт: **супервизор** считает шаги, шум и хосты, а по итогам
последних шагов бюджет **сам сжимается или расширяется** — в пределах жёстких
границ, записанных при открытии сессии. Каждое изменение — в журнал аудита с
причиной словами; оператор видит и текущий бюджет, и почему он такой.

Чего бюджет НЕ делает:

* **не отменяет одобрение** там, где оно нужно по рамкам (§27.3) и не снимает
  запреты ворот; бюджет — про темп, а не про разрешения;
* **не считает себя «хозяином» окна работ**: дедлайн сессии и кнопка СТОП
  сильнее бюджета;
* **не расширяется выше границ**, записанных при открытии: «подстроиться» —
  это шаг внутри рамки, а не выход из неё.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone

from . import store
from .settings import current_settings

# Вес шума шага: «шум» — это запросы к объекту. Низкий — одиночные запросы,
# средний — серии, высокий — сканирование. Числа не «на глаз»: они дают
# отношение 1:3:9, то есть высокий шаг стоит как девять тихих.
NOISE_WEIGHT = {"низкий": 1, "средний": 3, "высокий": 9, "": 3}

# Границы «подстройки»: во сколько раз бюджет может уйти от предложенного.
# Вниз — до половины (тише всегда можно), вверх — до двойного (но не больше).
SHRINK_MIN = 0.5
GROW_MAX = 2.0
FLOOR = {"hosts": 1, "steps_per_hour": 2, "noise_per_hour": 6, "files_at_once": 1}


def _now_ts() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _scope_size() -> int:
    """Сколько адресов в согласованной области договора."""
    settings = current_settings()
    configured_scope = (settings.get("ASM_SCOPE", "") if settings is not None
                        else os.environ.get("ASM_SCOPE", ""))
    raw = (store.kv_get("scope") or "") + " " + str(configured_scope or "")
    n = 0
    for tok in re.split(r"[,\s;]+", raw):
        tok = tok.strip()
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?", tok):
            if "/" in tok:
                try:
                    n += max(1, 2 ** (32 - int(tok.split("/")[1])))
                except ValueError:
                    n += 1
            else:
                n += 1
        elif re.fullmatch(r"[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}", tok.lower()):
            n += 1
    return n


def propose(session_id: int) -> dict:
    """Что объект может выдержать и что нужно нам — словами и цифрами.

    Возвращает бюджет и **основание** (`why`) — без него цифры неоткуда взять,
    и через неделю никто не вспомнит, почему стояло именно столько.
    """
    sess = store.agent_session(session_id)
    if not sess:
        return {"ok": False, "why": f"сессии {session_id} нет"}
    sess = dict(sess)
    t = store.target(sess.get("target_id") or 0)
    t = dict(t) if t else {}
    why: list[str] = []

    # --- срок
    hours = 24.0
    dl = str(sess.get("deadline") or "")
    if dl:
        try:
            when = datetime.fromisoformat(dl.replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            hours = max(1.0, (when - datetime.now(timezone.utc)).total_seconds() / 3600)
            why.append(f"до срока {round(hours, 1)} ч")
        except ValueError:
            why.append("срок задан, но не разобран — берём сутки")

    # --- область
    size = _scope_size()
    if size:
        why.append(f"в области {size} адрес(ов)")
    else:
        why.append("область не задана — считаем по одному адресу цели")

    # --- критичность заказчика
    crit = ""
    try:
        reg = store.registry_get(str(t.get("value") or "")) or {}
        crit = str(reg.get("criticality") or "").lower()
    except Exception:  # noqa: BLE001 — реестр не обязателен
        crit = ""
    if crit:
        why.append(f"критичность заказчика: {crit}")

    # --- режим и прошлый опыт
    try:
        from . import mode as modmod
        cur = (modmod.current() or {}).get("mode") or ""
    except Exception:  # noqa: BLE001
        cur = ""
    combat = cur == "combat"
    why.append("режим " + (cur or "по умолчанию"))
    past = 0
    try:
        past = sum(1 for s in store.agent_sessions(only_open=False)
                   if s["target_id"] == sess.get("target_id"))
    except Exception:  # noqa: BLE001
        past = 0
    if past > 1:
        why.append(f"по объекту уже было сессий: {past - 1}")

    # --- сами цифры: базовый темп от срока и области, потом поправки
    base_steps, base_noise = 6, 18
    if hours <= 4:
        base_steps, base_noise = 12, 40
        why.append("мало времени — темп выше")
    elif hours >= 72:
        base_steps, base_noise = 4, 12
        why.append("времени много — темп ниже")
    if size > 256:
        base_noise = max(base_noise, 30)
        why.append("периметр большой — шум в час выше, но не веером (>256 адресов)")
    if not combat:
        base_noise = max(FLOOR["noise_per_hour"], int(base_noise * 0.75))
        why.append("тихий режим — шум сжат")
    if crit in ("critical", "критичный", "высокая", "high"):
        base_noise = max(FLOOR["noise_per_hour"], int(base_noise * 0.6))
        base_steps = max(FLOOR["steps_per_hour"], int(base_steps * 0.75))
        why.append("критичный объект — тише и реже")

    hosts = max(2, min(6, 2 + size // 64))
    if not combat:
        hosts = max(1, hosts - 1)
    return {"ok": True, "hosts": hosts, "steps_per_hour": base_steps,
            "noise_per_hour": base_noise, "files_at_once": 1,
            "why": "; ".join(why)}


def ensure(session_id: int, *, operator: str = "") -> dict:
    """Взять бюджет сессии; нет — предложить и записать."""
    row = store.one("SELECT * FROM agent_budget WHERE session_id=?", (session_id,))
    if row:
        return _view(dict(row))
    p = propose(session_id)
    if not p.get("ok"):
        return p
    store.ex("INSERT OR REPLACE INTO agent_budget(session_id, hosts, steps_per_hour, "
             "noise_per_hour, files_at_once, bounds, usage, why, note, updated_at) "
             "VALUES (?,?,?,?,?,?,?,?,?,?)",
             (session_id, p["hosts"], p["steps_per_hour"], p["noise_per_hour"],
              p["files_at_once"],
              json.dumps({"base": {"hosts": p["hosts"],
                                   "steps_per_hour": p["steps_per_hour"],
                                   "noise_per_hour": p["noise_per_hour"]},
                          "grow_max": GROW_MAX, "shrink_min": SHRINK_MIN}),
              json.dumps({"steps": 0, "noise": 0, "hosts": [], "since": _now_ts(),
                          "warns": 0}), p["why"], "", store.now()))
    store.audit("agent_budget_set", {"session": session_id, "hosts": p["hosts"],
                                     "steps_per_hour": p["steps_per_hour"],
                                     "noise_per_hour": p["noise_per_hour"],
                                     "why": p["why"]})
    if operator:
        store.agent_note(session_id, store.NOTE_EVENT,
                         "бюджет сессии: " + _line(p) + f" (основание: {p['why']})",
                         source="агент")
    return _view(dict(store.one("SELECT * FROM agent_budget WHERE session_id=?", (session_id,))))


def _line(b: dict) -> str:
    return (f"хостов {b['hosts']}, шагов в час {b['steps_per_hour']}, "
            f"шум в час {b['noise_per_hour']}, файлов на объекте {b['files_at_once']}")


def _view(row: dict) -> dict:
    try:
        row["bounds"] = json.loads(row.get("bounds") or "{}")
    except Exception:  # noqa: BLE001
        row["bounds"] = {}
    try:
        row["usage"] = json.loads(row.get("usage") or "{}")
    except Exception:  # noqa: BLE001
        row["usage"] = {}
    row["ok"] = True
    return row


def _roll_window(session_id: int) -> dict:
    """Час — окно подсчёта. Отдельный вызов, чтобы не плодить логику в трёх местах."""
    b = store.one("SELECT usage FROM agent_budget WHERE session_id=?", (session_id,))
    if not b:
        return {}
    try:
        u = json.loads(b["usage"] or "{}")
    except Exception:  # noqa: BLE001
        u = {}
    if _now_ts() - float(u.get("since") or 0) > 3600:
        u["steps"] = 0
        u["noise"] = 0
        u["warns"] = 0
        u["since"] = _now_ts()
    return u


def set_budget(session_id: int, *, hosts: int | None = None, steps_per_hour: int | None = None,
               noise_per_hour: int | None = None, files_at_once: int | None = None,
               note: str = "", operator: str = "") -> dict:
    """Правка бюджета человеком. Границы при этом пересчитываются от новых цифр."""
    b = ensure(session_id)
    if not b.get("ok"):
        return b
    fields = {"hosts": hosts, "steps_per_hour": steps_per_hour,
              "noise_per_hour": noise_per_hour, "files_at_once": files_at_once}
    vals = {k: (int(v) if v else int(b[k])) for k, v in fields.items()}
    for k, v in vals.items():
        if v < FLOOR[k]:
            return {"ok": False, "why": f"{k}: {v} меньше предела {FLOOR[k]}"}
    bounds = {"base": vals, "grow_max": GROW_MAX, "shrink_min": SHRINK_MIN}
    store.ex("UPDATE agent_budget SET hosts=?, steps_per_hour=?, noise_per_hour=?, "
             "files_at_once=?, bounds=?, note=?, updated_at=? WHERE session_id=?",
             (vals["hosts"], vals["steps_per_hour"], vals["noise_per_hour"],
              vals["files_at_once"], json.dumps(bounds), note or b.get("note") or "",
              store.now(), session_id))
    got = _view(dict(store.one("SELECT * FROM agent_budget WHERE session_id=?", (session_id,))))
    store.audit("agent_budget_manual", {"session": session_id, "стало": _line(got),
                                        "кем": operator or "оператор", "пометка": note[:120]})
    return got


def check(session_id: int, *, step: dict | None = None) -> tuple[bool, str]:
    """Можно ли сделать этот шаг, не выйдя из бюджета. (ok, причина)."""
    b = ensure(session_id)
    if not b.get("ok"):
        return True, ""
    u = _roll_window(session_id)
    steps = int(u.get("steps") or 0)
    noise = int(u.get("noise") or 0)
    hosts = list(u.get("hosts") or [])
    if steps >= int(b["steps_per_hour"]):
        return False, (f"бюджет шагов исчерпан: {steps} за час при пределе "
                       f"{b['steps_per_hour']} — подождать или сказать «шире»: "
                       f"agent budget {session_id} --steps N")
    if step is not None:
        w = _weight(step)
        if noise + w > int(b["noise_per_hour"]):
            return False, (f"бюджет шума исчерпан: {noise}+{w} при пределе "
                           f"{b['noise_per_hour']} в час — либо подождать, либо шире: "
                           f"agent budget {session_id} --noise N")
        host = _step_host(step)
        if host and host not in hosts and len(hosts) >= int(b["hosts"]):
            return False, (f"бюджет хостов исчерпан: {len(hosts)} из {b['hosts']} — "
                           f"новый хост ({host}) требует решения оператора: "
                           f"agent budget {session_id} --hosts N")
        if _places_file(step):
            from . import handover
            left = len(handover.outstanding(session_id))
            if left >= int(b["files_at_once"]):
                return False, (f"на объекте уже {left} незакрытых файл(ов) — сначала уборка "
                               f"(пакет передачи), потом следующий файл")
    return True, ""


def spend(session_id: int, step: dict, *, executed: bool = True) -> dict:
    """Записать расход. Вызывается кодом после выполнения шага."""
    b = ensure(session_id)
    if not b.get("ok"):
        return b
    u = _roll_window(session_id)
    u["steps"] = int(u.get("steps") or 0) + (1 if executed else 0)
    u["noise"] = int(u.get("noise") or 0) + (_weight(step) if executed else 0)
    host = _step_host(step)
    hosts = list(u.get("hosts") or [])
    if host and host not in hosts:
        hosts.append(host)
    u["hosts"] = hosts[:200]
    store.ex("UPDATE agent_budget SET usage=?, updated_at=? WHERE session_id=?",
             (json.dumps(u), store.now(), session_id))
    return review(session_id)


def review(session_id: int) -> dict:
    """Подстроить бюджет под ситуацию: тихо и полезно — можно больше, шумно — тише.

    Ничего не спрашивает: решение оператора 06.10.2026 — «оно само считает и
    подстраивается». Но каждое изменение пишется в журнал с причиной, а границы
    (вниз — половина, вверх — двойной) стоят в `bounds` и не переступаются.
    """
    b = ensure(session_id)
    if not b.get("ok"):
        return b
    u = _roll_window(session_id)
    bounds = b.get("bounds") or {}
    base = bounds.get("base") or {}
    if not base:
        return b
    steps, noise = int(u.get("steps") or 0), int(u.get("noise") or 0)
    warns = int(u.get("warns") or 0)
    share_steps = steps / max(1, int(b["steps_per_hour"]))
    share_noise = noise / max(1, int(b["noise_per_hour"]))
    new: dict = {}
    reason = ""
    if warns >= 2 or share_noise > 0.9:
        new = {"noise_per_hour": int(max(FLOOR["noise_per_hour"],
                                         int(b["noise_per_hour"]) * 0.8)),
               "steps_per_hour": int(max(FLOOR["steps_per_hour"],
                                         int(b["steps_per_hour"]) * 0.8))}
        reason = (f"сжимаю: шума {noise} из {b['noise_per_hour']} за час, "
                  f"предупреждений ворот {warns}")
    elif share_steps < 0.25 and share_noise < 0.25 and steps >= 2:
        cap_noise = int(base.get("noise_per_hour") or b["noise_per_hour"]) * bounds.get("grow_max", GROW_MAX)
        cap_steps = int(base.get("steps_per_hour") or b["steps_per_hour"]) * bounds.get("grow_max", GROW_MAX)
        new = {"noise_per_hour": int(min(cap_noise, max(1, int(b["noise_per_hour"])) * 1.25)),
               "steps_per_hour": int(min(cap_steps, max(1, int(b["steps_per_hour"])) * 1.25))}
        reason = (f"расширяю: идём тихо ({noise} из {b['noise_per_hour']}, "
                  f"шагов {steps} из {b['steps_per_hour']}) и без предупреждений")
    if not new:
        return b
    # Границы: вниз не ниже половины предложенного, вверх не выше двойного.
    for k in ("noise_per_hour", "steps_per_hour"):
        lo = max(FLOOR[k], int(base.get(k) or b[k]) * bounds.get("shrink_min", SHRINK_MIN))
        hi = int(base.get(k) or b[k]) * bounds.get("grow_max", GROW_MAX)
        new[k] = int(max(lo, min(hi, new[k])))
        if new[k] == int(b[k]):
            new = {}
            break
    if not new:
        return b
    for k in ("noise_per_hour", "steps_per_hour"):
        store.ex(f"UPDATE agent_budget SET {k}=?, updated_at=? WHERE session_id=?",
                 (int(new[k]), store.now(), session_id))
    store.audit("agent_budget_adjusted", {"session": session_id, "стало": new,
                                          "причина": reason})
    store.agent_note(session_id, store.NOTE_EVENT,
                     f"бюджет подстроен: {reason}", source="агент")
    return _view(dict(store.one("SELECT * FROM agent_budget WHERE session_id=?", (session_id,))))


def note_warn(session_id: int) -> None:
    """Предупреждение ворот — сигнал, что темп, возможно, велик."""
    u = _roll_window(session_id)
    u["warns"] = int(u.get("warns") or 0) + 1
    store.ex("UPDATE agent_budget SET usage=? WHERE session_id=?",
             (json.dumps(u), session_id))


def _weight(step: dict) -> int:
    """Вес шума шага. Берётся из каталога; у свободного шага — по его же описанию."""
    if isinstance(step, (dict, )) and step.get("action_id"):
        pass
    try:
        from . import agent as agmod
        st = step if isinstance(step, dict) else dict(step)
        a = agmod.BY_ID.get(st.get("action_id") or "") or {}
        noise = a.get("noise") or ""
        if not noise and st.get("noise"):
            noise = str(st["noise"])
        return NOISE_WEIGHT.get(noise, 3)
    except Exception:  # noqa: BLE001
        return 3


def _step_host(step) -> str:
    st = step if isinstance(step, dict) else dict(step)
    try:
        p = st.get("params")
        p = json.loads(p) if isinstance(p, str) else (p or {})
    except Exception:  # noqa: BLE001
        p = {}
    for k in ("host", "target", "hosts"):
        v = p.get(k)
        if isinstance(v, list) and v:
            return str(v[0])
        if str(v or "").strip():
            return str(v).strip()
    return ""


def _places_file(step) -> bool:
    st = step if isinstance(step, dict) else dict(step)
    try:
        from . import agent as agmod
        a = agmod.BY_ID.get(st.get("action_id") or "") or {}
        return bool(a.get("places"))
    except Exception:  # noqa: BLE001
        return False


def text(session_id: int) -> str:
    """Бюджет для человека: цифры, расход и почему так."""
    b = ensure(session_id)
    if not b.get("ok"):
        return str(b.get("why") or "бюджет недоступен")
    u = _roll_window(session_id)
    return (f"бюджет сессии #{session_id}: {_line(b)}\n"
            f"  расход за текущий час: шагов {int(u.get('steps') or 0)} из {b['steps_per_hour']}, "
            f"шума {int(u.get('noise') or 0)} из {b['noise_per_hour']}, "
            f"хостов {len(u.get('hosts') or [])} из {b['hosts']}\n"
            f"  основание: {b.get('why') or '—'}\n"
            f"  менять: python3 app.py agent budget {session_id} --steps N --noise N --hosts N")
