# -*- coding: utf-8 -*-
"""Режим работ: набор переключателей одним словом.

Зачем это нужно. Настроек в коде 128, и для настоящей работы их надо
согласовать между собой: профиль скоростей, планировщик, скрытность, шумные
этапы. Собирать это вручную каждый раз — гарантированная ошибка «забыл
включить». Режим хранится в базе, а не в переменных окружения: в PowerShell
(и в Git Bash из него) переменные между командами не сохраняются, так что
настройка «на сессию» там просто не живёт.

Два режима:

  safe    — как инструмент ведёт себя по умолчанию: щадящие скорости,
            планировщик по правилам, скрытность выключена, шумные этапы
            выключены. Ничего не трогаем без нужды.
  combat  — рабочий, «боевой»: скорости pentest-профиля, план строит модель
            с подстраховкой правилами, скрытность в режиме «предупреждать»
            (require нельзя без прокси — см. ниже), очереди на подтверждение
            разрешены, включая необратимые шаги: их всё равно не выполнить
            без явного одобрения человека.

Чего режим НЕ делает и не может:

* не снимает ворота одобрения — они в коде (`agent.execute`), а не в настройках;
* не включает `ASM_STEALTH=require`: он запрещает выход без прокси, а прокси
  у нас нет; `warn` говорит о неприкрытом выходе, не блокируя работу;
* не включает шумные этапы (перебор путей `ASM_FFUF`, сети организации
  `ASM_ESTATE_ASN`, проверку живости ключей `ASM_TRUFFLEHOG_VERIFY`) — это
  решения на конкретную работу, а не «навсегда»;
* не задаёт адрес и имя модели: их знает только он (`ASM_LLM_BASE`).

Явно заданная настройка всегда важнее режима: если ключ уже есть в окружении
(например, через `--set`), режим его не переписывает.
"""
from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request

from . import store
from .settings import current_settings
from .settings_compat import call_with_settings

KV_KEY = "mode"

# Значения подобраны так, чтобы «боевой» отличался от «тихого» ровно тем,
# чем нужно для работы, и ничем больше.
PRESETS: dict[str, dict[str, str]] = {
    "safe": {
        "ASM_PROFILE": "safe",
        "ASM_PLANNER": "rules",
        "ASM_STEALTH": "off",
        "ASM_ACTIVE_SCAN": "1",
        "ASM_FFUF": "0",
        "ASM_QUEUE_IMPACT": "1",
    },
    "combat": {
        "ASM_PROFILE": "pentest",
        "ASM_PLANNER": "both",
        "ASM_STEALTH": "warn",
        "ASM_ACTIVE_SCAN": "1",
        "ASM_FFUF": "0",
        "ASM_QUEUE_IMPACT": "1",
    },
}

ALIASES = {
    "safe": "safe", "тихий": "safe", "спокойный": "safe", "default": "safe",
    "combat": "combat", "боевой": "combat", "бои": "combat", "work": "combat",
}

TITLE = {
    "safe": "тихий (по умолчанию): щадящие скорости, план по правилам",
    "combat": "боевой: скорости pentest, план моделью, предупреждать о неприкрытом выходе",
}


def normalize(name: str) -> str:
    return ALIASES.get((name or "").strip().lower(), "")


def preset_values(name: str) -> dict[str, str]:
    """Вернуть копию preset mapping без чтения БД и побочных эффектов."""
    normalized = normalize(name)
    return dict(PRESETS[normalized]) if normalized else {}


def stored_preset(st=None) -> tuple[str, dict[str, str]]:
    """Прочитать сохранённый режим и вернуть его значения, не меняя env.

    `st` позволяет вызывающему коду передать store-compatible объект; при
    отсутствии аргумента подключается штатное хранилище, как в legacy API.
    """
    db = st if st is not None else store
    if st is None:
        try:
            db.connect()
        except Exception:  # noqa: BLE001 — база может быть ещё не создана
            return "", {}
    try:
        name = normalize(db.kv_get(KV_KEY))
    except Exception:  # noqa: BLE001 — отсутствие/ошибка store не меняет конфиг
        return "", {}
    return name, preset_values(name)


# ---------------------------------------------------------------------------
# Применение к окружению (legacy adapter; новые consumers берут mapping)

def load_into_env(st=None) -> str:
    """Выставить настройки режима в окружение ДО импорта рабочих модулей.

    Модули (engines, stealth, scan) читают свои настройки один раз при импорте,
    поэтому режим обязан попасть в окружение раньше них. Явно заданные ключи
    не перезаписываются: решение человека важнее режима.
    """
    name, values = stored_preset(st)
    if not name:
        return ""
    for k, v in values.items():
        os.environ.setdefault(k, v)
    os.environ["ASM_MODE"] = name
    return name


def current() -> dict:
    """Что сейчас: записанный режим и значения из snapshot текущей операции."""
    name = normalize(store.kv_get(KV_KEY))
    keys = sorted({k for p in PRESETS.values() for k in p})
    settings = current_settings()
    values = {}
    for key in keys:
        value = (settings.get(key, "") if settings is not None
                 else os.environ.get(key, ""))
        if isinstance(value, bool):
            value = "1" if value else "0"
        values[key] = "" if value is None else str(value)
    return {"mode": name, "title": TITLE.get(name, "не задан — работают значения по умолчанию"),
            "keys": keys, "env": values}


def apply(name: str, *, force: bool = False, operator: str = "",
          checks: dict | None = None) -> dict:
    """Включить режим. Перед включением — проверка готовности машины.

    Без `force` режим не включается, пока есть блокеры: «боевой» на неготовой
    машине — это красивый отчёт о работе, которой не было. `force` разрешён
    осознанно и пишется в журнал аудита вместе с причинами.
    """
    nm = normalize(name)
    if not nm:
        return {"ok": False, "error": f"неизвестный режим: {name}",
                "known": sorted(set(ALIASES.values()))}
    # Проверка готовности нужна только для боевого режима: он поднимает
    # скорости и включает планировщик. Возврат в тихий режим ничего не
    # поднимает, и требовать для него готовности незачем — иначе откат
    # оказывается заблокирован ровно тогда, когда он нужнее всего.
    if nm != "combat":
        store.kv_set(KV_KEY, nm)
        for k, v in preset_values(nm).items():
            os.environ[k] = v
        os.environ["ASM_MODE"] = nm
        store.audit("mode_set", {"mode": nm, "operator": operator, "forced": False,
                                 "blockers": [], "warnings": []})
        return {"ok": True, "mode": nm, "title": TITLE.get(nm, ""),
                "blockers": [], "warnings": [], "forced": False}
    ch = checks if checks is not None else check()
    blockers, warns = ch.get("blockers") or [], ch.get("warnings") or []
    if blockers and not force:
        return {"ok": False, "mode": nm, "blockers": blockers, "warnings": warns,
                "error": "машина не готова к боевому режиму (см. блокеры)"}
    store.kv_set(KV_KEY, nm)
    for k, v in preset_values(nm).items():
        os.environ[k] = v
    os.environ["ASM_MODE"] = nm
    store.audit("mode_set", {"mode": nm, "operator": operator,
                             "forced": bool(blockers and force),
                             "blockers": blockers, "warnings": warns})
    return {"ok": True, "mode": nm, "title": TITLE.get(nm, ""),
            "blockers": blockers, "warnings": warns,
            "forced": bool(blockers and force)}


# ---------------------------------------------------------------------------
# Проверка готовности

def _kill_state() -> tuple[str, str]:
    """Кнопка СТОП на этой машине: живой самопроверкой, а не по коду.

    Проверяем ровно то, от чего зависит безопасность работы: если СТОП нажать,
    воздействие прекратится. Это дорогая проверка (поднимает и убивает
    процессы), поэтому она часть проверки готовности, а не чего-то ещё.
    """
    try:
        from . import engines
        res = engines.selftest()
        if res.get("ok"):
            return "ok", "кнопка СТОП: процессы снимаются целиком, проверено здесь"
        return "blocker", ("кнопка СТОП не сработала как надо: "
                           + "; ".join(res.get("notes") or []) or "см. приложение selftest")
    except Exception as e:  # noqa: BLE001
        return "warn", f"самопроверку кнопки провести не удалось: {e}"


def _tools_state() -> tuple[str, str]:
    try:
        from . import engines
        st = call_with_settings(engines.available, settings=current_settings())
    except Exception as e:  # noqa: BLE001
        return "warn", f"арсенал не опрошен: {e}"
    core = ("nuclei", "httpx", "naabu")
    miss_core = [e for e in core if not (st.get(e) or {}).get("installed")]
    all_eng = [k for k, v in st.items() if isinstance(v, dict) and "installed" in v]
    miss = [k for k in all_eng if not st[k]["installed"]]
    if miss_core:
        return "blocker", "нет основных движков: " + ", ".join(miss_core)
    if miss:
        return "warn", "не установлены: " + ", ".join(miss)
    return "ok", f"арсенал на месте: {len(all_eng)} движков"


def _panel_state() -> tuple[str, str]:
    """Панель: уже запущена или порт под неё свободен.

    Это не «панель обязана работать»: вести работу можно и из терминала.
    Проверка нужна, чтобы запуск не упал на занятом порте — на Windows его
    часто держит прежняя панель, а окно консоли уже закрыто.
    """
    settings = current_settings()
    port_value = (settings.get("ASM_PORT", 8000) if settings is not None
                  else os.environ.get("ASM_PORT", "8000"))
    port = int(port_value or 8000)
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/agent/state",
                                     headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as r:  # noqa: S310
            body = r.read(200)
        if b"stopped" in body:
            return "ok", f"панель уже отвечает: http://127.0.0.1:{port}"
    except Exception:  # noqa: BLE001 — не отвечает: проверим порт
        pass
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return "ok", f"порт {port} свободен — панель запустится: python3 app.py serve"
    except OSError:
        return "warn", (f"порт {port} занят другой программой: панель не "
                        f"поднимется, поможет «python3 app.py serve --port {port + 1}»")
    finally:
        s.close()


def _probe_model(base: str, timeout: float = 3.0) -> bool:
    """Дотягиваемся ли до модели. Без этого «боевой» будет тихо работать правилами."""
    if not base:
        return False
    url = base.rstrip("/") + ("/api/tags" if ":11434" in base or base.endswith("/api") else "/models")
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return 200 <= r.status < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _model_state() -> tuple[str, str]:
    settings = current_settings()
    base_value = (settings.get("ASM_LLM_BASE", "") if settings is not None
                  else os.environ.get("ASM_LLM_BASE", ""))
    planner_value = (settings.get("ASM_PLANNER", "") if settings is not None
                     else os.environ.get("ASM_PLANNER", ""))
    base = str(base_value or "").strip()
    planner = str(planner_value or "").strip().lower()
    wants = planner in ("model", "both")
    if not base:
        msg = ("модель не задана (ASM_LLM_BASE пуст): планировщик будет работать "
               "по правилам")
        return ("warn", msg) if wants else ("ok", "модель не требуется")
    if _probe_model(base):
        return "ok", f"модель отвечает: {base}"
    return "blocker", f"модель не отвечает: {base} (проверьте, запущен ли сервер)"


def _stealth_state() -> tuple[str, str]:
    """Прикрыт ли выход наружу. Три признака, и они не равны по силе.

    Прокси инструмент видит и умеет им пользоваться — это самый надёжный
    признак. SOCKS закрывает сырые соединения (перебор портов). Системный
    туннель (VPN) виден как адаптер, но проверить его работой инструмент не
    может: трафик идёт мимо процесса. Поэтому он считается прикрытием только
    при явной настройке ASM_COVER=vpn и найденном туннеле — и об этом честно
    сказано в строке проверки.
    """
    settings = current_settings()
    ste_value = (settings.get("ASM_STEALTH", "off") if settings is not None
                 else os.environ.get("ASM_STEALTH", "off"))
    ste = str(ste_value or "off").strip().lower()
    proxied = any((os.environ.get(k) or "").strip()
                  for k in ("ASM_PROXY", "ASM_PROXY_OUTWARD", "ASM_SOCKS"))
    cover: dict = {"mode": "off", "tunnels": [], "raised": False}
    try:
        from . import stealth as smod
        cover = call_with_settings(smod.cover_state, settings=settings)
    except Exception:  # noqa: BLE001 — проверка обязана ответить и без модуля
        pass
    if ste == "require" and not proxied and not cover["raised"]:
        if cover["mode"] == "vpn":
            return "blocker", ("ASM_STEALTH=require и ASM_COVER=vpn, но туннеля "
                               "в системе не видно: включите VPN или выберите "
                               "другой выход — иначе ни один запрос не уйдёт")
        return "blocker", ("ASM_STEALTH=require без прикрытия: ни один запрос не "
                           "уйдёт. Нужен прокси (ASM_PROXY_OUTWARD) или системный "
                           "туннель с ASM_COVER=vpn")
    if proxied:
        tail = "; сырые соединения — через SOCKS" if (os.environ.get("ASM_SOCKS") or "").strip() else ""
        return "ok", "выход через прокси задан" + tail
    if cover["raised"]:
        return "ok", ("прикрытие вне процесса: системный туннель — "
                      + "; ".join(cover["tunnels"][:2])
                      + " (проверить адрес: python3 app.py stealth check)")
    if ste in ("warn", "require"):
        return "warn", ("выход наружу не прикрыт: свой IP увидят третьи стороны. "
                        "Варианты — прокси (ASM_PROXY_OUTWARD), SOCKS для сканов "
                        "(ASM_SOCKS) или VPN с ASM_COVER=vpn")
    return "ok", "скрытность выключена — прямой выход"


def check() -> dict:
    """Готовность машины к боевому режиму: блокеры и предупреждения.

    Блокер — то, из-за чего работа будет выглядеть сделанной, а не быть ею.
    Предупреждение — то, что можно принять осознанно.
    """
    items: list[dict] = []
    for title, (kind, text) in (
            ("кнопка СТОП", _kill_state()),
            ("арсенал", _tools_state()),
            ("модель", _model_state()),
            ("панель", _panel_state()),
            ("выход наружу", _stealth_state())):
        items.append({"item": title, "state": kind, "text": text})
    blockers = [f"{i['item']}: {i['text']}" for i in items if i["state"] == "blocker"]
    warnings = [f"{i['item']}: {i['text']}" for i in items if i["state"] == "warn"]
    ok = [i["text"] for i in items if i["state"] == "ok"]
    return {"items": items, "blockers": blockers, "warnings": warnings, "ok": ok}


def as_json() -> str:
    return json.dumps(current(), ensure_ascii=False, indent=2)
