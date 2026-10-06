# -*- coding: utf-8 -*-
"""Скрытность: чем мы выглядим наружу и откуда выходим.

Задача не «спрятаться от заказчика» — на объекте наш трафик увидят, и это
нормально. Задача в другом: чтобы по нашему трафику нельзя было связать
личность и домашний адрес с работой по конкретному заказчику. За связывание
по договору предусмотрен штраф, поэтому всё, что выходит наружу, идёт через
этот модуль, а не напрямую.

Два направления — два разных требования:

  * НА ОБЪЕКТ (inward) — трафик неизбежно попадает в логи, но должен
    выглядеть как обычная работа с сайтом, а не как сканер. Отсюда браузерный
    User-Agent по умолчанию и запрет на подпись «пришёл аудит».
  * ВОВНЕ (outward) — crt.sh, InternetDB, NVD, CertSpotter, OTX, urlscan.
    Здесь мы получаем данные о заказчике, но эти сервисы видят НАШ адрес.
    Запрос с домашнего адреса по домену заказчика — это и есть та ниточка,
    которая связывает личность с работой. Такие запросы обязаны идти через
    отдельный выход.

Режимы (`ASM_STEALTH`):

  off      — как есть, ничего не проверяется. Значение по умолчанию, чтобы
             обычная работа не ломалась из-за отсутствия прокси.
  warn     — идём напрямую, но громко предупреждаем о каждом выходе наружу.
  require  — прямой выход наружу ЗАПРЕЩЁН. Нет прокси — запрос не делается
             вовсе. Это отказ в сторону безопасности: пустой результат поиска
             выглядит как «ничего не найдено», и такой отказ недопустим,
             поэтому он бросает исключение, а не возвращает пустоту.
"""
from __future__ import annotations

import os
import random
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

from .settings import current_settings
from .settings_compat import call_with_settings

# ---------------------------------------------------------------- User-Agent

# Подпись «идёт проверка безопасности» — прямая наводка для того, кто читает
# логи. В режимах warn/require она не используется никогда.
SIGNATURE_UA = "ASM-Prototype/0.1 (authorized-security-assessment)"

# Обычный браузерный UA. Выбран не «самый свежий», а распространённый: редкая
# версия выделяется в логах сильнее, чем устаревшая.
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# Для сторонних сервисов: те же сервисы ждут обычный клиент, а не браузер.
# Браузерный UA у API-запроса, наоборот, выглядит подозрительно.
RECON_UA = "Mozilla/5.0 (compatible; research)"

MODE = (os.environ.get("ASM_STEALTH") or "off").strip().lower()
if MODE not in ("off", "warn", "require"):
    MODE = "off"

# Прокси. Разделены намеренно: выход на объект и выход вовне — разные адреса.
# Через один и тот же прокси домашний адрес и объект оказываются связаны
# одним промежуточным узлом, а это ровно та связь, которую надо разорвать.
# Прикрытие вне процесса. Прокси инструмент видит и умеет им пользоваться,
# а системный туннель (VPN) — нет: трафик уходит через него потому, что так
# настроена система, и отличить это от прямого выхода внутри процесса нельзя.
# Поэтому третий признак называется честно: «туннель вне процесса, подтверждён
# настройкой». Значение выставляет человек: ASM_COVER=vpn.
COVER = (os.environ.get("ASM_COVER") or "").strip().lower()
if COVER not in ("", "vpn", "proxy"):
    COVER = ""

# Слова, по которым узнаётся туннель. Описания сетевых адаптеров содержат
# названия продуктов латиницей даже на русской Windows («ProtonVPN TUN»,
# «TAP-Windows Adapter V9», «WireGuard Tunnel»), поэтому перевод не мешает.
_TUNNEL_WORDS = ("wireguard", "wintun", "tap-windows", "openvpn", "proton",
                 "nordlynx", "ikev2", "l2tp", "sstp", "pptp", "tunnel",
                 " tun", "tun ", "vpn")


def tunnels() -> list[str]:
    """Туннели, видимые системе. Пустой список — прикрытия вне процесса нет.

    Проверяется только то, что видно без прав администратора и без сторонних
    библиотек: на Windows — сетевые адаптеры (`ipconfig /all`), на Linux — имена
    устройств из /sys/class/net, на macOS — `ifconfig -l`. Названия продуктов в
    описаниях адаптеров идут латиницей даже на русской Windows («ProtonVPN TUN»,
    «TAP-Windows Adapter V9», «WireGuard Tunnel») — переводить нечего.
    """
    names: list[str] = []

    def add(text: str) -> None:
        t = " ".join((text or "").split())
        if t and t[:60] not in names:
            names.append(t[:60])

    try:
        if os.name == "nt":
            r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True,
                               timeout=15, errors="replace")
            for line in (r.stdout or "").splitlines():
                low = line.lower()
                if not any(w in low for w in _TUNNEL_WORDS):
                    continue
                # Строка адаптера — «<описание> . . . : <имя>». Берём ту часть,
                # в которой и стоит ключевое слово: заголовок «Адаптер Ethernet
                # ProtonVPN TUN:» или описание справа от двоеточия.
                head, _, tail = line.partition(":")
                head_has = any(w in head.lower() for w in _TUNNEL_WORDS)
                add(head if head_has else (tail.strip() or head))
        elif sys.platform == "darwin":
            r = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True,
                               timeout=8, errors="replace")
            for dev in (r.stdout or "").replace(",", " ").split():
                if dev.startswith(("utun", "ipsec", "tun")):
                    add(dev)
        else:
            for dev in sorted(os.listdir("/sys/class/net")):
                if dev.lower().startswith(("tun", "wg", "ppp", "nordlynx", "proton")):
                    add(dev)
    except Exception:  # noqa: BLE001 — не определить: это не ошибка работы
        return []
    return names


def cover_state(*, settings=None) -> dict:
    """Есть ли прикрытие вне процесса и подтверждено ли оно настройкой."""
    cover = str(_config_value(settings, "ASM_COVER", COVER) or "").strip().lower()
    if cover not in ("", "vpn", "proxy"):
        cover = ""
    found = tunnels()
    return {"mode": cover or "off", "tunnels": found,
            "raised": bool(cover == "vpn" and found)}


PROXY_INWARD = (os.environ.get("ASM_PROXY_INWARD") or "").strip()
PROXY_OUTWARD = (os.environ.get("ASM_PROXY_OUTWARD") or "").strip()
# Общий выход: используется, если отдельный не задан. Удобно на одном VPS,
# но на реальной работе лучше два разных.
PROXY_ALL = (os.environ.get("ASM_PROXY") or "").strip()

# Подменять ли UA движкам, которые задают свой. nuclei и httpx по умолчанию
# представляются собой, и это такая же наводка, как подпись в нашем UA.
PATCH_ENGINE_UA = (os.environ.get("ASM_STEALTH_PATCH_ENGINES") or "1").strip() not in ("0", "false", "no")

_UA_OVERRIDE = (os.environ.get("ASM_UA") or "").strip()


def _config_value(settings, name: str, default):
    if settings is None:
        settings = current_settings()
    if settings is None:
        return os.environ.get(name, default)
    getter = getattr(settings, "get", None) if settings is not None else None
    value = getter(name, default) if callable(getter) else default
    return default if value is None else value


def _mode(settings=None) -> str:
    value = str(_config_value(settings, "ASM_STEALTH", MODE) or "off").strip().lower()
    return value if value in ("off", "warn", "require") else "off"


def _patch_engine_ua(settings=None) -> bool:
    value = _config_value(settings, "ASM_STEALTH_PATCH_ENGINES", PATCH_ENGINE_UA)
    if type(value) is bool:
        return value
    return str(value or "1").strip().lower() not in ("0", "false", "no", "off")


def ua(purpose: str = "inward", *, settings=None) -> str:
    """User-Agent для конкретного направления.

    purpose: "inward" (на объект) или "outward" (к стороннему сервису).

    Явно заданный ASM_UA уважается, кроме одного случая: в режимах warn/require
    подпись «authorized-security-assessment» не пропускается. Если оставить её,
    весь смысл режима теряется, а человек этого не заметит.
    """
    mode = _mode(settings)
    override = str(_config_value(settings, "ASM_UA", _UA_OVERRIDE) or "").strip()
    if override:
        if mode != "off" and "security-assessment" in override:
            raise RuntimeError(
                "ASM_UA содержит подпись «security-assessment», а режим "
                f"скрытности — {mode}. Это прямая наводка в логах объекта. "
                "Уберите ASM_UA или переключите ASM_STEALTH=off осознанно.")
        return override
    return RECON_UA if purpose == "outward" else BROWSER_UA


# ------------------------------------------------------------------- прокси

def proxy_for(purpose: str) -> str:
    """Адрес прокси для направления. Пустая строка — выхода нет."""
    if purpose == "outward":
        return PROXY_OUTWARD or PROXY_ALL
    return PROXY_INWARD or PROXY_ALL


def proxies(purpose: str = "inward") -> dict:
    """Словарь прокси в том виде, в каком его понимают библиотеки."""
    p = proxy_for(purpose)
    if not p:
        return {}
    return {"http": p, "https": p}


def has_proxy(purpose: str = "inward") -> bool:
    return bool(proxy_for(purpose))


def outward_allowed(*, settings=None) -> tuple[bool, str]:
    """Можно ли делать запрос вовне и почему.

    Возвращает (можно, причина). В режиме require без прокси — нельзя, и это
    не «тихо пропустить», а явный отказ наверху.
    """
    mode = _mode(settings)
    if mode != "require":
        return True, ""
    if has_proxy("outward"):
        return True, ""
    cov = call_with_settings(cover_state, settings=settings)
    cover = cov["mode"]
    if cov["raised"]:
        return True, ""
    if cover == "vpn":
        return False, ("режим ASM_STEALTH=require, ASM_COVER=vpn задан, но "
                       "туннеля в системе не видно: включите VPN или уберите "
                       "ASM_COVER — запрос не сделан, чтобы не засветить "
                       "домашний адрес")
    return False, ("режим ASM_STEALTH=require, но ASM_PROXY_OUTWARD не задан: "
                   "запрос не сделан, чтобы не засветить домашний адрес")


class BlockedByStealth(RuntimeError):
    """Запрос наружу не сделан по требованиям скрытности.

    Исключение, а не пустой результат: пустой результат неотличим от
    «ничего не найдено», и решение было бы принято на неверных данных.
    """


# --------------------------------------------------- отпечаток TLS (JA3/JA3S)
#
# UA — это косметика: заголовок виден только тому, кто его читает. Отпечаток
# TLS виден всем и сразу: набор шифров, порядок расширений, ALPN. У обычного
# Python-клиента он свой и узнаётся мгновенно («пришёл скрипт»), прокси его не
# меняет — прокси не пересобирает рукопожатие. Поэтому либо клиент, который
# умеет представляться браузером, либо честно названный недостаток.
#
# curl_cffi — свободная библиотека с настоящими отпечатками Chrome/Firefox.
# Если её нет, работа не ломается: идём как раньше, а состояние честно
# называется в `stealth status` и в `stealth check`.
FINGERPRINT = (os.environ.get("ASM_TLS_FINGERPRINT") or "auto").strip().lower()
_FP_OFF = ("off", "0", "no", "нет", "выкл")


def impersonate_state(*, settings=None) -> dict:
    """Чем выглядит HTTPS-клиент для конкретной операции."""
    fingerprint = str(_config_value(settings, "ASM_TLS_FINGERPRINT", FINGERPRINT) or "auto").strip().lower()
    if fingerprint in _FP_OFF:
        return {"on": False, "target": "",
                "why": "выключено настройкой ASM_TLS_FINGERPRINT=off"}
    try:
        import curl_cffi  # noqa: F401
    except Exception:  # noqa: BLE001 — отсутствие библиотеки не сбой сети
        return {"on": False, "target": "",
                "why": ("curl_cffi не установлен — отпечаток обычного Python "
                        "(ставится: python3 -m pip install curl_cffi)")}
    target = "chrome131" if fingerprint in ("auto", "") else fingerprint
    return {"on": True, "target": target, "why": ""}


class _CurlResponse:
    """Ответ curl_cffi в форме, которую уже ждут вызывающие: read/status/headers.

    Своя обёртка, а не «переписать всех»: двадцать мест читают r.read() и
    r.status, и менять их ради смены библиотеки — это двадцать шансов на
    ошибку в коде, который работает.
    """

    def __init__(self, r):
        self._r = r
        self.status = int(getattr(r, "status_code", 0) or 0)
        self.headers = getattr(r, "headers", {}) or {}

    def read(self, n: int | None = None) -> bytes:
        body = self._r.content or b""
        return body if n is None else body[:n]

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False


def _curl_open(req, *, purpose: str, timeout: int, context=None, settings=None):
    """Запрос настоящим браузерным отпечатком. Ошибки — в форме urllib."""
    from curl_cffi import requests as ccr
    st = call_with_settings(impersonate_state, settings=settings)
    pr = proxy_for(purpose)
    proxies = {"http": pr, "https": pr} if pr else None
    verify = True
    if context is not None and getattr(getattr(context, "verify_mode", None), "name", "") == "CERT_NONE":
        verify = False
    try:
        r = ccr.request(req.get_method(), req.full_url, data=req.data,
                        headers=dict(req.headers), timeout=timeout,
                        impersonate=st["target"], proxies=proxies, verify=verify,
                        allow_redirects=True)
    except Exception as e:  # noqa: BLE001 — переводим в язык вызывающих
        raise urllib.error.URLError(f"browser-клиент: {type(e).__name__}: {str(e)[:160]}")
    if r.status_code >= 400:
        # urllib на 4xx/5xx бросает HTTPError, и вызывающие это уже умеют
        # (404 у crt.sh — нормальный ответ, а не сбой).
        raise urllib.error.HTTPError(req.full_url, r.status_code,
                                     f"HTTP {r.status_code}", r.headers, None)
    return _CurlResponse(r)


def opener(purpose: str = "inward", *, context=None, settings=None) -> urllib.request.OpenerDirector:
    """Открывалка urllib с прокси этого направления.

    TLS-контекст передаётся СЮДА, а не в open(). `OpenerDirector.open()` такого
    параметра не принимает — он есть только у удобной обёртки urlopen(). Если
    передать его в open(), поднимается TypeError, и без явной обработки это
    выглядит как сбой сети: запрос уходит в повторы и возвращает пустоту.
    Проверено: так оно и было, пока не поймали.
    """
    handlers = [urllib.request.ProxyHandler(proxies(purpose))]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def open_url(req, *, purpose: str = "inward", timeout: int = 15, context=None,
            settings=None):
    """Единственный разрешённый способ сходить в сеть.

    Проверяет правила скрытности ДО запроса, подставляет proxy по назначению и,
    когда это возможно, идёт клиентом с браузерным отпечатком (§7.2.5): UA
    подделать мало, а JA3 обычного Python узнаётся сразу. Если библиотеки нет —
    идём urllib и не делаем вид, что отпечаток закрыт: об этом скажет
    `stealth status`.
    """
    if purpose == "outward":
        ok, why = call_with_settings(outward_allowed, settings=settings)
        if not ok:
            raise BlockedByStealth(why)
    if call_with_settings(impersonate_state, settings=settings)["on"]:
        return _curl_open(req, purpose=purpose, timeout=timeout, context=context,
                          settings=settings)
    return opener(purpose, context=context, settings=settings).open(req, timeout=timeout)


# ------------------------------------------------------- окружение процессов

# Переменные, которые понимает большинство консольных инструментов.
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
               "http_proxy", "https_proxy", "all_proxy")


def subprocess_env(base: dict | None = None, *, purpose: str = "inward",
                   settings=None) -> dict:
    """Окружение для внешнего движка с учётом прокси и подмены UA.

    Движки (nuclei, httpx, subfinder, naabu) идут в сеть сами, и передать им
    прокси можно только через окружение. Без этого прокси действует на нашу
    часть работы и не действует на движки — то есть на самый громкий трафик.
    """
    env = dict(base if base is not None else os.environ)
    # На объект идёт трафик движков — это inward. Вовне ходим мы сами,
    # через collect, поэтому здесь прокси именно inward.
    p = proxy_for(purpose)
    if p:
        for var in _PROXY_VARS:
            env[var] = p
    else:
        # Явно снять унаследованный прокси, если он не наш: иначе неизвестно,
        # откуда реально ушёл трафик.
        for var in _PROXY_VARS:
            env.pop(var, None)
    mode = _mode(settings)
    if mode != "off" or not p:
        env.setdefault("NO_PROXY", "127.0.0.1,localhost,::1")
    patch_engine_ua = _patch_engine_ua(settings)
    if patch_engine_ua:
        # Уважается не всеми инструментами, но там, где уважается, убирает
        # подпись сканера из логов объекта.
        env["ASM_UA"] = ua("inward", settings=settings)
    return env


# ---------------------------------------------------------------- что течёт

# Инвентарь выходов наружу. Держится рядом с кодом, а не в документе: при
# добавлении источника это единственное место, которое надо не забыть.
OUTBOUND = (
    {"id": "crtsh", "what": "crt.sh — журналы выдачи сертификатов",
     "dir": "outward", "where": "collect.crtsh_subdomains / crtsh_certs"},
    {"id": "certspotter", "what": "CertSpotter — имена из сертификатов",
     "dir": "outward", "where": "sources.py"},
    {"id": "internetdb", "what": "InternetDB (Shodan) — открытые порты по IP",
     "dir": "outward", "where": "collect.internetdb"},
    {"id": "rdap", "what": "RDAP — регистрационные данные адресов",
     "dir": "outward", "where": "collect.ripe_prefix"},
    {"id": "otx", "what": "AlienVault OTX — пассивный DNS",
     "dir": "outward", "where": "sources.py"},
    {"id": "urlscan", "what": "urlscan.io — история сканирований домена",
     "dir": "outward", "where": "sources.py"},
    {"id": "hackertarget", "what": "HackerTarget — пассивный DNS",
     "dir": "outward", "where": "sources.py"},
    {"id": "nvd", "what": "NVD — база уязвимостей по продукту и версии",
     "dir": "outward", "where": "cve.py"},
    {"id": "github", "what": "поиск утечек в открытых репозиториях",
     "dir": "outward", "where": "sources.py"},
    {"id": "target_http", "what": "объект: веб-пробы, чтение файлов, TLS",
     "dir": "inward", "where": "collect.http_probe, engines.fetch_text"},
    {"id": "target_raw", "what": "объект: перебор портов, сырые сокеты",
     "dir": "raw", "where": "engines.port_scan (naabu), collect.tcp_open", "socks": True},
    {"id": "interactsh", "what": "публичный interactsh — коллбэки OAST",
     "dir": "outward", "where": "engines.py (nuclei) — на публичном домене это наводка"},
    {"id": "notify", "what": "Telegram или вебхук — уведомления",
     "dir": "outward", "where": "notify.py"},
    {"id": "llm", "what": "модель, если она не на localhost",
     "dir": "outward", "where": "aiagent.py (ASM_LLM_URL)"},
)


def inventory(*, settings=None) -> list[dict]:
    """Куда инструмент ходит наружу и прикрыт ли этот путь.

    Показывает по каждому направлению, идёт ли трафик через прокси. Это
    и есть ответ на вопрос «а точно ли меня не видно» — по каждому каналу
    отдельно, а не общим утверждением.
    """
    rows = []
    for it in OUTBOUND:
        row = dict(it)
        if it.get("socks"):
            # Сырые сокеты прикрывает только SOCKS: HTTP-прокси их не берёт,
            # и «прокси задан» здесь ничего не значит.
            row["proxied"] = bool(SOCKS)
        else:
            row["proxied"] = has_proxy(it["dir"])
        row["covered"] = row["proxied"] or _mode(settings) == "off"
        rows.append(row)
    return rows


def endpoints_hidden(*, settings=None) -> list[str]:
    """Пути наружу, которые сейчас НЕ прикрыты. Пустой список — всё закрыто."""
    return [r["id"] for r in inventory(settings=settings) if not r["covered"]]


# ------------------------------------------------------------------ сводка

def status(*, settings=None) -> dict:
    """Текущее состояние одним словарём — для CLI и веб-интерфейса."""
    cov = call_with_settings(cover_state, settings=settings)
    return {
        "mode": _mode(settings),
        "cover": cov,
        "proxy_inward": PROXY_INWARD or PROXY_ALL,
        "proxy_outward": PROXY_OUTWARD or PROXY_ALL,
        "separate_exits": bool(PROXY_OUTWARD and PROXY_INWARD
                               and PROXY_OUTWARD != PROXY_INWARD),
        "ua_inward": call_with_settings(ua, "inward", settings=settings),
        "ua_outward": call_with_settings(ua, "outward", settings=settings),
        "ua_override": bool(_config_value(settings, "ASM_UA", _UA_OVERRIDE)),
        "fingerprint": call_with_settings(impersonate_state, settings=settings),
        "engine_ua_patched": _patch_engine_ua(settings),
        "socks": SOCKS,
        "uncovered": call_with_settings(endpoints_hidden, settings=settings),
        "inventory": call_with_settings(inventory, settings=settings),
    }


# --------------------------------------------------------------- самопроверка

# Сервис, который просто возвращает наш адрес. Нужен, чтобы ПРОВЕРИТЬ, что
# прокси действительно скрывает адрес, а не просто прописан в настройках.
ECHO_SERVICES = ("https://api.ipify.org?format=json",
                 "https://ifconfig.me/ip")


def my_ip(*, purpose: str = "inward", timeout: int = 12) -> tuple[str, str]:
    """Наш адрес с точки зрения того, к кому мы обращаемся.

    Возвращает (адрес, откуда получен). Пустой адрес — узнать не удалось.
    """
    for url in ECHO_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua("outward")})
            # Проверяем именно выход, поэтому режим require здесь не применяем:
            # иначе проверка прокси упиралась бы в запрет, который проверяет.
            if purpose == "inward":
                ok, why = outward_allowed()
                if not ok:
                    return "", why
            with opener(purpose).open(req, timeout=timeout) as r:
                txt = r.read(200).decode("utf-8", "replace")
            if url.endswith("json"):
                import json as _json
                try:
                    txt = str(_json.loads(txt).get("ip") or "")
                except Exception:
                    pass
            txt = txt.strip()
            if txt and len(txt) <= 64:
                return txt, url
        except Exception:
            continue
    return "", "не удалось обратиться ни к одному сервису"


def compare_exits() -> dict:
    """Показывает адрес напрямую и адрес через прокси.

    Смысл: «прокси настроен» и «прокси скрывает адрес» — разные утверждения.
    Первое проверяется чтением настройки, второе — только запросом.
    """
    out: dict = {"direct": "", "via_inward": "", "via_outward": "",
                 "direct_err": "", "note": ""}
    # Прямой выход: строим открывалку вообще без прокси, иначе при общем
    # ASM_PROXY «прямой» адрес оказался бы адресом прокси и сравнение врало бы.
    try:
        req = urllib.request.Request(ECHO_SERVICES[0],
                                     headers={"User-Agent": ua("outward")})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                req, timeout=12) as r:
            import json as _json
            out["direct"] = str(_json.loads(r.read(200).decode())["ip"])
    except Exception as e:  # noqa: BLE001
        out["direct_err"] = f"{type(e).__name__}: {e}"

    if has_proxy("inward"):
        ip_in, _ = my_ip(purpose="inward")
        out["via_inward"] = ip_in
    if has_proxy("outward"):
        ip_out, _ = my_ip(purpose="outward")
        out["via_outward"] = ip_out

    if not has_proxy("inward") and not has_proxy("outward"):
        out["note"] = "прокси не задан — весь трафик идёт с домашнего адреса"
    elif out["direct"] and out["via_inward"] == out["direct"]:
        out["note"] = ("адрес через прокси для объекта совпал с домашним — "
                       "прокси не работает или прозрачный")
    elif out["direct"] and out["via_outward"] == out["direct"]:
        out["note"] = ("адрес через прокси для внешних запросов совпал с "
                       "домашним — этот выход не скрывает")
    else:
        out["note"] = "адреса различаются — выход подменён"
    return out


def jitter(base: float = 0.0, spread: float = 0.0, *, settings=None) -> float:
    """Пауза со случайным разбросом и дополнительной базой из настроек.

    Ровные интервалы между запросами — такой же признак автоматизации, как
    подпись в User-Agent. `ASM_STEALTH_JITTER` добавляется к паузе каждого
    вызова; нулевое значение сохраняет прежний темп.
    """
    configured_base = _config_value(settings, "ASM_STEALTH_JITTER", JITTER_BASE)
    try:
        base = float(base) + max(0.0, float(configured_base or 0.0))
    except (TypeError, ValueError):
        base = float(base)
    if spread <= 0:
        return base
    return max(0.0, base + random.uniform(0.0, spread))


try:
    JITTER_BASE = max(0.0, float(os.environ.get("ASM_STEALTH_JITTER") or "0"))
except (TypeError, ValueError):
    # Operation snapshots validate this setting with SettingsError; keep the
    # legacy module import alive until that boundary can report the bad value.
    JITTER_BASE = 0.0

# ------------------------------------------------------ сырые соединения

# HTTP-прокси не умеет то, что не HTTP: перебор портов, сырой TLS, проверка
# живости порта. Для них нужен SOCKS5. Чаще всего это туннель, поднятый
# на своём VPS одной командой:  ssh -N -D 1080 user@vps
SOCKS = (os.environ.get("ASM_SOCKS") or "").strip()
SOCKS_TIMEOUT = float(os.environ.get("ASM_SOCKS_TIMEOUT") or "10")


def parse_socks(spec: str) -> tuple[str, int, str, str]:
    """Разобрать «[user:pass@]host:port» в части SOCKS5."""
    user = pwd = ""
    rest = spec
    if "@" in spec:
        cred, rest = spec.rsplit("@", 1)
        if ":" in cred:
            user, pwd = cred.split(":", 1)
        else:
            user = cred
    if ":" not in rest:
        raise ValueError(f"нужен вид host:port, получено «{spec}»")
    host, port = rest.rsplit(":", 1)
    return host, int(port), user, pwd


def socks5_connect(host: str, port: int, *, timeout: float | None = None,
                   spec: str | None = None) -> socket.socket:
    """Соединение с host:port через SOCKS5-прокси.

    Без этой функции перебор портов и проверка живости идут с домашнего
    адреса — то есть самый узнаваемый наш трафик оказывается самым открытым.

    Реализация минимальная: без GSSAPI и без UDP, только CONNECT. Имя хоста
    передаётся прокси как есть (ATYP=3), поэтому DNS тоже не утекает.
    """
    spec = spec or SOCKS
    if not spec:
        raise RuntimeError("ASM_SOCKS не задан — сырое соединение через прокси невозможно")
    phost, pport, user, pwd = parse_socks(spec)
    t = timeout if timeout is not None else SOCKS_TIMEOUT
    s = socket.create_connection((phost, pport), timeout=t)
    s.settimeout(t)
    try:
        if user or pwd:
            s.sendall(b"\x05\x02\x00\x02")
        else:
            s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5:
            raise RuntimeError("прокси не SOCKS5")
        if resp[1] == 2:
            u = user.encode(); w = pwd.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(w)]) + w)
            if s.recv(2)[1] != 0:
                raise RuntimeError("SOCKS5: неверные логин или пароль")
        elif resp[1] == 255:
            raise RuntimeError("SOCKS5: способ авторизации не принят")
        elif resp[1] != 0:
            raise RuntimeError(f"SOCKS5: нужна авторизация, а её нет в ASM_SOCKS")
        hb = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
        head = s.recv(4)
        if len(head) < 4:
            raise RuntimeError("SOCKS5: обрыв при ответе на CONNECT")
        if head[1] != 0:
            raise RuntimeError(f"SOCKS5: отказ в соединении, код {head[1]}")
        atype = head[3]
        if atype == 1:
            s.recv(4)
        elif atype == 3:
            n = s.recv(1)[0]
            s.recv(n)
        elif atype == 4:
            s.recv(16)
        s.recv(2)  # порт
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise


def raw_connect(host: str, port: int, timeout: float = 3.0) -> socket.socket:
    """Соединение с объектом: через SOCKS5, если он задан, иначе напрямую.

    Единая точка входа для всего, что ходит сырыми сокетами. Иначе прокси
    прикрывает часть работы, а часть — нет, и неизвестно, какая.
    """
    if SOCKS:
        return socks5_connect(host, port, timeout=timeout)
    return socket.create_connection((host, port), timeout=timeout)
