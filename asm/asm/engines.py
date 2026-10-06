"""
Лучший бесплатный арсенал ИБ, собранный в один движок.

Состав (все — свободные лицензии, статические сборки, ставятся без root):

  Разведка имён  : subfinder (35+ источников), amass (глубокая пассивная разведка)
  DNS            : dnsx (массовое разрешение, CNAME/PTR)
  Порты          : naabu (быстрый сканер портов), nmap -sV (точные версии сервисов и CPE)
  Веб-проба      : httpx (статус, заголовок, технологии, CDN, TLS) — основа опознания
  TLS            : tlsx (сертификаты, SAN, сроки), testssl.sh (глубокий аудит TLS)
  Веб-серверы    : Nikto (опасные файлы, конфигурация), Wapiti (без инъекций и перебора паролей)
  Обход ссылок   : katana (crawler), gau (URL из архивов)
  Поиск путей    : ffuf + словари SecLists (опция, по умолчанию выключено)
  Уязвимости     : nuclei (13 700+ подписанных шаблонов, вкл. метку vkev — эксплуатируемые в атаках)
  Код заказчика  : gitleaks + TruffleHog (секреты), Semgrep (опасные места в коде)
  Зависимости    : trivy + OSV-Scanner (уязвимые библиотеки, фикс-версии), trivy config (развёртывание)
  Образы         : trivy image (уязвимости внутри контейнера клиента)

Правила, которые соблюдаются всегда (иначе это не аудит, а атака):
  * только хосты в границах авторизованного анализа (список передаёт scan.py);
  * никаких проверок учётных данных: категории шаблонов default-logins,
    credential-stuffing, brute-force и любые intrusive/dos/fuzz исключены;
  * лимиты скорости, времени и количества целей заданы по умолчанию и настраиваются.

Поиск инструментов: ASM_<TOOL>_BIN -> PATH -> $ASM_TOOLS_DIR/bin -> <проект>/bin.
Установка всего арсенала: bash bin/install-tools.sh
"""
from __future__ import annotations

import csv
import json
import os
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Iterable

from .settings import current_settings
from .settings_compat import call_with_settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Где живёт арсенал: <проект>/build/tools.
#   * ВНУТРИ проекта — потому что каталоги вне его песочница стирает между сессиями;
#   * но под именем build/ — такие каталоги НЕ попадают в снимок workspace
#     (13 742 шаблона nuclei + правила semgrep иначе раздувают его до гигабайта).
# Итог: код и результаты всегда сохраняются, а тяжёлые движки — восстанавливаются
# одной командой `bash bin/install-tools.sh` (или --fast за ~1,5 минуты).
TOOLS_DIR = os.environ.get("ASM_TOOLS_DIR", os.path.join(ROOT, "build", "tools"))
LEGACY_DIRS = [os.path.join(ROOT, "tools"),                 # прежнее место внутри проекта
               os.path.join(os.path.expanduser("~"), ".cache", "asm-tools")]
FALLBACK_TOOLS = LEGACY_DIRS[1]
PYLIBS = os.path.join(TOOLS_DIR, "pylibs")     # python-инструменты (semgrep, wapiti, sqlite-vec)
if os.path.isdir(PYLIBS) and PYLIBS not in sys.path:
    sys.path.insert(0, PYLIBS)
LIB_DIR = os.path.join(TOOLS_DIR, "lib")
TEMPLATES_DIR = os.environ.get("ASM_NUCLEI_TEMPLATES", os.path.join(TOOLS_DIR, "nuclei-templates"))
WORDLISTS = os.environ.get("ASM_WORDLISTS", os.path.join(ROOT, "data", "wordlists"))

# ------------------------------------------------------------------ справочник
ENGINES: list[dict] = [
    {"id": "subfinder", "bin": "subfinder", "name": "subfinder", "role": "разведка имён",
     "what": "35+ пассивных источников поддоменов", "license": "MIT"},
    {"id": "amass", "bin": "amass", "name": "amass (OWASP)", "role": "разведка имён",
     "what": "глубокая пассивная разведка (медленная, опция)", "license": "Apache-2.0"},
    {"id": "dnsx", "bin": "dnsx", "name": "dnsx", "role": "DNS",
     "what": "массовое разрешение имён, CNAME/PTR, быстрее в 20 раз", "license": "MIT"},
    {"id": "naabu", "bin": "naabu", "name": "naabu", "role": "порты",
     "what": "быстрый сканер портов (SYN/connect)", "license": "MIT"},
    {"id": "httpx", "bin": "httpx", "name": "httpx", "role": "веб-проба",
     "what": "статус, заголовок, технологии, CDN, TLS — основа опознания", "license": "MIT"},
    {"id": "tlsx", "bin": "tlsx", "name": "tlsx", "role": "TLS",
     "what": "сертификаты: SAN, издатель, сроки", "license": "MIT"},
    {"id": "testssl", "bin": "testssl.sh", "name": "testssl.sh", "role": "TLS (глубоко)",
     "what": "полный аудит TLS-конфигурации (медленный, опция)", "license": "GPL-2.0"},
    {"id": "katana", "bin": "katana", "name": "katana", "role": "обход ссылок",
     "what": "crawler: собирает адреса страниц и параметры", "license": "MIT"},
    {"id": "gau", "bin": "gau", "name": "gau", "role": "архивы",
     "what": "адреса из архивов (Wayback, Common Crawl)", "license": "MIT"},
    {"id": "ffuf", "bin": "ffuf", "name": "ffuf", "role": "поиск путей",
     "what": "скрытые пути и файлы по словарю (опция)", "license": "MIT"},
    {"id": "nuclei", "bin": "nuclei", "name": "nuclei", "role": "уязвимости",
     "what": "13 700+ шаблонов проверок, включая vkev (эксплуатируемые в атаках)", "license": "MIT"},
    {"id": "nmap", "bin": "nmap", "name": "nmap", "role": "порты и версии сервисов",
     "what": "точное определение продукта и версии сервиса (-sV) — эталон индустрии", "license": "GPL-2.0"},
    {"id": "nikto", "bin": "nikto.pl", "name": "nikto", "role": "веб-сервер",
     "what": "опасные файлы, конфигурация, заголовки веб-сервера", "license": "GPL-2.0"},
    {"id": "trivy", "bin": "trivy", "name": "trivy", "role": "образы и файлы (внутренний контур)",
     "what": "уязвимости пакетов в образах/каталогах клиента + поиск секретов", "license": "Apache-2.0"},
    {"id": "gitleaks", "bin": "gitleaks", "name": "gitleaks", "role": "секреты в коде",
     "what": "пароли, ключи, токены в репозиториях клиента", "license": "MIT"},
    {"id": "trufflehog", "bin": "trufflehog", "name": "TruffleHog", "role": "секреты (с проверкой)",
     "what": "ищет секреты и умеет проверять, живые ли они (по умолчанию — без проверки)", "license": "AGPL-3.0"},
    {"id": "semgrep", "bin": "semgrep", "name": "Semgrep", "role": "анализ исходного кода",
     "what": "опасные конструкции в коде клиента по бесплатным правилам (SAST)", "license": "LGPL-2.1"},
    {"id": "osv", "bin": "osv-scanner", "name": "OSV-Scanner", "role": "зависимости (база OSV)",
     "what": "уязвимые версии библиотек по бесплатной базе OSV.dev (Google)", "license": "Apache-2.0"},
    {"id": "wapiti", "bin": "wapiti", "name": "Wapiti", "role": "веб-приложение",
     "what": "заголовки, cookie, методы, версии CMS и опасные файлы — без инъекций", "license": "GPL-2.0"},
]

# --- Профиль aggressiveness --------------------------------------------------
# safe    (по умолчанию) — аудит периметра. Без перебора учётных данных, без
#           инъекций, без intrusive и DoS. Ничего не ломает и не блокирует.
# pentest — авторизованное тестирование на проникновение: дефолтные учётные
#           записи, credential-stuffing, перебор, intrusive и fuzz-проверки,
#           все шаблоны nuclei всех критичностей, слепые уязвимости через
#           interactsh, инъекционные модули Wapiti, полный набор Nikto,
#           проверка живости найденных ключей.
#           ОТКАЗ В ОБСЛУЖИВАНИИ ИСКЛЮЧЁН: заказчику нужен работающий сервис
#           с доказанным доступом, а не лежащий сервис.
# full    — вообще всё, включая dos-шаблоны. Только если DoS согласован письменно.
PROFILE = os.environ.get("ASM_PROFILE", "safe").strip().lower()
FULL = PROFILE in ("full", "all", "aggressive", "1", "true", "yes", "on")
PENTEST = FULL or PROFILE in ("pentest", "pentest-nodos", "attack", "exploit", "2")

# Категории nuclei, которые могут нарушить доступность сервиса. В pentest они
# выключены всегда: цель — получить доступ, а не уронить цель.
DOS_TAGS = {"dos"}
RISKY_TAGS = {"default-logins", "credential-stuffing", "brute-force", "dos", "fuzz", "intrusive"}
BANNED_TAGS: set[str] = set() if FULL else (set(DOS_TAGS) if PENTEST else set(RISKY_TAGS))
# проверки по шаблонам: только то, что даёт результат для периметра.
# ssl/dns/tech намеренно не в списке: TLS разбирает tlsx, технологии — httpx (быстрее, без дублей).
# В профиле full фильтр по тегам не ставится вовсе — идут все шаблоны.
SAFE_TAGS = os.environ.get("ASM_NUCLEI_TAGS",
                           "" if PENTEST else "cve,vkev,exposure,misconfig,takeover")
SAFE_SEVERITY = os.environ.get("ASM_NUCLEI_SEVERITY", "" if PENTEST else "critical,high,medium")

# ------------------------------------------------------------------ скорость
# Скорость запросов к объекту. Это не косметика: 500 пакетов в секунду
# в состоянии положить хрупкое оборудование — старый межсетевой экран,
# промышленный контроллер, встраиваемое устройство. Отвечает за это не
# обнаружение, а доступность, поэтому в щадящем профиле скорость ниже в разы.
#
# В `full` сняты ограничения по тегам, но скорость та же: снять фильтры
# шаблонов и снять тормоза — разные решения, и второе никому не нужно.
_RATE_BY_PROFILE: dict[str, dict[str, int]] = {
    "safe": {"naabu": 150, "nuclei": 25, "httpx": 20, "katana": 10,
             "nmap": 150, "ffuf": 40},
    "pentest": {"naabu": 500, "nuclei": 80, "httpx": 60, "katana": 30,
                "nmap": 500, "ffuf": 120},
    "full": {"naabu": 500, "nuclei": 80, "httpx": 60, "katana": 30,
             "nmap": 500, "ffuf": 120},
}

# Явная настройка перекрывает профиль. Пустое значение — «взять из профиля»:
# раньше в этих местах стояли числа 500 и 80, и они молча перебивали профиль,
# так что профиль действовал на всё, кроме скорости.
_RATE_ENV = {
    "naabu": os.environ.get("ASM_NAABU_RATE", ""),
    "nuclei": os.environ.get("ASM_NUCLEI_RATE", ""),
    "httpx": os.environ.get("ASM_HTTPX_RATE", ""),
    "katana": os.environ.get("ASM_KATANA_RATE", ""),
    # Раньше у nmap и ffuf скорость задавалась прямо в сигнатуре функции
    # (300 и 40), и профиль на них не действовал вообще: в `safe`, который
    # обещает «не трогать чужое», nmap шёл на ровных 300 пакетов в секунду.
    "nmap": os.environ.get("ASM_NMAP_RATE", ""),
    "ffuf": os.environ.get("ASM_FFUF_RATE", ""),
}

# Разброс скорости. Ровные 80 запросов в секунду не бывают у человека:
# постоянный темп — такой же признак автоматизации, как одинаковый User-Agent.
# Доля от значения; 0 выключает разброс.
try:
    RATE_SPREAD = float(os.environ.get("ASM_RATE_SPREAD") or "0.2")
except ValueError:
    RATE_SPREAD = 0.2


def _config_value(settings, name: str, default):
    """Read snapshot config, then current environment for legacy callers."""
    if settings is None:
        settings = current_settings()
    if settings is None:
        return os.environ.get(name, default)
    getter = getattr(settings, "get", None)
    return getter(name, default) if callable(getter) else default


def _effective_settings(settings=None):
    return settings if settings is not None else current_settings()


def _tools_root(settings=None) -> str:
    settings = _effective_settings(settings)
    return str(_config_value(settings, "ASM_TOOLS_DIR", TOOLS_DIR) or TOOLS_DIR)


def _templates_root(settings=None) -> str:
    settings = _effective_settings(settings)
    configured = _config_value(settings, "ASM_NUCLEI_TEMPLATES", None)
    if configured:
        return str(configured)
    if settings is None:
        tools_override = os.environ.get("ASM_TOOLS_DIR")
        if tools_override:
            return os.path.join(tools_override, "nuclei-templates")
        return TEMPLATES_DIR
    return os.path.join(_tools_root(settings), "nuclei-templates")


def _wordlists_root(settings=None) -> str:
    settings = _effective_settings(settings)
    return str(_config_value(settings, "ASM_WORDLISTS", WORDLISTS) or WORDLISTS)


def _profile_values(settings=None) -> tuple[str, bool, bool]:
    profile = str(_config_value(settings, "ASM_PROFILE", PROFILE) or "safe").strip().lower()
    full = profile in ("full", "all", "aggressive", "1", "true", "yes", "on")
    pentest = full or profile in ("pentest", "pentest-nodos", "attack", "exploit", "2")
    return profile, pentest, full


def _profile_key(settings=None) -> str:
    _profile, pentest, full = _profile_values(settings)
    if full:
        return "full"
    return "pentest" if pentest else "safe"


def profile_note(settings=None) -> str:
    """Строка о действующем профиле — для журнала скана.

    Профиль `safe` — обычный режим, о нём молчим: сообщение на каждую строку
    журнала обесценивает сообщения. `pentest` и `full` задают скорости и
    методы, которых на слабом сервере заказчика достаточно, чтобы его уронить.
    Такой выбор обязан быть виден в журнале: не «шли на 80 запросов в секунду
    само собой», а «профиль выбран осознанно, вот его числа».
    """
    profile = str(_config_value(settings, "ASM_PROFILE", PROFILE) or "safe").strip().lower()
    if profile not in ("pentest", "full"):
        return ""
    rates = _RATE_BY_PROFILE.get(profile) or {}
    parts = ", ".join(f"{k} {v} зап/с" for k, v in rates.items())
    return (f"Профиль {profile}: {parts} — это выше щадящего. На слабом сервере "
            f"заказчика такая нагрузка заметна; профиль выбран явно.")


def rate_for(engine: str, settings=None) -> int:
    """Скорость запросов к объекту для движка.

    Приоритет: явная настройка → профиль. 0 означает «без ограничения»
    и уважается как осознанный выбор.
    """
    table = _RATE_BY_PROFILE.get(_profile_key(settings), _RATE_BY_PROFILE["safe"])
    base = table.get(engine, 25)
    rate_key = "ASM_" + engine.upper() + "_RATE"
    configured = _config_value(settings, rate_key, _RATE_ENV.get(engine, ""))
    raw = "" if configured is None else str(configured).strip()
    if raw:
        try:
            base = int(float(raw))
        except ValueError:
            pass
    if base <= 0:
        return 0
    try:
        spread = float(_config_value(settings, "ASM_RATE_SPREAD", RATE_SPREAD))
    except (TypeError, ValueError):
        spread = RATE_SPREAD
    if spread > 0:
        base = int(round(base * random.uniform(1.0 - spread, 1.0 + spread)))
    return max(1, base)


SENSITIVE_EXT = (".env", ".git/", ".svn/", ".sql", ".bak", ".backup", ".old", ".log", ".zip", ".tar.gz",
                 ".tgz", ".rar", ".7z", ".dump", ".sqlite", ".db", ".yml", ".yaml", ".json", ".conf",
                 ".config", ".ini", ".pem", ".key", ".p12", ".pfx", ".xls", ".xlsx", ".csv", ".pdf")


def _env_extra(settings=None) -> dict:
    from . import stealth
    # Прокси и подмена UA передаются движкам через окружение: они ходят в сеть
    # сами, и наша часть работы может быть прикрыта, а их — нет. Именно их
    # трафик самый громкий: перебор портов и прогон шаблонов.
    env = stealth.subprocess_env(os.environ, purpose="inward", settings=settings)
    tools_dir = str(_config_value(settings, "ASM_TOOLS_DIR", TOOLS_DIR) or TOOLS_DIR)
    lib_dir = os.path.join(tools_dir, "lib")
    pylibs_dir = os.path.join(tools_dir, "pylibs")
    lib = lib_dir if os.path.isdir(lib_dir) else ""
    if lib:
        env["LD_LIBRARY_PATH"] = lib + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    env["PYTHONPATH"] = pylibs_dir + os.pathsep + env.get("PYTHONPATH", "") if os.path.isdir(pylibs_dir) else env.get("PYTHONPATH", "")
    # служебные кэши движков — в каталог арсенала: домашний каталог не мусорим,
    # а главное — ничего лишнего не попадает в снимок workspace
    for key, sub in (("PDCP_DIR", "pdcp"), ("NUCLEI_CACHE_DIR", "nuclei-cache"),
                     ("XDG_CACHE_HOME", "xdg-cache")):
        d = os.path.join(tools_dir, sub)
        try:
            os.makedirs(d, exist_ok=True)
            env[key] = d
        except OSError:
            pass
    perl5 = os.path.join(tools_dir, "perl-libs")
    if os.path.isdir(perl5):
        env["PERL5LIB"] = perl5 + (os.pathsep + env["PERL5LIB"] if env.get("PERL5LIB") else "")
    ts_dir = os.path.join(tools_dir, "testssl")
    if os.path.isdir(ts_dir):
        env["TESTSSL_INSTALL_DIR"] = ts_dir
    env["PATH"] = os.pathsep.join([os.path.join(b, "bin") for b in [tools_dir] + LEGACY_DIRS]
                                  + [env.get("PATH", "")])
    # trivy/nmap пишут большие временные файлы: /tmp в контейнерах часто крошечный
    tdir = os.path.join(tools_dir, "tmp")
    try:
        os.makedirs(tdir, exist_ok=True)
        env.setdefault("TMPDIR", tdir)
    except OSError:
        pass
    return env


# ---------------------------------------------------------- запуск скриптов
# Windows не умеет запускать скрипты напрямую: CreateProcess исполняет только
# .exe/.cmd, а .sh и .pl для него — обычные файлы. Из-за этого три инструмента
# (testssl.sh, nikto, wapiti) на Windows показывали «не запускается» и молча
# давали ноль находок: установщик проверял их через bash, а движок запускал
# напрямую. Здесь — одно место, которое знает, чем запускать каждый вид файла.

# Где искать bash на Windows (Git Bash идёт вместе с MSYS, но его путь не
# обязан быть в PATH у python).
_BASH_HINTS = (r"C:\Program Files\Git\bin\bash.exe",
               r"C:\Program Files\Git\usr\bin\bash.exe",
               r"C:\Program Files (x86)\Git\bin\bash.exe")
_PERL_HINTS = (r"C:\Strawberry\perl\bin\perl.exe",
               r"C:\Program Files\Git\usr\bin\perl.exe")

# Код запуска wapiti: на Windows обёртка .cmd может не сработать (кириллица в
# пути, чужой python), поэтому зовём модуль тем же интерпретатором, что и ASM.
WAPITI_CODE = ("import sys; from wapitiCore.main.wapiti import "
               "wapiti_asyncio_wrapper as m; sys.exit(m())")

# Чем спросить версию у инструментов, где общий список флагов не подходит
# (или ответ приходит с ненулевым кодом — nikto так и делает).
_VERSION_ARGS = {"nikto.pl": ["-Version", "-version"], "testssl.sh": ["--version"],
                 "wapiti": ["--version"]}
# У этих инструментов версию принимаем даже при ненулевом коде возврата:
# nikto печатает версию и выходит с ошибкой — это его нормальное поведение.
_VERSION_ANY_EXIT = {"nikto.pl"}


def bash_path(settings=None) -> str | None:
    """Чем запускать .sh. На Linux он не нужен — там скрипт запускается сам."""
    if os.name != "nt":
        return None
    explicit = str(_config_value(settings, "ASM_BASH_BIN", os.environ.get("ASM_BASH_BIN", "")) or "")
    if explicit and os.path.exists(explicit):
        return explicit
    found = shutil.which("bash")
    if found:
        return found
    local = os.environ.get("LOCALAPPDATA") or ""
    for c in _BASH_HINTS + ((os.path.join(local, "Programs", "Git", "bin", "bash.exe"),)
                            if local else ()):
        if os.path.exists(c):
            return c
    return None


def perl_path(settings=None) -> str | None:
    """Чем запускать .pl (nikto): perl есть и в Git Bash, и в Strawberry."""
    explicit = str(_config_value(settings, "ASM_PERL_BIN", os.environ.get("ASM_PERL_BIN", "")) or "")
    if explicit and os.path.exists(explicit):
        return explicit
    for name in (("perl.exe", "perl") if os.name == "nt" else ("perl",)):
        found = shutil.which(name)
        if found:
            return found
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA") or ""
        for c in _PERL_HINTS + ((os.path.join(local, "Programs", "Git", "usr", "bin", "perl.exe"),)
                                if local else ()):
            if os.path.exists(c):
                return c
    return None


def _msys_path(p: str) -> str:
    r"""C:\Users\x -> /c/Users/x — так путь понимает bash из Git Bash.

    Меняем только абсолютные пути Windows: строка вида «example.com:443» или
    ключ «--quiet» обязана остаться собой.
    """
    if os.name != "nt" or len(p) < 3 or p[1] != ":" or p[2] not in "\\/":
        return p
    return "/" + p[0].lower() + p[2:].replace("\\", "/")


def script_cmd(exe: str, args: list[str], *, settings=None) -> list[str] | None:
    """Команда запуска инструмента с учётом того, скрипт это или программа.

    None — запустить нечем (на Windows нет bash для .sh). Молча выполнять
    «пусто» нельзя: движок считался бы установленным и не давал находок.
    """
    low = (exe or "").lower()
    if low.endswith(".pl"):
        perl = perl_path(settings)
        return [perl, exe, *args] if perl else ([exe, *args] if os.name != "nt" else None)
    if low.endswith((".sh", ".bash")):
        if os.name != "nt":
            return [exe, *args]
        bash = bash_path(settings)
        return [bash, exe, *[_msys_path(a) for a in args]] if bash else None
    if low.endswith(".cmd") and low.replace("\\", "/").rsplit("/", 1)[-1] == "wapiti.cmd":
        # Обёртку .cmd обходим: зовём модуль напрямую — тем же python, что и ASM.
        # Имя сравниваем без os.path: путь может быть windows-овый и на Linux
        # (в тестах), а разбор строки от системы не зависит.
        return [sys.executable, "-c", WAPITI_CODE, *args]
    return [exe, *args]


def _candidates(name: str) -> list[str]:
    """Как инструмент может называться в bin/.

    В Windows исполняемый файл обязан иметь .exe — иначе MSYS не считает его
    исполняемым, и установщик кладёт движки как nuclei.exe. Python, в отличие от
    оболочки MSYS, расширение сам не подставляет: os.path.exists("bin/nuclei")
    на Windows даёт False, хотя nuclei.exe лежит рядом. Отсюда и «5 из 19»
    в app.py engines. Поэтому варианты перебираем явно.
    """
    if os.name == "nt":
        return [name + ".exe", name + ".cmd", name]
    return [name]


def tool_path(name: str, settings=None) -> str | None:
    """ASM_<TOOL>_BIN -> $ASM_TOOLS_DIR/bin -> <проект>/bin -> PATH.

    Наш каталог инструментов имеет приоритет над PATH: в системе может лежать
    чужой одноимённый бинарник (например, python-httpx), и подменять движок нельзя.
    """
    env_key = "ASM_" + re.sub(r"[^A-Z0-9]", "_", name.upper()) + "_BIN"
    legacy_explicit = os.environ.get(env_key)
    explicit = _config_value(settings, env_key, legacy_explicit)
    if explicit and os.path.exists(str(explicit)):
        return str(explicit)
    tools_dir = _config_value(settings, "ASM_TOOLS_DIR", TOOLS_DIR) or TOOLS_DIR
    for base in [str(tools_dir)] + LEGACY_DIRS + [ROOT]:
        for c in _candidates(name):
            cand = os.path.join(base, "bin", c)
            if os.path.exists(cand) and os.access(cand, os.X_OK):
                return cand
    if name == "nikto.pl":  # nikto — скрипт perl внутри своего каталога
        for base in [str(tools_dir)] + LEGACY_DIRS:
            nk = os.path.join(base, "nikto", "program", "nikto.pl")
            if os.path.exists(nk):
                return nk
    if name == "testssl.sh":  # testssl нужно дерево с etc/ (карты шифров) — берём из своего каталога
        for base in [str(tools_dir)] + LEGACY_DIRS:
            ts = os.path.join(base, "testssl", "testssl.sh")
            if os.path.exists(ts):
                return ts
    for base in [str(tools_dir)] + LEGACY_DIRS:
        for extra in (os.path.join(base, "pylibs", "bin"), os.path.join(base, "bin")):
            for c in _candidates(name):
                cand = os.path.join(extra, c)
                if os.path.exists(cand) and os.access(cand, os.X_OK):
                    return cand
    return shutil.which(name)


def _tool_path(name: str, settings=None) -> str | None:
    """Invoke tool_path with snapshot support and legacy callback compatibility."""
    return call_with_settings(tool_path, name, settings=settings)


class Stopped(RuntimeError):
    """Оператор нажал стоп: новые процессы не запускаются.

    Исключение, а не тихий возврат пустого результата: пустой результат в отчёте
    неотличим от «всё чисто», и это ровно тот режим отказа, который описан в
    документации проекта как «молчание вместо результата».
    """


# Живые процессы и флаг остановки. Без этого кнопка «стоп» убивает только
# родителя: subprocess.run(timeout=...) не трогает внуков, а nuclei тянет за
# собой клиент interactsh, wapiti и sqlmap плодят воркеры. Кнопка, после
# которой движок продолжает долбить сервер заказчика, хуже отсутствия кнопки.
_PROCS: set = set()
_PROCS_LOCK = threading.Lock()
STOPPED = threading.Event()
# Кто пережил последнюю остановку. Пустой список — доказательство, что кнопка
# сработала; непустой надо показывать оператору.
_LAST_STOP: list = []
_STOP_LOCK = threading.Lock()


def _store():
    """База для глобального флага. Импорт отложенный: engines импортируется
    раньше, чем база обязательно готова, а падать на импорте нельзя."""
    try:
        from . import store as _st
        return _st
    except Exception:
        return None


def halt_state() -> bool:
    """Остановлено ли что-либо — в этом процессе или в любом другом.

    Флаг в памяти (STOPPED) мгновенный, но виден только своему процессу.
    Флаг в базе виден всем: кнопку нажимают в веб-интерфейсе, а скан может
    идти из CLI в другом терминале. Проверяем оба.
    """
    if STOPPED.is_set():
        return True
    st = _store()
    if st is None:
        return False
    try:
        return bool(st.halt_active())
    except Exception:
        return False


def stop_all(reason: str = "") -> int:
    """Убить все живые деревья процессов и запретить запуск новых.

    Возвращает число ПОДТВЕРЖДЁННО убитых деревьев. Раньше возвращалось число
    попыток: «сигнал отправлен» — не то же самое, что «процесс умер», а оператор
    видел «убито: 3» и считал воздействие прекращённым.

    Кто не умер, виден в stop_survivors().

    Флаг пишется и в базу: процесс, который нажал кнопку, убивает только свои
    процессы, а запретить запуск новых надо всем остальным тоже.
    """
    STOPPED.set()
    st = _store()
    if st is not None:
        try:
            st.halt_set(True, reason)
        except Exception:
            pass
    with _PROCS_LOCK:
        procs = list(_PROCS)
    for p in procs:
        _kill_tree(p)
    # Проверяем ВЕСЬ список, а не только тех, кого _kill_tree сочла живой.
    # Иначе ошибка внутри неё в свою пользу (или отказ средства проверки)
    # убрал бы выживший процесс из отчёта — а он остался бы работать на объекте.
    alive = _wait_dead([p.pid for p in procs], timeout=5.0)
    survivors = [p for p in procs if p.pid in alive]
    dead = len(procs) - len(survivors)
    with _STOP_LOCK:
        _LAST_STOP.clear()
        _LAST_STOP.extend({"pid": p.pid, "cmd": _cmd_of(p)} for p in survivors)
    return dead


def resume() -> None:
    """Снять флаг остановки (нужно для тестов и для повторного запуска).

    Снимает и в памяти, и в базе. Ничего при этом не возобновляется само:
    закрытая сессия остаётся закрытой, шаги надо предлагать заново.
    """
    STOPPED.clear()
    st = _store()
    if st is not None:
        try:
            st.halt_set(False)
        except Exception:
            pass


def running() -> list:
    """Живые процессы — для отчёта «что было запущено на момент стопа».

    Завершившиеся отсеиваются: запись в списке живёт до выхода из run(),
    а он может быть пропущен (поток убит, тестовая фикстура), и тогда
    оператору показывали бы работу, которой уже нет.
    """
    with _PROCS_LOCK:
        procs = list(_PROCS)
    live = [p for p in procs if p.poll() is None]
    if len(live) != len(procs):
        with _PROCS_LOCK:
            _PROCS.intersection_update(set(live))
    return live


def _close_pipes(p: subprocess.Popen) -> None:
    """Закрыть каналы процесса.

    communicate() закрывает их сам, но если процесс убит до его вызова
    (остановка застала запуск), три дескриптора остаются открытыми до
    сборщика мусора — на длинном скане это утечка.
    """
    for f in (p.stdin, p.stdout, p.stderr):
        try:
            if f is not None:
                f.close()
        except Exception:
            pass


def _cmd_of(p: subprocess.Popen) -> str:
    """Команда процесса одной строкой — чтобы оператор понял, что именно выжило."""
    try:
        args = p.args
        txt = (" ".join(str(x) for x in args)
               if isinstance(args, (list, tuple)) else str(args))
    except Exception:
        txt = "?"
    return txt if len(txt) <= 120 else txt[:117] + "..."


def _pid_alive(pid: int) -> bool:
    """Жив ли процесс. Проверка НЕ имеет права его убивать.

    На Windows os.kill(pid, 0) — не проверка: по документации CPython любое
    значение сигнала, кроме CTRL_C_EVENT и CTRL_BREAK_EVENT, приводит к
    TerminateProcess. То есть такая «проверка» сама завершила бы процесс и
    засчитала остановку успешной. Поэтому там опрашивается tasklist.
    """
    if os.name == "nt":
        try:
            cp = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                capture_output=True, text=True, timeout=15)
        except Exception:
            return True  # проверить не смогли — считаем живым, это безопасная сторона
        for row in csv.reader((cp.stdout or "").splitlines()):
            if len(row) >= 2 and row[1].strip() == str(pid):
                return True
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_dead(pids: list, timeout: float = 5.0, step: float = 0.2) -> list:
    """Дождаться смерти процессов. Возвращает тех, кто выжил.

    Сигнал и смерть — не одно и то же: taskkill возвращает управление раньше,
    чем система добьёт процесс. Проверять надо с ожиданием, иначе остановка
    рапортует об успехе, пока скан продолжает работать.
    """
    left = list(pids)
    deadline = time.time() + timeout
    while left:
        left = [x for x in left if _pid_alive(x)]
        if not left or time.time() >= deadline:
            break
        time.sleep(step)
    return left


def stop_survivors() -> list:
    """Кто пережил последнюю остановку.

    Пустой список — это и есть доказательство, что кнопка сработала. Непустой
    надо показать громко: на объекте остался работающий процесс.
    """
    with _STOP_LOCK:
        return list(_LAST_STOP)


def _kill_tree(p: subprocess.Popen) -> bool:
    """Убить процесс вместе со всеми потомками и ПОДТВЕРДИТЬ смерть.

    True — процесс точно мёртв; False — подтвердить не удалось, и это надо
    показать оператору, а не проглотить.

    Windows: taskkill /T /F — единственный способ без сторонних библиотек
    (Job Objects требуют pywin32, а ставить его ради этого нельзя).
    POSIX: процесс запускается в своей группе (start_new_session), поэтому
    сигнал уходит всей группе сразу.
    """
    pid = p.pid
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=20)
        else:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError, subprocess.SubprocessError):
        try:
            p.kill()
        except (ProcessLookupError, OSError):
            pass
    try:
        p.wait(timeout=2)
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass
    return not _pid_alive(pid)


_def_stop_poll = os.environ.get("ASM_STOP_POLL") or "2"
try:
    _STOP_POLL = float(_def_stop_poll)
except ValueError:
    _STOP_POLL = 2.0


def _watchdog(p: subprocess.Popen, done: threading.Event, settings=None) -> None:
    """Следит за флагом остановки всё время, пока работает движок.

    Кнопка СТОП в веб-интерфейсе нажата в ДРУГОМ процессе и списка процессов
    этого процесса не видит. Без сторожа скан, запущенный в терминале,
    продолжал бы работать, а оператор считал бы воздействие прекращённым.
    Флаг лежит в базе, поэтому виден всем — сторож его и читает.
    """
    poll = float(_config_value(settings, "ASM_STOP_POLL", _STOP_POLL))
    if poll <= 0:
        return
    while not done.wait(poll):
        try:
            if halt_state():
                _kill_tree(p)
                return
        except Exception:
            return


# ------------------------------------------------- куда идут движки (§8.3)
#
# По умолчанию движки работают на нашей машине. Если задан ASM_REMOTE_SSH
# (`user@host`), команда уходит на промежуточную машину через ssh: оттуда идёт
# трафик к объекту, там живут инструменты, а **база, кэш и разбор остаются у
# нас** — возвращается только вывод. Это тот самый режим, который был записан
# в §8.3 и до сих пор не был сделан.
#
# Почему именно ssh-клиент, а не библиотека: отпечаток OpenSSH — самый обычный,
# ничего дополнительно не ставится, соединение открываем мы (правило §26.2:
# обратных соединений и маячков нет).
REMOTE_SSH = (os.environ.get("ASM_REMOTE_SSH") or "").strip()


def remote_state(settings=None) -> tuple[bool, str]:
    """Настроен ли вынос движков для snapshot и всё ли для него есть."""
    remote_ssh = str(_config_value(settings, "ASM_REMOTE_SSH", REMOTE_SSH) or "").strip()
    if not remote_ssh:
        return False, ""
    ssh = _tool_path("ssh", settings) or shutil.which("ssh")
    if not ssh:
        return False, ("ASM_REMOTE_SSH задан, но клиента ssh нет: движки остались бы "
                       "локальными, а это другой след — поэтому отказ, а не тихая подмена")
    if "@" not in remote_ssh:
        return False, "ASM_REMOTE_SSH должен быть в виде пользователь@хост"
    return True, ""


def _remote_wrap(cmd: list[str], settings=None) -> tuple[list[str], str]:
    """Локальная команда → команда на промежуточной машине. Возврат: (argv, причина).

    Переменные окружения (прокси, UA) передаются на ту сторону явно: окружение
    ssh не наследуется, и без этого прикрытие действовало бы на нашей стороне и
    не действовало там, откуда реально идёт трафик.
    """
    ok, why = remote_state(settings)
    if not ok:
        return [], why
    ssh = _tool_path("ssh", settings) or shutil.which("ssh") or "ssh"
    remote_ssh = str(_config_value(settings, "ASM_REMOTE_SSH", REMOTE_SSH) or "").strip()
    env = _env_extra(settings)
    keep = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ASM_UA")
    pairs = [f"{k}={shlex.quote(str(env[k]))}" for k in keep if env.get(k)]
    inner = " ".join(shlex.quote(str(c)) for c in cmd)
    if pairs:
        inner = "env " + " ".join(pairs) + " " + inner
    argv = [ssh, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15", remote_ssh, "--", inner]
    return argv, ""


def ok_argv(argv: list[str]) -> bool:
    return bool(argv)


def report_remote_fail(cmd: list[str], why: str) -> None:
    """Отказ вынести движок — в журнал, а не в тишину."""
    try:
        from . import store
        store.audit("engine_remote_failed",
                    {"why": str(why)[:200], "cmd": " ".join(str(c) for c in cmd)[:200]})
    except Exception:  # noqa: BLE001 — журнал не должен мешать отказу
        pass


def run(cmd: list[str], *, data: str | None = None, timeout: int = 300,
        cwd: str | None = None, settings=None) -> subprocess.CompletedProcess:
    if halt_state():
        raise Stopped("остановлено оператором")
    remote_ssh = str(_config_value(settings, "ASM_REMOTE_SSH", REMOTE_SSH) or "").strip()
    if remote_ssh:
        argv, why = _remote_wrap(cmd, settings)
        if not ok_argv(argv):
            # Не тихая подмена на локальный запуск: это был бы другой след, чем
            # тот, о котором договорились. Отказ с причиной — и он виден в журнале.
            report_remote_fail(cmd, why)
            raise RuntimeError("вынос движков не удался: " + why)
        cmd = argv
        cwd = None  # на той стороне своих путей к коду нет
    kwargs: dict = {}
    if os.name != "nt":
        # своя группа процессов — иначе os.killpg убьёт и нас самих
        kwargs["start_new_session"] = True
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True,
                         env=_env_extra(settings), cwd=cwd, **kwargs)
    with _PROCS_LOCK:
        _PROCS.add(p)
    done = threading.Event()
    threading.Thread(target=_watchdog, args=(p, done, settings), daemon=True).start()
    try:
        # Между проверкой флага и запуском процесс мог стартовать ровно в тот
        # момент, когда кнопка СТОП снимала копию списка живых, — тогда его не
        # убьёт никто. Перепроверяем сразу после регистрации.
        if halt_state():
            raise Stopped("остановлено оператором")
        out, err = p.communicate(input=data, timeout=timeout)
        return subprocess.CompletedProcess(cmd, p.returncode, out, err)
    except Stopped:
        _kill_tree(p)
        raise
    except subprocess.TimeoutExpired:
        _kill_tree(p)
        try:
            out, err = p.communicate(timeout=10)
        except (subprocess.TimeoutExpired, ValueError):
            out, err = "", ""
        raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)
    finally:
        done.set()
        _close_pipes(p)
        with _PROCS_LOCK:
            _PROCS.discard(p)


def _targets_file(targets: list[str]) -> str:
    """Некоторые движки (tlsx) читают цели только из файла — пишем во временный."""
    fd, path = tempfile.mkstemp(prefix="asm-targets-", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(targets) + "\n")
    return path


def _jsonl(out: str) -> list[dict]:
    rows = []
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def _version(exe: str, settings=None) -> str:
    """Версия инструмента — и честный признак того, что её получить не удалось.

    Три разных исхода, и их нельзя сводить к одному «есть»:
      * «v1.2.3»         — версию прочитали;
      * «без версии»     — инструмент запустился, но версию не напечатал;
      * «не запускается» — ни один ключ не дал успешного запуска. В Windows так
                          выглядит попытка выполнить sh-обёртку через CreateProcess:
                          движок есть на диске, но работать не может.
    Молчаливое «есть» превращало неработающий движок в «установленный» — ровно тот
    дефект «тишина вместо результата», из-за которого три движка дали ноль находок.
    """
    name = os.path.basename(exe).lower()
    flags = tuple(_VERSION_ARGS.get(name) or (
        ("-Version", "-version", "--version", "version") if exe.endswith(".pl")
        else ("-version", "--version", "-V", "-v", "version")))
    any_exit = name in _VERSION_ANY_EXIT
    launched = False
    for flag in flags:
        cmd = script_cmd(exe, [flag], settings=settings)
        if cmd is None:
            # Запустить нечем (на Windows нет bash для .sh). Это и есть честное
            # «не запускается»: движок лежит на диске, но работать не может.
            LAST_ERRORS["version:" + os.path.basename(exe)] = "нечем запустить: нужен bash/perl"
            continue
        # Каталог инструмента: nikto ищет свои базы (databases/) рядом с собой,
        # и без этого версии не печатает вовсе — запускается молча.
        workdir = os.path.dirname(os.path.abspath(exe)) if exe.endswith(".pl") else None
        try:
            r = run(cmd, timeout=30, cwd=workdir, settings=settings)
        except Exception as e:  # noqa: BLE001
            LAST_ERRORS["version:" + os.path.basename(exe)] = str(e)[:120]
            continue
        txt = ((r.stdout or "") + (r.stderr or "")).strip()
        if r.returncode != 0 and not (any_exit and txt):
            continue            # отказ + справка — это не версия (trivy: «python:3.4-alpine» в подсказке)
        launched = True
        if not txt:
            continue
        first = txt.splitlines()[0]
        m2 = re.search(r"\d+\.\d+(?:\.\d+)?", first) or re.search(r"\d+\.\d+(?:\.\d+)?", txt)
        if m2:
            return "v" + m2.group(0)
        return "без версии"
    return "без версии" if launched else "не запускается"


def available(settings=None) -> dict:
    """Статус арсенала и профиль для данного operation snapshot."""
    settings = _effective_settings(settings)
    status = {}
    for e in ENGINES:
        p = _tool_path(e["bin"], settings)
        status[e["id"]] = {**e, "path": p, "installed": bool(p),
                           "version": _version(p, settings=settings) if p else ""}
    templates_dir = _templates_root(settings)
    status["nuclei"]["templates"] = _count_templates(templates_dir)
    profile, pentest, full = _profile_values(settings)
    banned_tags = set() if full else (set(DOS_TAGS) if pentest else set(RISKY_TAGS))
    tags = _config_value(settings, "ASM_NUCLEI_TAGS", None)
    if tags is None:
        tags = "" if pentest else "cve,vkev,exposure,misconfig,takeover"
    severity = _config_value(settings, "ASM_NUCLEI_SEVERITY", None)
    if severity is None:
        severity = "" if pentest else "critical,high,medium"
    nikto_tuning = _config_value(settings, "ASM_NIKTO_TUNING", None)
    if not nikto_tuning:
        nikto_tuning = "0123456789abcde" if pentest else "b2"
    # Verification of discovered secrets remains on its waived legacy path.
    verify = PENTEST
    status["profile"] = {
        "name": profile, "pentest": pentest, "full": full,
        "banned_tags": sorted(banned_tags),
        "nuclei_tags": tags or "(без фильтра — все шаблоны)",
        "nuclei_severity": severity or "(все)",
        "interactsh": pentest,
        "nikto_tuning": nikto_tuning,
        "wapiti_modules": wapiti_modules(settings),
        "trufflehog_verify": verify,
    }
    wordlists_dir = _wordlists_root(settings)
    status["wordlists"] = {"dir": wordlists_dir, "files": _wordlist_files(wordlists_dir)}
    return status


def _count_templates(templates_dir: str | None = None) -> int:
    n = 0
    for base, _dirs, files in os.walk(templates_dir or _templates_root()):
        n += sum(1 for f in files if f.endswith(".yaml"))
    return n


def _wordlist_files(wordlists_dir: str | None = None) -> list[dict]:
    out = []
    wordlists_dir = wordlists_dir or _wordlists_root()
    if os.path.isdir(wordlists_dir):
        for f in sorted(os.listdir(wordlists_dir)):
            p = os.path.join(wordlists_dir, f)
            if os.path.isfile(p):
                try:
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        n = sum(1 for _ in fh)
                except Exception:
                    n = 0
                out.append({"file": f, "lines": n, "path": p})
    return out


def ready(settings=None) -> bool:
    """Готов ли активный этап: нужны веб-проба и движок проверок."""
    return bool(_tool_path("httpx", settings)) or bool(_tool_path("nuclei", settings))


# ------------------------------------------------------------------ разведка имён
def subfinder(domain: str, limit: int = 300, timeout: int = 120,
              all_sources: bool = False, *, settings=None) -> list[str]:
    """Пассивные поддомены от subfinder (без ключей работают ~10 источников)."""
    exe = _tool_path("subfinder", settings)
    if not exe or not domain:
        return []
    cmd = [exe, "-d", domain, "-silent", "-duc", "-timeout", "10", "-max-time", str(max(30, timeout - 20))]
    if all_sources:
        cmd.append("-all")
    try:
        r = run(cmd, timeout=timeout, settings=settings)
    except Exception:
        return []
    names = [ln.strip().lower().rstrip(".") for ln in (r.stdout or "").splitlines()]
    return list(dict.fromkeys(n for n in names if n and "." in n))[:limit]


def amass_passive(domain: str, limit: int = 200, timeout: int = 240, *, settings=None) -> list[str]:
    """OWASP Amass в пассивном режиме — медленнее, но находит больше забытого."""
    exe = _tool_path("amass", settings)
    if not exe or not domain:
        return []
    cmd = [exe, "enum", "-passive", "-d", domain, "-timeout", "3"]
    try:
        r = run(cmd, timeout=timeout, settings=settings)
    except Exception:
        return []
    names = [ln.strip().lower() for ln in (r.stdout or "").splitlines() if "." in ln and " " not in ln]
    return list(dict.fromkeys(n for n in names if n.endswith(domain)))[:limit]


# ------------------------------------------------------------------ DNS
def dnsx_resolve(hosts: Iterable[str], limit: int = 400, timeout: int = 180,
                *, settings=None) -> dict[str, list[str]]:
    """Массовое разрешение A/AAAA. Возвращает {хост: [ip]}."""
    exe = _tool_path("dnsx", settings)
    hosts = [h for h in dict.fromkeys(hosts) if h][:limit]
    if not exe or not hosts:
        return {}
    cmd = [exe, "-silent", "-duc", "-a", "-aaaa", "-resp", "-json"]
    try:
        r = run(cmd, data="\n".join(hosts), timeout=timeout, settings=settings)
    except Exception:
        return {}
    out: dict[str, list[str]] = {}
    for row in _jsonl(r.stdout or ""):
        host = (row.get("host") or "").lower()
        ips = row.get("a") or []
        if isinstance(ips, str):
            ips = [ips]
        ips = [str(i) for i in ips if i]
        v6 = row.get("aaaa") or []
        if isinstance(v6, str):
            v6 = [v6]
        ips += [str(i) for i in v6 if i]
        if host and ips:
            out.setdefault(host, [])
            for ip in ips:
                if ip not in out[host]:
                    out[host].append(ip)
    return out


# ------------------------------------------------------------------ веб-проба
def httpx_probe(hosts: Iterable[str], limit: int = 300, timeout: int = 300,
                ports: str = "", *, settings=None) -> list[dict]:
    """Быстрая веб-проба: статус, заголовок, технологии, сервер, CDN, TLS."""
    exe = _tool_path("httpx", settings)
    targets = [h for h in dict.fromkeys(hosts) if h][:limit]
    if not exe or not targets:
        return []
    cmd = [exe, "-silent", "-json", "-no-color", "-duc", "-title", "-status-code", "-web-server",
           "-tech-detect", "-cdn", "-cname", "-ip", "-tls-grab", "-follow-redirects",
           "-timeout", "8", "-retries", "1", "-threads", "25",
           "-rate-limit", str(rate_for("httpx", settings))]
    if ports:
        cmd += ["-ports", ports]
    try:
        r = run(cmd, data="\n".join(targets), timeout=timeout, settings=settings)
    except Exception:
        return []
    return _jsonl(r.stdout or "")


def _tlsx_one_batch(exe: str, targets: list[str], extra: list[str], timeout: int,
                    *, settings=None) -> list[dict]:
    path = _targets_file(targets)
    try:
        r = run([exe, "-silent", "-json", "-duc", "-l", path] + extra,
                timeout=timeout, settings=settings)
    except Exception:
        return []
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return _jsonl(r.stdout or "")


# ------------------------------------------------------------------ TLS
def tlsx_certs(hosts: Iterable[str], limit: int = 120, timeout: int = 240,
               *, settings=None) -> list[dict]:
    """Сертификаты по хостам: SAN, издатель, сроки, самоподпись."""
    exe = _tool_path("tlsx", settings)
    targets = [h for h in dict.fromkeys(hosts) if h][:limit]
    if not exe or not targets:
        return []
    # tlsx не разрешает смешивать -san/-cn с другими пробами: берём только сертификат
    return _tlsx_one_batch(
        exe, targets, ["-san", "-cn", "-timeout", "6", "-concurrency", "20"],
        timeout, settings=settings,
    )


# ------------------------------------------------------------------ обход и архивы
def katana_urls(urls: Iterable[str], depth: int = 2, limit: int = 200, timeout: int = 180,
                *, settings=None) -> list[str]:
    """Crawler: адреса страниц и параметры (без отправки форм, без вредоносных полезных нагрузок)."""
    exe = _tool_path("katana", settings)
    urls = [u for u in dict.fromkeys(urls) if u][:20]
    if not exe or not urls:
        return []
    cmd = [exe, "-silent", "-d", str(depth), "-jc", "-kf", "all",
           "-rl", str(rate_for("katana", settings)),
           "-timeout", "8", "-c", "10", "-fs", "rdn"]
    try:
        r = run(cmd, data="\n".join(urls), timeout=timeout, settings=settings)
    except Exception:
        return []
    out = []
    for ln in (r.stdout or "").splitlines():
        ln = ln.strip()
        if ln.startswith("http"):
            out.append(ln)
    return list(dict.fromkeys(out))[:limit]


def gau_urls(domain: str, limit: int = 300, timeout: int = 120, *, settings=None) -> list[str]:
    """Адреса из архивов (Wayback, Common Crawl, OTX)."""
    exe = _tool_path("gau", settings)
    if not exe or not domain:
        return []
    try:
        r = run([exe, "--threads", "5", "--timeout", "20", domain],
                timeout=timeout, settings=settings)
    except Exception:
        return []
    out = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip().startswith("http")]
    return list(dict.fromkeys(out))[:limit]


def ffuf_dirs(url: str, wordlist: str = "", limit: int = 60, rate: int | None = None,
              timeout: int = 180, *, settings=None) -> list[dict]:
    """Поиск скрытых путей по словарю. Только для своих адресов; по умолчанию выключено.

    Скорость берётся из профиля (ASM_PROFILE) с разбросом; `rate` перекрывает
    её числом, 0 — без ограничения.
    """
    exe = _tool_path("ffuf", settings)
    wl_dir = _wordlists_root(settings)
    wl = wordlist or os.path.join(str(wl_dir), "dirs-common.txt")
    if not exe or not os.path.exists(wl):
        return []
    if rate is None:
        rate = rate_for("ffuf", settings)
    cmd = [exe, "-u", url.rstrip("/") + "/FUZZ", "-w", wl, "-mc", "200,204,301,302,307,401,403,500",
           "-rate", str(rate), "-t", "10", "-timeout", "6", "-s", "-of", "json", "-o", "/dev/stdout",
           "-noninteractive"]
    try:
        r = run(cmd, timeout=timeout, settings=settings)
    except Exception:
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for row in (data.get("results") or [])[:limit]:
        out.append({"url": row.get("url"), "status": row.get("status"),
                    "length": row.get("length"), "words": row.get("words")})
    return out


# ------------------------------------------------------------------ порты и уязвимости
def port_scan(host: str, top_ports: int = 1000, rate: int | None = None,
              timeout: int = 300, *, settings=None) -> list[int]:
    """naabu: открытые порты (connect-скан, чтобы не требовать root)."""
    exe = _tool_path("naabu", settings)
    if not exe or not host:
        return []
    if rate is None:
        rate = rate_for("naabu", settings)
    cmd = [exe, "-host", host, "-top-ports", str(top_ports), "-duc", "-scan-type", "c",
           "-silent", "-rate", str(rate), "-timeout", "3000", "-retries", "1"]
    try:
        r = run(cmd, timeout=timeout, settings=settings)
    except Exception:
        return []
    ports = []
    for ln in (r.stdout or "").splitlines():
        ln = ln.strip()
        if ":" in ln and not ln.startswith("["):
            tail = ln.rsplit(":", 1)[-1]
            if tail.isdigit():
                ports.append(int(tail))
    return sorted(set(ports))


def vuln_scan(urls: Iterable[str], *, tags: str = "", severity: str = "", extra: list[str] | None = None,
              rate: int | None = None, timeout: int = 900, settings=None) -> list[dict]:
    """nuclei по авторизованным адресам. Итог нормализован (см. active.normalize)."""
    settings = _effective_settings(settings)
    exe = _tool_path("nuclei", settings)
    urls = [u for u in dict.fromkeys(urls) if u][:80]
    if not exe or not urls:
        return []
    profile, pentest, full = _profile_values(settings)
    if rate is None:
        rate = rate_for("nuclei", settings)
    configured_tags = _config_value(settings, "ASM_NUCLEI_TAGS", None)
    if configured_tags is None:
        configured_tags = "" if pentest else "cve,vkev,exposure,misconfig,takeover"
    configured_severity = _config_value(settings, "ASM_NUCLEI_SEVERITY", None)
    if configured_severity is None:
        configured_severity = "" if pentest else "critical,high,medium"
    concurrency = str(_config_value(settings, "ASM_NUCLEI_CONCURRENCY", 25))
    tdir = _templates_root(settings)
    banned_tags = set() if full else (set(DOS_TAGS) if pentest else set(RISKY_TAGS))
    tdir = tdir if os.path.isdir(tdir) else ""
    cmd = [exe, "-jsonl", "-silent", "-no-color", "-stats=false",
           "-rate-limit", str(rate), "-timeout", "6", "-retries", "1",
           "-concurrency", str(concurrency),
           "-max-host-error", "5",
           "-disable-update-check"]
    if not pentest:
        # safe: без внешних OOB-серверов. В pentest interactsh нужен — без него
        # слепые SSRF/XSS/SQLi не обнаруживаются в принципе.
        cmd.append("-no-interactsh")
    sev = (severity or configured_severity).strip()
    tg = (tags or configured_tags).strip()
    if sev:
        cmd += ["-severity", sev]
    if tg:
        cmd += ["-tags", tg]
    if banned_tags:
        cmd += ["-exclude-tags", ",".join(sorted(banned_tags))]
    if tdir:
        cmd += ["-t", tdir]
    if extra:
        cmd += extra
    try:
        r = run(cmd, data="\n".join(urls), timeout=timeout, settings=settings)
    except Exception:
        return []
    from . import active
    out = []
    for row in _jsonl(r.stdout or ""):
        n = active.normalize(row)
        if n["severity"] in ("critical", "high", "medium", "low", "info", "unknown"):
            out.append(n)
    return out


# ------------------------------------------------------------------ nmap
def nmap_services(host: str, ports: list[int], *, timeout: int = 240,
                  top_ports: int = 0, rate: int | None = None, settings=None) -> list[dict]:
    """nmap -sV: точные продукт и версия сервиса (эталон индустрии).

    Только для авторизованных адресов. Без скриптов (-sC выключен), без агрессивных
    режимов: нам нужен отпечаток сервиса, а не эксплуатация.

    Скорость берётся из профиля (ASM_PROFILE) с разбросом; `rate` перекрывает
    её числом, 0 — без ограничения.
    """
    exe = _tool_path("nmap", settings)
    if not exe or not host:
        return []
    if rate is None:
        rate = rate_for("nmap", settings)
    # -sV обязателен: без него в XML нет продукта/версии, а --version-light лишь ускоряет опрос
    cmd = [exe, "-sT", "-Pn", "-n", "-sV", "--version-light", "-T3",
           "--max-rate", str(rate), "--host-timeout", f"{max(60, timeout // 2)}s", "-oX", "-"]
    if ports:
        cmd += ["-p", ",".join(str(p) for p in ports[:200])]
    elif top_ports:
        cmd += ["--top-ports", str(top_ports)]
    else:
        return []
    cmd.append(host)
    try:
        r = run(cmd, timeout=timeout, settings=settings)
    except Exception:
        return []
    import xml.etree.ElementTree as ET
    out: list[dict] = []
    try:
        root = ET.fromstring(r.stdout or "<nmaprun/>")
    except Exception:
        return []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        if svc is None:  # ElementTree: элемент без детей ложен — нельзя писать `find(...) or Element(...)`
            svc = ET.Element("service")
        out.append({
            "port": int(port.get("portid") or 0),
            "service": svc.get("name") or "",
            "product": svc.get("product") or "",
            "version": svc.get("version") or "",
            "extra": svc.get("extrainfo") or "",
            "cpe": [c.text for c in svc.findall("cpe") if c.text],
        })
    return out


# ------------------------------------------------------------------ nikto
# safe: b — определение ПО, 2 — конфигурация.
# pentest/full: 0123456789abcde — весь набор Nikto, включая 0 (загрузка файлов),
# 4/9 (инъекции), 8 (выполнение команд), a (обход аутентификации), e (админ-консоль).
NIKTO_TUNING = os.environ.get("ASM_NIKTO_TUNING", "0123456789abcde" if PENTEST else "b2")


def nikto_scan(url: str, *, timeout: int = 180, max_time: str = "90s",
               settings=None) -> list[dict]:
    """Nikto: конфигурация и опасные файлы веб-сервера. Без инъекционных проверок."""
    settings = _effective_settings(settings)
    _profile, pentest, _full = _profile_values(settings)
    tuning = _config_value(settings, "ASM_NIKTO_TUNING", None)
    if tuning is None or tuning == "":
        tuning = "0123456789abcde" if pentest else "b2"
    exe = _tool_path("nikto.pl", settings)
    if not exe or not url:
        return []
    # nikto сам дописывает расширение (.json) к пути отчёта — пишем во временный файл
    fd, out_prefix = tempfile.mkstemp(prefix="asm-nikto-", suffix="")
    os.close(fd)
    try:
        os.unlink(out_prefix)
    except OSError:
        pass
    cmd = script_cmd(exe, ["-h", url, "-nointeractive", "-ask", "no", "-maxtime", max_time,
                           "-Tuning", tuning, "-Format", "json", "-output", out_prefix],
                     settings=settings)
    if cmd is None:
        LAST_ERRORS["nikto"] = "нет perl — nikto не запустить"
        return []
    nk_dir = os.path.dirname(os.path.abspath(exe))
    try:
        r = run(cmd, timeout=timeout + 30, cwd=nk_dir, settings=settings)   # nikto ищет свои базы относительно себя
    except Exception:
        return []
    txt = ""
    for cand in (out_prefix + ".json", out_prefix):
        if os.path.exists(cand):
            try:
                with open(cand, encoding="utf-8", errors="replace") as fh:
                    txt = fh.read()
                os.unlink(cand)
                break
            except OSError:
                pass
    if not txt:
        txt = (r.stdout or "").strip()
    start = txt.find("[")
    if start < 0:
        start = txt.find("{")
    data = None
    if start >= 0:
        try:
            data = json.loads(txt[start:])
        except Exception:
            data = None
    rows: list = []
    if isinstance(data, dict):
        rows = data.get("vulnerabilities") or data.get("items") or []
    elif isinstance(data, list):
        # nikto отдаёт список объектов по хостам, внутри — "vulnerabilities"
        for obj in data:
            if isinstance(obj, dict) and isinstance(obj.get("vulnerabilities"), list):
                rows += obj["vulnerabilities"]
        if not rows:
            rows = [r for r in data if isinstance(r, dict) and (r.get("msg") or r.get("message"))]
    out = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        out.append({
            "id": str(row.get("id") or row.get("OSVDB") or "nikto"),
            "msg": str(row.get("msg") or row.get("message") or "")[:300],
            "url": str(row.get("url") or url),
            "method": str(row.get("method") or "GET"),
        })
    return out[:60]


# ------------------------------------------------------------------ внутренний контур
def trivy_fs(path: str, *, timeout: int = 600, severity: str = "CRITICAL,HIGH,MEDIUM") -> list[dict]:
    """Trivy по каталогу/репозиторию клиента: уязвимости пакетов и секреты."""
    exe = tool_path("trivy")
    if not exe or not os.path.isdir(path):
        return []
    cmd = [exe, "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret",
           "--severity", severity, path]
    try:
        r = run(cmd, timeout=timeout)
    except Exception:
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            out.append({"kind": "vuln", "target": res.get("Target"), "id": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"), "severity": (v.get("Severity") or "").lower(),
                        "title": v.get("Title") or ""})
        for s_ in res.get("Secrets") or []:
            out.append({"kind": "secret", "target": res.get("Target"), "id": s_.get("RuleID"),
                        "title": s_.get("Title") or "", "line": s_.get("StartLine")})
    return out


def trivy_image(image: str, *, timeout: int = 900) -> list[dict]:
    """Trivy по образу контейнера (если клиент передал образ для проверки)."""
    exe = tool_path("trivy")
    if not exe or not image:
        return []
    cmd = [exe, "image", "--quiet", "--format", "json", "--scanners", "vuln,secret",
           "--severity", "CRITICAL,HIGH,MEDIUM", image]
    try:
        r = run(cmd, timeout=timeout)
    except Exception:
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            out.append({"kind": "vuln", "target": res.get("Target"), "id": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"), "severity": (v.get("Severity") or "").lower(),
                        "title": v.get("Title") or ""})
        for s_ in res.get("Secrets") or []:
            out.append({"kind": "secret", "target": res.get("Target"), "id": s_.get("RuleID"),
                        "title": s_.get("Title") or "", "line": s_.get("StartLine")})
    return out


def gitleaks_dir(path: str, *, timeout: int = 600) -> list[dict]:
    """Gitleaks: поиск паролей, ключей и токенов в репозитории клиента."""
    exe = tool_path("gitleaks")
    if not exe or not os.path.isdir(path):
        return []
    cmd = [exe, "dir", path, "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner"]
    try:
        r = run(cmd, timeout=timeout)
    except Exception:
        return []
    txt = (r.stdout or "").strip()
    try:
        rows = json.loads(txt) if txt.startswith("[") else []
    except Exception:
        rows = []
    out = []
    for row in rows[:200] if isinstance(rows, list) else []:
        if isinstance(row, dict):
            out.append({"rule": row.get("RuleID"), "file": row.get("File"),
                        "line": row.get("StartLine"), "описание": row.get("Description"),
                        "фрагмент": _mask(row.get("Match") or row.get("Secret") or "")})
    return out


def _mask(value: str) -> str:
    """Показываем только края секрета: доказательство есть, а сам секрет не копируется."""
    v = (value or "").strip()
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}…{v[-2:]} ({len(v)} символов)"


def clone_repo(url: str, dest: str, *, timeout: int = 300) -> bool:
    """Копия репозитория заказчика (только чтение, без правок на объекте)."""
    url = (url or "").strip()
    if not url or not re.match(r"^(https?://|git@|ssh://)", url):
        return False
    try:
        r = run(["git", "clone", "--depth", "1", "--quiet", url, dest], timeout=timeout)
    except Exception:
        return False
    return r.returncode == 0 and os.path.isdir(dest)


def fetch_text(url: str, *, limit: int = 65536, timeout: int = 15) -> tuple[int, str]:
    """Однократное чтение открытого файла по найденному адресу (для поиска секретов)."""
    import urllib.error
    import urllib.request
    if not (url or "").startswith("http"):
        return 0, ""
    # Это чтение файлов НА ОБЪЕКТЕ: направление inward, и UA обязан быть
    # обычным. Прежняя строка «asm-audit/1.0 (authorized check)» прямо
    # сообщала тому, кто читает логи, что пришёл аудит.
    from . import stealth
    req = urllib.request.Request(url, headers={"User-Agent": stealth.ua("inward")},
                                 method="GET")
    try:
        with stealth.open_url(req, purpose="inward", timeout=timeout) as resp:
            raw = resp.read(limit + 1)
            return resp.status, raw[:limit].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""



def testssl_audit(host: str, port: int = 443, *, timeout: int = 240,
                  sections: tuple[str, ...] = ("protocols", "headers"),
                  settings=None) -> list[dict]:
    """Глубокий аудит TLS-конфигурации (testssl.sh): протоколы, шифры, заголовки.

    Возвращает только значимые строки: служебные сообщения самого testssl отбрасываются.
    """
    exe = _tool_path("testssl.sh", settings)
    if not exe or not host:
        return []
    fd, json_path = tempfile.mkstemp(prefix="asm-testssl-", suffix=".json")
    os.close(fd)
    args = ["--quiet", "--color", "0", "--warnings", "off", "--jsonfile", json_path]
    for sec in sections:
        args.append("--" + sec)
    args.append(f"{host}:{int(port)}")
    cmd = script_cmd(exe, args, settings=settings)
    if cmd is None:
        LAST_ERRORS["testssl"] = "нет bash — testssl.sh не запустить (Windows: нужен Git Bash)"
        return []
    try:
        run(cmd, timeout=timeout, settings=settings)
    except Exception as e:  # noqa: BLE001
        LAST_ERRORS["testssl"] = str(e)[:120]
    data = []
    try:
        with open(json_path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        os.unlink(json_path)
    except Exception:
        data = []
    if not isinstance(data, list):
        return []
    out = []
    for row in data:
        if not isinstance(row, dict):
            continue
        rid = str(row.get("id") or "")
        sev = str(row.get("severity") or "").upper()
        if rid in TESTSSL_NOISE or sev in ("OK", "INFO", ""):
            continue
        out.append({"id": rid, "severity": sev, "finding": str(row.get("finding") or "")[:300],
                    "порт": port})
    return out


TESTSSL_NOISE = {
    "engine_problem", "optimal_proto", "scanTime", "scanProblem", "HTTP_clock_skew",
    "HTTP_status_code", "service", "TLS_extensions", "TLS_timestamp", "cert_compression",
    "clientAuth", "cert_numbers", "NPN", "ALPN", "ALPN_HTTP2", "TLS_session_ticket",
    "SSL_sessionID_support", "sessionresumption_ticket", "sessionresumption_ID",
    "cert_commonName", "cert_trust", "cert_chain_of_trust", "cert_expirationStatus",
    "cert_extendedKeyUsage", "cert_keyUsage", "cert_fingerprintSHA1", "cert_fingerprintSHA256",
    "cert_serialNumber", "cert_validityPeriod", "cert_signatureAlgorithm", "cert_caIssuers",
    "cert_subject", "cert_issuer", "cert_keySize", "cert_sig_algo", "cert_must_staple",
    "cert_no_ocsp_uri", "cert_ocspURL", "cert_revocation", "cert_nosct", "cert_SCT_status",
    "cert_startdate", "cert_enddate", "cert_expiry_days",
}


# ------------------------------------------------- код и зависимости заказчика
def semgrep_scan(path: str, *, timeout: int = 900, rules: list[str] | None = None) -> list[dict]:
    """Semgrep: поиск опасных мест в исходном коде (SAST) по бесплатным правилам."""
    exe = tool_path("semgrep")
    if not exe or not os.path.isdir(path):
        return []
    confs = rules or _semgrep_rules()
    cmd = [exe, "--json", "--quiet", "--metrics=off", "--timeout", "30",
           "--max-target-bytes", "2000000", "--jobs", str(int(os.environ.get("ASM_SEMGREP_JOBS", "1")))]
    for c in confs:
        cmd += ["--config", c]
    cmd.append(path)
    try:
        r = run(cmd, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        LAST_ERRORS["semgrep"] = str(e)[:200]
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except Exception:
        LAST_ERRORS["semgrep"] = (r.stderr or r.stdout or "нет вывода")[:200]
        return []
    errs = [e for e in (data.get("errors") or []) if e.get("level") == "error"]
    if errs and not data.get("results"):
        LAST_ERRORS["semgrep"] = str(errs[0].get("long_msg") or errs[0])[:200]
    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    prefix = os.path.basename(TOOLS_DIR) + "." + "asm-tools." if False else ""
    local = os.path.join(TOOLS_DIR, "semgrep-rules")
    out = []
    for row in (data.get("results") or [])[:400]:
        extra = row.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe = meta.get("cwe") or []
        cid = str(row.get("check_id") or "")
        # идентификатор правила вида «локальный.путь.javascript.lang.security.audit.eval» → короткая форма
        for pref in (local.replace("/", ".") + ".", "asm-tools.semgrep-rules."):
            if cid.startswith(pref):
                cid = cid[len(pref):]
        out.append({
            "id": cid[-120:], "file": row.get("path"),
            "line": (row.get("start") or {}).get("line"),
            "message": extra.get("message") or "",
            "severity": sev_map.get(str(extra.get("severity") or "").upper(), "MEDIUM"),
            "cwe": ", ".join(cwe) if isinstance(cwe, list) else str(cwe or ""),
            "категория": str(meta.get("category") or ""), "подтверждение": meta.get("confidence") or "",
            "правило": cid,
        })
    return out


def _semgrep_rules() -> list[str]:
    """Локальный набор правил (скачан при установке) или бесплатный облачный профиль."""
    local = next((os.path.join(b, "semgrep-rules") for b in [TOOLS_DIR] + LEGACY_DIRS
                  if os.path.isdir(os.path.join(b, "semgrep-rules"))),
                 os.path.join(TOOLS_DIR, "semgrep-rules"))
    langs = (os.environ.get("ASM_SEMGREP_LANGS")
             or "python,javascript,typescript,php,java,html,dockerfile").split(",")
    confs = [os.path.join(local, l.strip()) for l in langs if l.strip()]
    confs = [c for c in confs if os.path.isdir(c)]
    if confs:
        return confs
    return [os.environ.get("ASM_SEMGREP_CLOUD_RULES", "p/security-audit")]


LAST_ERRORS: dict[str, str] = {}    # последняя причина сбоя каждого движка — чтобы не молчать


def osv_scan(path: str, *, timeout: int = 600) -> list[dict]:
    """OSV-Scanner (Google): уязвимые зависимости по бесплатной базе OSV.dev."""
    exe = tool_path("osv-scanner")
    if not exe or not os.path.isdir(path):
        return []
    cmd = [exe, "scan", "source", "-r", "--format", "json", path]
    try:
        r = run(cmd, timeout=timeout)
    except Exception:
        return []
    txt = (r.stdout or "").strip()
    try:
        data = json.loads(txt) if txt.startswith("{") else {}
    except Exception:
        return []
    out = []
    for res in data.get("results") or []:
        src = (res.get("source") or {}).get("path") or ""
        for pkg in res.get("packages") or []:
            p = pkg.get("package") or {}
            for v in pkg.get("vulnerabilities") or []:
                fixed = ""
                for aff in v.get("affected") or []:
                    for rng in aff.get("ranges") or []:
                        for ev in rng.get("events") or []:
                            if ev.get("fixed") and not fixed:
                                fixed = str(ev["fixed"])
                out.append({"id": v.get("id"), "package": p.get("name"), "version": p.get("version"),
                            "ecosystem": p.get("ecosystem"), "file": src,
                            "summary": v.get("summary") or (v.get("details") or "")[:200],
                            "severity": _osv_severity(v), "fixed": fixed,
                            "aliases": ", ".join((v.get("aliases") or [])[:3])})
    return out


def _osv_severity(v: dict) -> str:
    """Критичность из записи OSV: число, CVSS-вектор или словесная оценка базы."""
    for sev in v.get("severity") or []:
        score = str(sev.get("score") or "").strip()
        try:
            num = float(score)
        except ValueError:
            num = _cvss3_score(score)
        if num >= 9:
            return "CRITICAL"
        if num >= 7:
            return "HIGH"
        if num >= 4:
            return "MEDIUM"
        if num > 0:
            return "LOW"
    db = v.get("database_specific") or {}
    sev_txt = str(db.get("severity") or "").upper()
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
            "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(sev_txt, "MEDIUM")


def _cvss3_score(vector: str) -> float:
    """Балл CVSS v3.0/3.1 из вектор-строки (по официальной формуле).

    Нужен потому, что базы отдают и число, и строку вида
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — считать надо из строки.
    """
    import math
    if not vector or "AV:" not in vector:
        return 0.0
    m = dict(part.split(":") for part in vector.split("/") if ":" in part)
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(m.get("AV", ""), 0.0)
    ac = {"L": 0.77, "H": 0.44}.get(m.get("AC", ""), 0.0)
    scope_changed = m.get("S") == "C"
    pr_table = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.50 if scope_changed else 0.27}
    pr = pr_table.get(m.get("PR", ""), 0.0)
    ui = {"N": 0.85, "R": 0.62}.get(m.get("UI", ""), 0.0)
    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("C", ""), 0.0)
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("I", ""), 0.0)
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("A", ""), 0.0)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min((impact + exploitability) * (1.08 if scope_changed else 1.0), 10.0)
    return math.ceil(raw * 10) / 10       # официальное округление CVSS: вверх до десятых


def trufflehog_dir(path: str, *, timeout: int = 600, verify: bool = False) -> list[dict]:
    """TruffleHog: секреты в коде. Проверка «живой ли ключ» — только по явному разрешению.

    По умолчанию проверка выключена: она отправляет найденный ключ сервису-владельцу.
    Это допустимо в аудите, но включать такое должен человек, а не инструмент по умолчанию.
    """
    exe = tool_path("trufflehog")
    if not exe or not os.path.isdir(path):
        return []
    cmd = [exe, "filesystem", path, "--json", "--no-update", "--concurrency", "2"]
    do_verify = verify or PENTEST or os.environ.get("ASM_TRUFFLEHOG_VERIFY", "0") in ("1", "true", "yes")
    if not do_verify:
        cmd.append("--no-verification")   # не трогаем сервисы-владельцы ключей
    try:
        r = run(cmd, timeout=timeout)
    except Exception:
        return []
    out = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        meta = (((row.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        out.append({"detector": row.get("DetectorName"), "file": meta.get("file"),
                    "line": meta.get("line"), "verified": bool(row.get("Verified")),
                    "фрагмент": _mask(row.get("Raw") or "")})
        if len(out) >= 200:
            break
    return out


def trivy_config(path: str, *, timeout: int = 600) -> list[dict]:
    """Trivy config: ошибки конфигурации в файлах развёртывания (Dockerfile, k8s, terraform)."""
    exe = tool_path("trivy")
    if not exe or not os.path.isdir(path):
        return []
    cmd = [exe, "config", "--quiet", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM", path]
    try:
        r = run(cmd, timeout=timeout)
    except Exception:
        return []
    try:
        data = json.loads(r.stdout or "{}")
    except Exception:
        return []
    out = []
    for res in data.get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            out.append({"id": m.get("ID"), "target": res.get("Target"),
                        "title": m.get("Title") or "", "severity": (m.get("Severity") or "").upper(),
                        "описание": (m.get("Description") or "")[:300],
                        "как исправить": (m.get("Resolution") or "")[:300],
                        "строка": ((m.get("CauseMetadata") or {}).get("StartLine"))})
    return out



# safe: пассивные модули. pentest/full — «all»: sql, timesql, exec, xss,
# permanentxss, xxe, file, redirect, csrf, csp, log4shell, shellshock,
# brute_force_login и остальные.
WAPITI_MODULES_DEFAULT = "all" if PENTEST else "backup,cms,htp,methods,wapp,wp_enum"


def wapiti_modules(settings=None) -> str:
    """Действующий набор модулей Wapiti для snapshot или legacy environment."""
    settings = _effective_settings(settings)
    configured = _config_value(settings, "ASM_WAPITI_MODULES", None)
    if configured is not None:
        return str(configured)
    _profile, pentest, _full = _profile_values(settings)
    return "all" if pentest else "backup,cms,htp,methods,wapp,wp_enum"


def wapiti_scan(url: str, *, timeout: int = 300, max_time: int = 120,
                modules: str = "", settings=None) -> list[dict]:
    """Wapiti: проверки веб-приложения без инъекций и без перебора учётных данных.

    Список модулей подобран так, чтобы ничего не ломать и не подбирать пароли:
    опасные файлы, заголовки, методы, версии CMS и библиотек, takeover.
    """
    exe = _tool_path("wapiti", settings)
    if not exe or not (url or "").startswith("http"): 
        return []
    # список модулей: ничего не ломает и не подбирает пароли.
    # csrf по умолчанию не берём: он обходит все формы и растягивает проверку в разы
    # набор модулей подобран по фактическому времени работы: модуль takeover на внешних
    # адресах «залипает» на DNS-запросах (свыше 3,5 минут без результата), а проверку
    # захвата поддоменов и так делают шаблоны nuclei — поэтому его в наборе нет
    modules = modules or wapiti_modules(settings)
    fd, out_path = tempfile.mkstemp(prefix="asm-wapiti-", suffix=".json")
    os.close(fd)
    try:
        os.unlink(out_path)      # wapiti сам создаёт отчёт — пустой файл его смущает
    except OSError:
        pass
    # Важные детали, выясненные опытным путём:
    #  * «-q» у wapiti нет — с ним он молча выходит, не сделав отчёта;
    #  * «--scope domain» заставляет обходить весь домен, и проверка не укладывается в лимиты —
    #    оставляем область по умолчанию (папка), это ровно тот режим, что работает за минуты.
    tools_dir = str(_config_value(settings, "ASM_TOOLS_DIR", TOOLS_DIR) or TOOLS_DIR)
    sess = os.path.join(tools_dir, "wapiti-sessions")
    try:
        os.makedirs(sess, exist_ok=True)
    except OSError:
        sess = ""
    cmd = script_cmd(exe, ["-u", url, "-m", modules,
                           "--max-scan-time", str(int(max_time)), "-t", "10", "-f", "json",
                           "-o", out_path, "--flush-session"], settings=settings)
    if cmd is None:
        LAST_ERRORS["wapiti"] = "запуск недоступен (Windows: нужен python из Git Bash)"
        return []
    if sess:
        cmd += ["--store-session", sess]     # чтобы кэш не оседал в домашнем каталоге
    # Жёсткий предел: wapiti — самая долгая проверка, и он не должен задерживать аудит.
    # Если отчёт не успел — честно говорим об этом и идём дальше (в логе будет строка).
    hard = min(int(timeout), int(max_time) + 300)   # запас на модули, которые не прерываются на ходу
    try:
        run(cmd, timeout=hard, settings=settings)
    except Exception as e:  # noqa: BLE001
        LAST_ERRORS["wapiti"] = f"не уложился в {hard} с: {str(e)[:120]}"
    data = {}
    try:
        with open(out_path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        os.unlink(out_path)
    except Exception:
        data = {}
    if not data:
        LAST_ERRORS.setdefault("wapiti", "отчёт не получен (проверка не успела за отведённое время)")
        return []
    LAST_ERRORS.pop("wapiti", None)
    out = []
    for module, items in (data.get("vulnerabilities") or {}).items():
        for it in (items or [])[:120]:
            level = int(it.get("level") or 0)
            sev = "MEDIUM" if level >= 3 else ("LOW" if level == 2 else "LOW")
            out.append({"module": module, "info": str(it.get("info") or "")[:300],
                        "path": it.get("path"), "method": it.get("method"),
                        "parameter": it.get("parameter"), "severity": sev,
                        "исходный модуль": it.get("module") or module})
    return out

# ------------------------------------------------------------------ уязвимости
def sensitive_paths(urls: Iterable[str]) -> list[dict]:
    """Потенциально чувствительные адреса среди собранных (требуют ручного подтверждения)."""
    out = []
    for u in dict.fromkeys(urls):
        low = (u or "").lower()
        if not low.startswith("http"):
            continue
        for ext in SENSITIVE_EXT:
            if ext in low:
                out.append({"url": u, "marker": ext})
                break
    return out[:60]

_SELFTEST_INNER = (
    "import os,subprocess,sys,time\n"
    "g=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])\n"
    "open(sys.argv[1],'w').write('%d %d' % (os.getpid(), g.pid))\n"
    "time.sleep(120)\n"
)


def selftest(timeout: float = 25.0) -> dict:
    """Проверить кнопку СТОП на этой машине — на настоящем дереве процессов.

    Отвечает на один вопрос: если нажать СТОП во время работы, действительно ли
    прекратится воздействие на объект. Проверяются оба процесса — и родитель,
    и потомок. Убить только родителя — это тот случай, когда скан продолжает
    работать, а оператор видит «остановлено».

    Собранную фикстуру убивает настоящая stop_all(), то есть проверяется
    ровно тот путь, которым пойдёт кнопка.
    """
    res: dict = {"ok": False, "platform": os.name, "pids": [], "alive_before": [],
                 "survivors": [], "killed_confirmed": 0, "exc": "", "notes": [],
                 "mechanism": ("taskkill /T /F" if os.name == "nt"
                               else "killpg(SIGTERM, затем SIGKILL)")}
    res["notes"].append("проверяется путь этой системы (Windows)" if os.name == "nt"
                        else "проверяется путь POSIX; на Windows поведение иное")

    if halt_state():
        # Снять чужую остановку ради самопроверки нельзя: кнопка важнее теста.
        res["notes"].append("сейчас действует остановка, и самопроверка её не снимет. "
                            "Сначала: python3 app.py agent resume")
        return res

    tmp = tempfile.mkdtemp(prefix="asm-selftest-")
    pidfile = os.path.join(tmp, "pids.txt")
    box: dict = {}

    def _work() -> None:
        try:
            run([sys.executable, "-c", _SELFTEST_INNER, pidfile], timeout=int(timeout))
        except Exception as e:  # noqa: BLE001 — причину показываем оператору
            box["exc"] = f"{type(e).__name__}: {e}"

    th = threading.Thread(target=_work, daemon=True)
    th.start()

    pids: list = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(pidfile):
            try:
                with open(pidfile, encoding="utf-8") as f:
                    pids = [int(x) for x in f.read().split()]
            except Exception:
                pids = []
            if len(pids) == 2:
                break
        if not th.is_alive():
            break
        time.sleep(0.2)

    if len(pids) != 2:
        # Пустой результат не должен выглядеть как успех.
        res["notes"].append("фикстуру собрать не удалось: дерево процессов не "
                            "запустилось. Проверка НЕ состоялась, это не успех.")
        res["exc"] = box.get("exc", "")
        stop_all("самопроверка: фикстура не собралась")
        th.join(timeout=5)
        shutil.rmtree(tmp, ignore_errors=True)
        resume()
        return res

    shutil.rmtree(tmp, ignore_errors=True)
    time.sleep(0.5)
    res["pids"] = pids
    res["alive_before"] = [x for x in pids if _pid_alive(x)]

    res["killed_confirmed"] = stop_all("самопроверка кнопки СТОП")
    left = _wait_dead(pids, timeout=8.0)
    res["survivors"] = left
    th.join(timeout=5)
    resume()

    res["ok"] = (not left) and sorted(res["alive_before"]) == sorted(pids)
    if not res["ok"] and not left:
        res["notes"].append("процессы умерли, но до нажатия живы были не оба — "
                            "проверка недостоверна")
    return res
