# -*- coding: utf-8 -*-
"""Агент с обязательным подтверждением каждого действия.

Правило, от которого нельзя отступать: агент не выполняет ничего сам. Он собирает
контекст, предлагает следующий шаг и ждёт явного решения человека. Без одобрения
действие не выполняется никогда — ни по таймауту, ни при ошибке модели, ни при
потере связи с ней. Автоодобрения в коде нет ни в каком виде.

Почему так устроено: часть действий необратима. Перебор учётных данных может
заблокировать учётную запись заказчика, инъекционная проверка — записать полезные
данные в боевую базу, тяжёлый шаблон — уронить сервис. Отменить это нельзя,
поэтому решение всегда за человеком, а у каждого решения остаётся след в журнале
аудита: кто предложил, кто одобрил, что получилось.

Классы действий:
  observe — объект не трогаем вовсе: публичные индексы, CT-логи, пассивный DNS,
            материалы заказчика (код, образ).
  probe   — лёгкий контакт с объектом, только чтение, состояние не меняется.
  impact  — может изменить состояние объекта или оказаться необратимым.

Класс части действий зависит от профиля ASM_PROFILE: nuclei и wapiti в профиле
safe читают, а в pentest уже проверяют инъекции и перебирают учётные данные.
"""
from __future__ import annotations

import json
import os
import re

from . import engines, gate, store
from .contracts import ContractError, Step
from .settings import current_settings
from .settings_compat import call_with_settings

OBSERVE, PROBE, IMPACT = "observe", "probe", "impact"

CLASS_TITLE = {
    OBSERVE: "наблюдение (объект не трогаем)",
    PROBE: "проверка (только чтение)",
    IMPACT: "воздействие (может быть необратимым)",
}

# Действия, класс которых зависит от профиля: в safe они читают, в pentest — нет.
_PROFILE_DEPENDENT = {"check_vulns", "check_webapp", "check_webserver", "enum_paths"}

ACTIONS: list[dict] = [
    {"id": "recon_names", "bin": "subfinder", "cls": OBSERVE, "title": "Разведка имён по публичным источникам",
     "tool": "subfinder + amass + sources",
     "why": "CT-логи, пассивный DNS, InternetDB — объект не получает ни одного запроса",
     "risk": "нет: запросы идут к третьим сторонам, не к цели",
     "noise": "низкий", "reversible": True},
    {"id": "recon_dns", "bin": "dnsx", "cls": OBSERVE, "title": "Разрешение имён в адреса",
     "tool": "dnsx", "why": "нужно понять, какие имена вообще живы",
     "risk": "нет", "noise": "низкий", "reversible": True},
    {"id": "recon_archives", "bin": "gau", "cls": OBSERVE, "title": "Адреса из веб-архивов",
     "tool": "gau", "why": "Wayback/CommonCrawl помнят то, чего уже нет на сайте",
     "risk": "нет", "noise": "низкий", "reversible": True},
    {"id": "probe_http", "bin": "httpx", "cls": PROBE, "title": "Проба веб-портов: заголовки, титул, TLS",
     "tool": "httpx", "why": "один лёгкий запрос на порт — статус, сервер, технологии",
     "risk": "низкий: один запрос, состояние не меняется",
     "noise": "низкий", "reversible": True},
    {"id": "probe_tls", "bin": "tlsx", "cls": PROBE, "title": "Сертификаты: SAN, издатель, сроки",
     "tool": "tlsx", "why": "SAN-имена дают новые цели, сроки — находку сами по себе",
     "risk": "низкий", "noise": "низкий", "reversible": True},
    {"id": "probe_testssl", "bin": "testssl.sh", "cls": PROBE, "title": "Аудит TLS-конфигурации",
     "tool": "testssl.sh", "why": "протоколы, шифры, цепочка, HSTS",
     "risk": "низкий, но много соединений к одному порту",
     "noise": "средний", "reversible": True},
    {"id": "enum_ports", "bin": "naabu", "cls": PROBE, "title": "Свои открытые порты",
     "tool": "naabu", "why": "публичные индексы знают не всё и отстают",
     "risk": "низкий, но это уже сканирование", "noise": "высокий", "reversible": True},
    {"id": "enum_services", "bin": "nmap", "cls": PROBE, "title": "Отпечатки сервисов и версии",
     "tool": "nmap -sV", "why": "версия сервиса — то, что уходит в NVD",
     "risk": "низкий без скриптов (-sC выключен)", "noise": "средний", "reversible": True},
    {"id": "crawl_links", "bin": "katana", "cls": PROBE, "title": "Обход ссылок и параметров",
     "tool": "katana", "why": "нужен список адресов для следующих проверок",
     "risk": "низкий", "noise": "средний", "reversible": True},
    {"id": "enum_paths", "bin": "ffuf", "cls": PROBE, "title": "Скрытые пути и файлы по словарю",
     "tool": "ffuf", "why": "панели, бэкапы, служебные файлы",
     "risk": "только чтение, но это перебор путей",
     "noise": "очень высокий", "reversible": True},
    {"id": "check_vulns", "bin": "nuclei", "cls": PROBE, "title": "Проверки по шаблонам nuclei",
     "tool": "nuclei", "why": "основной источник находок по версиям и конфигурации",
     "risk": "зависит от профиля: в safe — чтение, в pentest — перебор и intrusive",
     "noise": "высокий", "reversible": True},
    {"id": "check_webserver", "bin": "nikto.pl", "cls": PROBE, "title": "Конфигурация и опасные файлы веб-сервера",
     "tool": "nikto", "why": "ошибки настройки, служебные файлы, заголовки",
     "risk": "зависит от профиля: в safe — b2, в pentest — инъекции и обход аутентификации",
     "noise": "высокий", "reversible": True},
    {"id": "check_webapp", "bin": "wapiti", "cls": PROBE, "title": "Проверки веб-приложения",
     "tool": "wapiti", "why": "заголовки, методы, версии CMS, takeover",
     "risk": "в pentest — sql/exec/xss и перебор учётных данных: может записать данные "
              "в базу и заблокировать учётную запись",
     "noise": "высокий", "reversible": False},
    {"id": "check_code", "bin": "semgrep", "cls": OBSERVE, "title": "Анализ кода заказчика",
     "tool": "semgrep + osv-scanner", "why": "опасные конструкции и уязвимые библиотеки",
     "risk": "нет: работа по копии материалов", "noise": "нет", "reversible": True},
    {"id": "check_secrets", "bin": "gitleaks", "cls": OBSERVE, "title": "Секреты в коде и открытых файлах",
     "tool": "gitleaks + trufflehog", "why": "ключи дают доступ быстрее любой уязвимости",
     "risk": "в профиле pentest trufflehog проверяет живость ключа — ключ уходит "
            "сервису-владельцу", "noise": "нет", "reversible": True},
    {"id": "check_image", "bin": "trivy", "cls": OBSERVE, "title": "Уязвимости в образе контейнера",
     "tool": "trivy", "why": "образы тянут сотни уязвимых библиотек",
     "risk": "нет", "noise": "нет", "reversible": True},
    {"id": "handoff_access", "bin": "", "cls": IMPACT, "title": "Получение доступа по найденной точке входа",
     "tool": "вручную (Burp / Metasploit)",
     "why": "эксплуатацию агент не выполняет: он готовит точку входа и точную команду",
     "risk": "необратимо: доступ к данным заказчика",
     "noise": "зависит от выбранного способа", "reversible": False},
]

# ---------------------------------------------------------------------------
# Внутренняя работа: то, что делается ПОСЛЕ получения первого доступа.
#
# Почему это отдельный список, а не ещё строки в ACTIONS.
#
# 1. Класс. Всё, что кладёт файл на чужой хост, необратимо: файл остаётся
#    в файловой системе заказчика и находится при разборе. Поэтому класс
#    impact и он не понижается профилем — см. effective_class.
#
# 2. Канал. Агент канал не строит — соединение всегда открывает наша сторона
#    (SSH-клиент, PowerShell Remoting, §26.2). Решением оператора от 06.10.2026
#    («он сам отправляет») команды шага уходят на хост сами, но только по
#    одобренному шагу, с записью доступа в пакете передачи, с уборкой в том же
#    соединении и с воротами на каждой команде. Туннель по-прежнему ручной:
#    это канал, а не транспорт.
#
# 3. След. Шаг знает, какой файл он кладёт на хост, и отдаёт готовую команду
#    отметки в пакете передачи. Иначе уборка держится на памяти оператора,
#    а память через два месяца работы по объекту подводит.
#
# 4. Один хост — одно одобрение. Шаг перемещения принимает ровно один хост;
#    список хостов отклоняется. Это правило задано в коде, а не в инструкции.
INTERNAL: list[dict] = [
    {"id": "inside_whoami", "cls": PROBE,
     "title": "Внутри: где мы и от чьего имени",
     "tool": "whoami /hostname / ipconfig | ip a",
     "why": "первое, что нужно после входа: подтвердить, что доступ работает, "
            "и понять, чей это хост",
     "risk": "нет: только чтение",
     "noise": "низкий", "reversible": True, "payload": (), "places": False},
    {"id": "inside_privileges", "cls": IMPACT,
     "title": "Внутри: аудит привилегий на хосте",
     "tool": "linpeas.sh / winPEASx64.exe",
     "why": "находит путь к локальному администратору: чужие права, службы, "
            "задачи, сохранённые учётные данные",
     "risk": "оставляет файл на хосте заказчика; сам скрипт только читает",
     "noise": "средний", "reversible": False,
     "payload": ("linpeas.sh", "winPEASx64.exe"), "places": True},
    {"id": "inside_processes", "cls": IMPACT,
     "title": "Внутри: что запускается по расписанию",
     "tool": "pspy64",
     "why": "задача по расписанию от имени служебной учётной записи — "
            "самый частый путь наверх",
     "risk": "оставляет файл на хосте заказчика",
     "noise": "низкий", "reversible": False,
     "payload": ("pspy64",), "places": True},
    {"id": "inside_ad_collect", "cls": IMPACT,
     "title": "Внутри: карта путей к администратору домена",
     "tool": "SharpHound.exe + BloodHound (разбор на нашей стороне)",
     "why": "показывает, через какие учётные записи и права достигается "
            "цель, вместо перебора вслепую",
     "risk": "оставляет файл на хосте; выгрузка содержит структуру каталога — "
             "учётные записи, группы, права",
     "noise": "средний", "reversible": False,
     "payload": ("SharpHound.exe",), "places": True},
    {"id": "inside_tunnel", "cls": IMPACT,
     "title": "Внутри: доступ к сегменту, закрытому снаружи",
     "tool": "ligolo-ng agent + proxy / chisel",
     "why": "часть сети снаружи не видна вообще, и без туннеля туда не дойти",
     "risk": "оставляет агента на хосте и открывает постоянный канал",
     "noise": "высокий", "reversible": False,
     "payload": ("ligolo-agent.exe", "ligolo-agent-linux"), "places": True},
    {"id": "inside_next_host", "cls": IMPACT,
     "title": "Внутри: следующий хост по одобренному маршруту",
     "tool": "вручную",
     "why": "шаг перемещения. Один хост за одно решение, с названной целью "
            "и остановкой после неё",
     "risk": "необратимо: действие на новом хосте",
     "noise": "зависит от способа", "reversible": False,
     "payload": (), "places": False},
]

INTERNAL_BY_ID = {a["id"]: a for a in INTERNAL}

# Свободный шаг. Решение оператора (06.10.2026): «он не работает только так, как
# мы сказали — он ищет лучший путь». Каталог остаётся для типовых работ, но
# агенту больше не нужно подгонять задачу под 23 готовых действия: он формулирует
# шаг сам (чем именно, с какими параметрами) — а рамки проверяет код.
#
# Класс свободного шага вычисляет НЕ автор шага, а его содержание: чтение —
# наблюдение, запросы к объекту — проверка, всё, что пишет или может уронить, —
# воздействие (и значит, решение оператора). Иначе «свобода методов» стала бы
# свободой объявлять опасное безобидным.
FREE = {
    "id": "free_run", "cls": PROBE,
    "title": "Свободный шаг: способ выбирает агент",
    "tool": "чем решил агент",
    "why": "задача не сводится к готовому действию каталога — способ и параметры "
           "предложены агентом под конкретную ситуацию",
    "risk": "зависит от содержания: оценивает код, а не автор шага",
    "noise": "средний", "reversible": True,
}
FREE_BY_ID = {FREE["id"]: FREE}

BY_ID = {a["id"]: a for a in ACTIONS}
BY_ID.update(INTERNAL_BY_ID)
BY_ID.update(FREE_BY_ID)

# Классы свободного шага по содержанию. `observe` — на нашей стороне (разбор
# добытого, работа с базой и файлами), `probe` — чтение объекта, `impact` —
# запись/изменение/тяжёлое. Угадывать тут нельзя: класс решает, спросят человека
# или нет, поэтому словарь узкий и объяснимый.
# Класс свободного шага считается по содержанию — и считается разбором, а не
# поиском подстроки. Разница не академическая: подстрочный поиск объявил
# `cat /etc/os-release` «воздействием», потому что в слове «cat » есть «at ».
#
# Как считаем: команда режется на сегменты (`;`, `&&`, `||`, `|`, перевод строки),
# у каждого сегмента берётся программа — первый токен, по имени файла. Дальше:
#
#   * программа из списка записи или признак записи (перенаправление в файл,
#     `-delete`, `-exec`, `sed -i`) → impact, и причина называет, что именно;
#   * все программы из списка чтения → observe/probe;
#   * хоть одна программа незнакома → «содержание не опознано»: это не
#     «воздействие» (мы про команду ничего плохого не знаем) и не «чтение»
#     (мы про неё вообще ничего не знаем) — решает человек.
_READ_PROGS = frozenset("""
    curl wget dig nslookup host whois openssl httpx dnsx tlsx subfinder gau nmap
    naabu nuclei nikto wapiti testssl whatweb smbclient rpcclient ldapsearch
    enum4linux kerbrute winrs python python3 sqlite3 jq grep awk sort uniq wc sed
    whoami id hostname uname uptime date ps tasklist systeminfo netstat ss ip
    ifconfig arp route ls dir cat head tail stat file wc find locate df free
    getent nltest gpresult w32tm wevtutil auditpol type
""".split())
_WRITE_PROGS = frozenset("""
    rm mv cp chmod chown mkdir touch tee install pip pip3 apt apt-get yum dnf
    systemctl service schtasks sc crontab at sudo su kill pkill killall docker
    git shred chattr truncate dd mkfs ln setfacl attrib icacls takeown wmic netsh
    taskkill shutdown reboot halt poweroff logrotate useradd usermod groupadd
    passwd chpasswd mount umount sysctl iptables ufw firewall-cmd
""".split())
# Флаги записи: программа читающая, а флаг делает её пишущей.
_WRITE_FLAGS = ("-delete", "-exec", "-execdir", "sed -i", "--in-place", "-o ",
                "--output", "-w ", "--write")
# Python может всё, поэтому для него отдельно проверяются слова записи в теле.
_PY_WRITE = ("open(", "write", "shutil", "subprocess", "os.system", "remove(",
             "rmtree", "rename(", "unlink", "mkdir", "chmod", "socket", "requests.post")

# Перенаправление в файл — запись; перенаправление в /dev/null и слияние потоков
# (`2>&1`, `>&2`) — нет: иначе половина чтений объявлялась бы воздействием.
_NULL_RX = re.compile(r"\d?>>?\s*/dev/null|\d?>&\d?|\d?>&-")


def _segments(cmd: str) -> list[list[str]]:
    out = []
    for part in re.split(r"[;&|\n]+", cmd or ""):
        toks = part.strip().split()
        if toks:
            out.append(toks)
    return out


def free_class_why(cmd: str, declared: str = "") -> tuple[str, str]:
    """Класс свободного шага и **почему** он такой.

    Возвращаем пару: класс и причину словами. «Воздействие» про `uptime` — это
    неправда, а оператор читает именно класс; поэтому состояние и объяснение
    считаются вместе, а не подставляются отдельно.
    """
    declared = (declared or "").strip().lower()
    c = (cmd or "").strip()
    if not c:
        return IMPACT, "пустая команда"
    saw_read = saw_unknown = False
    for toks in _segments(c):
        prog = os.path.basename(toks[0].strip("\"'")).lower()
        full = " ".join(toks).lower()
        rest = " ".join(toks[1:]).lower()
        if prog in _WRITE_PROGS:
            return IMPACT, f"по содержанию меняет состояние («{prog}»)"
        if _NULL_RX.sub(" ", " ".join(toks)).count(">") > 0:
            return IMPACT, "по содержанию меняет состояние (запись в файл)"
        # Флаги ищем по всему сегменту, а не по «хвосту»: `sed -i` — это
        # программа плюс флаг, и по хвосту флаг не находился.
        if any(f in " " + full for f in _WRITE_FLAGS):
            return IMPACT, "по содержанию меняет состояние (флаг записи)"
        if prog in ("python", "python3") and any(w in rest for w in _PY_WRITE):
            return IMPACT, "python со словами записи — это уже не чтение"
        if prog in _READ_PROGS:
            saw_read = True
        else:
            saw_unknown = True
    if saw_unknown:
        return IMPACT, "содержание не опознано — решает человек, а не догадка"
    return (declared if declared in (OBSERVE, PROBE) else PROBE), \
        "чтение по содержанию: " + ", ".join(sorted({os.path.basename(t[0]).lower()
                                                     for t in _segments(c)}))[:120]


def free_class(cmd: str, declared: str = "") -> str:
    """Класс свободного шага по его содержанию. Слово автора — только подсказка."""
    return free_class_why(cmd, declared)[0]


def needs_operator(step) -> tuple[bool, str]:
    """Нужно ли решение человека по этому шагу (вариант «б» по доступности).

    Возвращается (нужно, причина). Это правило одно на все места, где что-то
    одобряется автоматически: автопилот, чат, свободный шаг. Разойдись они —
    и «сам одобряет только чтение» превратилось бы в «сам одобряет, что успел».
    """
    st = step if isinstance(step, dict) else dict(step)
    aid = st.get("action_id") or ""
    if aid in INTERNAL_IDS:
        return True, "внутренняя работа: решение оператора"
    a = BY_ID.get(aid) or {}
    if a.get("places"):
        return True, "оставит файл на объекте: нужна уборка"
    if str(st.get("cls") or "") == IMPACT:
        return True, "воздействие"
    if aid == "free_run":
        try:
            pp = st.get("params")
            pp = json.loads(pp) if isinstance(pp, str) else (pp or {})
        except Exception:  # noqa: BLE001
            pp = {}
        if str(pp.get("free_kind") or "").lower() == "impact":
            return True, "свободный шаг, который что-то меняет"
    g = gate_step(st.get("id") or 0)
    if g.get("action") == gate.WARN:
        cats = {str(f.get("category")) for f in (g.get("findings") or [])}
        if "availability" in cats:
            return True, "может повлиять на доступность объекта"
        return False, ""      # прочее предупреждение — не повод спрашивать
    if g.get("action") == gate.BLOCK:
        return True, "ворота: " + str(g.get("note") or "")[:120]
    return False, ""

# Шаги внутренней работы не предлагаются ДО записи доступа: они описывают
# работу внутри объекта, а доступа ещё нет, и шаг в плане выглядел бы как
# разрешение, которого никто не давал. После записи доступа (handover access)
# они ставятся в очередь наравне с остальными — и всё равно ничего не делают
# на объекте: агент лишь готовит команды человеку, а выполнить их может только
# он, своими руками и по своему решению.
INTERNAL_IDS = frozenset(INTERNAL_BY_ID)

# Порядок первого прохода: сначала ничего не трогаем, потом читаем, потом проверяем.
OPENING = ["recon_names", "recon_dns", "recon_archives",
           "probe_http", "probe_tls", "enum_ports", "enum_services",
           "crawl_links", "check_vulns", "check_webserver", "check_webapp"]


def _setting_value(name: str, default=None, settings=None):
    snapshot = settings if settings is not None else current_settings()
    if snapshot is not None:
        return snapshot.get(name, default)
    return os.environ.get(name, default)


def effective_class(action_id: str, settings=None) -> str:
    """Класс действия с учётом профиля из snapshot текущей операции."""
    a = BY_ID.get(action_id)
    if not a:
        return IMPACT
    if action_id == "free_run":
        # Класс свободного шага идёт от содержания, а не от профиля: профиль
        # умеет только повышать, а тут важно не понизить случайно «тихое».
        return a.get("cls") or IMPACT
    if a.get("places"):
        # Без исключений: размещение файла не может стать probe при любом профиле.
        return IMPACT
    profile = _setting_value("ASM_PROFILE", None, settings)
    pentest = engines.PENTEST if profile is None else str(profile).strip().lower() in (
        "pentest", "pentest-nodos", "attack", "exploit", "2",
        "full", "all", "aggressive", "1", "true", "yes", "on",
    )
    if action_id in _PROFILE_DEPENDENT and pentest:
        return IMPACT
    return a["cls"]


def catalog(settings=None) -> list[dict]:
    """Что агент умеет предлагать — с settings snapshot текущей операции."""
    out = []
    for a in ACTIONS + INTERNAL:
        cls = effective_class(a["id"], settings=settings)
        # Внутренний шаг не «не установлен» — у него нет движка на этой
        # машине по устройству: он готовит команды для человека.
        installed = True if a["id"] in INTERNAL_IDS else (
            (not a.get("bin")) or bool(call_with_settings(
                engines.tool_path, a["bin"], settings=settings)))
        out.append({**a, "cls": cls, "cls_title": CLASS_TITLE[cls],
                    "installed": installed, "internal": a["id"] in INTERNAL_IDS})
    return out


def open_session(target_id: int, operator: str = "", note: str = "",
                 deadline: str = "") -> int:
    """Сессия агента. Без неё ни один шаг не создаётся.

    deadline — жёсткий срок в ISO-формате: после него агент не выполнит
    ничего, даже если шаг одобрен (см. execute). Пустая строка — без срока.
    """
    return store.agent_open(target_id, operator, note, deadline)


def _queue_impact(settings=None) -> bool:
    """Ставить ли в очередь необратимые шаги из snapshot текущей операции."""
    snapshot = settings if settings is not None else current_settings()
    if snapshot is not None:
        return bool(snapshot.get("ASM_QUEUE_IMPACT", True))
    raw = (os.environ.get("ASM_QUEUE_IMPACT", "1") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def agreed_scope(sess=None, settings=None) -> tuple:
    """Согласованная область работ: адреса и домены, названные человеком.

    Источники: ASM_SCOPE (список через запятую) и цель сессии. Проверка области
    нужна не для запрета, а для того, чтобы шаг, уходящий не туда, куда
    договорились, был виден ДО выполнения. Чужую инфраструктуру мы не трогаем
    никогда, и полагаться здесь на внимательность оператора нельзя.
    """
    out: list[str] = []
    raw = _setting_value("ASM_SCOPE", "", settings)
    for piece in re.split(r"[,\s;]+", raw or ""):
        piece = piece.strip().lower()
        if piece:
            out.append(piece)
    if sess is not None:
        try:
            tid = sess["target_id"]
        except (TypeError, KeyError, IndexError):
            tid = None
        if tid:
            row = store.one("SELECT value FROM targets WHERE id=?", (tid,))
            if row and row["value"]:
                out.append(str(row["value"]).strip().lower())
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return tuple(uniq)


def gate_step(step_id: int, *, sess=None) -> dict:
    """Проверить шаг агента воротами. Ничего не выполняет и ничего не меняет."""
    st = store.agent_step(step_id)
    if not st:
        return {"action": gate.BLOCK, "kind": "шаг", "findings": [], "trace": [],
                "places": False, "needs_cleanup": False, "note": "шаг не найден"}
    try:
        params = json.loads(st["params"] or "{}")
    except Exception:  # noqa: BLE001 — испорченные условия не должны мешать проверке
        params = {}
    item = dict(st)
    item["params"] = params
    try:
        item = Step.from_legacy(item).to_legacy()
    except ContractError:
        return {"action": gate.BLOCK, "kind": "шаг", "findings": [], "trace": [],
                "places": False, "needs_cleanup": False,
                "note": "структура шага нарушает контракт"}
    return gate.check_step_with(item, scope=agreed_scope(
        sess if sess is not None else store.agent_session(st["session_id"])))


def propose(session_id: int, action_id: str, *, params: dict | None = None,
            rationale: str = "") -> int | None:
    """Положить шаг в очередь на подтверждение. Ничего при этом не выполняется."""
    a = BY_ID.get(action_id)
    if not a:
        return None
    # Внутренний шаг ставится в очередь только явно указанным хостом:
    # без хоста непонятно, куда именно он готовит команды.
    if action_id in INTERNAL_IDS:
        if not str((params or {}).get("host") or "").strip():
            return None
        # Правило «один хост — одно решение» проверяется ЗДЕСЬ, а не только при
        # выполнении: шаг с несколькими хостами не должен попадать в очередь
        # вовсе. Отказ при выполнении сработал бы, но список хостов успел бы
        # полежать в плане и выглядеть одобренным планом.
        if action_id == "inside_next_host":
            _h, _why = _one_host(params or {})
            if _why:
                return None
        # Шаг, кладущий файл, не ставится без системы хоста: от неё зависит,
        # какой файл класть. Тот же отказ есть в internal_plan — здесь он
        # нужен, чтобы шаг не попал в план вовсе.
        if a.get("places") and a.get("payload"):
            _chosen, _why = _payload_for(a, str((params or {}).get("os") or ""))
            if _why:
                return None
    cls = effective_class(action_id)
    params = dict(params or {})
    # Команды внутреннего шага пишет модель, если она настроена. Делается это
    # ДО ворот: тогда проверке подвергается и текст команд, а оператор видит,
    # что именно предложено, ещё на одобрении. Модель не ответила — шаг
    # готовится правилами, и это видно в его описании.
    if action_id in INTERNAL_IDS:
        params = _with_model_cmds(action_id, params, session_id)
    # Ворота на входе в очередь. Запрещённый шаг не «выполнится когда-нибудь
    # потом» — он не появляется в плане вовсе, иначе план выглядит как
    # разрешение, которого никто не давал.
    g = gate.check_step_with({"action_id": action_id, "places": bool(a.get("places")),
                              "params": params},
                             scope=agreed_scope(store.agent_session(session_id)))
    if g["action"] == gate.BLOCK:
        store.audit("agent_gate_blocked", {"action": action_id, "where": "propose",
                                           "note": g["note"][:200]})
        return None
    return store.agent_propose(
        session_id, action_id, cls, a["title"], params=params,
        rationale=rationale or a["why"],
        risk=a["risk"], reversible=a["reversible"])


# Команды, которые опасны для НАШЕЙ машины, а не для объекта: свободный шаг
# исполняется у нас, и «ищет лучший путь» не должно означать «может снести свою
# же систему». Список узкий: только то, что уже необратимо на нашей стороне.
_SELF_HARM = (
    (r"rm\s+-rf\s+/(\s|$)", "удаление корня файловой системы на нашей машине"),
    (r"mkfs", "форматирование раздела на нашей машине"),
    (r"dd\s+if=.*of=/dev/", "запись образа на устройство"),
    (r":\(\)\s*\{.*\};:", "самоплодящийся процесс (fork bomb)"),
    (r"curl[^|]*\|\s*(sh|bash)", "скачанное сразу исполняется без проверки"),
    (r"wget[^|]*\|\s*(sh|bash)", "скачанное сразу исполняется без проверки"),
    (r">\s*/dev/sd", "запись напрямую в устройство"),
    (r"shutdown|reboot|halt\b", "остановка нашей машины"),
)


def aiagent_sanitize(text: str, limit: int = 7000) -> str:
    """Вывод свободного шага — тоже недоверенный текст, и тоже чистится."""
    try:
        from . import aiagent
        return aiagent.sanitize(text, limit=limit)
    except Exception:  # noqa: BLE001
        return (text or "")[:limit]


def free_self_check(cmd: str) -> str:
    """Почему свободный шаг нельзя исполнить у нас. Пусто — можно."""
    c = (cmd or "").strip()
    if not c:
        return "пустая команда"
    for pat, why in _SELF_HARM:
        if re.search(pat, c, re.I):
            return why
    return ""


def propose_free(session_id: int, cmd: str, *, intent: str = "", target: str = "",
                 tool: str = "", kind: str = "", local: bool = False,
                 trace: str = "") -> dict:
    """Поставить свободный шаг: способ предложил агент, рамки проверил код.

    Возвращает словарь: `ok`, `step` (номер шага) и `reason` — почему не вышло.
    Отказ здесь всегда с причиной: «нельзя» без объяснения оператор всё равно
    обойдёт руками, и обойдёт без проверок.
    """
    bad = free_self_check(cmd)
    if bad:
        store.audit("agent_free_refused", {"session": session_id, "причина": bad,
                                           "команда": cmd[:200]})
        return {"ok": False, "step": 0, "reason": f"свободный шаг отклонён: {bad}"}
    # Класс идёт от содержания; `local` лишь уточняет, что чтение на нашей
    # стороне, — и только если чтение. Первая версия по одному лишь «local»
    # объявляла наблюдением и `cp`, то есть запись проходила без решения.
    cls = free_class(cmd, kind)
    if local and not target and cls == PROBE:
        cls = OBSERVE
    a = dict(FREE)
    a["cls"] = cls
    params = {"cmd": cmd.strip(), "intent": (intent or "")[:300],
              "free_kind": cls, "tool": (tool or "")[:120],
              "trace": (trace or "")[:300]}
    if target:
        params["target"] = target.strip()
    scope = agreed_scope(store.agent_session(session_id))
    g = gate.check_step_with({"action_id": "free_run", "places": False, "params": params},
                             scope=scope)
    if g["action"] == gate.BLOCK:
        store.audit("agent_free_refused", {"session": session_id, "причина": g["note"][:200],
                                           "команда": cmd[:200]})
        return {"ok": False, "step": 0, "reason": "ворота: " + str(g["note"])}
    title = ("Свободный шаг: " + (intent or cmd)[:70]).strip()
    step_id = store.agent_propose(session_id, "free_run", cls, title, params=params,
                                  rationale=(intent or "способ предложен агентом")[:300],
                                  risk=("может повлиять на доступность объекта"
                                        if any(f.get("category") == "availability"
                                               for f in (g.get("findings") or []))
                                        else a["risk"]),
                                  reversible=bool(a["reversible"]))
    if g["action"] == gate.WARN:
        budget_note_warn(session_id)
    return {"ok": bool(step_id), "step": step_id or 0,
            "reason": "" if step_id else "шаг не поставлен",
            "gate": {"action": g["action"], "note": g.get("note") or "",
                     "findings": g.get("findings") or []},
            "cls": cls}


def budget_note_warn(session_id: int) -> None:
    """Предупреждение ворот — сигнал супервизору, что темп, возможно, велик."""
    try:
        from . import budget as bmod
        bmod.note_warn(session_id)
    except Exception:  # noqa: BLE001 — бюджет не обязателен для шага
        pass


def propose_opening(session_id: int, target: str, *, limit: int = 4) -> list[int]:
    """Первые шаги: наблюдение, потом чтение. Воздействие не предлагается само."""
    made = []
    done = {s["action_id"] for s in store.agent_steps(session_id)}
    for aid in OPENING:
        if aid in done or len(made) >= limit:
            continue
        made.append(propose(session_id, aid, params={"target": target},
                            rationale="первый проход"))
    return [m for m in made if m]


def scan_signals(scan_id: int) -> dict:
    """Что реально observed на цели — порты, сервисы, продукты, баннеры."""
    ports: set[int] = set()
    services: set[str] = set()
    products: set[str] = set()
    banners: list[str] = []
    for a in store.scan_assets(scan_id):
        v = str(a.get("value") or "")
        if ":" in v:
            try:
                ports.add(int(v.rsplit(":", 1)[1]))
            except ValueError:
                pass
        meta = a.get("meta") or {}
        if meta.get("service"):
            services.add(str(meta["service"]))
            banners.append(str(meta["service"]))
        if meta.get("product"):
            products.add(str(meta["product"]))
            banners.append(str(meta["product"]))
    for f in store.scan_findings(scan_id):
        if f.get("port"):
            try:
                ports.add(int(f["port"]))
            except (TypeError, ValueError):
                pass
        if f.get("service"):
            services.add(str(f["service"]))
            banners.append(str(f["service"]))
        if f.get("product"):
            products.add(str(f["product"]))
            banners.append(str(f["product"]))
    return {"ports": ports, "services": services, "products": products,
            "banners": banners}


def propose_from_scan(session_id: int, scan_id: int, *, limit: int = 6) -> dict:
    """Предложить следующие шаги по плейбукам, подходящим к результатам скана.

    Плейбук задаёт последовательность, но не выполняет ничего: каждый шаг
    ложится в очередь на подтверждение ровно как предложенный вручную.
    Шаги класса impact плейбуками не предлагаются вовсе — см.
    knowledge.FORBIDDEN_IN_PLAYBOOK.

    Возвращает словарь с предложенными шагами и предупреждениями загрузки
    плейбуков. Предупреждения обязан показывать вызывающий: плейбук, который
    не загрузился из-за опечатки, иначе выглядит как «агент ничего не предложил».
    """
    from . import knowledge
    sig = scan_signals(scan_id)
    actions = {a["id"] for a in catalog()}
    pbs, warns = knowledge.match_playbooks(
        ports=sig["ports"], services=sig["services"], products=sig["products"],
        banners=sig["banners"], known_actions=actions)

    done = {s["action_id"] for s in store.agent_steps(session_id)}
    made: list[int] = []
    used: list[str] = []
    for pb in pbs:
        for st in pb.get("steps") or []:
            aid = str(st.get("action") or "")
            if not aid or aid in done or aid not in actions:
                continue
            # Внутренняя работа не предлагается автоматически НИКОГДА, даже
            # если класс у шага «наблюдение»: он требует уже полученного
            # доступа, а доступ даёт человек, не плейбук.
            if aid in INTERNAL_IDS:
                continue
            # Воздействие ставится в очередь наравне с остальным, но остаётся
            # воздействием: ничто не выполнится, пока человек не одобрит шаг
            # явно. В профиле pentest сюда попадают и проверки движками (они
            # помечены как воздействие за перебор учётных данных и правки в
            # базе) — раньше в боевом профиле они исчезали из плана вовсе,
            # и цепочка плейбука обрывалась на самом нужном месте.
            # Выключить это поведение: ASM_QUEUE_IMPACT=0.
            if effective_class(aid) == IMPACT and not _queue_impact():
                continue
            sid = propose(session_id, aid,
                          params={"target": "", "scan_id": scan_id},
                          rationale=f"плейбук «{pb.get('title') or pb.get('id')}»: "
                                    f"{st.get('why') or 'шаг цепочки'}")
            if sid:
                made.append(sid)
                done.add(aid)
                used.append(pb.get("id") or "")
            if len(made) >= limit:
                break
        if len(made) >= limit:
            break

    # Доступ записан — значит вход состоялся, и первый внутренний шаг уместен:
    # подтвердить, где мы и от чьего имени. Ставится в очередь, как любой
    # другой шаг, и ничего на объекте не делает: агент готовит команды, их
    # выполняет человек.
    if len(made) < limit and "inside_whoami" not in done:
        access = _access_for(session_id)
        if access.get("host"):
            sid = propose(session_id, "inside_whoami",
                          params={"host": str(access.get("host") or ""),
                                  "user": str(access.get("account") or ""),
                                  "scan_id": scan_id},
                          rationale="доступ записан — первым делом удостовериться, "
                                    "где мы и от чьего имени")
            if sid:
                made.append(sid)
    return {"steps": made, "warnings": warns,
            "playbooks": sorted({u for u in used if u}),
            "signals": {"портов": len(sig["ports"]),
                        "сервисов": len(sig["services"]),
                        "продуктов": len(sig["products"])},
            "matched": [p.get("id") for p in pbs]}


def pending(session_id: int) -> list[dict]:
    return store.agent_pending(session_id)


def describe(step: dict) -> str:
    """Как шаг выглядит для человека, который принимает решение."""
    cls = step.get("cls", IMPACT)
    mark = {"observe": "·", "probe": "△", "impact": "⚠"}[cls]
    lines = [f"{mark} [{cls}] {step.get('title')}",
             f"    зачем: {step.get('rationale')}",
             f"    риск : {step.get('risk')}"]
    if not step.get("reversible"):
        lines.append("    ОБРАТИМОСТЬ: действие нельзя отменить")
    if cls == IMPACT:
        lines.append("    требуется явное подтверждение")
    # Команды внутреннего шага показываются прямо здесь: их пишет модель, и
    # оператор должен видеть, что именно он одобряет, — а не узнавать это
    # после нажатия.
    try:
        step_params = json.loads(step.get("params") or "{}")
    except Exception:  # noqa: BLE001
        step_params = {}
    cmds = list(step_params.get("cmds") or [])
    if cmds:
        lines.append(f"    команды: {len(cmds)} — написала модель, проверены воротами")
        for c in cmds[:3]:
            lines.append("      " + str(c)[:100])
        if len(cmds) > 3:
            lines.append(f"      … ещё {len(cmds) - 3}")
        # Модель могла предложить и запретное: оно не попало в шаг, но оператор
        # должен это видеть — иначе «модель пишет команды» выглядит как доверие
        # без проверки.
        for d in (step_params.get("cmds_dropped") or [])[:1]:
            lines.append("      отброшено воротами: " + str(d.get("cmd") or "")[:60])
    # Свободный шаг: видно саму команду, чем работаем и какой ожидается след.
    # Без этого «свобода методов» превратилась бы в «одобрите, не читая».
    if step_params.get("free_kind"):
        lines.append("    команда: " + str(step_params.get("cmd") or "")[:170])
        if step_params.get("tool"):
            lines.append("    чем: " + str(step_params.get("tool"))[:80])
        if step_params.get("target"):
            lines.append("    куда: " + str(step_params.get("target"))[:80])
        if step_params.get("trace"):
            lines.append("    след: " + str(step_params.get("trace"))[:120])
    elif step_params.get("cmds_error"):
        lines.append("    команды: правилами — "
                     + str(step_params["cmds_error"])[:90])
        for d in (step_params.get("cmds_dropped") or [])[:1]:
            lines.append("      отброшено воротами: "
                         + str(d.get("cmd") or "")[:60])
    return "\n".join(lines)


def execute(step_id: int, secret: str = "") -> dict:
    """Выполнить шаг. Единственная дверь — статус approved, поставленный человеком.

    Если шаг не одобрен, не существует или уже обработан — не делается ничего.
    Возвращается словарь с исходом, исключения наружу не уходят.

    `secret` — пароль доступа на время отправки (решение оператора 06.10.2026:
    «он сам отправляет»). Он не сохраняется: живёт в памяти процесса, пока
    команды уходят на хост, и нигде не записывается.
    """
    st = store.agent_step(step_id)
    if not st:
        return {"ok": False, "reason": "шаг не найден"}
    if st["status"] != store.AGENT_APPROVED:
        # вот здесь и только здесь решается, запускать ли что-либо
        return {"ok": False, "reason": f"шаг не одобрен (статус: {st['status']})"}

    # Одобрения мало: сессия могла быть остановлена оператором, закрыта или
    # выйти за окно работ. Одобрение, выданное до стопа, не должно переживать стоп.
    sess = store.agent_session(st["session_id"])
    if not sess:
        return {"ok": False, "reason": "сессия не найдена"}
    if sess["status"] != "open":
        return {"ok": False, "reason": f"сессия не активна (статус: {sess['status']})"}
    if store.agent_expired(st["session_id"]):
        # помечаем явно, чтобы в отчёте было видно причину, а не просто отказ
        store.ex("UPDATE agent_sessions SET status=? WHERE id=?",
                 (store.AGENT_EXPIRED, st["session_id"]))
        store.audit("agent_session_expired", {"session": st["session_id"],
                                              "deadline": sess["deadline"]})
        return {"ok": False, "reason": f"окно работ закрылось ({sess['deadline']})"}
    if engines.halt_state():
        return {"ok": False, "reason": "остановлено оператором"}

    aid = st["action_id"]
    a = BY_ID.get(aid)
    if not a:
        store.agent_mark_result(step_id, False, error="неизвестное действие")
        return {"ok": False, "reason": "неизвестное действие"}

    # Ворота. Проверка стоит на выполнении, а не только на предложении,
    # потому что одобрение могло быть выдано до правки условий шага, а условия
    # (хосты, адреса, параметры) живут в базе и могли измениться.
    g = gate_step(step_id, sess=sess)
    if g["action"] == gate.BLOCK:
        store.agent_mark_result(step_id, False, error="ворота: " + g["note"])
        store.audit("agent_gate_blocked", {"step": step_id, "action": aid,
                                           "where": "execute", "note": g["note"][:200]})
        return {"ok": False, "reason": "ворота: " + g["note"], "gate": g}

    # Внутренние шаги агент не выполняет — он готовит команды человеку.
    #
    # Причина не в осторожности, а в устройстве: канала внутрь у агента нет
    # и быть не должно (он не эксплуатирует и не строит канал). Поэтому
    # «выполнить» здесь означает «выдать точные команды», как у handoff_access.
    if aid in INTERNAL_IDS:
        a_i = INTERNAL_BY_ID[aid]
        if a_i.get("places"):
            acc = _access_for(st["session_id"])
            if not acc:
                # Не формальность: без записи о доступе пакет передачи не
                # соберётся, а файл на хосте заказчика уже появится.
                reason = ("сначала запишите, какой доступ получен: "
                          f"python3 app.py handover access {st['session_id']} "
                          "--account … --privilege … --target-host … --method …")
                store.agent_mark_result(step_id, False, error=reason)
                return {"ok": False, "reason": reason}
        params_i = json.loads(st["params"] or "{}")
        if aid == "inside_next_host":
            _h, why = _one_host(params_i)
            if why:
                store.agent_mark_result(step_id, False, error=why)
                return {"ok": False, "reason": why}
        sess_d = dict(sess)
        # Отправляем сами, если транспорт может и оператор это разрешил. Правило
        # «агент внутрь не ходит» заменено его же решением 06.10.2026: ходит —
        # но по одобренному шагу, с одного хоста, с уборкой в том же соединении
        # и с записью в журнал. Всё, что транспорт не может (туннель, забор
        # файлов без разрешения, нет пароля или key), остаётся подготовкой
        # текста — и причина называется прямо, а не прячется.
        sent = None
        try:
            from . import transport as trans
            if trans.enabled():
                sent = trans.run(aid, params_i, sess_d, secret=secret, step_id=step_id,
                                 scope=agreed_scope(sess))
        except Exception as e:  # noqa: BLE001 — транспорт не должен ронять шаг
            sent = {"sent": False, "ok": False, "text": "",
                    "reason": f"транспорт не сработал: {type(e).__name__}: {str(e)[:140]}"}

        if sent and sent.get("sent"):
            text = (f"Отправлено и выполнено транспортом (шаг {step_id}, "
                    f"{sent.get('commands')} команд, {sent.get('seconds')} с).\n\n"
                    + str(sent.get("text") or ""))
            store.agent_mark_result(step_id, bool(sent.get("ok")), result=text)
            try:
                from . import budget as bmod
                bmod.spend(st["session_id"], st)
            except Exception:  # noqa: BLE001
                pass
            return {"ok": bool(sent.get("ok")), "internal": True, "inward": True,
                    "count": sent.get("commands"), "result": text,
                    "reason": "" if sent.get("ok") else "часть команд вернулась с ошибкой"}

        text = internal_plan(aid, {**params_i, "session_id": st["session_id"]}, sess_d)
        if sent and sent.get("reason"):
            # Почему не отправлено — первой строкой: иначе шаблоны читаются как
            # «агент поработал», хотя он только подготовил команды.
            text = "Отправка не выполнена: " + str(sent["reason"]) + "\n\n" + text
        store.agent_mark_result(step_id, True, result=text, handoff=True)
        store.audit("agent_internal_prepared",
                    {"step": step_id, "action": aid,
                     "host": params_i.get("host") or "",
                     "places_file": bool(a_i.get("places")),
                     "отправлено": bool(sent and sent.get("sent")),
                     "причина": (sent or {}).get("reason", "")[:160] if sent else "транспорт недоступен"})
        return {"ok": True, "handoff": True, "internal": True, "result": text,
                "sent": bool(sent and sent.get("sent"))}

    # Свободный шаг: «лучший путь», который агент выбрал сам (связка движков,
    # разбор добытого, свой скрипт). Рамки проверены дважды — при постановке и
    # здесь, на выполнении.
    #
    # Куда он идёт, решает не класс, а адрес в шаге:
    #   * без адреса объекта — у нас (subprocess, окружение скрытности);
    #   * с адресом — на объект транспортом (§40), как внутренний шаг: команда
    #     заново проходит ворота **на отправке**, соединение открываем мы, ни
    #     маячков, ни обратных соединений; один шаг — один хост.
    if aid == "free_run":
        import subprocess
        import time as _time
        from . import stealth as _stealth
        params_f = json.loads(st["params"] or "{}")
        cmd = str(params_f.get("cmd") or "").strip()
        bad = free_self_check(cmd)
        if bad:
            store.agent_mark_result(step_id, False, error="свободный шаг отклонён: " + bad)
            store.audit("agent_free_refused", {"step": step_id, "причина": bad,
                                               "команда": cmd[:200]})
            return {"ok": False, "reason": "свободный шаг отклонён: " + bad}
        ok_b, why_b = True, ""
        try:
            from . import budget as bmod
            ok_b, why_b = bmod.check(st["session_id"], step=st)
        except Exception:  # noqa: BLE001 — бюджет не должен мешать шагу
            ok_b = True
        if not ok_b:
            store.agent_mark_result(step_id, False, error="бюджет: " + why_b)
            store.audit("agent_budget_stop", {"step": step_id, "причина": why_b[:200]})
            return {"ok": False, "reason": "бюджет: " + why_b}
        params_f["os"] = str(params_f.get("os") or "")
        target = str(params_f.get("target") or "").strip()
        if target:
            # К объекту: отправляем транспортом. Команда пойдёт через ворота ещё
            # раз — уже на отправке, и это не дубль, а разные вопросы: «можно ли
            # вообще» и «можно ли отсюда и сейчас».
            sent = None
            try:
                from . import transport as trans
                # Спрашиваем транспорт всегда, даже когда он выключен: «выключено
                # (ASM_INWARD=off)» — это ответ, а «транспорт недоступен» — отговорка.
                sent = trans.run("free_run",
                                 {"host": target, "cmds": [cmd],
                                  "user": str(params_f.get("user") or ""),
                                  "os": params_f.get("os")},
                                 dict(sess), secret=secret, step_id=step_id,
                                 scope=agreed_scope(sess))
            except Exception as e:  # noqa: BLE001 — транспорт не должен ронять шаг
                sent = {"sent": False, "ok": False, "text": "",
                        "reason": f"транспорт не сработал: {type(e).__name__}: {str(e)[:140]}"}
            if sent and sent.get("sent"):
                text = (f"Свободный шаг отправлен на {target} транспортом "
                        f"({sent.get('commands')} команд, {sent.get('seconds')} с).\n\n"
                        + aiagent_sanitize(str(sent.get("text") or "")))
                store.agent_mark_result(step_id, bool(sent.get("ok")), result=text)
                store.audit("agent_free_inward",
                            {"step": step_id, "session": st["session_id"], "host": target,
                             "команда": cmd[:200], "отправлено": True})
                try:
                    from . import budget as bmod
                    bmod.spend(st["session_id"], st)
                except Exception:  # noqa: BLE001
                    pass
                return {"ok": bool(sent.get("ok")), "free": True, "inward": True,
                        "count": sent.get("commands"), "result": text,
                        "reason": "" if sent.get("ok") else "часть команд вернулась с ошибкой"}
            why_sent = (sent or {}).get("reason") or "транспорт недоступен"
            text = (f"Свободный шаг к объекту не отправлен: {why_sent}\n\n"
                    f"Команда остаётся за вами, целиком:\n  {cmd[:500]}")
            store.agent_mark_result(step_id, True, result=text, handoff=True)
            store.audit("agent_free_inward",
                        {"step": step_id, "session": st["session_id"], "host": target,
                         "команда": cmd[:200], "отправлено": False,
                         "причина": str(why_sent)[:160]})
            return {"ok": True, "handoff": True, "free": True, "result": text,
                    "sent": False, "reason": ""}

        started = _time.time()
        try:
            pr = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                timeout=int(params_f.get("timeout") or 600),
                                env=call_with_settings(
                                    _stealth.subprocess_env, None, purpose="inward",
                                    settings=current_settings()))
        except subprocess.TimeoutExpired:
            store.agent_mark_result(step_id, False, error=f"нет ответа за {params_f.get('timeout') or 600} с")
            return {"ok": False, "reason": "команда не завершилась за отведённое время"}
        out = ((pr.stdout or "") + (("\n" + pr.stderr) if pr.stderr else ""))
        text_out = aiagent_sanitize(out)
        took = round(_time.time() - started, 1)
        store.audit("agent_free_run", {"step": step_id, "session": st["session_id"],
                                       "команда": cmd[:200], "код": pr.returncode,
                                       "секунд": took})
        if not text_out.strip():
            text_out = ("Команда прошла без вывода (код " + str(pr.returncode) + "). "
                        "Это не «всё хорошо»: судить не по чему — проверьте сами.")
        head = (f"Свободный шаг (способ выбрал агент), {took} с, код {pr.returncode}:\n"
                f"  {cmd[:300]}\n\n")
        store.agent_mark_result(step_id, pr.returncode == 0, result=head + text_out)
        try:
            from . import budget as bmod
            bmod.spend(st["session_id"], st)
        except Exception:  # noqa: BLE001
            pass
        return {"ok": pr.returncode == 0, "result": head + text_out, "free": True,
                "count": 1}

    # Эксплуатацию агент не выполняет никогда — только готовит передачу человеку.
    if aid == "handoff_access":
        text = handoff(st)
        store.agent_mark_result(step_id, True, result=text, handoff=True)
        return {"ok": True, "handoff": True, "result": text}

    # Бюджет работ: он про темп, а не про разрешения. Проверяется до запуска и
    # расходуется после — поэтому и стоит рядом с выполнением, а не в интерфейсе.
    ok_b, why_b = True, ""
    try:
        from . import budget as bmod
        ok_b, why_b = bmod.check(st["session_id"], step=st)
    except Exception:  # noqa: BLE001 — бюджет не должен мешать работе
        ok_b, why_b = True, ""
    if not ok_b:
        store.agent_mark_result(step_id, False, error="бюджет: " + why_b)
        store.audit("agent_budget_stop", {"step": step_id, "action": aid,
                                          "причина": why_b[:200]})
        return {"ok": False, "reason": "бюджет: " + why_b}

    binname = a.get("bin") or ""
    if binname and not call_with_settings(
            engines.tool_path, binname, settings=current_settings()):
        # «ноль находок без ошибки» — худший вид дефекта: в отчёте он выглядит как
        # «всё чисто». Поэтому отсутствие движка — это провал шага, а не пустой результат.
        reason = f"движок {binname} не установлен"
        store.agent_mark_result(step_id, False, error=reason)
        return {"ok": False, "reason": reason}

    store.agent_mark_running(step_id)
    params = json.loads(st["params"] or "{}")
    try:
        out = _run(aid, params)
    except Exception as e:  # noqa: BLE001
        store.agent_mark_result(step_id, False, error=str(e)[:500])
        return {"ok": False, "reason": str(e)[:500]}

    n = len(out) if isinstance(out, list) else 1
    store.agent_mark_result(step_id, True,
                            result=json.dumps(out, ensure_ascii=False)[:4000])
    # Расход записывается после работы: супервизор считает сделанное, а не
    # обещанное, и по расходу сам подстраивает темп (budget.review).
    try:
        from . import budget as bmod
        bmod.spend(st["session_id"], st)
    except Exception:  # noqa: BLE001 — учёт не должен мешать работе
        pass
    if g.get("action") == gate.WARN:
        # Предупреждение ворот — сигнал супервизору: возможно, идём громко.
        budget_note_warn(st["session_id"])
    return {"ok": True, "count": n, "result": out}


# ---------------------------------------------------------------------------
# Подготовка внутреннего шага
_ONLY_HOST = ("шаг перемещения принимает РОВНО ОДИН хост. Список хостов "
              "отклоняется: одно решение — один хост, как в правилах работы.")


def _one_host(params: dict) -> tuple[str, str]:
    """Проверить, что назван ровно один хост. Возвращает (хост, причина отказа)."""
    host = str(params.get("host") or "").strip()
    if not host:
        return "", "не указан хост: нужен --host"
    # Разделители приводятся к одному и разбираются одним правилом.
    # Первая версия искала пробел как разделитель, но разбивала только по
    # запятой — и «srv-01 srv-02» проходило проверку как один хост.
    parts = [x for x in re.split(r"[\s,;]+", host) if x]
    if len(parts) > 1:
        return "", _ONLY_HOST + f" Получено хостов: {len(parts)}: {', '.join(parts[:4])}."
    return parts[0] if parts else "", ""


def _access_for(session_id: int) -> dict:
    """Записан ли доступ по этой сессии. Импорт внутри: handover тянет store,
    а agent обязан остаться без лишних зависимостей на уровне модуля."""
    from . import handover
    return handover.access(session_id)


def _payload_for(a: dict, osname: str) -> tuple[str, str]:
    """Какой файл кладём под эту систему. Возвращает (файл, причина отказа).

    Один и тот же выбор нужен и при постановке шага, и при подготовке команд,
    поэтому он живёт в одном месте: разойдясь, они дали бы шаг, который
    ставится, но не готовится — то есть отказ на пустом месте.
    """
    all_payloads = list(a.get("payload") or ())
    if not all_payloads:
        return "<файл>", ""
    os_l = (osname or "").strip().lower()
    if not (os_l.startswith("win") or os_l.startswith("lin")):
        return "", ("Не указана система хоста, а шаг кладёт файл.\n"
                    "  Для Windows: %s\n  Для Linux:   %s\n"
                    "Укажите её: --inside-os windows или --inside-os linux"
                    % (", ".join(x for x in all_payloads if x.lower().endswith(".exe")) or "нет",
                       ", ".join(x for x in all_payloads if not x.lower().endswith(".exe")) or "нет"))
    win = os_l.startswith("win")
    match = [x for x in all_payloads if win == x.lower().endswith(".exe")]
    if not match:
        return "", ("Под %s файла для этого шага нет.\n  Есть только под %s: %s.\n"
                    "  Инструмент чужой системы на хосте не запустится, а оставленный\n"
                    "  неработающий файл — это след без результата.\n"
                    "Смените систему шага или закройте цель другим шагом."
                    % ("Windows" if win else "Linux", "linux" if win else "windows",
                       ", ".join(all_payloads)))
    return match[0], ""


def _remote_path(win: bool) -> str:
    """Имя файла инструмента на хосте. Одно на весь шаг — от него зависит уборка."""
    return ("C:\\Windows\\Temp\\upd-<цифры>.exe" if win else "/tmp/.cache-upd")


def _cmds_block(params: dict) -> list[str] | None:
    """Команды, написанные моделью (если они есть у этого шага).

    В шаге лежат отдельные поля, а не готовый текст: оператору важно видеть
    источник — «написала модель» и «правила» читаются по-разному.
    """
    cmds = list(params.get("cmds") or [])
    if not cmds:
        return None
    try:
        from . import modelcmd
        return modelcmd.text_block({
            "ok": True, "cmds": cmds, "why": params.get("cmds_why") or "",
            "cleanup": params.get("cmds_cleanup") or [],
            "dropped": params.get("cmds_dropped") or [], "error": ""})
    except Exception:  # noqa: BLE001 — без модуля шаг обязан собраться
        return ["Команды (написала модель):", ""] + ["  " + str(c) for c in cmds]


def _with_model_cmds(action_id: str, params: dict, session_id: int) -> dict:
    """Дописать шагу команды от модели. Ошибки глушим: шаг важнее команды.

    Ничего не выполняется — команды попадают в шаг текстом, чтобы человек
    увидел их при одобрении и запустил сам.
    """
    try:
        from . import modelcmd
        if not modelcmd.enabled():
            why = ("модель выключена (ASM_MODEL_CMDS=off)"
                   if getattr(modelcmd, "MODE", "auto") == "off"
                   else "модель не задана (ASM_LLM_BASE пуст)")
            params.setdefault("cmds_error", why)
            return params
        a = INTERNAL_BY_ID.get(action_id) or {}
        sess = store.agent_session(session_id)
        s = dict(sess) if sess else {}
        fix: dict = {}
        if a.get("places") and a.get("payload"):
            chosen, why = _payload_for(a, str(params.get("os") or ""))
            if why:
                return params
            win = str(params.get("os") or "").strip().lower().startswith("win")
            fix = {"файл на хосте": _remote_path(win),
                   "запускать инструмент": chosen}
        res = modelcmd.commands(action_id, params, s, scope=agreed_scope(sess),
                                title=str(a.get("title") or action_id),
                                why=str(a.get("why") or ""), fix=fix)
        if res.get("ok"):
            params["cmds"] = res["cmds"]
            params["cmds_source"] = "модель"
            if res.get("why"):
                params["cmds_why"] = res["why"]
            if res.get("cleanup"):
                params["cmds_cleanup"] = res["cleanup"]
            if res.get("dropped"):
                params["cmds_dropped"] = res["dropped"][:4]
        else:
            # Текст ошибки становится параметром шага, а параметры целиком
            # уходят в ворота. Цитата из собственного запрета («…секретами,
            # сессиями…», имя инструмента) заблокировала бы сам шаг — то есть
            # запрет на команду отменял бы шаг, которого никто не запрещал.
            # В параметры идёт одна суть; разбор остаётся в описании шага.
            err = str(res.get("error") or "модель не дала команд")
            if ":" in err:
                head = err.split(":", 1)[0].strip()
                if head.startswith(("все команды отброшены", "после проверки ответа")):
                    err = head
            params["cmds_error"] = err[:160]
            if res.get("dropped"):
                params["cmds_dropped"] = res["dropped"][:4]
    except Exception as e:  # noqa: BLE001 — модель не должна ронять постановку шага
        params["cmds_error"] = f"модель: {type(e).__name__}"[:160]
    return params


def internal_plan(action_id: str, params: dict, sess: dict | None = None) -> str:
    """Команды для человека по внутреннему шагу. Ничего не выполняется.

    Возвращает готовый текст: что сделать, чем именно, что останется на хосте
    и как это убрать. Последнее обязательно: шаг, который кладёт файл и молчит
    об уборке, оставляет мусор в чужой файловой системе.
    """
    a = INTERNAL_BY_ID.get(action_id)
    if not a:
        return f"неизвестный внутренний шаг: {action_id}"
    host = str(params.get("host") or "<хост>").strip()
    user = str(params.get("user") or "<учётная запись>").strip()
    osname = str(params.get("os") or "").strip().lower()
    sid = (sess or {}).get("id") or params.get("session_id") or "<сессия>"

    win = osname.startswith("win") or osname in ("windows", "win")
    mb = _cmds_block(params)
    L: list[str] = [f"Внутренний шаг: {a['title']}",
                    f"Хост: {host}",
                    f"От имени: {user}"]
    # Кто написал команды — видно сразу, а не по догадке. Модель не ответила:
    # говорим причину; иначе оператор считал бы шаблоны работой модели.
    if mb:
        L.append("Команды шага: написала модель, проверены воротами.")
    elif params.get("cmds_error"):
        L.append("Команды шага: по правилам инструмента — "
                 + str(params["cmds_error"])[:120] + ".")
    L.append("")

    if action_id == "inside_whoami":
        L += ["Что сделать (только чтение, ничего не меняется):", ""]
        if mb:
            L += ["  " + x for x in mb]
        elif win:
            L += ["  whoami /all", "  hostname", "  systeminfo | findstr /C:\"Domain\" /C:\"OS Name\"",
                  "  ipconfig /all", "  net user %USERNAME% /domain"]
        else:
            L += ["  id", "  hostname", "  uname -a", "  sudo -n -l 2>/dev/null || true",
                  "  cat /etc/os-release 2>/dev/null"]
        L += ["", "Файлов на хосте не остаётся — убирать нечего."]
        return "\n".join(L)

    if action_id == "inside_next_host":
        goal = str(params.get("goal") or "<что именно нужно на этом хосте>").strip()
        L += [f"Цель шага: {goal}", "",
              "Что сделать: перемещение на этот хост и ничего сверх названной цели.",
              "  Способ и учётные данные выбираются вручную, исходя из того,",
              "  что уже известно. Остановиться сразу после достижения цели.", ""]
        L += ["Правило: одно решение — один хост. Следующий хост — отдельное решение.",
              "После шага зафиксировать, что получено:",
              f"  python3 app.py handover access {sid} --account … --privilege … "
              f"--target-host {host} --method …"]
        if mb:
            L += [""] + ["  " + x for x in mb]
        return "\n".join(L)

    # Остальные шаги кладут файл на хост
    chosen, why = _payload_for(a, osname)
    if why:
        return "\n".join(L + why.split("\n"))
    # Имя файла на хосте. Раньше здесь стояло %RANDOM%: cmd раскрывает его заново
    # при каждом вызове, поэтому имя из пункта 1 не совпадало с именем в пункте 4,
    # и уборка била мимо — файл оставался. Теперь имя выбирает человек один раз,
    # и дальше везде идёт один и тот же путь.
    remote = _remote_path(win)
    # Чем запускается файл: скрипту исполняемый бит не нужен, двоичному нужен.
    chmod = "" if chosen.lower().endswith(".sh") else "chmod +x %s && " % remote
    runner = ("%s" % remote) if win else ("sh %s" % remote if chosen.lower().endswith(".sh")
                                          else chmod + remote)

    L += ["Что останется на хосте: файл инструмента. Убрать обязательно.", ""]
    L += ["Порядок:", f"  1. Перенести build/tools/payloads/{chosen} на {host} и переименовать:",
          f"       {remote}", "     Имя — это подпись. Инструмент, названный своим именем,",
          "     отличает настоящую находку от ложной при разборе."]
    if win:
        L += [f"     Выберите имя и запомните его: оно нужно в пунктах 3 и 4.",
              "     Один и тот же файл — одно и то же имя."]
    L += [""]
    if action_id == "inside_privileges":
        # Запуск — из того же файла, что записан в пункте 3. Копии в %TEMP% и
        # mktemp убраны: это были вторые файлы на хосте, которых нет ни в одной
        # записи об уборке.
        L += ["  2. Запустить:", f"       {runner}",
              "     Вывод забрать на нашу сторону.", ""]
    elif action_id == "inside_processes":
        L += ["  2. Запустить на несколько минут и посмотреть, что стартует:", "",
              f"       {runner} -pfK", "",
              "     Интересуют задачи от служебных учётных записей и обращения",
              "     к файлам, доступным на запись.", ""]
    elif action_id == "inside_ad_collect":
        L += ["  2. Запустить сбор:", "", f"       {runner} -c All --outputdirectory <куда сохранить>",
              "     Разобрать в BloodHound локально.", "",
              "     Выгрузка (zip) — второй файл на хосте. Забрать её на нашу сторону",
              "     и удалить там же, отметив в пакете передачи отдельно.", "",
              "     ВАЖНО: этот файл содержит структуру каталога заказчика.", "",
              "     Он остаётся у нас и не входит ни в отчёт, ни в пакет передачи.", ""]
    elif action_id == "inside_tunnel":
        L += ["  2. Поднять агента на хосте:",
              f"       {runner} -connect <наш прокси>:11601 -ignore-cert",
              "     На нашей стороне — proxy и интерфейс туннеля.", "",
              "     Канал живёт, пока запущен агент. После работы агент остановить.", ""]

    if mb:
        # Команды модели заменяют только пункт «запустить»: перенос файла, его
        # имя и уборка остаются в коде — иначе уборка разошлась бы с тем, что
        # реально лежит на хосте.
        L += ["", "  Запуск (команды написала модель, проверены воротами):", ""]
        L += ["      " + x.strip() for x in mb]
        L += ["", "     Вывод забрать на нашу сторону.", ""]

    L += ["  3. Отметить в пакете передачи, что файл на хосте:",
          f"       python3 app.py handover placed {sid} --file {chosen} "
          f"--where-host {host} --path {remote}", "",
          "  4. Когда закончили — убрать файл и отметить уборку:", ""]
    if win:
        L += [f"       del {remote}", ]
    else:
        L += [f"       rm -f {remote}"]
    L += [f"       python3 app.py handover removed {sid} --id <номер из пункта 3 выше>", "",
          "Пока уборка не отмечена, пакет передачи считается неготовым."]
    return "\n".join(L)


def handoff(step) -> str:
    """Что передать человеку для эксплуатации: точка входа и чем её проверить.

    Шаг приходит из базы строкой sqlite3.Row: доступ по имени есть, а .get()
    нет. Раньше это не всплывало — шаг получения доступа в очередь
    автоматически не ставился, и путь «одобрить → выполнить» для него не
    проходился ни разу. Как только он стал достижим, дефект вышел наружу
    падением вместо пакета передачи.
    """
    row = dict(step) if not isinstance(step, dict) else step
    params = json.loads(row.get("params") or "{}")
    target = params.get("target", "<цель>")
    return (
        f"Точка входа: {params.get('entry') or 'указать из находок'}\n"
        f"Цель: {target}\n"
        "Эксплуатацию выполняет человек вручную. Агент не отправляет пейлоады,\n"
        "не закрепляется в системе и не перемещается по сети.\n"
        "Перед началом свериться с границами работ из договора.\n"
        "\n"
        "Когда доступ получен, работа заканчивается пакетом передачи —\n"
        "документом, который остаётся у заказчика и сопровождает демонстрацию:\n"
        "  python3 app.py handover access <сессия> --account … --privilege … \n"
        "  python3 app.py handover show <сессия>\n"
        "Секрет в нём не хранится и не спрашивается: только учётная запись,\n"
        "уровень доступа и чем заказчик проверит доступ сам."
    )


def _run(action_id: str, p: dict):
    """Диспетчер: действие → вызов реального движка из engines.py."""
    target = p.get("target", "")
    targets = p.get("targets") or ([target] if target else [])
    timeout = int(p.get("timeout") or 300)
    settings = current_settings()
    if action_id == "recon_names":
        return engines.subfinder(target, timeout=timeout, settings=settings)
    if action_id == "recon_dns":
        return engines.dnsx_resolve(targets, timeout=timeout, settings=settings)
    if action_id == "recon_archives":
        return engines.gau_urls(target, timeout=timeout, settings=settings)
    if action_id == "probe_http":
        return engines.httpx_probe(targets, timeout=timeout, settings=settings)
    if action_id == "probe_tls":
        return engines.tlsx_certs(targets, timeout=timeout, settings=settings)
    if action_id == "probe_testssl":
        return engines.testssl_audit(target, timeout=timeout, settings=settings)
    if action_id == "enum_ports":
        # port_scan принимает один хост, а не список
        return engines.port_scan(target, timeout=timeout, settings=settings)
    if action_id == "enum_services":
        return engines.nmap_services(target, p.get("ports") or [], timeout=timeout,
                                     settings=settings)
    if action_id == "crawl_links":
        return engines.katana_urls(targets, timeout=timeout, settings=settings)
    if action_id == "enum_paths":
        return engines.ffuf_dirs(target, timeout=timeout, settings=settings)
    if action_id == "check_vulns":
        return engines.vuln_scan(targets, timeout=timeout, settings=settings)
    if action_id == "check_webserver":
        return engines.nikto_scan(target, timeout=timeout, settings=settings)
    if action_id == "check_webapp":
        return engines.wapiti_scan(target, timeout=timeout, settings=settings)
    if action_id == "check_code":
        return engines.semgrep_scan(p.get("path", ""), timeout=timeout)
    if action_id == "check_secrets":
        return engines.gitleaks_dir(p.get("path", ""), timeout=timeout)
    if action_id == "check_image":
        return engines.trivy_image(p.get("image", ""), timeout=timeout)
    raise ValueError(f"нет исполнителя для действия {action_id}")


def profile_note() -> str:
    """Строка о действующем профиле из snapshot текущей операции."""
    settings = current_settings()
    if settings is not None:
        profile = str(settings.get("ASM_PROFILE", "safe") or "safe").strip().lower()
        if profile in ("full", "all", "aggressive", "1", "true", "yes", "on"):
            return "профиль full: включены и DoS-проверки"
        if profile in ("pentest", "pentest-nodos", "attack", "exploit", "2"):
            return "профиль pentest: DoS выключен, остальное без ограничений"
        return "профиль safe: только чтение"
    if engines.FULL:
        return "профиль full: включены и DoS-проверки"
    if engines.PENTEST:
        return "профиль pentest: DoS выключен, остальное без ограничений"
    return "профиль safe: только чтение"


def session_ready(session_id: int) -> bool:
    """Открыта ли сессия. Закрытая сессия шагов не принимает."""
    s = store.agent_session(session_id)
    return bool(s) and s["status"] == "open"
