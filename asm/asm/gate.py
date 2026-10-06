# -*- coding: utf-8 -*-
"""Ворота: проверка любого шага и любого кода перед выполнением.

Рамки — это то, что нельзя, а не то, что можно. Внутри рамок метод любой:
выбор инструмента, порядок, параметры, свой код. Отвечает не «взято ли
действие из списка», а «прошёл ли шаг через ворота».

Почему ворота в коде, а не в промпте. Промпт — уговор: он сработал на живой
проверке 05.10.2026 (см. ПЛАН §30.5), но снимается правкой текста, сменой
модели или длинным диалогом. То, что стоит денег заказчика — блокировка
учётных записей перебором, падение сервиса, выход за пределы объекта, —
обязан проверять код. Поэтому здесь проверка **текста команды и кода**, а не
намерений автора.

Чего ворота НЕ делают, и это важно не переоценивать:

* это не песочница: они не мешают запустить то, что не распознали по тексту;
* это не замена решению человека: одобряет по-прежнему оператор, и без его
  «да» не выполняется ничего (agent.execute);
* проверка по образцам, поэтому она консервативна и объяснима: у каждого
  найденного совпадения есть категория и причина, которые видит оператор.

Итог проверки — один из трёх: `allow` (можно), `warn` (можно, но оператор
должен видеть, чем платит), `block` (не выполняется: агент обязан показать
причину и предложить замену, а решение снять рамку принимает только человек).
"""
from __future__ import annotations

import ipaddress
import os
import re

ALLOW, WARN, BLOCK = "allow", "warn", "block"

# ---------------------------------------------------------------------------
# Категории. Порядок важен: первое совпадение по категории и показывается,
# потому что оператору нужна причина, а не список совпадений.
# Регулярные выражения намеренно широкие — лучше лишнее предупреждение,
# чем пропущенный перебор учётных записей.

_CATEGORIES: list[tuple[str, str, str, list[str]]] = [
    # (id, уровень, заголовок, образцы)
    ("c2", BLOCK, "обратное соединение / C2 / payload-канал",
     [r"\bnc\b[^\n]*\s-e\b", r"\bncat\b[^\n]*\s-e\b", r"/dev/tcp/", r"bash\s+-i\s*>&",
      r"socat[^\n]*exec:", r"reverse_tcp", r"reverse_https", r"meterpreter",
      r"msfvenom", r"msfconsole[^\n]*-x\b", r"empire", r"cobalt\s*strike",
      r"meterp", r"beacon\b[^\n]*sleep"]),
    ("persistence", BLOCK, "закрепление на хосте (персистентность)",
     [r"crontab\s+-", r"crontab\s+/", r"systemctl\s+enable", r"New-Service\b",
      r"sc\s+create\b", r"schtasks[^\n]*/create", r"reg\s+add[^\n]*\\Run\b",
      r"HKCU[^\n]*\\Run\b", r"HKLM[^\n]*\\Run\b", r"rc\.local", r"/etc/init\.d",
      r"\.bashrc[^\n]*>>", r"authorized_keys[^\n]*>>", r"at\s+now\s+\+",
      r"launchctl\s+load", r"Add-Type[^\n]*ServiceInstaller"]),
    ("logs", BLOCK, "удаление или подмена логов",
     [r"wevtutil\s+cl\b", r"Clear-EventLog", r"Remove-EventLog",
      r"journalctl[^\n]*--vacuum", r"rm\s+[^\n]*/(var/log|var/run/utmp|var/log/wtmp)",
      r"truncate\s+-s\s*0[^\n]*log", r">\s*/var/log", r"history\s+-c\b",
      r"unset\s+HISTFILE", r"shred[^\n]*log", r"auditpol[^\n]*/clear",
      r"Set-ItemProperty[^\n]*EventLog", r"del\s+[^\n]*\.evtx"]),
    ("data", BLOCK, "выгрузка или изменение данных заказчика",
     [r"--dump-all", r"sqlmap[^\n]*--dump\b", r"mysqldump", r"pg_dump",
      r"tar[^\n]*\.\./\.",
      r"scp[^\n]*:/var/lib", r"aws\s+s3\s+cp", r"DROP\s+TABLE", r"DELETE\s+FROM",
      r"UPDATE\s+[a-z_]+\s+SET", r"rm\s+-rf\s+/var/lib"]),
    ("bruteforce", BLOCK, "перебор или подбор учётных данных",
     [r"\bhydra\b", r"\bmedusa\b", r"\bpatator\b", r"\bncrack\b", r"\bcrowbar\b",
      r"kerbrute[^\n]*(bruteuser|passwordspray|bruteforce)",
      r"nxc?[^\n]*--continue-on-success", r"crackmapexec[^\n]*spray",
      r"password\s*spray", r"-\s*p\s+['\"]?(password|123456|admin)",
      # Списки учёток и паролей: одиночная пара «пользователь + пароль» —
      # законная проверка известных данных, а вот файл со списком — уже подбор.
      r"-\s*u\s+\S*\.(txt|lst)\b", r"-\s*p\s+\S*\.(txt|lst)\b",
      r"-\s*U\s+\S*\.(txt|lst)\b", r"-\s*P\s+\S*\.(txt|lst)\b",
      r"\b(users?|usernames?|pass|passwords?|pwd|wordlist|dict)\w*\.(txt|lst)\b",
      r"--pass-pol\b", r"--no-bruteforce\b", r"--continue-on-success\b",
      r"\bspray\w*\b", r"\bbrute[-_]?force\w*\b", r"\bhydra\b", r"\bmedusa\b",
      r"--password-file\b", r"-w\s+\S*(rockyou|wordlist|dict|pass)\S*",
      r"ffuf[^\n]*-w[^\n]*pass", r"--passwords\b[^\n]*\bwordlist"]),
    # Перехват и релей аутентификации — то, что модель предложила сама
    # («через SMB Relay»), и то, чего мы не делаем: это работа с чужим
    # трафиком, чужими сессиями и чужими учётными данными. Найдено прогоном
    # сложной задачи (§31.9).
    ("creds", BLOCK, "работа с чужими учётными данными, сессиями и секретами",
     [r"\bntlmrelayx\w*", r"\bsmbrelayx\w*", r"\bsmb\s*relay\b", r"\brelay\w*\s+auth",
      r"\bresponder\b", r"\bmitm6\b", r"\bpoison\w*\s+(llmnr|nbt-ns|mdns)",
      r"\bllmnr\s+poison", r"\bcrack\w*\s+ntlmv?2", r"\bhashcat\b",
      # Смысловые формулировки. Инструменты ловились, а советы «словами» — нет:
      # прогон большой задачи (§33.10) дал «захват сессии администратора» и
      # «root ради ключей и паролей» без единого названия утилиты.
      r"захват\w*\s+сесси", r"перехват\w*\s+сесси", r"чуж\w*\s+сесси",
      r"активн\w*\s+сесси\w*[^\n]{0,24}(администратор|пользовател)",
      r"снять\s+секрет", r"собрать\s+секрет", r"собирать\s+секрет", r"сбор\s+секрет",
      r"дамп\s+(секрет|парол)", r"всем\s+ключам?\s+и\s+парол",
      r"доступ\s+ко\s+всем\s+ключ", r"поиск\s+ключей", r"найти\s+ключи",
      # Громкие методы: выделены, чтобы в разрешённом режиме о них было сказано
      # отдельно — дампы оставляют самый заметный след для EDR.
      r"\blsass\b", r"\bmimikatz\b", r"\bsecretsdump\b", r"\bdcsync\b",
      r"\bdump\s+(lsass|sam|ntds)",
      # Дамперы памяти и файлы-хранилища учётных данных: раньше жили в «data»
      # и «malware» и при подписанном разрешении всё равно упирались в запрет.
      # После 06.10.2026 это работа с секретами (тихая или громкая), а не
      # выгрузка данных заказчика и не малварь.
      r"procdump[^\n]*lsass", r"comsvcs\.dll[^\n]*minidump",
      r"ntdsutil[^\n]*activate", r"sekurlsa",
      r"cat\s+/etc/shadow", r"Get-Content[^\n]*\\(SAM|SYSTEM|SECURITY)\b",
      # «Root через docker» — отдельный путь наверх, который модель предлагала
      # словами (§33.10: «риск минимальный»), а ворота не видели: сам по себе он
      # не «поиск ключей», но даёт root на хосте — то есть доступ ко всем
      # секретам сразу. Через запись доступа проверять каждый такой шаг отдельно.
      r"root\s+через\s+docker", r"docker[^\n]{0,30}\broot\b",
      r"\bdocker\s+(run|exec)[^\n]*--privileged\b", r"--privileged\b",
      r"docker\.sock", r"-v\s+/:[^\n\s]*",
      r"контейнер[^\n]{0,24}(root|привилег)"]),
    ("availability", WARN, "риск для доступности объекта",
     [r"nuclei[^\n]*-tags[^\n]*\bdos\b", r"--script[^\n]*\bdos\b",
      r"\bmkfs\b", r"dd\s+if=[^\n]*of=/dev/", r"iptables\s+-F",
      r"\bshutdown\b", r"\breboot\b", r"killall\s+-9", r"rm\s+-rf\s+/(?!tmp|home)",
      r"ffuf[^\n]*-rate\s+[0-9]{4,}", r"nmap[^\n]*-T5", r"--threads\s+[0-9]{3,}",
      r"trufflehog[^\n]*--verify"]),
    # Сетевое устройство по пути — не «ещё один хост». Падение роутера или
    # точки доступа оставляет заказчика без связи и без VPN, а это уже отказ
    # в обслуживании всей площадки. Поэтому не запрет, а предупреждение:
    # решение принимает оператор, и лучше в согласованное окно.
    ("netdev", WARN, "похоже на сетевое устройство, а не на сервер",
     [r"\brouter\b", r"роутер", r"маршрутизатор", r"\bgateway\b", r"\bшлюз\b",
      r"openwrt", r"mikrotik", r"keenetic", r"ubiquiti", r"\bubnt\b", r"zyxel",
      r"tp-?link", r"d-?link", r"коммутатор", r"\bswitch\b", r"точка доступа",
      r"access\s+point", r"\bac\s+controller\b", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.(1|254)\b"]),
    ("malware", BLOCK, "вредоносное ПО, соц. инженерия, слежка за людьми",
     [r"keylog", r"phish", r"ransom", r"Gophish", r"Set-Clipboard[^\n]*password",
      r"spearphish", r"Get-Keystrokes", r"Invoke-Phant0m"]),
    # Уровень warn, и это не описка: адрес вне списка не запрет, а «оператор
    # должен увидеть». Запись в таблице нужна, чтобы категория существовала,
    # а сами находки строит проверка области ниже (там отсекаются имена файлов
    # и разбираются адреса внутри URL).
    ("scope", WARN, "выход за пределы согласованного объекта",
     [r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b"]),
]

_COMPILED = [(cid, lvl, title, [re.compile(p, re.I) for p in pats])
             for cid, lvl, title, pats in _CATEGORIES]

# Что оставляет след на объекте: файл, задача, запись в реестр, копия.
_PLACES = [
    (re.compile(p, re.I), what) for p, what in [
        (r"(^|\s)(-o|--output)\s+\S", "файл с результатом на диске"),
        (r"(^|\s)>\s*\S", "перенаправление вывода в файл"),
        (r"Out-File|Set-Content|Add-Content", "запись файла (PowerShell)"),
        (r"curl\s+[^\n]*-o\s|wget\s+[^\n]*-O\s", "скачанный файл"),
        (r"crontab\s|schtasks|reg\s+add|systemctl\s+enable", "задание или служба"),
        (r"\bscp\b|UploadFile|Invoke-WebRequest[^\n]*-OutFile", "перенос файла"),
    ]]

_VERSIONS = re.compile(r"\b(\d+\.\d+(\.\d+)?)\b")


def _in_cidr(ip: str, net: str) -> bool:
    """Адрес внутри согласованной подсети?

    Область почти всегда задают подсетью (10.20.4.0/24), а не списком адресов.
    Без этого шаг по своему же адресу выглядел бы выходом за договор — и
    оператор приучался бы не читать предупреждения.
    """
    if "/" not in (net or ""):
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False

# Имена файлов, которые похожи на домен: rockyou.txt, pass.log, dump.sql.
# Без этого списка проверка области сообщала бы «адрес вне согласованного
# списка» про словарь паролей — то есть шумела бы ровно там, где ворота и так
# сказали «нельзя», и оператор переставал бы читать причину.
# Домены бывают трёхбуквенные (com, net, org, ru, io) и длинные. Одного
# правила «есть точка — значит домен» мало: оно ловило «claude-opus-5.5»
# и версии вроде «2.4.1» как адреса вне области. Живой случай 08.10.2026
# на разборе ответов моделей.
_TAIL_RE = re.compile(r"^[a-z]{2,24}$")


def _looks_like_host(name: str) -> bool:
    """Похоже ли это на имя хоста, а не на версию, модель или имя файла."""
    h = (name or "").strip().strip(".").lower()
    if not h or "." not in h:
        return False
    tail = h.rsplit(".", 1)[-1]
    if tail in _FILE_TAILS:
        return False
    if not _TAIL_RE.match(tail):
        return False                  # «5.5», «2.4.1» — версии, не домены
    if h.replace(".", "").isdigit():
        return False                  # голый IP разбирается отдельно
    return True


# Слова, рядом с которыми находка становится ЦИТАТОЙ, а не действием.
# Так устроен честный ответ модели: в нём есть список «чего нельзя», и наши
# ворота обязаны отличать «не трогаем 10.20.7.0/24» от «идём на 10.20.7.0/24».
_NEGATION = (
    "нельзя", "запрещ", "не трога", "не ходи", "не сканир", "не стоит",
    "не делаем", "не дела", "не использ", "избег", "опасн", "исключ",
    "отказ", "ни в коем случае", "вне области", "вне зоны", "не касаемся",
    "не пыта", "не пробу", "не подбир", "не перебира", "не запуск", "нет ",
)


def cited_not_acted(text: str, pos: int, span: int = 220) -> bool:
    """Находка стоит рядом с запретом — значит это цитата, а не действие."""
    around = (text[max(0, pos - span):pos + span] or "").lower()
    return any(w in around for w in _NEGATION)


_FILE_TAILS = {
    "txt", "log", "conf", "cfg", "exe", "dll", "pyc", "ps1", "bat", "cmd", "json",
    "xml", "csv", "ini", "yml", "yaml", "gguf", "sqlite", "tgz", "gz", "tar",
    "iso", "img", "pem", "key", "crt", "cer", "pcap", "pcapng", "sql", "lst",
    "dat", "tmp", "bak", "swp", "out", "err", "pid", "lock", "jar", "war",
    "htm", "jpeg", "jpg", "png", "gif", "svg", "pdf", "docx", "xlsx", "pptx",
    # имена инструментов: psexec.py, testssl.sh, nikto.pl. Домены .py/.sh/.pl
    # существуют, но в работе на объекте имена скриптов встречаются в тысячу
    # раз чаще, чем суверенные сайты Парагвая и острова Святой Елены.
    "py", "sh", "pl", "rb", "go", "js", "php",
    # deploy.env, config.env, старые копии
    "env", "old",
}


# Что вместо запрещённого. Отказ без альтернативы — тупик, из которого
# оператор выходит «снять рамку» или «сделать тихо». У каждого запрета есть
# законный путь к тому же знанию, и он должен быть назван сразу.
ALTERNATIVES = {
    "bruteforce": ("подтвердить слабый пароль можно и без перебора: секреты в коде "
                   "и конфигах (check_secrets), материалы заказчика, архивы, "
                   "забытый пароль в скрипте. Перебор — это правка рамки: "
                   "письменное согласование порога блокировки, окна и обнуления "
                   "счётчиков заказчиком; лимит в 1–2 попытки безопасным НЕ делает, "
                   "потому что счётчик мог быть уже ненулевым, и это не спрашивали"),
    "data": ("доказать доступность данных, не выгружая их: путь и права (листинг "
             "каталога, права на файл, доступность по сети). Копия — отдельное "
             "решение заказчика, он отвечает за утечку"),
    "logs": ("журналы остаются как есть: след — часть работы, он описывается в "
             "отчёте, а не устраняется"),
    "persistence": ("закрепление не нужно по условиям работы: доступ передаётся "
                    "человеку, а не поддерживается машиной"),
    "c2": ("канал управления заменяется согласованным транспортом, который "
           "обсуждается с оператором отдельно"),
    "malware": ("приём, работающий на людей, техническим не заменяется: меняется "
                "точка входа"),
    "creds": ("аутентификацию не перехватываем и не релеим, чужие сессии не "
              "захватываем: доступ берём известными данными и штатными средствами. "
              "Работа с секретами включается документом (ASM_CREDS=approved) — "
              "без него это запрещено"),
    "availability": ("шаг выполняется в согласованное окно, на стенде или с "
                     "ограничением скорости; иначе — решение оператора и "
                     "письменное согласие заказчика"),
    "netdev": ("устройства по пути трогаются только в окно и с согласия; "
               "начните с того, что видно снаружи, и с подтверждения области"),
}


_LOUD = [re.compile(p, re.I) for p in (
    r"\blsass\b", r"\bmimikatz\b", r"\bsecretsdump\b", r"\bdcsync\b",
    r"дамп\s+(секрет|парол)", r"\bdump\s+(lsass|sam|ntds)",
    r"procdump[^\n]*lsass", r"comsvcs\.dll[^\n]*minidump",
    r"ntdsutil[^\n]*activate", r"sekurlsa")]


def creds_approved() -> bool:
    """Разрешена ли работа с секретами документом.

    По умолчанию нет: `ASM_CREDS=block`. Значение `approved` включается только
    после подписанного разрешения заказчика — и не снимает проверок: находка
    остаётся, но переходит из «нельзя» в «можно под одобрение на объект».
    """
    return os.environ.get("ASM_CREDS", "block").strip().lower() in (
        "approved", "allow", "allowed", "on")


def check(text: str, *, kind: str = "команда", scope: tuple = (),
          target: str = "") -> dict:
    """Проверить команду или код. Возвращает разбор, а не приговор.

    `scope` — согласованные адреса и домены. Адрес из текста, которого в
    списке нет, — отдельная находка уровня `warn`: это не «запрещено», это
    «оператор должен увидеть, что шаг уходит не туда, куда договорились».
    """
    t = text or ""
    # Текст ответа читает человек: «не трогаем 10.20.7.0/24» — правильная фраза,
    # и ворота не должны звать её нарушением. Команду же исполняют буквально,
    # поэтому понижение «цитата вместо действия» касается только разбора текстов.
    review = kind in ("ответ", "ответ модели", "текст")
    findings: list[dict] = []
    for cid, level, title, pats in _COMPILED:
        if cid == "scope":
            continue                      # область проверяется по списку ниже
        for rx in pats:
            m = rx.search(t)
            if m:
                seen = m.group(0)
                # Длинное совпадение (шаблон разошёлся по всей строке) режем:
                # оператору нужен признак, по которому сработало правило,
                # а не копия команды целиком.
                if len(seen) > 60:
                    seen = seen[:57] + "…"
                # В разборе текста находка рядом с запретом — цитата. Автор
                # отвечает на вопрос «чего делать нельзя» и обязан называть
                # запрещённое; ругать его за это значит ругать за честный ответ.
                cited = review and cited_not_acted(t, m.start())
                item = {"category": cid,
                        "level": WARN if cited else level,
                        "title": (title + " — упомянуто как запрещённое") if cited else title,
                        "match": seen, "cited": cited}
                if not cited:
                    if cid == "creds" and any(rx.search(seen) for rx in _LOUD):
                        item["loud"] = True
                findings.append(item)
                break

    # Область: адреса и имена, которых нет в согласованном списке.
    if scope:
        scope_l = {str(x).strip().lower() for x in scope if str(x).strip()}
        seen: list[str] = []
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", t):
            if ip in scope_l or ip in seen:
                continue
            if any(_in_cidr(ip, x) for x in scope_l if "/" in x):
                continue
            seen.append(ip)
        # Имена хостов ищем двумя проходами: сначала в адресах вида
        # «https://mail.corp.local/x» (обычный разбор пропустил бы их из-за
        # косых черт перед именем), потом в остальном тексте.
        candidates = re.findall(r"https?://([a-z0-9][a-z0-9.\-]*)", t, re.I)
        trimmed = re.sub(r"https?://\S+", " ", t)
        candidates += re.findall(
            r"(?<![\w./\\])([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)\b", trimmed, re.I)
        for host in candidates:
            h = (host or "").strip(".").lower()
            if not _looks_like_host(h):
                continue          # имя файла, версия или имя модели — не адрес
            if h in scope_l:
                continue
            if any(h == s or h.endswith("." + s) for s in scope_l):
                continue
            if h not in seen:
                seen.append(h)
        for x in seen[:6]:
            pos = t.lower().find(x.lower())
            cited = review and pos >= 0 and cited_not_acted(t, pos)
            findings.append({"category": "scope",
                             "level": WARN,
                             "title": ("адрес вне области упомянут как запрещённый"
                                       if cited else "адрес вне согласованного списка"),
                             "match": x, "cited": cited})

    # Документ разрешил работу с секретами: «нельзя» становится «можно под
    # одобрение», но не исчезает — оператор должен видеть каждый такой шаг.
    if creds_approved():
        for f in findings:
            if f["category"] == "creds" and f["level"] == BLOCK:
                f["level"] = WARN
                f["approved"] = True

    trace = [what for rx, what in _PLACES if rx.search(t)]
    places = bool(trace)
    lvl = ALLOW
    if any(f["level"] == BLOCK for f in findings):
        lvl = BLOCK
    elif any(not f.get("cited") for f in findings):
        lvl = WARN
    elif findings:
        lvl = WARN                  # только цитаты: показать, но не браковать
    return {"action": lvl, "kind": kind, "findings": findings, "trace": trace,
            "places": places,
            "needs_cleanup": places,
            "note": _note(lvl, findings, trace)}


def _note(level: str, findings: list[dict], trace: list[str]) -> str:
    if level == BLOCK:
        f = next(x for x in findings if x["level"] == BLOCK)
        out = (f"не выполняется: {f['title']}. Совпадение: «{f['match']}». "
               "Рамку снимает только человек, и то осознанно.")
        extra = ALTERNATIVES.get(f["category"])
        if extra:
            out += " Что вместо: " + extra + "."
        return out
    if level == WARN:
        parts = [f["title"] for f in findings]
        if trace:
            parts.append("оставит на объекте: " + ", ".join(trace))
        out = "можно, но оператор должен видеть: " + "; ".join(parts)
        first = findings[0]
        if first.get("approved"):
            out += (". Работа с секретами разрешена документом: одобрение оператора "
                    "на конкретный объект обязательно")
            if any(f.get("loud") for f in findings):
                out += ("; громкий метод (дамп) оставляет самый заметный след — "
                        "только в согласованное окно")
        else:
            extra = ALTERNATIVES.get(first["category"])
            if extra:
                out += ". Как безопаснее: " + extra
        return out
    if trace:
        return ("можно; оставит на объекте: " + ", ".join(trace)
                + " — уборка обязательна и записывается в пакет передачи")
    return "можно: ничего запрещённого и никакого следа на объекте"


def describe(res: dict) -> str:
    """Как результат ворот выглядит для оператора."""
    mark = {ALLOW: "✓", WARN: "!", BLOCK: "✗"}[res["action"]]
    out = [f"{mark} ворота: {res['note']}"]
    for f in res["findings"]:
        out.append(f"    · [{f['category']}] {f['title']}: «{f['match']}»")
    return "\n".join(out)


def check_step_with(step: dict, scope: tuple = ()) -> dict:
    """Проверить шаг с учётом согласованной области."""
    params = step.get("params") or {}
    text = " ".join(str(v) for v in params.values() if isinstance(v, (str, int)))
    text = f"{step.get('action_id') or ''} {text}".strip()
    res = check(text, kind="шаг", scope=scope)
    if step.get("places"):
        res["places"] = True
        res["needs_cleanup"] = True
        if not any("файл на объекте" in t for t in res["trace"]):
            res["trace"].append("файл на объекте (шаг из каталога)")
        if res["action"] == ALLOW and "уборка" not in res["note"]:
            res["note"] = res["note"] + " — уборка обязательна"
    return res


def check_step(step: dict) -> dict:
    """Проверить шаг агента: параметры и признак «кладёт файл на хост».

    Шаг из каталога уже размечен, но проверка нужна по той же причине, что и
    для свободного кода: параметры называет человек или модель, и в них может
    оказаться чужой адрес или команда уборки, которую никто не выполнит.
    """
    params = step.get("params") or {}
    text = " ".join(str(v) for v in params.values() if isinstance(v, (str, int)))
    res = check(text, kind="шаг", target=str(params.get("target") or ""))
    if step.get("places"):
        res["places"] = True
        res["needs_cleanup"] = True
        if "файл на объекте" not in res["trace"]:
            res["trace"].append("файл на объекте (шаг из каталога)")
    return res
