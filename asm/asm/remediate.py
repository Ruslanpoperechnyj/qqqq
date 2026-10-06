"""
База знаний «как закрыть найденное» — то, за что клиент и платит.

Для каждой находки выдаём:
  * что это простыми словами,
  * чем опасно,
  * что сделать по шагам,
  * готовые команды/конфиги под конкретный стек.

База расширяемая: правила сматчиваются по продукту (Apache, nginx, WordPress, БД...),
по классу уязвимости (RCE, XSS, SQLi, SSRF...), по тегам и id шаблонов nuclei,
по «опасным» портам и по конкретным CVE.
"""
from __future__ import annotations

import re

# ------------------------------------------------------------------ продукты
PRODUCT_RULES: list[tuple[str, dict]] = [
    ("apache", {
        "что это": "Веб-сервер Apache HTTP Server",
        "как закрыть": [
            "Обновить пакет веб-сервера до актуальной версии ветки 2.4 (или новее), перезапустить службу",
            "Отключить лишние модули: mod_status, mod_info, mod_autoindex — если они не нужны",
            "Запретить листинг каталогов: Options -Indexes",
            "Ограничить доступ к служебным путям (server-status, .git, .env) на уровне конфигурации",
        ],
        "команды": [
            "# Debian/Ubuntu\nsudo apt update && sudo apt install --only-upgrade apache2 && sudo systemctl restart apache2",
            "# RHEL/CentOS/Astra\nsudo dnf update httpd && sudo systemctl restart httpd",
            "# запрет листинга каталогов: в <Directory> добавить\nOptions -Indexes",
        ],
    }),
    ("nginx", {
        "что это": "Веб-сервер и обратный прокси nginx",
        "как закрыть": [
            "Обновить nginx до актуальной стабильной версии",
            "Скрыть версию в заголовке: server_tokens off",
            "Запретить отдачу служебных файлов (.git, .env, .bak) отдельным location",
            "Ограничить методы: разрешить только GET/POST/HEAD, если приложению больше не нужно",
        ],
        "команды": [
            "sudo apt update && sudo apt install --only-upgrade nginx && sudo systemctl reload nginx",
            r"# в блоке server:\nserver_tokens off;\nlocation ~ /\.(git|env|svn|bak|old|sql) { deny all; return 404; }",
        ],
    }),
    ("openssh", {
        "что это": "Служба удалённого доступа SSH",
        "как закрыть": [
            "Обновить openssh-server и перезапустить службу",
            "Запретить вход по паролю: только ключи (PasswordAuthentication no)",
            "Запретить вход root напрямую: PermitRootLogin no",
            "Ограничить доступ по IP через firewall; при возможности — не публиковать 22-й порт в интернет",
        ],
        "команды": [
            "sudo apt update && sudo apt install --only-upgrade openssh-server && sudo systemctl restart ssh",
            r"# /etc/ssh/sshd_config:\nPasswordAuthentication no\nPermitRootLogin no\nMaxAuthTries 3\nAllowUsers deploy",
        ],
    }),
    ("wordpress", {
        "что это": "CMS WordPress",
        "как закрыть": [
            "Обновить ядро, тему и все плагины; удалить неиспользуемые плагины (это главный источник взломов)",
            "Отключить листинг каталогов и доступ к wp-config.php, xmlrpc.php",
            "Включить двухфакторную аутентификацию и сменить пароли администраторов",
            "Поставить защиту на вход: ограничение попыток входа (limit-login-attempts / fail2ban)",
        ],
        "команды": [
            "wp core update --all && wp plugin update --all && wp theme update --all",
            r"# в nginx:\nlocation ~* /(wp-config\.php|xmlrpc\.php|readme\.html) { deny all; }",
        ],
    }),
    ("drupal", {"что это": "CMS Drupal", "как закрыть": [
        "Обновить ядро и модули: известные RCE (Drupalgeddon) закрываются только обновлением",
        "Ограничить доступ к /user/register и служебным путям",
        "Сменить пароли администраторов, включить 2FA"],
        "команды": ["# через composer или интерфейс обновлений\ncomposer update drupal/core --with-dependencies"]}),
    ("joomla", {"что это": "CMS Joomla", "как закрыть": [
        "Обновить ядро и расширения, удалить неиспользуемые",
        "Удалить шаблоны и плагины, которые не поддерживаются"], "команды": []}),
    ("php", {"что это": "Интерпретатор PHP", "как закрыть": [
        "Обновить PHP до поддерживаемой ветки (8.2+)",
        "Отключить вывод ошибок на боевом сайте: display_errors = Off",
        "Запретить опасные функции, если используются: exec, shell_exec, system"],
        "команды": ["sudo apt install --only-upgrade php8.3-fpm && sudo systemctl restart php8.3-fpm",
                    "# php.ini\ndisplay_errors = Off\nlog_errors = On\nexpose_php = Off"]}),
    ("mysql|mariadb", {"что это": "СУБД MySQL/MariaDB", "как закрыть": [
        "НЕ публиковать порт 3306 в интернет — только localhost или приватная сеть",
        "Проверить пользователей и их права: не должно быть root@'%' ",
        "Включить require_secure_transport и сменить слабые пароли"],
        "команды": ["# закрыть порт снаружи\nsudo ufw deny 3306\n# в my.cnf\nbind-address = 127.0.0.1\n# список доступных отовсюду\nSELECT user,host FROM mysql.user WHERE host NOT IN ('localhost','127.0.0.1');"]}),
    ("postgres", {"что это": "СУБД PostgreSQL", "как закрыть": [
        "Убрать публикацию порта 5432; доступ — только через VPN или приватную сеть",
        "Проверить pg_hba.conf: методы trust и md5 для внешних адресов недопустимы",
        "Сменить пароли, ограничить роли"],
        "команды": ["sudo ufw deny 5432", "# postgresql.conf\nlisten_addresses = 'localhost'"]}),
    ("redis", {"что это": "Хранилище Redis", "как закрыть": [
        "Redis не должен быть доступен из интернета: bind 127.0.0.1 + requirepass",
        "Включить аутентификацию и переименовать опасные команды (CONFIG, FLUSHALL)",
        "Перезапустить сервис и проверить, что порт 6379 закрыт снаружи"],
        "команды": ["# redis.conf\nbind 127.0.0.1\nrequirepass <сложный_пароль>\nrename-command CONFIG \"\"",
                    "sudo ufw deny 6379"]}),
    ("elastic", {"что это": "Elasticsearch", "как закрыть": [
        "Закрыть 9200 снаружи, включить X-Pack Security или обратный прокси с аутентификацией",
        "Проверить, что индексы не отдаются анонимно: curl http://<ip>:9200/_cat/indices",
        "Ограничить доступ по IP на уровне firewall и прокси"],
        "команды": ["# elasticsearch.yml\nnetwork.host: 127.0.0.1\nxpack.security.enabled: true", "sudo ufw deny 9200"]}),
    ("mongodb", {"что это": "СУБД MongoDB", "как закрыть": [
        "Включить авторизацию (authorization: enabled) и создать отдельного пользователя приложения",
        "Закрыть порт 27017 снаружи", "Проверить, что базы читаются только по аутентификации"],
        "команды": ["# mongod.conf\nnet:\n  bindIp: 127.0.0.1\nsecurity:\n  authorization: enabled", "sudo ufw deny 27017"]}),
    ("ntp", {"что это": "Служба точного времени NTP", "как закрыть": [
        "Обновить ntpd/chrony до актуальной версии",
        "Отключить режим мониторинга (monlist/mode 6), который использовали для DDoS",
        "Разрешить запросы только своим адресам в конфигурации restrict"],
        "команды": ["sudo apt update && sudo apt install --only-upgrade ntp", "# ntp.conf\nrestrict default kod nomodify nopeer noquery\nrestrict 127.0.0.1"]}),
    ("iis", {"что это": "Веб-сервер Microsoft IIS / Windows-стек", "как закрыть": [
        "Установить обновления Windows (в т.ч. для .NET и IIS)",
        "Убрать заголовки с версией: X-Powered-By, Server",
        "Отключить ненужные обработчики и модули, ограничить права сайта"],
        "команды": ["# PowerShell: убрать X-Powered-By\nSet-WebConfigurationProperty -filter \"system.webServer/httpProtocol/customHeaders\" -name \".\" -value @{name='X-Powered-By';value=''}"]}),
    ("tomcat|jetty|weblogic", {"что это": "Java-сервер приложений", "как закрыть": [
        "Обновить сервер приложений: известные цепочки десериализации дают выполнение кода",
        "Удалить примеры, менеджер и документацию (/examples, /manager, /host-manager), если они не нужны",
        "Закрыть админ-панели аутентификацией с сильными паролями, желательно за VPN"],
        "команды": ["sudo apt update && sudo apt install --only-upgrade tomcat9",
                    "# удалить webapps-примеры\nsudo rm -rf /var/lib/tomcat9/webapps/examples"]}),
    ("grafana|kibana|zabbix|jenkins|gitlab|webmin|phpmyadmin", {
        "что это": "Панель управления / админ-интерфейс",
        "как закрыть": [
            "Панели не должны быть в открытом интернете: закрыть firewall-ом и поставить за VPN",
            "Сменить учётные данные по умолчанию, включить двухфакторную аутентификацию",
            "Обновить панель: у большинства таких интерфейсов есть критические CVE",
            "Ограничить доступ по IP администраторов",
        ],
        "команды": ["sudo ufw deny <порт_панели>", "# доступ только с офисного IP\nsudo ufw allow from <белый_IP> to any port <порт_панели>"]}),
    ("docker", {"что это": "Среда контейнеров Docker", "как закрыть": [
        "Никогда не публиковать Docker API (2375/2376) в интернет — это полный контроль над сервером",
        "Использовать TLS с клиентскими сертификатами, если удалённый доступ нужен",
        "Закрыть порт и настроить доступ только через SSH-туннель"],
        "команды": ["sudo ufw deny 2375", "# проверка\ncurl http://<ip>:2375/version   # не должно отвечать"]}),
]

# ------------------------------------------------------------------ классы уязвимостей
CLASS_RULES: list[tuple[str, dict]] = [
    ("rce|remote code execution|code execution|command execution", {
        "класс": "Выполнение кода на сервере (RCE) — самая опасная категория",
        "как закрыть": [
            "Немедленно обновить компонент до версии с исправлением",
            "Если обновление невозможно — временно закрыть доступ к сервису (firewall/VPN), понизить привилегии процессов",
            "Проверить логи на признаки компрометации: подозрительные процессы, новые пользователи, исходящие подключения",
            "Сменить все пароли и ключи, которые могли быть доступны с этого сервера",
        ],
        "команды": ["# после закрытия уязвимости проверить следы\ngrep -i \"new user\\|session opened\" /var/log/auth.log | tail -50",
                    "ps aux --sort=-%cpu | head -20"]}),
    ("sql injection|sqli", {"класс": "SQL-инъекция — чтение и изменение базы данных",
        "как закрыть": ["Использовать подготовленные выражения (prepared statements) на уровне приложения",
                        "Отключить вывод ошибок СУБД наружу", "Ограничить права учётной записи приложения: без DROP/GRANT",
                        "Провести ревизию: какие данные могли прочитать"],
        "команды": ["# проверка прав пользователя приложения\nSHOW GRANTS FOR 'app'@'localhost';"]}),
    ("xss|cross-site scripting", {"класс": "XSS — подмена страниц и кража сессий пользователей",
        "как закрыть": ["Экранировать вывод во всех местах, где данные попадают в HTML",
                        "Включить Content-Security-Policy",
                        "Поставить флаг HttpOnly для cookies сессии"],
        "команды": [r"# в nginx"+chr(10)+"add_header Content-Security-Policy \"default-src 'self'\";\nadd_header Set-Cookie \"SameSite=Lax; HttpOnly; Secure\";"]}),
    ("ssrf|server-side request forgery", {"класс": "SSRF — доступ к внутренней сети через сервер",
        "как закрыть": ["Запретить запросы к внутренним адресам (whitelist доменов/подсетей)",
                        "Изолировать сервис в отдельный сетевой сегмент"],
        "команды": []}),
    ("path traversal|directory traversal|lfi|local file inclusion", {"класс": "Обход каталогов и чтение файлов",
        "как закрыть": ["Обновить компонент до исправленной версии",
                        "Нормализовать и валидировать пути в приложении",
                        "Запретить чтение служебных файлов на уровне веб-сервера"],
        "команды": ["# nginx\nlocation ~ /\\.(git|env|bak|sql|conf) { deny all; }"]}),
    ("denial of service|dos ", {"класс": "Отказ в обслуживании (DoS)",
        "как закрыть": ["Обновить компонент", "Ограничить частоту запросов (rate limit) на балансировщике/nginx",
                        "Вынести сервис за защиту от DDoS, если он публично доступен"],
        "команды": ["# nginx\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;"]}),
    ("authentication bypass|auth bypass|default login|default credential", {"класс": "Обход аутентификации или учётные данные по умолчанию",
        "как закрыть": ["Немедленно сменить пароли по умолчанию и переименовать администратора",
                        "Включить двухфакторную аутентификацию",
                        "Ограничить доступ к панели по IP", "Проверить журналы входа на подозрительные сессии"],
        "команды": ["# кто входил\nlast -a | head -20\njournalctl -u <служба> --since \"7 days ago\" | grep -i \"login\\|auth\""]}),
    ("information disclosure|exposed|sensitive", {"класс": "Раскрытие чувствительной информации",
        "как закрыть": ["Удалить или закрыть публикацию файла/эндпоинта",
                        "Почистить историю репозитория, если в открытом доступе были ключи и пароли",
                        "Сменить все секреты, которые были доступны: ключи API, токены, пароли БД"],
        "команды": ["# nginx\nlocation ~ /\\.(env|git|svn|htaccess|zip|sql|bak) { deny all; }"]}),
    ("outdated|obsolete|eol|end of life", {"класс": "Устаревшее ПО без поддержки",
        "как закрыть": ["Планировать обновление до поддерживаемой версии: устаревшие версии не получают патчи безопасности",
                        "Составить список зависимостей и их версий, обновлять по графику"],
        "команды": []}),
    ("tls|ssl|certificate|cipher", {"класс": "Проблемы TLS/SSL",
        "как закрыть": ["Отключить устаревшие протоколы TLS 1.0/1.1 и слабые шифры",
                        "Настроить автоматическое продление сертификатов",
                        "Включить HSTS после проверки, что сайт полностью работает по HTTPS"],
        "команды": ["# nginx\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                    "# Let's Encrypt\nsudo certbot renew --dry-run"]}),
]

# ------------------------------------------------------------------ шаблоны nuclei
TEMPLATE_RULES: list[tuple[str, dict]] = [
    ("http-missing-security-headers", {
        "класс": "Отсутствуют заголовки безопасности",
        "как закрыть": ["Добавить базовые заголовки безопасности: HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy",
                        "Проверить, что они не ломают работу сайта"],
        "команды": [
            "# nginx — вставить в блок server\n"
            "add_header X-Content-Type-Options nosniff always;\n"
            "add_header X-Frame-Options SAMEORIGIN always;\n"
            "add_header Referrer-Policy strict-origin-when-cross-origin always;\n"
            "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
        ]}),
    ("apache-mod-negotiation-listing|directory-listing|listing", {
        "класс": "Включён листинг каталогов",
        "как закрыть": ["Запретить вывод списка файлов",
                        "Проверить все каталоги, доступные без авторизации"],
        "команды": ["# Apache: в <Directory>\nOptions -Indexes", "# nginx\nautoindex off;"]}),
    ("git-config|gitignore|exposed-git|svn", {
        "класс": "Служебный репозиторий доступен из интернета",
        "как закрыть": ["Закрыть доступ к служебным каталогам на уровне веб-сервера",
                        "Если в открытом доступе были ключи/пароли — отозвать их и почистить историю"],
        "команды": ["# nginx\nlocation ~ /\\.git { deny all; return 404; }",
                    "# проверить, что закрылось\ncurl -I http://<сайт>/.git/config"]}),
    (r"env|dotenv|config-file|backup-file|sql-file|\.old|\.bak|\.zip", {
        "класс": "В открытом доступе файл с секретами или резервной копией",
        "как закрыть": ["Удалить файл из публичного каталога или закрыть правило доступа",
                        "Обязательно сменить все секреты из этого файла: пароли БД, ключи API, токены",
                        "Проверить, не индексировался ли файл поисковиками, при необходимости запросить удаление из кэша"],
        "команды": ["# nginx\nlocation ~* \\.(env|bak|old|sql|zip|tar\\.gz|log)$ { deny all; }",
                    "# убрать из индекса Google — через Search Console ускоренное удаление"]}),
    ("wp-|wordpress|joomla|drupal|typo3|magento|opencart|bitrix", {
        "класс": "Уязвимость или открытая административная часть CMS",
        "как закрыть": ["Обновить ядро CMS и все расширения; удалить неиспользуемые плагины",
                        "Ограничить доступ к админ-панели по IP",
                        "Включить 2FA и сменить пароли администраторов",
                        "Проверить файлы на шелл-скрипты (uploads), если сайт давно не обновлялся"],
        "команды": ["# WordPress\nwp core verify-checksums\nwp plugin list --status=active",
                    "# поиск свежих php-файлов в uploads\nfind wp-content/uploads -name \"*.php\" -mtime -30"]}),
    ("default-login|default-password", {
        "класс": "Вход с учётными данными по умолчанию",
        "как закрыть": ["Сменить пароль и логин администратора немедленно",
                        "Включить двухфакторную аутентификацию",
                        "Проверить логи на входы со сторонних IP"],
        "команды": []}),
    ("cve-|cve", {"класс": "Известная уязвимость (CVE) в компоненте",
        "как закрыть": ["Обновить компонент до версии с исправлением",
                        "Если обновление недоступно — временно ограничить доступ к сервису",
                        "Проверить, не эксплуатировалась ли уязвимость: логи, процессы, задания в cron"],
        "команды": ["# проверить подозрительные задания\ntcrontab -l; cat /etc/crontab; ls -la /etc/cron.d/"]}),
    ("takeover", {"класс": "Возможен перехват поддомена (subdomain takeover)",
        "как закрыть": ["Удалить DNS-запись, которая указывает на несуществующий сервис",
                        "Либо заново занять ресурс у провайдера, если поддомен нужен"],
        "команды": ["dig +short <поддомен> CNAME   # куда указывает",
                    "# удалить запись в панели DNS-провайдера или перевыпустить сервис"]}),
]

# ------------------------------------------------------------------ опасные сервисы наружу
PORT_RULES: dict[int, dict] = {
    21: {"класс": "FTP доступен из интернета", "как закрыть": [
        "Перейти на SFTP/SSH, FTP передаёт пароль в открытом виде",
        "Если FTP нужен — закрыть доступ по IP и включить FTP over TLS"],
        "команды": ["sudo ufw deny 21"]},
    23: {"класс": "Telnet доступен из интернета", "как закрыть": [
        "Отключить telnet, использовать SSH", "Закрыть порт в firewall"],
        "команды": ["sudo systemctl disable --now telnet.socket", "sudo ufw deny 23"]},
    445: {"класс": "SMB (сетевая папка Windows) доступен из интернета", "как закрыть": [
        "Закрыть порт 445 и 139 в firewall — SMB не должен быть доступен снаружи",
        "Проверить, не троян ли это: семейство шифровальщиков атакует именно этот порт",
        "Для удалённой работы использовать VPN"],
        "команды": ["sudo ufw deny 445", "sudo ufw deny 139"]},
    3389: {"класс": "RDP (удалённый рабочий стол) доступен из интернета", "как закрыть": [
        "Убрать RDP из публичного доступа: только через VPN",
        "Включить блокировку по числу попыток, двухфакторную аутентификацию",
        "Проверить журналы входов на подбор пароля"],
        "команды": ["sudo ufw deny 3389", "# вход только с офисного IP\nsudo ufw allow from <белый_IP> to any port 3389"]},
    5900: {"класс": "VNC доступен из интернета", "как закрыть": [
        "Закрыть порт и использовать VNC через SSH-туннель или VPN", "Установить пароль доступа"],
        "команды": ["sudo ufw deny 5900"]},
    2375: {"класс": "Docker API открыт наружу", "как закрыть": [
        "Критично: полный контроль над сервером. Закрыть порт немедленно",
        "Проверить, не запущены ли посторонние контейнеры"],
        "команды": ["sudo ufw deny 2375", "docker ps -a"]},
}


def _match(rules, text: str):
    for pattern, data in rules:
        if re.search(pattern, text, re.I):
            return data
    return None


def _clean(text: str) -> str:
    """Нормализуем переносы строк в командах (в базе они хранятся по-разному)."""
    return (text.replace("\\\\n", "\n").replace("\\n", "\n").strip())


def advice(finding: dict) -> dict:
    """
    Возвращает {'класс': ..., 'пункты': [...], 'команды': [...]}.
    Учитывает: продукт, класс уязвимости (по NVD-описанию), id/теги nuclei, номер порта.
    """
    parts: list[dict] = []
    blob_parts = [
        str(finding.get("product") or ""),
        str(finding.get("title") or ""),
        str(finding.get("template_id") or ""),
        " ".join(finding.get("tags") or []) if isinstance(finding.get("tags"), list) else str(finding.get("tags") or ""),
        str((finding.get("evidence") or {}).get("описание (NVD)") or ""),
        str(finding.get("description") or ""),
        str(finding.get("evidence") or ""),
    ]
    blob = " ".join(blob_parts)

    # 1) конкретный продукт
    prod = _match(PRODUCT_RULES, blob)
    if prod:
        parts.append({"источник": "продукт", **prod})
    # 2) шаблон nuclei
    tpl = _match(TEMPLATE_RULES, blob)
    if tpl:
        parts.append({"источник": "тип проверки", **tpl})
    # 3) класс уязвимости по описанию
    cls = _match(CLASS_RULES, blob)
    if cls:
        parts.append({"источник": "класс уязвимости", **cls})
    # 4) открытый порт
    port = finding.get("port")
    if isinstance(port, int) and port in PORT_RULES:
        parts.append({"источник": "открытый сервис", **PORT_RULES[port]})

    if not parts:
        return {"класс": "Рекомендации общего характера", "команды": [], "пункты": [
            "Обновить компонент до актуальной версии и перезапустить службу",
            "Проверить, нужен ли этот сервис в открытом интернете: если нет — закрыть firewall-ом или убрать за VPN",
            "Убедиться, что используются сложные пароли и двухфакторная аутентификация",
            "Сделать резервную копию перед изменениями",
        ], "команды": []}

    # объединяем пункты без дублей
    points: list[str] = []
    commands: list[str] = []
    classes: list[str] = []
    for p in parts:
        if p.get("класс") and p["класс"] not in classes:
            classes.append(p["класс"])
        for it in p.get("как закрыть", []):
            if it not in points:
                points.append(it)
        for c in p.get("команды", []):
            if c not in commands:
                commands.append(c)
    return {"класс": " · ".join(classes[:2]), "пункты": points[:8],
            "команды": [_clean(c) for c in commands[:6]], "разбор": parts}


def plan_new_week(findings: list[dict]) -> list[str]:
    """Сводный план устранения: сначала критичное, сгруппировано по типу работ."""
    buckets: dict[str, list[str]] = {}
    for f in findings:
        if f.get("priority") not in ("P0", "P1"):
            continue
        a = advice(f)
        key = a["класс"] or "Прочее"
        item = f.get("asset") or f.get("ip") or ""
        if f.get("cve_id"):
            item = f"{f['cve_id']} @ {item}"
        elif f.get("title"):
            item = f"{f['title'][:70]} @ {item}"
        buckets.setdefault(key, [])
        if item not in buckets[key]:
            buckets[key].append(item)
    out = []
    for k, items in sorted(buckets.items(), key=lambda x: -len(x[1])):
        out.append(f"{k} — объектов: {len(items)} ({'; '.join(items[:4])}{' …' if len(items) > 4 else ''})")
    return out
