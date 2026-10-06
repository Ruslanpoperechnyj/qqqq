"""
Определение технологий по пассивным признакам: заголовки, баннеры, meta, порты.

Это упрощённый аналог Wappalyzer/WhatWeb: правила «признак -> продукт/версия».
Из продукта+версии строится CPE, который дальше скармливается в NVD.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------- порты -> сервисы
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    2379: "etcd", 3000: "grafana", 3306: "mysql", 3389: "rdp", 4443: "https-alt",
    5000: "http-alt", 5432: "postgres", 5601: "kibana", 5672: "rabbitmq", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 6443: "kubernetes-api", 7001: "weblogic", 8000: "http-alt",
    8080: "http-alt", 8081: "http-alt", 8086: "influxdb", 8123: "clickhouse", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 9443: "https-alt", 10000: "webmin", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 50000: "sap",
}

# «Опасные» сервисы: сами по себе находка, если торчат наружу
RISKY_PORTS = {
    21: ("FTP наружу", "Открытый FTP часто допускает анонимный вход и передаёт данные в открытом виде."),
    23: ("Telnet наружу", "Telnet передаёт пароль в открытом виде. Его не должно быть в периметре."),
    111: ("rpcbind наружу", "Используется для amplification-атак и разведки подсистемы RPC."),
    445: ("SMB наружу", "Классический вектор (EternalBlue и др.). SMB не должен быть доступен из интернета."),
    1433: ("MSSQL наружу", "СУБД в интернете: подбор паролей, кража данных."),
    2375: ("Docker API без TLS", "Даёт полный контроль над хостом: запуск контейнеров с маунтом /."),
    3306: ("MySQL наружу", "СУБД в интернете: подбор паролей, утечка баз."),
    3389: ("RDP наружу", "Массовый вектор брутфорса и шифровальщиков."),
    5432: ("PostgreSQL наружу", "СУБД в интернете: подбор паролей, утечка баз."),
    5900: ("VNC наружу", "Часто без пароля или со слабым. Полный доступ к рабочему столу."),
    6379: ("Redis наружу", "Без авторизации по умолчанию: запись файлов, RCE."),
    9200: ("Elasticsearch наружу", "Без авторизации по умолчанию: чтение всех индексов, включая ПДн."),
    11211: ("Memcached наружу", "Утечка кэша + amplification-атаки."),
    27017: ("MongoDB наружу", "Без авторизации по умолчанию: полное чтение баз."),
    2181: ("Zookeeper наружу", "Утечка конфигурации, потенциальный доступ к кластеру."),
    2379: ("etcd наружу", "Хранилище секретов Kubernetes: полная компрометация кластера."),
    5601: ("Kibana наружу", "Панель управления логами: утечка чувствительных данных."),
    15672: ("RabbitMQ mgmt наружу", "Панель управления брокером, часто с дефолтными кредами."),
    10000: ("Webmin наружу", "Исторически дефолтные учётки и RCE."),
}

WEB_PORTS = {80: "http", 443: "https", 8000: "http", 8080: "http", 8081: "http", 8443: "https",
             8888: "http", 9000: "http", 9090: "http", 9443: "https", 5000: "http", 4443: "https",
             3000: "http", 5601: "http", 9200: "http", 15672: "http", 10000: "http"}

# Продукт -> типовой порт. Нужно, чтобы не приписывать, например, OpenSSH порт 80:
# от этого зависит и оценка экспозиции, и корректность отчёта.
PRODUCT_PORTS: list[tuple[str, list[int]]] = [
    ("openssh", [22]), ("ssh", [22]), ("ntp", [123]), ("ftp", [21]), ("vsftpd", [21]),
    ("proftpd", [21]), ("samba", [445, 139]), ("telnet", [23]), ("rdp", [3389]),
    ("vnc", [5900]), ("mysql", [3306]), ("mariadb", [3306]), ("postgres", [5432]),
    ("mongodb", [27017]), ("redis", [6379]), ("elasticsearch", [9200, 9300]), ("kibana", [5601]),
    ("memcached", [11211]), ("rabbitmq", [15672, 5672]), ("docker", [2375, 2376]),
    ("zookeeper", [2181]), ("etcd", [2379]), ("clickhouse", [8123, 9000]), ("webmin", [10000]),
    ("grafana", [3000]), ("jenkins", [8080]), ("tomcat", [8080, 8081]), ("weblogic", [7001]),
    ("http_server", [80, 443, 8080, 8000, 8888]), ("nginx", [80, 443, 8080]), ("iis", [80, 443]),
    ("openresty", [80, 443]), ("caddy", [80, 443]), ("jetty", [8080]), ("php", [80, 443]),
]


def port_for_product(text: str, open_ports: list[int]) -> int | None:
    """Подбирает порт продукта среди реально открытых портов хоста."""
    low = (text or "").lower()
    for token, ports in PRODUCT_PORTS:
        if token in low:
            for p in ports:
                if p in open_ports:
                    return p
            return None
    return None

# ---------------------------------------------------------------- продуктовые правила
# (regex, продукт, cpe_vendor, cpe_product, извлечение версии)
HEADER_RULES: list[tuple[str, str, str, str, str]] = [
    (r"nginx/?([\d.]+)?", "nginx", "f5", "nginx", "ver"),
    (r"apache/?([\d.]+)?", "Apache HTTP Server", "apache", "http_server", "ver"),
    (r"openresty/?([\d.]+)?", "OpenResty", "openresty", "openresty", "ver"),
    (r"microsoft-iis/?([\d.]+)?", "Microsoft IIS", "microsoft", "internet_information_services", "ver"),
    (r"litespeed", "LiteSpeed", "litespeedtech", "litespeed_web_server", "none"),
    (r"jetty[^\d]*([\d.]+)?", "Jetty", "eclipse", "jetty", "ver"),
    (r"tomcat/?([\d.]+)?", "Apache Tomcat", "apache", "tomcat", "ver"),
    (r"caddy", "Caddy", "caddyserver", "caddy", "none"),
    (r"cloudflare", "Cloudflare (CDN/WAF)", "", "", "none"),
]

XPB_RULES: list[tuple[str, str, str, str]] = [
    (r"php/?([\d.]+)?", "PHP", "php", "php", "ver"),
    (r"asp\.net", "ASP.NET", "microsoft", "asp.net", "none"),
    (r"express", "Express", "expressjs", "express", "none"),
    (r"next\.js", "Next.js", "vercel", "next.js", "none"),
    (r"nuxt", "Nuxt.js", "nuxt", "nuxt", "none"),
    (r"django/?([\d.]+)?", "Django", "djangoproject", "django", "ver"),
    (r"flask/?([\d.]+)?", "Flask", "pallets", "flask", "ver"),
    (r"laravel", "Laravel", "laravel", "laravel", "none"),
    (r"ruby on rails", "Ruby on Rails", "rubyonrails", "rails", "none"),
]

GENERATOR_RULES: list[tuple[str, str, str, str]] = [
    (r"wordpress\s*([\d.]+)?", "WordPress", "wordpress", "wordpress", "ver"),
    (r"joomla!?\s*([\d.]+)?", "Joomla", "joomla", "joomla", "ver"),
    (r"drupal\s*([\d.]+)?", "Drupal", "drupal", "drupal", "ver"),
    (r"1c-bitrix", "1C-Bitrix", "1c-bitrix", "1c-bitrix", "none"),
    (r"typo3", "TYPO3", "typo3", "typo3", "none"),
    (r"magento", "Magento", "magento", "magento", "none"),
    (r"opencart", "OpenCart", "opencart", "opencart", "none"),
    (r"modx", "MODX", "modx", "modx", "none"),
]

COOKIE_RULES: list[tuple[str, str]] = [
    (r"wordpress_", "WordPress"),
    (r"wp-settings", "WordPress"),
    (r"laravel_session", "Laravel"),
    (r"laravel", "Laravel"),
    (r"jsessionid", "Java (JSESSIONID)"),
    (r"phpsessid", "PHP (PHPSESSID)"),
    (r"asp\.net_sessionid", "ASP.NET"),
    (r"bitrix", "1C-Bitrix"),
    (r"csrftoken", "Django"),
    (r"django", "Django"),
    (r"ci_session", "CodeIgniter"),
]

TITLE_RULES: list[tuple[str, str]] = [
    (r"grafana", "Grafana"),
    (r"kibana", "Kibana"),
    (r"phpmyadmin", "phpMyAdmin"),
    (r"jenkins", "Jenkins"),
    (r"gitlab", "GitLab"),
    (r"zabbix", "Zabbix"),
    (r"roundcube", "Roundcube"),
    (r"mikrotik|routeros", "MikroTik RouterOS"),
    (r"webmin", "Webmin"),
    (r"vpn|fortinet|fortigate|pfsense|openvpn", "VPN/шлюз"),
]


def parse_version(text: str, mode: str) -> str:
    if mode != "ver":
        return ""
    m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[\w.\-]*)?)", text)
    return m.group(1) if m else ""


def fingerprint(last: dict) -> list[dict]:
    """
    last: результат collect.http_probe (или его подмножество) + 'port',
          по которому получен ответ.
    """
    found: list[dict] = []

    def add(product: str, vendor: str = "", cpe_product: str = "", version: str = "", evidence: str = ""):
        if not any(o["product"] == product for o in found):
            found.append({"product": product, "vendor": vendor, "cpe_product": cpe_product,
                          "version": version, "evidence": evidence[:200]})

    hdrs = last.get("headers") or {}

    # --- заголовок Server
    server = (hdrs.get("server") or last.get("server") or "").strip()
    if server:
        for rx, product, vendor, cpe_product, mode in HEADER_RULES:
            m = re.search(rx, server.lower())
            if m:
                ver = ""
                if mode == "ver":
                    ver = (m.group(1) if m.groups() else "") or parse_version(server, "ver")
                add(product, vendor, cpe_product, ver, f"Server: {server}")
                for token in re.findall(r"\(([^)]+)\)", server):
                    for rx2, p2, v2, c2, m2 in HEADER_RULES:
                        if p2 in ("nginx", "Apache HTTP Server"):
                            continue
                        mm = re.search(rx2, token.lower())
                        if mm:
                            add(p2, v2, c2, (mm.group(1) if mm.groups() and m2 == "ver" else ""), f"Server: {server}")
                break

    # --- X-Powered-By и прочие X-*
    for hname in ("x-powered-by", "x-generator", "x-aspnet-version", "x-drupal-cache",
                  "x-drupal-dynamic-cache", "x-nginx-cache", "x-runtime", "x-version"):
        if hname in hdrs:
            val = str(hdrs[hname])
            for rx, product, vendor, cpe_product, mode in XPB_RULES:
                m = re.search(rx, val.lower().strip())
                if m:
                    ver = (m.group(1) if m.groups() else "") if mode == "ver" else ""
                    add(product, vendor, cpe_product, ver or (val if hname == "x-aspnet-version" else ""),
                        f"{hname}: {val}")

    # --- заголовки-двойники (X-AspNet-Version и т.п.)
    if hdrs.get("x-aspnet-version"):
        add("ASP.NET", "microsoft", "asp.net", str(hdrs["x-aspnet-version"]), "X-AspNet-Version")

    # --- cookies
    cookies = str(hdrs.get("set-cookie", "")) + str(hdrs.get("cookie", ""))
    for rx, product in COOKIE_RULES:
        if re.search(rx, cookies.lower()):
            add(product, evidence="cookie-маркер")

    # --- meta generator / title
    html = last.get("body_snippet") or last.get("html") or ""
    gen = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if m:
        gen = m.group(1)
    for rx, product, vendor, cpe_product, mode in GENERATOR_RULES:
        src = (gen or "").lower()
        mm = re.search(rx, src)
        if mm:
            ver = (mm.group(1) if mm.groups() else "") if mode == "ver" else ""
            add(product, vendor, cpe_product, ver, f"meta generator: {gen}")

    title = (last.get("title") or "").lower()
    for rx, product in TITLE_RULES:
        if re.search(rx, title):
            add(product, evidence=f"title: {last.get('title','')[:80]}")

    # --- по портам: узнаём сервис
    port = last.get("port")
    if port in PORT_SERVICES:
        svc = PORT_SERVICES[port]
        if svc in ("elasticsearch",):
            add("Elasticsearch", "elastic", "elasticsearch", "", f"порт {port}")
        if svc == "kibana":
            add("Kibana", "elastic", "kibana", "", f"порт {port}")
        if svc == "grafana":
            add("Grafana", "grafana", "grafana", "", f"порт {port}")
        if svc == "jenkins":
            add("Jenkins", "jenkins", "jenkins", "", f"порт {port}")

    return found


def risky_port_findings(ports: list[int]) -> list[dict]:
    out = []
    for p in ports:
        if p in RISKY_PORTS:
            name, why = RISKY_PORTS[p]
            out.append({
                "asset": "", "port": p, "service": PORT_SERVICES.get(p, "?"),
                "product": name, "version": "", "cve_id": None, "cvss": None,
                "severity": "HIGH", "title": name,
                "rationale": why,
                "evidence": {"обнаружение": f"порт {p} доступен из интернета"},
                "priority": "P1", "score": 70.0, "is_risky_port": True,
            })
    return out
