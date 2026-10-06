# -*- coding: utf-8 -*-
""""
Расширение цели до ВСЕЙ инфраструктуры по одному адресу.

Идея: аналитик вводит один адрес (домен компании или IP), инструмент сам находит
всё, что этой организации принадлежит, и передаёт конвейеру сканирования:

  домен → имена (CT-логи + словарь типовых имён + записи NS/MX/SPF/DMARC)
        → IP-адреса (DNS)
        → сети организации (RIPEstat: анонсированные префиксы её AS)
        → адреса в этих сетях (только близкие к уже найденным, с лимитом)

Для IP-цели: обратное имя + сети того же AS.

ВАЖНО про сети AS: они могут содержать чужие адреса (общий хостинг, транзит).
Поэтому такое расширение включается отдельным флагом `estate_asn` (в интерфейсе —
«проверять сети организации»), все найденные так адреса помечаются источником,
и в отчёт выводится предупреждение: подтвердите принадлежность заказчику.
Никаких «ковровых» обходов: лимиты на префиксы и адреса, только адреса рядом
с уже подтверждёнными.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from . import collect, store
from .settings_compat import call_with_settings

# типовые имена поддоменов (по-русски: то, что чаще всего торчит наружу)
WORDS = [
    "www", "mail", "smtp", "imap", "pop", "webmail", "mx", "ns1", "ns2", "dns", "dns1", "dns2",
    "api", "api2", "gateway", "gw", "portal", "lk", "office", "intranet", "extranet", "vpn",
    "remote", "rdp", "ssh", "ftp", "sftp", "files", "cloud", "storage", "backup", "bak",
    "dev", "develop", "test", "tests", "qa", "stage", "staging", "beta", "demo", "sandbox",
    "admin", "panel", "cp", "cpanel", "manage", "monitor", "status", "zabbix", "grafana",
    "kibana", "prometheus", "metrics", "log", "logs", "syslog", "jira", "git", "gitlab",
    "jenkins", "ci", "cd", "docker", "registry", "nexus", "artifactory", "wiki", "confluence",
    "help", "support", "docs", "doc", "shop", "store", "cart", "pay", "payment", "billing",
    "crm", "erp", "1c", "sso", "auth", "login", "id", "oauth", "ldap", "ad", "dc", "dc1",
    "db", "mysql", "postgres", "pgsql", "mssql", "mongo", "redis", "es", "elastic", "kafka",
    "mq", "rabbit", "smtp2", "relay", "mail2", "autodiscover", "autoconfig", "m", "mobile",
    "app", "apps", "web", "web1", "web2", "server", "host", "old", "new", "v2", "test1",
    "prod", "production", "cluster", "node1", "node2", "k8s", "kubernetes", "rancher",
    "edge", "cdn", "static", "assets", "media", "img", "video", "stream", "rtmp",
    "sip", "voip", "pbx", "asterisk", "camera", "nvr", "iot", "printer", "print",
    "router", "switch", "firewall", "fw", "mikrotik", "ubnt", "unifi", "ap", "wifi",
]


def _is_ip(s: str) -> bool:
    return bool(s) and s[0].isdigit() and ":" not in s and all(c.isdigit() or c == "." for c in s)


def dns_wordlist(root: str, limit: int = 120, workers: int = 16, *, settings=None) -> list[str]:
    """Проверяет типовые имена: есть ответ — имя живёт в инфраструктуре заказчика."""
    words = WORDS[:max(10, limit)]
    found: list[str] = []

    def probe(w: str) -> tuple[str, bool]:
        name = f"{w}.{root}"
        try:
            return name, bool(call_with_settings(collect.resolve_ips, name, settings=settings))
        except Exception:
            return name, False

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for f in as_completed([ex.submit(probe, w) for w in words]):
            try:
                name, ok = f.result()
            except Exception:
                continue
            if ok:
                found.append(name)
    return found


def dns_records(root: str, *, settings=None) -> dict[str, list[str]]:
    """NS, MX, TXT (SPF/DMARC/verify) — дают имена почты и сторонних сервисов."""
    out: dict[str, list[str]] = {"NS": [], "MX": [], "TXT": []}
    for rtype in ("NS", "MX", "TXT"):
        try:
            out[rtype] = call_with_settings(collect.dns, root, rtype, settings=settings)
        except Exception:
            pass
    # разворачиваем MX/NS в имена хостов
    hosts: list[str] = []
    for v in out["MX"]:
        v = v.strip().rstrip(".")
        parts = v.split()
        name = parts[-1] if parts else v
        if name and "." in name and name.endswith(root):
            hosts.append(name)
    return {"records": out, "hosts": sorted(set(hosts))}


def spf_include_domains(txt: list[str]) -> list[str]:
    """Из SPF-записей достаём include:… — это почтовые провайдеры и свои же домены."""
    doms: list[str] = []
    for t in txt:
        low = (t or "").lower()
        if "v=spf1" not in low:
            continue
        for part in low.split():
            if part.startswith("include:"):
                doms.append(part.split(":", 1)[1])
            elif part.startswith("a:") or part.startswith("mx:"):
                doms.append(part.split(":", 1)[1])
    return sorted(set(d for d in doms if d))


def asn_prefixes(ip: str, limit: int = 8, *, settings=None) -> list[dict]:
    """Сети (анонсированные префиксы) автономной системы, которой принадлежит адрес."""
    try:
        ripe = call_with_settings(collect.ripe_prefix, ip, settings=settings)
    except Exception:
        return []
    asn = ripe.get("asn") or ""
    if not asn:
        return []
    asn_id = f"AS{asn}"
    data = collect._http(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_id}",
                         ttl=86400 * 7, settings=settings)
    out: list[dict] = []
    for p in (data.get("data", {}) or {}).get("prefixes", [])[:limit * 4]:
        pref = p.get("prefix")
        if pref:
            out.append({"prefix": pref, "asn": asn_id, "holder": ripe.get("holder", "")})
    return out[:limit]


def prefix_ips(prefix: str, near_ip: str, cap: int = 64) -> list[str]:
    """До cap адресов из сети; сначала — из той же /24, что уже подтверждённый адрес."""
    import ipaddress
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except Exception:
        return []
    if net.version != 4 or net.num_addresses > 4096:
        return []
    ips = [str(a) for a in net.hosts()]
    if len(ips) <= cap:
        return [i for i in ips if i != near_ip]
    same24 = [i for i in ips if i.rsplit(".", 1)[0] == near_ip.rsplit(".", 1)[0] and i != near_ip]
    rest = [i for i in ips if i not in same24 and i != near_ip]
    return (same24 + rest)[:cap]


def expand(sid: int, root: str, is_ip: bool, L: dict, log, seed_ips: list | None = None) -> dict:
    """Возвращает дополнительные имена, адреса и связи для конвейера сканирования.

    Ключи результата:
      hosts      — дополнительные имена (поддомены, NS/MX-хосты, SPF-домены)
      sources    — откуда взято имя
      ips        — дополнительные IP с пометкой источника (сети организации)
      warn       — предупреждения для отчёта и журнала
    """
    res: dict = {"hosts": [], "sources": {}, "ips": [], "warn": []}
    settings = L.get("__settings__")
    if not L.get("estate"):
        return res

    # ------------------------------------------------ 1. типовые имена
    if not is_ip:
        limit = int(L.get("estate_words", 120))
        if limit > 0:
            try:
                names = dns_wordlist(root, limit, settings=settings)
            except Exception as e:  # noqa: BLE001
                names = []
                log(sid, f"Словарь имён: сбой ({e})")
            fresh = [n for n in names if n not in res["hosts"]]
            res["hosts"] += fresh
            for n in fresh:
                res["sources"][n] = "типовое имя (словарь)"
            log(sid, f"Словарь типовых имён: найдено {len(fresh)}")

        # -------------------------------------------- 2. записи DNS
        try:
            recs = dns_records(root, settings=settings)
            rec = recs["records"]
            log(sid, "DNS-записи: NS " + str(len(rec["NS"])) + ", MX " + str(len(rec["MX"]))
                       + ", TXT " + str(len(rec["TXT"])))
            for h in recs["hosts"]:
                if h not in res["hosts"] and h != root:
                    res["hosts"].append(h)
                    res["sources"][h] = "почтовый/служебный хост (MX/NS)"
            for d in spf_include_domains(rec["TXT"]):
                # include содержит сторонние сервисы; берём только домены заказчика
                if d.endswith(root) and d not in res["hosts"]:
                    res["hosts"].append(d)
                    res["sources"][d] = "SPF include"
        except Exception as e:  # noqa: BLE001
            log(sid, f"DNS-записи: сбой ({e})")

        max_hosts = int(L.get("estate_max_hosts", 300))
        if len(res["hosts"]) > max_hosts:
            log(sid, f"Лимит имён: оставляем {max_hosts} из {len(res['hosts'])}")
            res["hosts"] = res["hosts"][:max_hosts]
    else:
        # ------------------------------------------------ 2b. IP-цель: обратное имя
        try:
            names = call_with_settings(collect.dns, root, "PTR", settings=settings)
            for n in names:
                n = n.rstrip(".")
                if n and n not in res["hosts"]:
                    res["hosts"].append(n)
                    res["sources"][n] = "обратная запись IP"
            if names:
                log(sid, f"Обратные имена IP: {len(names)}")
        except Exception:
            pass

    # ------------------------------------------------ 3. сети организации (AS)
    if L.get("estate_asn"):
        try:
            asn_seen: set[str] = set()
            extra: list[dict] = []
            for ip in (seed_ips or []):
                for p in asn_prefixes(ip, limit=int(L.get("estate_max_prefixes", 8)),
                                      settings=settings):
                    key = (p["asn"], p["prefix"])
                    if key in asn_seen:
                        continue
                    asn_seen.add(key)
                    for cand in prefix_ips(p["prefix"], ip, cap=int(L.get("estate_prefix_ips", 64))):
                        extra.append({"ip": cand, "meta": {"источник": f"сеть {p['prefix']} ({p['asn']})",
                                                           "провайдер": p.get("holder", ""),
                                                           "рядом_с": ip}})
                    if len(extra) >= int(L.get("estate_max_extra_ips", 128)):
                        break
                if len(extra) >= int(L.get("estate_max_extra_ips", 128)):
                    break
            res["ips"] = extra[:int(L.get("estate_max_extra_ips", 128))]
            if extra:
                res["warn"].append(
                    "Расширение по сетям организации дало "
                    f"{len(res['ips'])} адресов. Сети AS могут содержать чужие адреса — "
                    "подтвердите принадлежность заказчику перед выводами.")
                log(sid, f"Сети организации: добавлено адресов {len(res['ips'])} "
                         f"(из {len(asn_seen)} префиксов) — проверьте принадлежность")
        except Exception as e:  # noqa: BLE001
            log(sid, f"Сети организации: сбой ({e})")

    return res
