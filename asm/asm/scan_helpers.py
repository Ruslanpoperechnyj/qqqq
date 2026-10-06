# -*- coding: utf-8 -*-
"""Мелкие помощники конвейера: то, что нужно сразу нескольким этапам.

Здесь лежат разбор адресов и CPE, отсев «шумных» имён, сравнение прогонов и
запись в журнал. Всё это нужно и `scan.py`, и `stages.py`; держать это в одном
из них нельзя — вышел бы замкнутый импорт.
"""
from __future__ import annotations

import ipaddress
import re

from . import identify, store


NOISE = re.compile(r"^(www\d*|cdn\d*|static\d*|assets?\d*|img\d*|mail\d*|smtp\d*|ns\d*|"
                   r"dns\d*|mx\d*|autodiscover|_dmarc|_.*|[0-9a-f]{16,})", re.I)



HOT_WORDS = ("dev", "test", "stage", "staging", "qa", "admin", "panel", "vpn", "api", "old",
             "backup", "beta", "demo", "1c", "sso", "db", "git", "jenkins", "mail", "portal",
             "lk", "office", "remote", "rdp", "ftp", "monitor", "grafana", "kibana", "cloud")




def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False




def _interesting(sub: str, root: str) -> int:
    name = sub.replace("." + root, "")
    for w in HOT_WORDS:
        if name.startswith(w) or f"-{w}" in name or f".{w}" in name:
            return 0
    return 1 if name.count(".") <= 1 else 2




DISPLAY_NAMES = {
    ("apache", "http_server"): "Apache HTTP Server",
    ("openbsd", "openssh"): "OpenSSH",
    ("ntp", "ntp"): "NTP",
    ("canonical", "ubuntu_linux"): "Ubuntu Linux",
    ("microsoft", "internet_information_services"): "Microsoft IIS",
    ("f5", "nginx"): "nginx",
    ("php", "php"): "PHP",
    ("apache", "tomcat"): "Apache Tomcat",
    ("wordpress", "wordpress"): "WordPress",
    ("elastic", "elasticsearch"): "Elasticsearch",
    ("openresty", "openresty"): "OpenResty",
}


# Как называть продукт в отчёте: (vendor, product) → человекочитаемое имя.
# Нужен только разбору CPE, поэтому живёт рядом с ним.
def _pretty_cpe(uri_or_cpe23: str) -> tuple[str, str, str]:
    """'cpe:/a:apache:http_server:2.4.7' -> ('Apache HTTP Server', 'apache', 'http_server')"""
    s = uri_or_cpe23
    if s.startswith("cpe:/"):
        parts = s[5:].split(":")
        vendor, product = (parts + ["", ""])[1], (parts + ["", ""])[2]
    else:
        parts = s.split(":")
        vendor, product = parts[3], parts[4]
    disp = DISPLAY_NAMES.get((vendor, product))
    if not disp:
        disp = product.replace("_", " ") if product and product != vendor else \
            f"{vendor} {product}".replace("_", " ").strip()
    return disp, vendor, product




def cpe_version(uri: str) -> str:
    """Версия из CPE-URI Shodan ('cpe:/a:apache:http_server:2.4.7' -> '2.4.7')."""
    if not uri or not uri.startswith("cpe:/"):
        return ""
    parts = uri[5:].split(":")
    return parts[3] if len(parts) > 3 else ""



def diff_scans(prev: dict | None, cur: dict) -> dict:
    if not prev:
        return {"first_scan": True}
    prev_a = {(a["kind"], a["value"]) for a in prev["assets"]}
    cur_a = {(a["kind"], a["value"]) for a in cur["assets"]}
    prev_f = {(f.get("cve_id") or f.get("title"), f.get("asset"), f.get("ip"), f.get("port"))
              for f in prev["findings"]}
    cur_f = {(f.get("cve_id") or f.get("title"), f.get("asset"), f.get("ip"), f.get("port"))
             for f in cur["findings"]}
    return {
        "first_scan": False,
        "previous_scan_id": prev["scan_id"],
        "new_assets": sorted(f"{k}:{v}" for k, v in (cur_a - prev_a))[:200],
        "removed_assets": sorted(f"{k}:{v}" for k, v in (prev_a - cur_a))[:200],
        "new_findings": [{"what": f[0], "asset": f[1] or f[2], "port": f[3]}
                         for f in sorted(cur_f - prev_f, key=str)][:200],
        "fixed_findings": [{"what": f[0], "asset": f[1] or f[2], "port": f[3]}
                           for f in sorted(prev_f - cur_f, key=str)][:200],
    }




# Как исправить конкретную проблему TLS: подпись из отчёта testssl.sh
# сулит текст. Живёт рядом с этапом, который её использует.
TLS_FIX = {
    "SSLv2": "Отключить SSLv2 (устаревший протокол с известными атаками).",
    "SSLv3": "Отключить SSLv3 (POODLE). Оставить TLS 1.2 и TLS 1.3.",
    "TLS1": "Отключить TLS 1.0: включить только TLS 1.2/1.3 (браузеры и платежные системы этого и требуют).",
    "TLS1_1": "Отключить TLS 1.1: включить только TLS 1.2/1.3.",
    "TLS1_2": "Проверить конфигурацию TLS 1.2: набор шифров и порядок предпочтения сервера.",
    "TLS1_3": "Включить TLS 1.3 — это самая современная версия протокола.",
    "pre_128cipher": "Убрать шифры короче 128 бит и исправить ошибку ограничения 128 шифров (обновить библиотеку TLS).",
    "security_headers": "Добавить заголовки безопасности: HSTS, X-Content-Type-Options, X-Frame-Options, CSP.",
    "HSTS": "Включить HSTS (Strict-Transport-Security) — браузеры перестанут допускать http-переходы.",
    "cookie": "Пометить cookie флагами Secure и HttpOnly.",
    "cert_expirationStatus": "Продлить или заменить сертификат — он истёк или истекает.",
    "cert_trust": "Устранить проблему доверия к сертификату: неполная цепочка или неизвестный издатель.",
    "cert_chain_of_trust": "Настроить сервер отдавать полную цепочку сертификатов (частая причина «недоверенного» сайта).",
    "cert_commonName": "Выпустить сертификат на правильное имя (несовпадение имени ломает доверие).",
    "OCSP_stapling": "Включить OCSP stapling — ускоряет проверку сертификата и уменьшает утечку данных о посещениях.",
    "cert_revocation": "Проверить отзыв сертификата (CRL/OCSP).",
    "tls_truncated_hmac": "Включить truncated HMAC или сменить набор шифров (атака Lucky13).",
    "RC4": "Убрать шифры RC4 — они считаются сломанными.",
    "cipherlist_3DES_IDEA": "Убрать 3DES/IDEA из списка шифров.",
    "cipher_order": "Задать порядок предпочтения шифров на сервере.",
    "FS": "Включить шифры с прямой секретностью (ECDHE) — важно для защиты прошлого трафика.",
}



def _exposure_rank(port) -> int:
    if not port:
        return 0
    if port in identify.RISKY_PORTS:
        return 3
    if port in (443, 8443, 9443, 80, 8080, 8000, 8888, 9090):
        return 2
    return 1



def _log(sid: int, msg: str) -> None:
    """Строка в журнал скана. Живёт здесь, потому что пишут в журнал этапы."""
    store.scan_log(sid, msg)




# ------------------------------------------------------------------ основной прогон

def merge_engine_findings(rows: list[dict]) -> tuple[list[dict], int]:
    """Склеить находки движков, найденные несколькими сканерами одновременно.

    trivy и osv-scanner проверяют одни и те же lock-файлы и выдают одну и ту же
    CVE по одному и тому же пакету. Без склейки в отчёте получаются две строки
    об одной проблеме — а заказчик читает расхождение в количестве находок как
    невнимательность.

    Совпадение не выбрасывается молча: факт, что проблему независимо подтвердили
    два сканера, повышает доверие к ней, поэтому второй источник сохраняется
    в доказательствах под ключом «подтверждено также».

    Возвращает (склеенный список, сколько дублей убрано).
    """
    def key(ef: dict) -> tuple:
        ev = ef.get("evidence") or {}
        ident = ef.get("cve_id") or ef.get("template_id") or ""
        if ident:
            return (str(ident).upper(),
                    str(ev.get("пакет") or "").casefold(),
                    str(ef.get("asset") or "").casefold())
        # без идентификатора склеиваем только полное совпадение заголовка
        return ("", str(ef.get("title") or "").casefold(), "")

    merged: dict[tuple, dict] = {}
    order: list[tuple] = []
    for ef in rows:
        k = key(ef)
        if k in merged:
            kept_ev = merged[k].setdefault("evidence", {})
            corrob = kept_ev.setdefault("подтверждено также", [])
            src = str((ef.get("evidence") or {}).get("тип проверки") or "").strip()
            if src and src not in corrob:
                corrob.append(src)
            continue
        merged[k] = dict(ef)
        # копия поверхностная, а evidence — вложенный словарь: без отдельной
        # копии правка «подтверждено также» портила бы исходную строку вызывающего
        merged[k]["evidence"] = dict(ef.get("evidence") or {})
        order.append(k)
    return [merged[k] for k in order], len(rows) - len(order)
