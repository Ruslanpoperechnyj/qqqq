"""
Активное сканирование — то, чего не хватало нашему прототипу.

Два движка (оба MIT, статические бинарники, ставятся одной командой):
  * naabu  — сканирование портов/сервисов
  * nuclei — поиск уязвимостей по 13 000+ шаблонам

Правила безопасности по умолчанию (чтобы не уронить чужой сервер):
  rate-limit, ограничение времени, исключение агрессивных категорий шаблонов
  (dos, fuzz, intrusive), ограничение глубины. Всё настраивается через окружение.

Пути к бинарникам задаются переменными:
  ASM_NAABU_BIN, ASM_NUCLEI_BIN, ASM_NUCLEI_TEMPLATES
Если их нет — активный этап просто пропускается (пассивный режим продолжает работать).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Iterable

from .settings import current_settings

NAABU = os.environ.get("ASM_NAABU_BIN", "naabu")
NUCLEI = os.environ.get("ASM_NUCLEI_BIN", "nuclei")
TEMPLATES = os.environ.get("ASM_NUCLEI_TEMPLATES", "")

try:
    from . import engines as _engines
except Exception:  # noqa: BLE001 — активный модуль должен работать и без engines
    _engines = None


def _run(cmd: list[str], *, data: str | None = None, timeout: int = 300, settings=None):
    """Запуск через engines.run, чтобы процесс попал в общий реестр.

    Без этого naabu и nuclei, запущенные отсюда, не убивались бы кнопкой стоп:
    они шли в обход engines.run и в реестр живых процессов не попадали.
    """
    settings = settings if settings is not None else current_settings()
    if _engines is not None:
        return _engines.run(cmd, data=data, timeout=timeout, settings=settings)
    from . import stealth as _stealth
    return subprocess.run(cmd, input=data, capture_output=True, text=True,
                          timeout=timeout,
                          env=_stealth.subprocess_env(os.environ, purpose="inward",
                                                      settings=settings))

# агрессивные категории: по умолчанию не трогаем чужие сервисы
EXCLUDE_TAGS = os.environ.get("ASM_NUCLEI_EXCLUDE_TAGS", "dos,fuzz,intrusive,brute-force")
DEFAULT_TAGS = os.environ.get("ASM_NUCLEI_TAGS", "cve,exposure,misconfiguration,default-logins,takeover,tech")
DEFAULT_SEVERITY = os.environ.get("ASM_NUCLEI_SEVERITY", "critical,high,medium")
def _setting(settings, name: str, default):
    if settings is None:
        settings = current_settings()
    if settings is None:
        return os.environ.get(name, default)
    getter = getattr(settings, "get", None)
    return getter(name, default) if callable(getter) else default


def _rate_default(settings=None) -> int:
    """Скорость по умолчанию.

    Профиль (safe/pentest/full) живёт в engines, и если он доступен, спрашиваем
    его: иначе профиль действовал бы на всё, кроме скорости, — а скорость как
    раз и есть то, чем можно уронить чужой сервис. Без engines (модуль
    рассчитан и на такой запуск) остаётся своё умолчание.
    """
    if _engines is not None:
        try:
            return _engines.rate_for("nuclei", settings=settings)
        except Exception:
            pass
    try:
        configured = _setting(settings, "ASM_NUCLEI_RATE", os.environ.get("ASM_NUCLEI_RATE", ""))
        if configured not in (None, ""):
            return int(float(configured))
        profile = str(_setting(settings, "ASM_PROFILE", os.environ.get("ASM_PROFILE", "safe"))).lower()
        return 80 if profile in ("pentest", "full", "all", "aggressive", "1", "true", "yes", "on") else 25
    except ValueError:
        return 25
TIMEOUT = int(os.environ.get("ASM_ACTIVE_TIMEOUT", "600"))
TOPPORTS = int(os.environ.get("ASM_NAABU_TOP_PORTS", "1000"))


def tool_path(name: str, settings=None) -> str | None:
    """Ищем бинарник: явный путь из env, затем в PATH, затем в ./bin рядом с проектом."""
    if _engines is not None:
        found = _engines.tool_path(name, settings=settings)
        if found:
            return found
    if os.path.isabs(name) and os.path.exists(name):
        return name
    p = shutil.which(name)
    if p:
        return p
    local = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", name)
    if os.path.exists(local):
        return local
    return None


def available(settings=None) -> dict:
    # сначала спрашиваем арсенал (engines): он знает про $ASM_TOOLS_DIR/bin
    try:
        from . import engines as _eng
    except Exception:  # noqa: BLE001
        _eng = None
    naabu_name = str(_setting(settings, "ASM_NAABU_BIN", NAABU) or NAABU)
    nuclei_name = str(_setting(settings, "ASM_NUCLEI_BIN", NUCLEI) or NUCLEI)
    n = (_eng.tool_path("naabu", settings=settings) if _eng else None) or tool_path(naabu_name, settings=settings)
    nc = (_eng.tool_path("nuclei", settings=settings) if _eng else None) or tool_path(nuclei_name, settings=settings)
    configured_templates = _setting(settings, "ASM_NUCLEI_TEMPLATES", TEMPLATES)
    tdir = str(configured_templates or "")
    if not tdir and _eng:
        template_root = getattr(_eng, "_templates_root", None)
        candidate = template_root(settings) if callable(template_root) else getattr(_eng, "TEMPLATES_DIR", "")
        if candidate and os.path.isdir(candidate):
            tdir = candidate
    if not tdir:
        for cand in ("/root/nuclei-templates", os.path.expanduser("~/nuclei-templates"),
                     os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "nuclei-templates")):
            if os.path.isdir(cand):
                tdir = cand
                break
    return {"naabu": n, "nuclei": nc, "templates": tdir,
            "ready": bool(nc and tdir), "ports_ready": bool(n)}


# ------------------------------------------------------------------ naabu
def ports_plausible(ports: list[int], scanned_ports: int) -> tuple[bool, str]:
    """
    Защита от недостоверного результата: если «открыто» почти всё, что сканировали,
    значит мы стоим за прозрачным прокси/NAT или сканер получил SYN-ACK на всё.
    Такие данные хуже, чем их отсутствие: они порождают ложные находки.
    """
    if not ports:
        return True, ""
    share = len(ports) / max(scanned_ports, 1)
    if share >= 0.5:
        return False, (f"недостоверный результат: «открыто» {len(ports)} из {scanned_ports} портов "
                       f"({share:.0%}). Похоже на прозрачный прокси/NAT в канале — "
                       f"результат сканирования портов отброшен")
    return True, ""


def scan_ports(host: str, top_ports: int | None = None, rate: int | None = None,
               timeout: int = 240, *, settings=None) -> list[int]:
    """Открытые порты хоста. naabu сам пробует SYN, при нехватке прав — connect-скан."""
    settings = settings if settings is not None else current_settings()
    exe = tool_path(str(_setting(settings, "ASM_NAABU_BIN", NAABU) or NAABU), settings=settings)
    if not exe:
        return []
    if rate is None:
        rate = _rate_default(settings) if settings is not None else 500
    top_ports = int(_setting(settings, "ASM_NAABU_TOP_PORTS", TOPPORTS) if top_ports is None else top_ports)
    cmd = [exe, "-host", host, "-top-ports", str(top_ports),
           "-silent", "-rate", str(rate), "-timeout", "3000", "-retries", "1"]
    try:
        out = _run(cmd, timeout=timeout, settings=settings)
    except subprocess.TimeoutExpired:
        return []
    ports = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("["):
            tail = line.rsplit(":", 1)[-1]
            if tail.isdigit():
                ports.append(int(tail))
    return sorted(set(ports))


# ------------------------------------------------------------------ nuclei
def scan_templates(urls: Iterable[str], *, tags: str = "", severity: str = "",
                   templates_dir: str = "", rate: int | None = None,
                   timeout: int | None = None, extra: list[str] | None = None,
                   settings=None) -> list[dict]:
    """
    Прогон nuclei по списку URL. Возвращает разобранные находки (JSONL).
    """
    settings = settings if settings is not None else current_settings()
    exe = tool_path(str(_setting(settings, "ASM_NUCLEI_BIN", NUCLEI) or NUCLEI), settings=settings)
    if not exe:
        return []
    urls = [u for u in urls if u]
    if not urls:
        return []
    configured_templates = _setting(settings, "ASM_NUCLEI_TEMPLATES", TEMPLATES)
    template_candidate = templates_dir or str(configured_templates or "")
    if not template_candidate and _engines is not None:
        template_root = getattr(_engines, "_templates_root", None)
        template_candidate = (template_root(settings) if callable(template_root)
                              else str(getattr(_engines, "TEMPLATES_DIR", "") or ""))
    tdir = template_candidate if os.path.isdir(template_candidate) else ""
    cmd = [exe, "-jsonl", "-silent", "-no-color", "-stats=false",
           "-rate-limit", str(rate if rate is not None else _rate_default(settings)),
           "-timeout", "10", "-retries", "1"]
    if settings is None:
        exclude_tags, configured_severity, configured_tags = EXCLUDE_TAGS, DEFAULT_SEVERITY, DEFAULT_TAGS
    else:
        profile, pentest, full = (_engines._profile_values(settings) if _engines is not None
                                  else (str(_setting(settings, "ASM_PROFILE", "safe")).lower(), False, False))
        if _engines is None:
            full = profile in ("full", "all", "aggressive", "1", "true", "yes", "on")
            pentest = full or profile in ("pentest", "pentest-nodos", "attack", "exploit", "2")
            hard_banned = set() if full else ({"dos"} if pentest else
                                                {"default-logins", "credential-stuffing", "brute-force",
                                                 "dos", "fuzz", "intrusive"})
        else:
            hard_banned = set() if full else (
                set(_engines.DOS_TAGS) if pentest else set(_engines.RISKY_TAGS))
        configured_excludes = _setting(settings, "ASM_NUCLEI_EXCLUDE_TAGS", EXCLUDE_TAGS)
        exclude_tags = ",".join(sorted(hard_banned | {t.strip() for t in str(configured_excludes or "").split(",") if t.strip()}))
        configured_severity = _setting(settings, "ASM_NUCLEI_SEVERITY", None)
        if configured_severity is None:
            configured_severity = "" if pentest else "critical,high,medium"
        configured_tags = _setting(settings, "ASM_NUCLEI_TAGS", None)
        if configured_tags is None:
            configured_tags = "" if pentest else "cve,vkev,exposure,misconfig,takeover"
    if exclude_tags:
        cmd += ["-exclude-tags", str(exclude_tags)]
    if severity or configured_severity:
        cmd += ["-severity", severity or str(configured_severity)]
    if tags or configured_tags:
        cmd += ["-tags", tags or str(configured_tags)]
    if tdir:
        cmd += ["-t", tdir]
    if extra:
        cmd += extra
    # URL-ы передаём через stdin (надёжнее длинных командных строк)
    try:
        out = _run(cmd, data="\n".join(urls),
                    timeout=timeout or int(_setting(settings, "ASM_ACTIVE_TIMEOUT", TIMEOUT)),
                    settings=settings)
    except subprocess.TimeoutExpired:
        return []
    findings = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            continue
    return findings


def normalize(f: dict) -> dict:
    """Приводим находку nuclei к нашему виду."""
    info = f.get("info") or {}
    cls = info.get("classification") or {}
    cve_ids = cls.get("cve-id") or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    return {
        "template_id": f.get("template-id") or "",
        "name": info.get("name") or f.get("template-id") or "",
        "severity": (info.get("severity") or "info").lower(),
        "description": info.get("description") or "",
        "remediation": info.get("remediation") or "",
        "tags": info.get("tags") or [],
        "cve_ids": cve_ids,
        "cvss": cls.get("cvss-score"),
        "cwe": cls.get("cwe-id") or [],
        "matched_at": f.get("matched-at") or f.get("host") or "",
        "host": f.get("host") or "",
        "matcher": f.get("matcher-name") or "",
        "extracted": f.get("extracted-results") or [],
        "type": f.get("type") or "",
        "raw": f,
    }


def scan_urls(urls: Iterable[str], **kw) -> list[dict]:
    return [normalize(f) for f in scan_templates(urls, **kw)]
