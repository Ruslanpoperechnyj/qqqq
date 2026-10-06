"""
Черновики проверок Nuclei (замыкание цикла «нашли — научили искать снова»).

Идея простая: каждая находка, у которой есть адрес, превращается в заготовку
шаблона nuclei. Проверяющий запускает её одной командой:

    nuclei -validate -t drafts/scan-19/asm-*.yaml      # проверка синтаксиса
    nuclei -t drafts/scan-19/asm-*.yaml -u https://site.ru

Заготовка не заменяет ручную работу: она фиксирует то, что мы уже видели
(путь, признак в ответе), и позволяет перепроверять это после починки —
без повторного полного аудита.

Шаблоны не содержат ничего опасного: только GET-запрос и проверка признака.
"""
from __future__ import annotations

import hashlib
import os
import re
import zipfile
from io import BytesIO

from .settings import current_settings

DRAFT_DIR = os.environ.get("ASM_DRAFT_DIR", "")


def _draft_dir() -> str:
    settings = current_settings()
    configured = (settings.get("ASM_DRAFT_DIR", DRAFT_DIR) if settings is not None
                  else os.environ.get("ASM_DRAFT_DIR", DRAFT_DIR))
    return str(configured or DRAFT_DIR)

_SAFE = re.compile(r"[^a-z0-9\-]+")

# Ссылки на чужие ресурсы (NVD, MITRE и т.п.) — это справка, а не адрес клиента.
# Никогда не превращаем их в цель проверки: иначе «черновик» пойдёт по чужому сайту.
REF_BLOCK = ("nvd.nist.gov", "cve.org", "cve.mitre.org", "mitre.org", "exploit-db.com",
             "first.org", "cisa.gov", "github.com", "owasp.org", "wikipedia.org",
             "securitylab.ru", "bdu.fstec.ru")


def _slug(text: str, limit: int = 40) -> str:
    s = (text or "").lower()
    table = {"а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ж": "zh", "з": "z",
             "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p",
             "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "c", "ч": "ch",
             "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya"}
    s = "".join(table.get(ch, ch) for ch in s)
    s = _SAFE.sub("-", s).strip("-")
    return s[:limit].strip("-") or "check"


def _host_of(value: str) -> str:
    m = re.match(r"^(?:https?://)?([^/:\s]+)", (value or "").strip())
    return (m.group(1) if m else "").lower()


def _asset_host(finding: dict) -> str:
    return _host_of(str(finding.get("asset") or "").split(" (")[0])


def _allowed(url: str, finding: dict) -> bool:
    """URL годится, только если ведёт на сам проверяемый актив, а не на справочник."""
    host = _host_of(url)
    if not host or any(host == b or host.endswith("." + b) for b in REF_BLOCK):
        return False
    own = _asset_host(finding)
    return bool(own) and (host == own or host.endswith("." + own))


def _url_of(finding: dict) -> str:
    ev = finding.get("evidence") or {}
    for key in ("адрес", "url", "URL", "ссылка", "путь"):
        v = str(ev.get(key) or "")
        if v.startswith("http") and _allowed(v, finding):
            return v
    asset = str(finding.get("asset") or "")
    if asset.startswith("http") and _allowed(asset, finding):
        return asset
    return ""


def _looks_web(addr: str) -> bool:
    _, _, port = (addr or "").partition(":")
    return port in ("", "80", "443", "8080", "8443", "8000")


def _recheck_command(finding: dict) -> dict | None:
    """Если находка снята шаблоном nuclei — даём готовую команду повторной проверки."""
    ev = finding.get("evidence") or {}
    tpl = str(ev.get("шаблон") or ev.get("template") or "").strip()
    addr = str(ev.get("адрес") or finding.get("asset") or "").strip()
    if not tpl or not addr:
        return None
    host = _host_of(addr)
    if not host or any(host == b or host.endswith("." + b) for b in REF_BLOCK):
        return None
    if own := _asset_host(finding):
        if host != own:
            return None
    cats = str(ev.get("категории") or "")
    network = "network" in cats or "ssh" in cats or not _looks_web(addr)
    target = addr if addr.startswith("http") else (addr if network else "https://" + addr)
    tid = "recheck-" + _slug(str(finding.get("title")), 30)
    text = (f"#!/bin/sh\n"
            f"# Повторная проверка находки: {finding.get('title')}\n"
            f"# Актив: {addr}\n"
            f"# Запускать только по авторизованной инфраструктуре заказчика.\n"
            f"nuclei -id {tpl} -u {target} -tags cve,ssh,misconfig,network -severity critical,high,medium "
            f"-silent -no-interactsh -disable-update-check\n")
    return {"kind": "command", "id": tid, "filename": f"{tid}.sh", "url": addr,
            "title": str(finding.get("title") or ""), "severity": str(finding.get("severity") or ""),
            "yaml": text, "finding_id": finding.get("id"), "template": tpl}


def _path_of(url: str) -> str:
    m = re.match(r"https?://[^/]+(/.*)?$", url or "")
    path = (m.group(1) if m and m.group(1) else "/")
    return path or "/"


def draft_for(finding: dict) -> dict | None:
    """Заготовка шаблона nuclei по одной находке. Нет адреса — нет заготовки."""
    url = _url_of(finding)
    if not url:
        return _recheck_command(finding)
    title = str(finding.get("title") or "проверка").strip()
    sev = str(finding.get("severity") or "medium").lower()
    sev = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
           "info": "info"}.get(sev, "medium")
    path = _path_of(url)
    tid = "asm-" + _slug(title, 36) + "-" + hashlib.sha1(url.encode("utf-8")).hexdigest()[:6]
    words = []
    ev = finding.get("evidence") or {}
    for key in ("признак", "найдено", "заголовок", "заголовок ответа", "фрагмент"):
        v = str(ev.get(key) or "")
        if v and len(v) < 90:
            words.append(v)
    status = None
    try:
        status = int(str(ev.get("код ответа") or ev.get("status") or "").strip())
    except (TypeError, ValueError):
        status = None
    matchers = []
    if status:
        matchers.append(f"""      - type: status
        status:
          - {status}""")
    if words:
        block = "\n".join(f'          - "{w.replace(chr(34), "")}"' for w in words[:3])
        matchers.append(f"""      - type: word
        part: body
        words:
{block}
        condition: or""")
    if not matchers:      # без признака проверяем хотя бы доступность адреса
        matchers.append("""      - type: status
        status:
          - 200""")
    matchers_yaml = "\n".join(matchers)
    topic = str(ev.get("тип проверки") or ev.get("источник") or "находка ASM")
    cve = str(finding.get("cve_id") or "")
    refs = [url]
    if cve:
        refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
    refs_yaml = "\n".join(f"    - {r}" for r in refs[:4])
    yaml = f"""id: {tid}

info:
  name: "{title[:120]}"
  author: asm-audit
  severity: {sev}
  description: |
    Заготовка проверки по находке аудита внешнего периметра.
    Что нашли: {title[:200]}
    Где: {url}
    Как определили: {topic}
    Это черновик: подтвердите признак вручную и уточните matcher перед боевым запуском.
  reference:
{refs_yaml}
  tags: asm,audit,draft

http:
  - method: GET
    path:
      - "{path}"
    matchers-condition: and
    matchers:
{matchers_yaml}
"""
    return {"kind": "template", "id": tid, "filename": f"{tid}.yaml", "url": url, "severity": sev,
            "title": title, "yaml": yaml, "finding_id": finding.get("id")}


def drafts_for_scan(findings: list[dict], limit: int = 60,
                    kinds: tuple[str, ...] = ("template", "command")) -> list[dict]:
    out, seen = [], set()
    for f in findings:
        if len(out) >= limit:
            break
        if str(f.get("status") or "open") not in ("open", "confirmed"):
            continue
        d = draft_for(f)
        if d and d["id"] not in seen and d.get("kind", "template") in kinds:
            seen.add(d["id"])
            out.append(d)
    return out


def write_drafts(scan_id: int, drafts: list[dict]) -> str:
    """Сохраняем заготовки на диск и возвращаем каталог."""
    base = _draft_dir() or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                         "reports", "drafts")
    folder = os.path.join(base, f"scan-{scan_id}")
    os.makedirs(folder, exist_ok=True)
    for d in drafts:
        fp = os.path.join(folder, d["filename"])
        with open(fp, "w", encoding="utf-8") as fh:
            fh.write(d["yaml"])
        if d.get("kind") == "command":
            os.chmod(fp, 0o755)
    with open(os.path.join(folder, "КАК-ЗАПУСКАТЬ.txt"), "w", encoding="utf-8") as fh:
        fh.write("Черновики проверок, снятые с находок анализа.\n"
                 "\n"
                 "1) *.yaml — заготовки шаблонов nuclei по найденным адресам. Проверить синтаксис:\n"
                 "     nuclei -validate -t *.yaml\n"
                 "   Прогнать по своему сайту:\n"
                 "     nuclei -t *.yaml -u https://ваш-сайт -silent\n"
                 "\n"
                 "2) recheck-*.sh — готовые команды повторной проверки тем же шаблоном, которым\n"
                 "   находка была снята впервые. Запускать только по авторизованной инфраструктуре.\n"
                 "\n"
                 "3) После починки запустите всё снова: находок быть не должно.\n")
    return folder


def zip_bytes(scan_id: int, drafts: list[dict]) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for d in drafts:
            z.writestr(f"scan-{scan_id}/{d['filename']}", d["yaml"])
        z.writestr(f"scan-{scan_id}/КАК-ЗАПУСКАТЬ.txt",
                   "Черновики проверок Nuclei. Синтаксис: nuclei -validate -t *.yaml")
    return buf.getvalue()
