# -*- coding: utf-8 -*-
"""Стадии конвейера сканирования, вынесенные из scan.py.

Здесь лежат этапы, которые раньше были внутри `_run` одной простынёй на
полторы тысячи строк. Перенос механический: тело каждого этапа перенесено
дословно и сверено сравнением дерева разбора, а не «на глаз». Поэтому
разделение не меняло поведение — и именно поэтому его можно было делать
постепенно, по одному этапу.

Как устроено:

* всё, что этап читает, приходит **параметрами** — свободных имён внутри нет;
* что этап переприсваивает и что нужно дальше — **возвращается** наружу;
* имена, которые к моменту этапа могут быть не привязаны (например
  `sensitive`, когда обход ссылок не запускался), передаются **пустым
  значением**: ровно так же вёл себя прежний `except NameError` вокруг
  чтения этого имени;
* контейнеры (`findings`, `assets`, `engine_findings`) передаются как есть:
  этапы их дописывают, а не заменяют.

Порядок этапов — тот же, что был в `_run`, и вызываются они оттуда же.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import (active, ai, collect, cve, estate, identify, notify, remediate, score, sources, store)
from .scan_helpers import (NOISE, TLS_FIX, _exposure_rank, _interesting, _is_ip, _log,
                           _pretty_cpe, cpe_version, diff_scans, merge_engine_findings)


def _operation_settings(L):
    return L.get("__settings__") if isinstance(L, dict) else None


def _setting(L, name: str, default):
    settings = _operation_settings(L)
    if settings is None:
        return default
    getter = getattr(settings, "get", None)
    return getter(name, default) if callable(getter) else default


def _call_with_settings(fn, *args, settings=None, **kwargs):
    """Pass the operation snapshot when supported, retaining legacy plugin calls."""
    if settings is None:
        return fn(*args, **kwargs)
    try:
        parameters = inspect.signature(fn).parameters.values()
        accepts_settings = any(
            item.name == "settings" or item.kind is inspect.Parameter.VAR_KEYWORD
            for item in parameters
        )
    except (TypeError, ValueError):
        accepts_settings = True
    if accepts_settings:
        kwargs["settings"] = settings
    return fn(*args, **kwargs)


try:                                      # арсенал может отсутствовать
    from . import engines
except Exception:                         # noqa: BLE001
    engines = None                        # type: ignore


def stage_secrets_code(L, engine_counts, engine_findings, engines_status, scan_id, tgt, sensitive=()):
    # --------------------- 5д. Секреты в открытых файлах, код и образы заказчика
    # Идея: то, что нельзя увидеть снаружи, но что клиент отдал сам (репозиторий, каталог,
    # образ контейнера), проверяется бесплатными движками gitleaks и trivy — без правок
    # на объекте: только чтение копии.
    if engines and L.get("engines"):
        import shutil as _shutil
        import tempfile as _tempfile

        def _sev_upper(v: str) -> str:
            return (v or "").strip().upper() or "MEDIUM"

        mat: dict = {}
        try:
            mat = store.target_materials(tgt["id"])
        except Exception:
            mat = {}
        code_path = str(L.get("code_path") or mat.get("code_path") or "").strip()
        code_repo = str(L.get("code_repo") or mat.get("repo") or "").strip()
        image = str(L.get("image") or mat.get("image") or "").strip()

        sec_total = 0          # секреты (gitleaks): открытые файлы + код клиента
        pkg_total = 0          # уязвимые пакеты (trivy): код + образ
        pkg_more = 0           # сколько отложили, чтобы отчёт не распух
        code_work = ""

        # (1) Секреты в файлах, которые не должны быть открыты, но нашлись в обходе и архивах
        cands: list[dict] = []
        try:
            cands = [c for c in sensitive if isinstance(c, dict)]
        except NameError:
            cands = []
        if cands and engines_status.get("gitleaks", {}).get("installed"):
            limit_urls = int(os.environ.get("ASM_SECRET_URLS", "6"))
            work = _tempfile.mkdtemp(prefix="asm-open-")
            url_of: dict[str, str] = {}
            for i, c in enumerate(cands[:limit_urls]):
                u = str(c.get("url") or "")
                status, body = engines.fetch_text(u, limit=int(os.environ.get("ASM_SECRET_BYTES", "65536")))
                if status == 200 and body.strip():
                    fname = os.path.join(work, f"open{i:02d}.txt")
                    try:
                        with open(fname, "w", encoding="utf-8") as fh:
                            fh.write(body)
                        url_of[fname] = u
                    except OSError:
                        pass
            if url_of:
                try:
                    leaks = engines.gitleaks_dir(work, timeout=int(os.environ.get("ASM_GITLEAKS_TIMEOUT", "180")))
                except Exception as e:  # noqa: BLE001
                    leaks = []
                    _log(scan_id, f"  gitleaks (открытые файлы): сбой ({str(e)[:110]})")
                for lk in leaks:
                    sec_total += 1
                    where = url_of.get(str(lk.get("file") or ""), str(lk.get("file") or ""))
                    engine_findings.append({
                        "asset": where, "severity": "CRITICAL", "source_kind": "secret",
                        "template_id": f"gitleaks-{lk.get('rule') or 'secret'}",
                        "title": f"В открытом доступе файл с секретом ({lk.get('rule') or 'учётные данные'}): {where[:90]}",
                        "fix": "Немедленно закрыть файл от внешнего доступа (403/удалить), затем отозвать "
                               "и заменить найденный ключ или пароль — он уже мог попасть в чужие руки.",
                        "evidence": {"тип проверки": "gitleaks по прочитанному открытому файлу",
                                     "адрес": where, "правило": lk.get("rule"),
                                     "фрагмент": lk.get("фрагмент"), "файл-источник": lk.get("file"),
                                     "важно": "файл действительно был прочитан — это подтверждённый доступ, а не догадка"},
                    })
                if leaks:
                    _log(scan_id, f"gitleaks: в открытых файлах найдено секретов {len(leaks)} "
                                  f"(прочитано адресов: {len(url_of)})")
            _shutil.rmtree(work, ignore_errors=True)

        # (2) Материалы заказчика: каталог кода или git-репозиторий (+ образ контейнера)
        if (code_path or code_repo) and not code_path and code_repo:
            code_work = _tempfile.mkdtemp(prefix="asm-repo-")
            dest = os.path.join(code_work, "repo")
            code_path = dest if engines.clone_repo(code_repo, dest,
                                                   timeout=int(os.environ.get("ASM_CODE_TIMEOUT", "300"))) else ""
            if code_path:
                _log(scan_id, f"Код заказчика: получена копия репозитория {code_repo} (только чтение)")
            else:
                _log(scan_id, f"Код заказчика: репозиторий {code_repo} не удалось скопировать")
                code_work = ""

        if code_path and os.path.isdir(code_path):
            store.scan_progress(scan_id, "6/10 — код заказчика: секреты и уязвимые пакеты", 60)

            def _rel_code(p_: str) -> str:
                """Имя файла для отчёта. Путь на машине аудитора (временный каталог копии
                репозитория) заказчику не нужен и только мешает читать отчёт."""
                p_ = (p_ or "").replace(chr(92), "/")
                # сначала более длинный префикс (сам каталог кода), иначе от пути останется
                # служебное имя копии: «repo/app/...» вместо «app/...»
                for prefix in (code_path, code_work):
                    if prefix:
                        pref = str(prefix).replace(chr(92), "/").rstrip("/")
                        if p_ == pref:
                            return ""
                        if p_.startswith(pref + "/"):
                            p_ = p_[len(pref) + 1:]
                if p_.startswith("/"):
                    p_ = os.path.basename(p_)
                return p_
            try:
                leaks = engines.gitleaks_dir(code_path, timeout=int(os.environ.get("ASM_GITLEAKS_TIMEOUT", "300")))
            except Exception as e:  # noqa: BLE001
                leaks = []
                _log(scan_id, f"  gitleaks (код): сбой ({str(e)[:110]})")
            for lk in leaks[:200]:
                sec_total += 1
                engine_findings.append({
                    "asset": f"код: {os.path.basename(code_path)}", "severity": "HIGH",
                    "source_kind": "secret", "template_id": f"gitleaks-{lk.get('rule') or 'secret'}",
                    "title": f"Секрет ({lk.get('rule') or 'учётные данные'}) в файле кода "
                             f"{(lk.get('file') or '').replace(code_path + os.sep, '')}:{lk.get('line')}",
                    "fix": "Отозвать и заменить найденный ключ, убрать его из репозитория и хранить в "
                           "менеджере секретов или переменных окружения.",
                    "evidence": {"тип проверки": "gitleaks по коду заказчика",
                                 "файл": (lk.get("file") or "").replace(code_path + os.sep, ""),
                                 "строка": lk.get("line"), "правило": lk.get("rule"),
                                 "фрагмент": lk.get("фрагмент"),
                                 "источник": "репозиторий/каталог, переданный заказчиком"},
                })
            if leaks:
                _log(scan_id, f"gitleaks: секретов в коде {len(leaks)}")

            # TruffleHog: второй, независимый поиск секретов (другие правила и детекторы).
            # Проверка «живой ли ключ» выключена: она отправляет найденный ключ сервису-владельцу.
            try:
                th = engines.trufflehog_dir(code_path,
                                            timeout=int(os.environ.get("ASM_TRUFFLEHOG_TIMEOUT", "600")))
            except Exception as e:  # noqa: BLE001
                th = []
                _log(scan_id, f"  trufflehog: сбой ({str(e)[:110]})")
            for t_ in th[:100]:
                sec_total += 1
                engine_findings.append({
                    "asset": f"код: {os.path.basename(code_path)}", "severity": "CRITICAL",
                    "source_kind": "secret", "template_id": f"trufflehog-{t_.get('detector') or 'secret'}",
                    "title": f"Секрет ({t_.get('detector') or 'ключ'}) в "
                             f"{(t_.get('file') or '').replace(code_path + os.sep, '')}:{t_.get('line')}",
                    "fix": "Отозвать и заменить найденный ключ, удалить его из репозитория и хранить "
                           "в менеджере секретов. Проверить, кто и когда к нему обращался.",
                    "evidence": {"тип проверки": "trufflehog (поиск секретов)",
                                 "файл": (t_.get("file") or "").replace(code_path + os.sep, ""),
                                 "строка": t_.get("line"), "тип секрета": t_.get("detector"),
                                 "подтверждён проверкой": "да" if t_.get("verified") else "нет (проверка выключена)",
                                 "фрагмент": t_.get("фрагмент"),
                                 "источник": "материалы заказчика (код)"},
                })
            if th:
                _log(scan_id, f"trufflehog: секретов в коде {len(th)} (второй независимый поиск)")

            # Semgrep: опасные конструкции в самом коде (SAST) по бесплатным правилам сообщества
            try:
                sg = engines.semgrep_scan(code_path, timeout=int(os.environ.get("ASM_SEMGREP_TIMEOUT", "900")))
            except Exception as e:  # noqa: BLE001
                sg = []
                _log(scan_id, f"  semgrep: сбой ({str(e)[:110]})")
            sast_total = 0
            sast_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sg = sorted(sg, key=lambda x: sast_rank.get(_sev_upper(x.get("severity")), 9))
            for r_ in sg[:int(os.environ.get("ASM_CODE_SAST", "60"))]:
                sast_total += 1
                engine_findings.append({
                    "asset": f"код: {_rel_code(r_.get('file')) or 'репозиторий'}",
                    "severity": _sev_upper(r_.get("severity")), "source_kind": "sast",
                    "template_id": f"semgrep-{str(r_.get('id') or '').split('.')[-1]}",
                    "title": f"Опасное место в коде: {str(r_.get('id') or '').split('.')[-1]} "
                             f"({_rel_code(r_.get('file'))}:{r_.get('line')})",
                    "fix": "Исправить по описанию правила (приведено ниже). Если код не используется — удалить; "
                           "если используется — переписать безопасно и закрыть это правило тестом.",
                    "evidence": {"тип проверки": "semgrep (анализ исходного кода, бесплатные правила сообщества)",
                                 "правило": r_.get("правило") or r_.get("id"),
                                 "файл": (r_.get("file") or "").replace(code_path + os.sep, ""),
                                 "строка": r_.get("line"), "что нашёл": r_.get("message"),
                                 "CWE": r_.get("cwe") or "не указан",
                                 "источник": "материалы заказчика (код)"},
                })
            if sg:
                _log(scan_id, f"semgrep: опасных мест в коде {len(sg)} "
                              f"(в отчёт вошли {sast_total}, остальные — в отчёте semgrep)")
            if engines.LAST_ERRORS.get("semgrep"):
                _log(scan_id, f"  semgrep: {engines.LAST_ERRORS['semgrep']}")

            # OSV-Scanner: уязвимые зависимости по бесплатной базе OSV.dev (независимо от trivy)
            try:
                osv_rows = engines.osv_scan(code_path, timeout=int(os.environ.get("ASM_OSV_TIMEOUT", "600")))
            except Exception as e:  # noqa: BLE001
                osv_rows = []
                _log(scan_id, f"  osv-scanner: сбой ({str(e)[:110]})")
            osv_total = 0
            for o_ in osv_rows[:int(os.environ.get("ASM_OSV_VULNS", "40"))]:
                osv_total += 1
                fixed = o_.get("fixed") or ""
                engine_findings.append({
                    "asset": f"код: {_rel_code(o_.get('file')) or 'репозиторий'}",
                    "severity": _sev_upper(o_.get("severity")), "source_kind": "deps",
                    "template_id": f"osv-{o_.get('id')}", "cve_id": o_.get("id"),
                    "title": f"{o_.get('package')} {o_.get('version')}: {o_.get('id')} "
                             f"{(o_.get('summary') or '')[:110]}".strip(),
                    "fix": (f"Обновить {o_.get('package')} до {fixed} (исправление уже выпущено)."
                            if fixed else
                            f"Обновить {o_.get('package')} до последней версии: исправления на момент "
                            f"проверки нет, следить за {o_.get('id')}."),
                    "evidence": {"тип проверки": "OSV-Scanner (база OSV.dev, Google)",
                                 "пакет": o_.get("package"), "установлено": o_.get("version"),
                                 "исправлено в": fixed or "исправления нет",
                                 "файл": o_.get("file"), "экосистема": o_.get("ecosystem"),
                                 "источник": "материалы заказчика (зависимости)"},
                })
            if osv_rows:
                _log(scan_id, f"osv-scanner: уязвимых зависимостей {len(osv_rows)} "
                              f"(независимая проверка от trivy)")

            # Trivy config: ошибки конфигурации развёртывания (Dockerfile, k8s, terraform)
            try:
                iac = engines.trivy_config(code_path, timeout=int(os.environ.get("ASM_TRIVY_TIMEOUT", "600")))
            except Exception as e:  # noqa: BLE001
                iac = []
                _log(scan_id, f"  trivy config: сбой ({str(e)[:110]})")
            for i_ in iac[:int(os.environ.get("ASM_CODE_IAC", "40"))]:
                engine_findings.append({
                    "asset": f"развёртывание: {i_.get('target')}", "severity": _sev_upper(i_.get("severity")),
                    "source_kind": "iac", "template_id": f"trivy-config-{i_.get('id')}",
                    "title": f"Ошибка конфигурации развёртывания: {i_.get('title') or i_.get('id')}",
                    "fix": i_.get("как исправить") or "Исправить конфигурацию по рекомендации проверки.",
                    "evidence": {"тип проверки": "trivy config (проверка конфигурации развёртывания)",
                                 "файл": i_.get("target"), "проверка": i_.get("id"),
                                 "строка": i_.get("строка"), "описание": i_.get("описание"),
                                 "источник": "материалы заказчика (файлы развёртывания)"},
                })
            if iac:
                _log(scan_id, f"trivy config: ошибок конфигурации {len(iac)}")

            try:
                pkgs = engines.trivy_fs(code_path, timeout=int(os.environ.get("ASM_TRIVY_TIMEOUT", "600")))
            except Exception as e:  # noqa: BLE001
                pkgs = []
                _log(scan_id, f"  trivy (код): сбой ({str(e)[:110]})")
            sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            pkgs = sorted([p for p in pkgs if p.get("kind") == "vuln"],
                          key=lambda p: sev_rank.get(_sev_upper(p.get("severity")), 9))
            for pv in pkgs[:int(os.environ.get("ASM_CODE_VULNS", "40"))]:
                pkg_total += 1
                fixed = pv.get("fixed") or ""
                engine_findings.append({
                    "asset": f"код: {_rel_code(pv.get('target')) or 'репозиторий'}",
                    "severity": _sev_upper(pv.get("severity")), "source_kind": "code",
                    "template_id": f"trivy-{pv.get('id')}", "cve_id": pv.get("id"),
                    "title": f"{pv.get('package')} {pv.get('installed')}: {pv.get('id')} "
                             f"{(pv.get('title') or '')[:100]}".strip(),
                    "fix": (f"Обновить {pv.get('package')} до {fixed} — исправление уже вышло."
                            if fixed else
                            f"Обновить {pv.get('package')} до последней версии; исправления на момент "
                            f"проверки ещё нет — включить слежение за {pv.get('id')}."),
                    "evidence": {"тип проверки": "trivy (база уязвимостей пакетов)",
                                 "пакет": pv.get("package"), "установлено": pv.get("installed"),
                                 "исправлено в": fixed or "исправления нет",
                                 "источник": "код/каталог заказчика", "файл": pv.get("target")},
                })
            pkg_more += max(0, len(pkgs) - int(os.environ.get("ASM_CODE_VULNS", "40")))
            if pkgs:
                _log(scan_id, f"trivy: уязвимых пакетов в коде {len(pkgs)}")
            if code_work:
                _shutil.rmtree(code_work, ignore_errors=True)
            engine_counts["gitleaks"] = sec_total
            engine_counts["trivy"] = pkg_total

        # (3) Образ контейнера заказчика
        if image and engines_status.get("trivy", {}).get("installed"):
            store.scan_progress(scan_id, "6/10 — образ контейнера: уязвимые пакеты", 60)
            try:
                pkgs = engines.trivy_image(image, timeout=int(os.environ.get("ASM_TRIVY_IMAGE_TIMEOUT", "900")))
            except Exception as e:  # noqa: BLE001
                pkgs = []
                _log(scan_id, f"  trivy (образ {image}): сбой ({str(e)[:110]})")
            sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            pkgs = sorted([p for p in pkgs if p.get("kind") == "vuln"],
                          key=lambda p: sev_rank.get(_sev_upper(p.get("severity")), 9))
            for pv in pkgs[:int(os.environ.get("ASM_IMAGE_VULNS", "40"))]:
                pkg_total += 1
                fixed = pv.get("fixed") or ""
                engine_findings.append({
                    "asset": f"образ {image}", "severity": _sev_upper(pv.get("severity")),
                    "source_kind": "image", "template_id": f"trivy-image-{pv.get('id')}",
                    "cve_id": pv.get("id"),
                    "title": f"{pv.get('package')} {pv.get('installed')}: {pv.get('id')} "
                             f"{(pv.get('title') or '')[:100]}".strip(),
                    "fix": (f"Обновить пакет {pv.get('package')} до {fixed} или пересобрать образ "
                            f"на свежем базовом слое." if fixed else
                            f"Пересобрать образ на свежем базовом слое; следить за {pv.get('id')}."),
                    "evidence": {"тип проверки": "trivy (образ контейнера)",
                                 "образ": image, "пакет": pv.get("package"),
                                 "установлено": pv.get("installed"), "исправлено в": fixed or "исправления нет"},
                })
            pkg_more += max(0, len(pkgs) - int(os.environ.get("ASM_IMAGE_VULNS", "40")))
            if pkgs:
                engine_counts["trivy"] = engine_counts.get("trivy", 0) + min(
                    len(pkgs), int(os.environ.get("ASM_IMAGE_VULNS", "40")))
                _log(scan_id, f"trivy: уязвимых пакетов в образе {image} — {len(pkgs)}")

        if sec_total or pkg_total:
            _log(scan_id, f"Код и образы заказчика: секретов {sec_total}, уязвимых пакетов в отчёт "
                          f"включено {pkg_total}"
                          + (f" (ещё {pkg_more} находок trivy — в полном отчёте инструмента)"
                             if pkg_more else ""))


def stage_crawl_archives(L, assets, edges, engine_counts, engine_findings, engines_status, is_ip, probe_results, root, scan_id):
    # ------------------------------- 5в. обходы, архивы, TLS-сертификаты (движки)
    live_urls = [r.get("url") for r in probe_results.values() if r.get("url") and not r.get("error")]
    engine_crawl = bool(engines and L.get("engines") and L.get("engine_crawl") and live_urls)
    if engine_crawl:
        store.scan_progress(scan_id, "6/10 — обход ссылок (katana) и архивы (gau)", 57)
    if engine_crawl and live_urls:
        found_urls: list[str] = []
        try:
            if engines_status.get("katana", {}).get("installed"):
                kat = engines.katana_urls(live_urls[:int(_setting(L, "ASM_KATANA_URLS", "8"))],
                                          depth=int(_setting(L, "ASM_KATANA_DEPTH", "2")),
                                          limit=int(_setting(L, "ASM_KATANA_LIMIT", "200")),
                                          timeout=int(_setting(L, "ASM_KATANA_TIMEOUT", "180")),
                                          settings=_operation_settings(L))
                if kat:
                    engine_counts["katana"] = len(kat)
                    found_urls += kat
                    _log(scan_id, f"katana: собрано адресов {len(kat)} (страницы, скрипты, параметры)")
        except Exception as e:  # noqa: BLE001
            _log(scan_id, f"katana: сбой ({str(e)[:120]})")
        if L.get("engine_archives") and not is_ip:
            try:
                if engines_status.get("gau", {}).get("installed"):
                    gau = engines.gau_urls(root, limit=int(_setting(L, "ASM_GAU_LIMIT", "300")),
                                           timeout=int(_setting(L, "ASM_GAU_TIMEOUT", "120")),
                                           settings=_operation_settings(L))
                    if gau:
                        engine_counts["gau"] = len(gau)
                        found_urls += gau
                        _log(scan_id, f"gau: адресов из архивов {len(gau)} (включая забытые страницы)")
            except Exception as e:  # noqa: BLE001
                _log(scan_id, f"gau: сбой ({str(e)[:120]})")
        seen_u = {u.get("url") for u in assets if u.get("kind") == "url"}
        fresh_urls = [u for u in dict.fromkeys(found_urls) if u not in seen_u]
        for u in fresh_urls[:int(_setting(L, "ASM_MAX_URLS", "400"))]:
            assets.append({"kind": "url", "value": u, "meta": {
                "источник": "обход katana" if "katana" in engine_counts and u in found_urls[:engine_counts.get("katana", 0)] else "архивы gau",
                "роль": "адрес страницы"}})
            edges.append({"src": root, "dst": u, "rel": "адрес"})
        if fresh_urls:
            _log(scan_id, f"Новых адресов в графе: {min(len(fresh_urls), int(_setting(L, 'ASM_MAX_URLS', '400')))}")

        # потенциально чувствительные адреса — как зацепки для ручной проверки
        try:
            sensitive = engines.sensitive_paths(fresh_urls)
        except Exception:
            sensitive = []
        for s_ in sensitive[:20]:
            engine_findings.append({
                "asset": s_["url"], "ip": None, "port": None, "service": None,
                "product": None, "version": None, "cve_id": None, "cvss": None,
                "severity": "MEDIUM", "source_kind": "exposure", "template_id": "sensitive-url",
                "title": f"В открытом доступе найден адрес с признаком «{s_['marker']}» — {s_['url'][:80]}",
                "evidence": {"тип проверки": "сопоставление собранных адресов с признаками чувствительных файлов",
                             "адрес": s_["url"], "признак": s_["marker"],
                             "важно": "требует ручного подтверждения: наличие в адресе не доказывает доступность файла"},
            })
        if sensitive:
            _log(scan_id, f"Потенциально чувствительных адресов: {len(sensitive)} (требуют ручной проверки)")

        # перебор путей (ffuf) — только по явному разрешению
        if L.get("deep_paths") and engines_status.get("ffuf", {}).get("installed"):
            wl = ""
            try:
                wls = engines._wordlist_files(
                    _setting(L, "ASM_WORDLISTS", engines.WORDLISTS))
                wl = next((w["path"] for w in wls if w["file"] == "dirs-common.txt"), "")
            except Exception:
                wl = ""
            checked = 0
            for u in live_urls[:3]:
                res = engines.ffuf_dirs(
                    u, wordlist=wl, limit=40,
                    timeout=int(_setting(L, "ASM_FFUF_TIMEOUT", "180")),
                    settings=_operation_settings(L),
                )
                checked += len(res)
                for row in res:
                    assets.append({"kind": "url", "value": row["url"], "meta": {
                        "код ответа": row.get("status"), "источник": "поиск путей ffuf",
                        "роль": "скрытый путь (проверить вручную)"}})
            if checked:
                engine_counts["ffuf"] = checked
                _log(scan_id, f"ffuf: найдено скрытых путей {checked} (проверьте вручную значимость)")
    return live_urls


def stage_tlsx_certs(L, assets, edges, engine_counts, engine_findings, engines_status, hosts, name_src, root, scan_id):
    # --- TLS-сертификаты движком tlsx: имена, сроки, самоподпись
    # TLS-сертификаты читаются и у IP-цели: самоподписанный сертификат на адресе
    # часто единственный источник внутреннего имени хоста. Раньше этап
    # отключался для IP вовсе (not is_ip) — это теряло главный признак.
    if engines and L.get("engines") and engines_status.get("tlsx", {}).get("installed"):
        store.scan_progress(scan_id, "6/10 — TLS-сертификаты (tlsx)", 58)
        try:
            certs = engines.tlsx_certs(
                hosts, limit=int(_setting(L, "ASM_TLSX_LIMIT", "80")),
                timeout=int(_setting(L, "ASM_TLSX_TIMEOUT", "180")),
                settings=_operation_settings(L),
            )
        except Exception as e:  # noqa: BLE001
            certs = []
            _log(scan_id, f"tlsx: сбой ({str(e)[:120]})")
        import datetime as _dt
        san_names: set[str] = set()
        for c in certs:
            cn = str(c.get("subject_cn") or "")
            issuer = ", ".join(c.get("issuer_org") or []) or str(c.get("issuer_cn") or "")
            not_after = str(c.get("not_after") or "")
            sans = [str(x) for x in (c.get("subject_an") or [])]
            assets.append({"kind": "cert", "value": cn or str(c.get("host")), "meta": {
                "издатель": issuer, "действует до": not_after, "SAN": ", ".join(sans[:12]),
                "TLS": c.get("tls_version", ""), "самоподписанный": bool(c.get("self_signed")),
                "источник": "TLS-сертификат (tlsx)"}})
            for nm in sans:
                nm = nm.strip().lower().lstrip("*.")
                if nm.endswith(root) and nm not in name_src and nm not in san_names:
                    san_names.add(nm)
                    assets.append({"kind": "subdomain", "value": nm, "meta": {
                        "источник": "TLS-сертификат (tlsx)", "роль": "имя из сертификата — не сканировалось"}})
                    edges.append({"src": root, "dst": nm, "rel": "имя из сертификата"})
            # срок действия сертификата — реальная находка при скором истечении
            if not_after:
                try:
                    dt = _dt.datetime.fromisoformat(not_after.replace("Z", "+00:00")).replace(tzinfo=None)
                    days = (dt - _dt.datetime.utcnow()).days
                    if -3650 < days < 21:
                        engine_findings.append({
                            "asset": cn or str(c.get("host")), "severity": "HIGH" if days < 7 else "MEDIUM",
                            "source_kind": "tls", "template_id": "cert-expiry",
                            "title": f"Сертификат {(cn or c.get('host'))} {'истёк' if days < 0 else 'истекает'} "
                                     f"{'назад ' + str(-days) + ' дн.' if days < 0 else 'через ' + str(days) + ' дн.'}",
                            "evidence": {"тип проверки": "разбор TLS-сертификата (tlsx)",
                                         "действует до": not_after, "издатель": issuer},
                        })
                except Exception:
                    pass
            if c.get("self_signed"):
                engine_findings.append({
                    "asset": cn or str(c.get("host")), "severity": "MEDIUM", "source_kind": "tls",
                    "template_id": "self-signed-cert",
                    "title": f"Самоподписанный TLS-сертификат у {(cn or c.get('host'))} — браузеры показывают предупреждение",
                    "evidence": {"тип проверки": "разбор TLS-сертификата (tlsx)",
                                 "причина": "сертификат подписан сам собой, доверие не подтверждено"},
                })
        if certs:
            engine_counts["tlsx"] = len(certs)
            _log(scan_id, f"tlsx: сертификатов {len(certs)}, новых имён из SAN {len(san_names)}")


def stage_nikto(L, engine_counts, engine_findings, engines_status, live_urls, scan_id):
    # ------------------------------- 5г. Nikto: конфигурация веб-сервера
    # Пул и словарь задач создаются внутри условия ниже, но читает их ещё и
    # этап Wapiti — под своим условием, которое не требует установленного
    # Nikto. Тогда прежний код падал с NameError и валил весь скан. Теперь они
    # определены заранее: Wapiti просто не находит готовых задач и запускает
    # проверки сам, как и задумано.
    web_pool = None
    web_futures = {}
    if engines and L.get("engines") and engines_status.get("nikto", {}).get("installed") \
            and _setting(L, "ASM_NIKTO", "1") not in ("0", "false", "no") and live_urls:
        store.scan_progress(scan_id, "6/10 — Nikto: конфигурация и опасные файлы веб-сервера", 59)
        nk_total = 0
        nk_urls = live_urls[:int(_setting(L, "ASM_NIKTO_URLS", "2"))]
        nk_items: dict[str, list] = {}
        # Nikto и Wapiti (веб-проверки) идут ОДНОВРЕМЕННО: они самые долгие, но независимы.
        # Общий пул создаём здесь, а результаты Wapiti собираем в его секции ниже.
        web_pool = ThreadPoolExecutor(max_workers=4)
        web_futures: dict = {}
        for u in nk_urls:
            web_futures[("nikto", u)] = web_pool.submit(
                engines.nikto_scan, u,
                timeout=int(_setting(L, "ASM_NIKTO_TIMEOUT", "180")),
                max_time=_setting(L, "ASM_NIKTO_MAXTIME", "90s"),
                settings=_operation_settings(L))
        wp_on = _setting(L, "ASM_WAPITI", "1") not in ("0", "false", "no") \
            and engines_status.get("wapiti", {}).get("installed")
        if wp_on:
            for u in live_urls[:int(_setting(L, "ASM_WAPITI_URLS", "1"))]:
                web_futures[("wapiti", u)] = web_pool.submit(
                    engines.wapiti_scan, u,
                    timeout=int(_setting(L, "ASM_WAPITI_TIMEOUT", "300")),
                    max_time=int(_setting(L, "ASM_WAPITI_MAXTIME", "90")),
                    settings=_operation_settings(L))
        for u in nk_urls:
            try:
                nk_items[u] = web_futures[("nikto", u)].result() or []
            except Exception as e:  # noqa: BLE001
                nk_items[u] = []
                _log(scan_id, f"  nikto {u}: сбой ({str(e)[:110]})")
        for u in nk_urls:
            items = nk_items.get(u) or []
            for it in items:
                nk_total += 1
                sev = "MEDIUM"
                low = (it["msg"] or "").lower()
                if any(k in low for k in ("password", "разреш", "auth", "backup", "config", ".env", "phpinfo")):
                    sev = "HIGH"
                elif any(k in low for k in ("header", "заголов", "cookie", "robots", "server leaks")):
                    sev = "LOW"
                engine_findings.append({
                    "asset": it.get("url") or u, "severity": sev, "source_kind": "engine",
                    "template_id": f"nikto-{it.get('id','')}", "cve_id": None,
                    "title": f"Nikto: {it['msg'][:150]}",
                    "evidence": {"тип проверки": "Nikto (конфигурация веб-сервера)",
                                 "адрес": it.get("url") or u, "метод": it.get("method"),
                                 "номер проверки": it.get("id"),
                                 "источник": "nikto"},
                })
        if nk_total:
            engine_counts["nikto"] = nk_total
            tuning = (engines_status.get("profile") or {}).get("nikto_tuning", engines.NIKTO_TUNING)
            _log(scan_id, f"nikto: замечаний по веб-серверу {nk_total} "
                          f"(проверки инъекций отключены параметром -Tuning {tuning})")
    return web_futures, web_pool


def stage_wapiti(L, engine_counts, engine_findings, engines_status, live_urls, scan_id, web_futures, web_pool):
    # ------------------------------- 5е. Wapiti: проверки веб-приложения без инъекций
    if engines and L.get("engines") and engines_status.get("wapiti", {}).get("installed") \
            and _setting(L, "ASM_WAPITI", "1") not in ("0", "false", "no") and live_urls:
        store.scan_progress(scan_id, "6/10 — Wapiti: проверки веб-приложения", 59)
        wp_total = 0
        wp_urls = [u for (kind, u) in web_futures if kind == "wapiti"] or \
            live_urls[:int(_setting(L, "ASM_WAPITI_URLS", "1"))]
        for u in wp_urls:
            fut = web_futures.get(("wapiti", u))
            try:
                items = (fut.result() if fut else
                     engines.wapiti_scan(u, settings=_operation_settings(L))) or []
            except Exception as e:  # noqa: BLE001
                items = []
                _log(scan_id, f"  wapiti {u}: сбой ({str(e)[:110]})")
            for it in items:
                wp_total += 1
                engine_findings.append({
                    "asset": it.get("path") or u, "severity": it.get("severity"),
                    "source_kind": "wapiti", "template_id": f"wapiti-{it.get('module')}",
                    "title": f"Веб-проверка ({it.get('module')}): {it['info'][:150]}",
                    "fix": "Разобрать замечание и закрыть по описанию; для библиотек — обновить до "
                           "исправленной версии, для заголовков и методов — поправить конфигурацию сервера.",
                    "evidence": {"тип проверки": f"Wapiti, модуль «{it.get('module')}» (без инъекций и перебора паролей)",
                                 "адрес": it.get("path"), "метод": it.get("method"),
                                 "параметр": it.get("parameter"), "найдено": it["info"][:400],
                                 "источник": "wapiti"},
                })
        if engines.LAST_ERRORS.get("wapiti"):
            _log(scan_id, f"  wapiti: {engines.LAST_ERRORS['wapiti']} — проверка пропущена, остальной аудит не задержан")
        if wp_total:
            engine_counts["wapiti"] = wp_total
            _log(scan_id, f"wapiti: замечаний по веб-приложению {wp_total} "
                          f"(модули без инъекций: {engines.wapiti_modules(_operation_settings(L))})")

    try:                      # пул веб-проверок своё отработал
        web_pool.shutdown(wait=False)
    except Exception:
        pass


def stage_testssl(L, engine_counts, engine_findings, engines_status, live_urls, scan_id):
    # ------------------------------- 5ж. testssl.sh: глубокий аудит TLS-конфигурации
    if engines and L.get("engines") and engines_status.get("testssl", {}).get("installed") \
            and _setting(L, "ASM_TESTSSL", "1") not in ("0", "false", "no") and live_urls:
        https_hosts: list[str] = []
        for u in live_urls:
            m = re.match(r"https://([^/]+)", u or "")
            if m and m.group(1) not in https_hosts:
                https_hosts.append(m.group(1))
        limit_ts = int(_setting(L, "ASM_TESTSSL_HOSTS", "2"))
        if https_hosts[:limit_ts]:
            store.scan_progress(scan_id, "6/10 — TLS-конфигурация (testssl.sh)", 60)
        ts_total = 0
        for hp in https_hosts[:limit_ts]:
            host_only, _, port_s = hp.partition(":")
            port = int(port_s or 443)
            try:
                rows = engines.testssl_audit(
                    host_only, port,
                    timeout=int(_setting(L, "ASM_TESTSSL_TIMEOUT", "240")),
                    settings=_operation_settings(L),
                )
            except Exception as e:  # noqa: BLE001
                rows = []
                _log(scan_id, f"  testssl {hp}: сбой ({str(e)[:110]})")
            for row in rows:
                text = row.get("finding") or ""
                sev = row["severity"]
                # тест может честно ошибаться там, где сервер ведёт себя нестандартно —
                # такие строки помечаем мягче и прямо пишем об этом в отчёте
                if "connection failed rather than downgrading" in text:
                    sev = "LOW"
                if row["id"] == "pre_128cipher":
                    sev = "MEDIUM"
                ts_total += 1
                engine_findings.append({
                    "asset": hp, "port": port, "severity": sev, "source_kind": "tls",
                    "template_id": f"testssl-{row['id']}",
                    "title": f"TLS ({hp}): {text[:150]}",
                    "fix": TLS_FIX.get(row["id"], "Привести TLS-конфигурацию к рекомендациям: только TLS 1.2+, "
                                                 "современные шифры, полная цепочка сертификата."),
                    "evidence": {"тип проверки": "testssl.sh (глубокий аудит TLS)",
                                 "проверка": row["id"], "найдено": text,
                                 "уровень важности по мнению testssl": row["severity"],
                                 "источник": "testssl"},
                })
        if ts_total:
            engine_counts["testssl"] = ts_total
            _log(scan_id, f"testssl: значимых замечаний по TLS {ts_total} "
                          f"(проверено хостов: {len(https_hosts[:limit_ts])})")


def stage_enrich_scoring(ip_ports, raw_cve, scan_id):
    # ---------------------------------------------------- 7. обогащение и скоринг
    store.scan_progress(scan_id, "8/10 — обогащение (EPSS) и скоринг", 86)
    ids = sorted({c["cve_id"] for c in raw_cve})
    epss = cve.epss_lookup(ids)
    kev_all = cve.kev_lookup(ids)
    for c in raw_cve:
        c["epss"] = epss.get(c["cve_id"], 0.0)
        c["kev"] = c["cve_id"] in kev_all
        c["kev_info"] = kev_all.get(c["cve_id"], {})

    # агрегация: одна находка на (CVE, продукт) со списком затронутых объектов
    groups: dict[tuple, dict] = {}
    for c in raw_cve:
        # Ключ нормализуем: banner-идентификация отдаёт «OpenSSL», а сканер
        # пакетов — «openssl», и без приведения регистра одна и та же CVE
        # давала бы две строки в отчёте.
        prod = c.get("product") or c.get("ip") or ""
        gkey = (str(c["cve_id"]).upper(), str(prod).casefold())
        g = groups.setdefault(gkey, {"cve": c, "hosts": [], "worst_port": None})
        where = f"{c['ip']}:{c['port']}" if c.get("port") else (c.get("ip") or "")
        if where and where not in g["hosts"]:
            g["hosts"].append(where)
        if _exposure_rank(c.get("port")) > _exposure_rank(g["worst_port"]):
            g["worst_port"] = c.get("port")
        # при агрегации сохраняем самую информативную запись о проблеме
        if not g["cve"].get("product") and c.get("product"):
            g["cve"] = c

    findings: list[dict] = []
    for (cve_id, _), g in groups.items():
        c = g["cve"]
        hosts = g["hosts"]
        head = hosts[0] if hosts else (c.get("product") or "")
        f = {
            "asset": head + (f" (+{len(hosts)-1})" if len(hosts) > 1 else ""),
            "ip": c.get("ip"), "port": g["worst_port"] or c.get("port"),
            "service": identify.PORT_SERVICES.get(g["worst_port"] or c.get("port") or -1),
            "product": c.get("product"), "version": c.get("version"),
            "cve_id": cve_id, "cvss": c.get("cvss"), "severity": (c.get("severity") or "").upper() or None,
            "epss": c.get("epss"), "kev": c.get("kev"), "kev_info": c.get("kev_info", {}),
            "title": (f"{cve_id}" +
                      (f" в {c['product']}" + (f" {c['version']}" if c.get("version") else "")
                       if c.get("product") else " (продукт не определён)")) +
                     f" — {cve.nvd_text_summary(c)}",
            "evidence": {
                "затронутые объекты": ", ".join(hosts[:20]) + (f" … всего {len(hosts)}" if len(hosts) > 20 else ""),
                "источник данных": c.get("source", "nvd"),
                "описание (NVD)": (c.get("description") or "")[:600],
                "признак обнаружения": c.get("evidence", ""),
                "ссылка": c.get("url", ""),
                "CVSS-вектор": c.get("vector", "") or "",
                "CISA KEV": (c.get("kev_info") or {}).get("name", "") if c.get("kev") else "",
            },
            "published": c.get("published", ""),
            "published_year": (c.get("published") or "")[:4],
        }
        findings.append(score.score_finding(f))

    # опасные сервисы наружу — находка сама по себе
    for ip, ports in ip_ports.items():
        for r in identify.risky_port_findings(ports):
            rr = dict(r)
            rr["ip"] = ip
            rr["asset"] = f"{ip}:{r['port']}"
            rr["evidence"] = {"обнаружение": f"порт {r['port']} доступен из интернета у {ip}",
                              "источник": "публичный индекс баннеров"}
            findings.append(score.score_finding(rr))
    return findings


def stage_probe_light(L, all_ips, host_to_ips, ip_ports, root, scan_id):
    # ---------------------------------------------------- 4. лёгкая проба
    store.scan_progress(scan_id, "5/10 — HTTP/TLS-проба веб-сервисов", 42)
    probes: list[tuple[str, str, int]] = []
    for ip in all_ips:
        ports = set(ip_ports.get(ip, []))
        names = [h for h, ips in host_to_ips.items() if ip in ips] or [ip]
        for port in sorted(ports):
            if port in identify.WEB_PORTS and len(probes) < L["max_probes"]:
                probes.append((names[0], ip, port))
        if ip in host_to_ips.get(root, []) and not (ports & set(identify.WEB_PORTS)):
            for p in (443, 80):
                if len(probes) < L["max_probes"]:
                    probes.append((root, ip, p))

    probe_results: dict[tuple[str, int], dict] = {}
    return probe_results, probes


def stage_discovery_sources(L, assets, edges, engine_counts, is_ip, root, scan_id):
    # ------------------------------------------- 1. discovery (мульти-источники)
    subs: list[str] = []
    src_counts: dict[str, int] = {}
    src_errors: dict[str, str] = {}
    name_src: dict[str, list[str]] = {}
    if not is_ip:
        store.scan_progress(scan_id, "1/10 — мульти-источниковая разведка (сертификаты, passive DNS, urlscan, имена с IP)", 5)
        _log(scan_id, f"Пассивная разведка по «{root}»: все источники без ключей "
                      f"(CertSpotter, crt.sh, Mnemonic, OTX, urlscan, HackerTarget)")
        try:
            multi = _call_with_settings(
                sources.collect_domain, root,
                log=lambda m: _log(scan_id, "  " + m),
                settings=_operation_settings(L),
            )
        except Exception as e:  # noqa: BLE001 — разведка не должна ломать анализ
            multi = {"names": {}, "counts": {}, "errors": {"все": str(e)}, "found": {}}
            _log(scan_id, f"Мульти-источники: общий сбой ({e}) — продолжаем")
        name_src = multi["names"]
        src_counts = multi["counts"]
        src_errors = multi["errors"]
        all_subs = list(name_src)
        contrib = ", ".join(f"{sources.label(k)}: {v}" for k, v in
                            sorted(src_counts.items(), key=lambda kv: -kv[1]) if v > 0)
        _log(scan_id, f"Найдено имён всего: {len(all_subs)}" +
                      (f"; вклад источников — {contrib}" if contrib else "; новых имён источники не дали"))
        # плюс собственные источники subfinder/amass (движки), если установлены
        if engines and L.get("engines"):
            est = engines.available(settings=_operation_settings(L))
            if est.get("subfinder", {}).get("installed"):
                try:
                    got = engines.subfinder(
                        root, limit=int(_setting(L, "ASM_SUBFINDER_LIMIT", "300")),
                        settings=_operation_settings(L),
                    )
                except Exception as e:  # noqa: BLE001
                    got = []
                    _log(scan_id, f"  subfinder: сбой ({str(e)[:120]})")
                new_names = [g for g in got if g not in name_src]
                for g in new_names:
                    name_src[g] = ["subfinder"]
                if got:
                    engine_counts["subfinder"] = len(got)
                    _log(scan_id, f"  subfinder: имён {len(got)}, новых для разведки {len(new_names)}")
                    all_subs = list(name_src)
            if est.get("amass", {}).get("installed") and _setting(L, "ASM_AMASS", "0") not in ("0", "false", "no"):
                try:
                    got = engines.amass_passive(
                        root, timeout=int(_setting(L, "ASM_AMASS_TIMEOUT", "240")),
                        settings=_operation_settings(L),
                    )
                except Exception as e:  # noqa: BLE001
                    got = []
                    _log(scan_id, f"  amass: сбой ({str(e)[:120]})")
                new_names = [g for g in got if g not in name_src]
                for g in new_names:
                    name_src[g] = ["amass"]
                if got:
                    engine_counts["amass"] = len(got)
                    _log(scan_id, f"  amass (пассивно): имён {len(got)}, новых {len(new_names)}")
                    all_subs = list(name_src)
        subs = [s for s in all_subs if s != root and not NOISE.match(s.replace("." + root, ""))]
        subs.sort(key=lambda s: (_interesting(s, root), len(s)))
        if len(subs) > L["max_subdomains"]:
            _log(scan_id, f"Лимит: анализируем {L['max_subdomains']} самых интересных имён из {len(subs)}")
            subs = subs[:L["max_subdomains"]]
        try:
            for c in collect.crtsh_certs(root, settings=_operation_settings(L))[:40]:
                assets.append({"kind": "cert", "value": c.get("common_name") or "?",
                               "meta": {"issuer": (c.get("issuer") or "")[:160],
                                        "not_after": c.get("not_after"),
                                        "names": (c.get("names") or [])[:8]}})
                if c.get("common_name"):
                    edges.append({"src": root, "dst": c.get("common_name"), "rel": "сертификат"})
        except Exception:
            pass
    return name_src, src_counts, src_errors, subs


def stage_expand_by_ip(L, assets, edges, is_ip, name_src, root, scan_id, src_counts, src_errors, subs):
    # ------------------------------------------ 1б. расширение по адресу
    store.scan_progress(scan_id, "2/10 — расширение: типовые имена, DNS-записи", 12)
    est_sources: dict[str, str] = {}
    estate_warn: list[str] = []
    if estate is not None and L.get("estate"):
        try:
            e1 = estate.expand(scan_id, root, is_ip, L, _log)
        except Exception as e:  # noqa: BLE001
            e1 = {"hosts": [], "sources": {}, "ips": [], "warn": []}
            _log(scan_id, f"Расширение по адресу: сбой ({e})")
        est_sources = e1.get("sources", {})
        known = set(subs) | {root}
        for h in e1.get("hosts", []):
            if h not in known:
                subs.append(h)
                known.add(h)
        estate_warn += list(e1.get("warn", []))
        for w in e1.get("warn", []):
            _log(scan_id, "ВНИМАНИЕ: " + w)
        if est_sources:
            _log(scan_id, f"Дополнительных имён из расширения: {len(est_sources)}")

    # IP-цель: по найденным обратным именам прогоняем ту же пассивную разведку,
    # что и по домену. Без этого по адресу остаётся почти один nmap: сертификаты,
    # passive DNS и архивы ключуются по имени, а имя мы только что узнали из PTR.
    if is_ip and subs:
        limit_ptr = int(_setting(L, "ASM_PTR_RECON_MAX", "5"))
        _log(scan_id, f"Пассивная разведка по обратным именам IP: {len(subs[:limit_ptr])} "
                      f"(сертификаты, passive DNS, urlscan)")
        for h in subs[:limit_ptr]:
            try:
                m2 = _call_with_settings(
                    sources.collect_domain, h,
                    log=lambda msg: _log(scan_id, "  " + msg),
                    settings=_operation_settings(L),
                )
            except Exception as e:  # noqa: BLE001 — разведка не должна ломать анализ
                _log(scan_id, f"  {h}: сбой разведки ({str(e)[:100]})")
                continue
            known_names = set(subs) | {root}
            added = 0
            for nm, srcs in (m2.get("names") or {}).items():
                if nm not in known_names:
                    subs.append(nm)
                    known_names.add(nm)
                    added += 1
                bucket = name_src.setdefault(nm, [])
                for src in srcs or []:
                    if src not in bucket:
                        bucket.append(src)
            for k, v in (m2.get("counts") or {}).items():
                src_counts[k] = src_counts.get(k, 0) + int(v or 0)
            for k, v in (m2.get("errors") or {}).items():
                src_errors.setdefault(k, v)
            _log(scan_id, f"  {h}: новых имён {added}")
        if len(subs) > L["max_subdomains"]:
            _log(scan_id, f"Лимит: оставляем {L['max_subdomains']} имён из {len(subs)}")
            subs = subs[:L["max_subdomains"]]

    # Для IP-цели subs — это обратные имена (PTR), найденные при расширении.
    # Раньше они отбрасывались: [root] if is_ip. Терять их нельзя — внутреннее
    # имя хоста из самоподписанного сертификата или PTR часто единственный
    # признак, по которому объект вообще опознаётся.
    hosts = [root] + subs
    for h in hosts:
        meta_h = {"роль": "корневой домен" if h == root else "найден в открытых источниках"}
        if name_src.get(h):
            meta_h["источник"] = ", ".join(sources.label(s) for s in name_src[h])
            meta_h["роль"] = "найден в разведке"
        if est_sources.get(h):
            meta_h["источник"] = est_sources[h]
            meta_h["роль"] = "найден при расширении"
        assets.append({"kind": "ip" if (is_ip and h == root) else "subdomain", "value": h, "meta": meta_h})
        if h != root:
            edges.append({"src": root, "dst": h, "rel": "поддомен"})
    return est_sources, hosts, subs, estate_warn


def stage_resolve_hosts(L, assets, edges, hosts, is_ip, root, scan_id):
    # ---------------------------------------------------- 2. resolve
    store.scan_progress(scan_id, "2/10 — DNS-разрешение", 15)
    host_to_ips: dict[str, list[str]] = {}
    if is_ip:
        host_to_ips[root] = [root]
    # Разрешение нужно не только доменным целям: у IP-цели обратные имена (PTR)
    # — обычные имена, и без разрешения они останутся в списке hosts без
    # адресов и дальше нигде не всплывут.
    to_resolve = hosts if not is_ip else [h for h in hosts if h != root]
    if to_resolve:
        dns_done = False
        if engines and L.get("engines"):
            try:
                if engines.available(settings=_operation_settings(L)).get("dnsx", {}).get("installed"): 
                    res = engines.dnsx_resolve(
                        to_resolve, limit=int(_setting(L, "ASM_DNSX_LIMIT", "500")),
                        settings=_operation_settings(L),
                    )
                    for h, ips in res.items():
                        good = [i for i in ips if _is_ip(i)]
                        if good:
                            host_to_ips[h] = good
                    got = [h for h in to_resolve if host_to_ips.get(h)]
                    if got:
                        dns_done = True
                        _log(scan_id, f"DNS (dnsx): отвечают {len(got)} имён из {len(to_resolve)}")
            except Exception as e:  # noqa: BLE001
                _log(scan_id, f"dnsx: сбой ({str(e)[:100]}) — переходим на встроенный резолвер")
        if not dns_done:
            with ThreadPoolExecutor(max_workers=L["workers"]) as ex:
                futs = {ex.submit(collect.resolve_ips, h, settings=_operation_settings(L)): h
                        for h in to_resolve}
                for f in as_completed(futs):
                    h = futs[f]
                    try:
                        ips = [i for i in f.result() if _is_ip(i)]
                    except Exception:
                        ips = []
                    if ips:
                        host_to_ips[h] = ips
        if is_ip:
            _log(scan_id, f"Обратные имена разрешены: {len([h for h in to_resolve if h in host_to_ips])}"
                          f" из {len(to_resolve)}")

    all_ips: list[str] = []
    for h, ips in host_to_ips.items():
        for ip in ips:
            if ip not in all_ips:
                all_ips.append(ip)
            edges.append({"src": h, "dst": ip, "rel": "разрешается в"})
            assets.append({"kind": "ip", "value": ip, "meta": {"хост": h}})

    _log(scan_id, f"Отвечающих хостов: {len(host_to_ips)} из {len(hosts)}; уникальных IP: {len(all_ips)}")
    return all_ips, host_to_ips


def stage_reverse_ip(L, all_ips, assets, edges, est_sources, host_to_ips, name_src, root, scan_id):
    # --- обратный поиск по IP (ip.thc.org): какие ещё домены живут на наших адресах
    related: list[str] = []
    if all_ips and "ipthc" in sources._enabled_ids(settings=_operation_settings(L)):
        store.scan_progress(scan_id, "3/10 — обратный поиск по IP (ip.thc.org, база 6 млрд имён)", 18)
        _log(scan_id, "Обратный поиск по IP: какие домены ещё живут на наших адресах")
        known_names = {root} | set(name_src) | set(est_sources) | set(host_to_ips)
        for ip in all_ips[:3]:
            try:
                got = sources.domains_on_ip(ip, settings=_operation_settings(L))
            except Exception as e:  # noqa: BLE001
                _log(scan_id, f"  ip.thc.org {ip}: сбой ({str(e)[:100]})")
                continue
            fresh = [d for d in got if d and d not in known_names and d not in related
                     and not re.match(r"^[0-9][0-9-]*\.", d)
                     and not NOISE.match(d.split(".", 1)[0])]
            for d in fresh[:min(50, L["max_subdomains"])]:
                related.append(d)
                known_names.add(d)
                assets.append({"kind": "domain", "value": d, "meta": {
                    "источник": "ip.thc.org (обратный DNS)",
                    "роль": "домен на том же IP — только справочно, не сканируется"}})
                edges.append({"src": ip, "dst": d, "rel": "на том же IP"})
            if fresh:
                _log(scan_id, f"  {ip}: доменов на том же IP {len(fresh)} (справочно, без сканирования)")
        if related:
            _log(scan_id, f"Связанные домены (для проверки владельцем): {len(related)} — "
                          f"{', '.join(related[:8])}{' …' if len(related) > 8 else ''}")
    return related


def stage_org_nets(L, assets, edges, is_ip, root, scan_id, all_ips, estate_warn):
    # --- сети организации (только по флагу; чужие адреса возможны — предупреждаем)
    if estate is not None and L.get("estate_asn") and all_ips:
        store.scan_progress(scan_id, "3/10 — сети организации (RIPEstat): анонсированные префиксы", 20)
        L2 = dict(L)
        L2["estate_words"] = 0
        try:
            e2 = estate.expand(scan_id, root, is_ip, L2, _log, seed_ips=all_ips[:4])
        except Exception as e:  # noqa: BLE001
            e2 = {"ips": [], "warn": []}
            _log(scan_id, f"Сети организации: сбой ({e})")
        added = 0
        for item in e2.get("ips", []):
            ip = item["ip"]
            if ip not in all_ips:
                all_ips.append(ip)
                added += 1
            assets.append({"kind": "ip", "value": ip, "meta": item.get("meta", {})})
            edges.append({"src": item.get("meta", {}).get("рядом_с", root), "dst": ip, "rel": "сеть организации"})
        estate_warn += [w for w in e2.get("warn", []) if w not in estate_warn]
        for w in e2.get("warn", []):
            _log(scan_id, "ВНИМАНИЕ: " + w)
        if added:
            _log(scan_id, f"Из сетей организации добавлено адресов: {added} (всего IP {len(all_ips)})")
    if len(all_ips) > L["max_ips"]:
        _log(scan_id, f"Лимит: анализируем {L['max_ips']} IP")
        all_ips = all_ips[:L["max_ips"]]
    return all_ips, estate_warn


def stage_enrich_ip(L, all_ips, assets, edges, ip_meta, scan_id):
    # ---------------------------------------------------- 3. обогащение IP
    store.scan_progress(scan_id, "4/10 — открытые порты и сети (InternetDB, RIPEstat)", 30)
    ip_ports: dict[str, list[int]] = {}
    ip_cpes: dict[str, list[str]] = {}
    ip_index_cves: dict[str, list[str]] = {}

    operation_settings = _operation_settings(L)

    def enrich_ip(ip: str):
        return (ip, collect.internetdb(ip, settings=operation_settings),
                collect.ripe_prefix(ip, settings=operation_settings))

    enrich_fail: list[str] = []
    with ThreadPoolExecutor(max_workers=L["workers"]) as ex:
        futs = [ex.submit(enrich_ip, ip) for ip in all_ips]
        for f in as_completed(futs):
            try:
                ip, idb, ripe = f.result()
            except Exception as e:  # noqa: BLE001
                # Раньше здесь стояло молчаливое `continue`. Внешний источник
                # может быть недоступен или запрещён режимом скрытности — и тогда
                # из отчёта бесследно исчезали порты и сети по адресу, выглядя
                # как «данных нет». Причину надо назвать.
                enrich_fail.append(f"{type(e).__name__}: {str(e)[:120]}")
                continue
            ip_meta[ip] = ripe
            if idb:
                ports = idb.get("ports", [])
                ip_ports[ip] = ports
                ip_cpes[ip] = idb.get("cpes", [])
                ip_index_cves[ip] = idb.get("vulns", [])
                if ripe.get("asn"):
                    edges.append({"src": ip, "dst": f"AS{ripe['asn']}",
                                  "rel": f"принадлежит ({ripe.get('holder','')})"})
                for port in ports:
                    svc = identify.PORT_SERVICES.get(port, "?")
                    edges.append({"src": ip, "dst": f"{ip}:{port}", "rel": "порт открыт",
                                  "meta": {"service": svc}})
                    assets.append({"kind": "service", "value": f"{ip}:{port}",
                                   "meta": {"service": svc, "источник": "публичный индекс"}})

    if enrich_fail:
        # Причина видна в журнале скана и в отчёте. Без этого «нет портов»
        # и «источник не ответил» выглядят одинаково.
        uniq = sorted(set(enrich_fail))
        _log(scan_id, f"Обогащение по внешним источникам не удалось для "
                      f"{len(enrich_fail)} адресов: " + "; ".join(uniq[:3]))
        store.audit("scan_enrich_failed",
                    {"scan_id": scan_id, "failed": len(enrich_fail),
                     "reasons": uniq[:5]})
    return ip_cpes, ip_index_cves, ip_ports


def stage_service_versions(L, all_ips, assets, edges, engine_counts, engines_status, ip_ports, is_ip, scan_id):
    # ------------------------- 3б. точные версии сервисов (nmap -sV)
    nmap_products: list[dict] = []
    if engines and L.get("engines") and engines_status.get("nmap", {}).get("installed"):
        nmap_ips = all_ips[:int(_setting(L, "ASM_NMAP_HOSTS", "3"))]
        if nmap_ips:
            store.scan_progress(scan_id, "4/10 — версии сервисов (nmap -sV): SSH, SMTP, базы, веб", 38)
            _log(scan_id, f"nmap -sV: уточняем продукты и версии сервисов у {len(nmap_ips)} адресов "
                          f"(это то, по чему точно подбираются CVE)")
        for ip in nmap_ips:
            ports = sorted(set(ip_ports.get(ip, [])))[:int(_setting(L, "ASM_NMAP_PORTS", "40"))]
            # По одиночному адресу сканировать можно шире: 120 портов не
            # покрывают ни WinRM (5985/47001), ни SMB (445), ни альтернативный
            # веб (8080) — а вход обычно стоит именно там.
            legacy_top = os.environ.get("ASM_NMAP_TOP", "1000" if is_ip else "120")
            top_ports_n = int(_setting(L, "ASM_NMAP_TOP", legacy_top))
            try:
                found = engines.nmap_services(
                    ip, ports, timeout=int(_setting(L, "ASM_NMAP_TIMEOUT", "240")),
                    top_ports=0 if ports else top_ports_n,
                    settings=_operation_settings(L),
                )
            except Exception as e:  # noqa: BLE001
                found = []
                _log(scan_id, f"  nmap {ip}: сбой ({str(e)[:110]})")
            # та же проверка достоверности, что и для naabu: «открыто всё» = прозрачный прокси
            if found and not ports:
                total = top_ports_n
                ok_nm, why_nm = active.ports_plausible([r2.get("port") for r2 in found], total)
                if not ok_nm:
                    _log(scan_id, f"  nmap {ip}: {why_nm} — результат отброшен")
                    found = []
            for row in found:
                prod = str(row.get("product") or "").strip()
                ver = str(row.get("version") or "").strip()
                svc = row.get("service") or identify.PORT_SERVICES.get(row.get("port") or -1, "?")
                if svc:
                    if row.get("port") not in ip_ports.get(ip, []):
                        ip_ports.setdefault(ip, [])
                        ip_ports[ip] = sorted(set(ip_ports[ip]) | {row["port"]})
                        assets.append({"kind": "service", "value": f"{ip}:{row['port']}", "meta": {
                            "service": svc, "источник": "nmap -sV"}})
                        edges.append({"src": ip, "dst": f"{ip}:{row['port']}", "rel": "порт открыт",
                                      "meta": {"service": svc}})
                if not prod:
                    continue
                disp = prod + (f" {ver}" if ver else "")
                assets.append({"kind": "tech", "value": disp, "meta": {
                    "ip": ip, "порт": row.get("port"), "служба": svc, "источник": "nmap -sV"}})
                edges.append({"src": f"{ip}:{row.get('port')}", "dst": prod, "rel": "работает на"})
                nmap_products.append({"product": prod, "version": ver, "ip": ip,
                                      "port": row.get("port"), "service": svc,
                                      "cpe": row.get("cpe") or [], "evidence": f"nmap -sV: {disp}" + (
                                          f" ({row.get('extra')})" if row.get("extra") else "")})
            if found:
                _log(scan_id, f"  nmap {ip}: сервисов определено {len(found)} "
                              f"({', '.join((r.get('product') or r.get('service') or '?')[:18] for r in found[:6])})")
        if nmap_products:
            engine_counts["nmap"] = len(nmap_products)
    return nmap_products


def stage_web_httpx(engine_counts, engines_status, hosts, probe_results, scan_id,
                    *, settings=None):
    # --- основной путь: httpx (статусы, заголовок, технологии, CDN, TLS)
    config = {"__settings__": settings}
    if engines_status.get("httpx", {}).get("installed"):
        hosts_for_httpx = [h for h in hosts if h][:int(_setting(config, "ASM_MAX_HTTPX", "300"))]
        try:
            rows = engines.httpx_probe(
                hosts_for_httpx, limit=int(_setting(config, "ASM_MAX_HTTPX", "300")),
                timeout=int(_setting(config, "ASM_HTTPX_TIMEOUT", "420")), settings=settings,
            )
        except Exception as e:  # noqa: BLE001
            rows = []
            _log(scan_id, f"httpx: сбой ({str(e)[:120]}) — переходим на встроенную пробу")
        for row in rows:
            ip = row.get("host_ip") or ((row.get("a") or [""])[0] if isinstance(row.get("a"), list) else "") or ""
            if not ip:
                for cand in (row.get("a") or []) + (row.get("aaaa") or []):
                    if _is_ip(str(cand)):
                        ip = str(cand)
                        break
            try:
                port = int(row.get("port") or 0)
            except Exception:
                port = 0
            if not ip or not port:
                continue
            probe_results[(ip, port)] = {
                "status": row.get("status_code"), "server": row.get("webserver") or "",
                "title": row.get("title") or "", "headers": {}, "body_snippet": "",
                "error": "нет ответа" if row.get("failed") else None,
                "tech": [str(t) for t in (row.get("tech") or [])],
                "cdn": row.get("cdn_name") or "", "url": row.get("url") or "",
                "from": "httpx",
            }
        if probe_results:
            engine_counts["httpx"] = len(probe_results)
            _log(scan_id, f"httpx: живых веб-сервисов {len(probe_results)} из {len(hosts_for_httpx)} имён "
                          f"(технологии, заголовки, CDN — одним проходом)")


def stage_probe_gap_fill(L, engine_counts, probe_results, probes, scan_id):
    # --- добивка встроенной пробой по тем парам, что не покрыл httpx
    missing = [p for p in probes if (p[1], p[2]) not in probe_results]
    if missing:
        def do_probe(item):
            hn, ip, port = item
            return (ip, port), collect.http_probe(
                hn, port, identify.WEB_PORTS.get(port),
                settings=_operation_settings(L),
            )

        with ThreadPoolExecutor(max_workers=min(L["workers"], 6)) as ex:
            futs = [ex.submit(do_probe, p) for p in missing]
            for f in as_completed(futs):
                try:
                    key, r = f.result()
                except Exception:
                    continue
                probe_results[key] = r
        if engine_counts.get("httpx"):
            _log(scan_id, f"Встроенная проба: добавлено {len(probe_results) - engine_counts['httpx']} сервисов")
    _log(scan_id, f"Опрошено веб-сервисов: {len(probe_results)} (по одному запросу, без перебора)")


def stage_live_fingerprints(assets, edges, probe_results):
    # --- адреса живых сервисов как цифровые следы + ссылки на технологии
    for (ip, port), r in probe_results.items():
        url = r.get("url") or ""
        if url and not r.get("error"):
            assets.append({"kind": "url", "value": url, "meta": {
                "status": r.get("status"), "title": (r.get("title") or "")[:120],
                "технологии": ", ".join(r.get("tech") or [])[:160],
                "CDN": r.get("cdn") or "", "источник": "веб-проба httpx" if r.get("from") == "httpx" else "встроенная проба"}})
            edges.append({"src": f"{ip}:{port}", "dst": url, "rel": "веб-сервис"})


def stage_identify(assets, edges, probe_results, scan_id):
    # ---------------------------------------------------- 5. идентификация
    store.scan_progress(scan_id, "6/10 — определение технологий", 52)
    products: dict[tuple, dict] = {}

    # карта «название технологии -> вендор/CPE» из правил identify
    tech_map: dict[str, tuple[str, str]] = {}
    for rx, product, vendor, cpe_product, mode in list(getattr(identify, "HEADER_RULES", [])) + \
            list(getattr(identify, "XPB_RULES", [])):
        if product and vendor and cpe_product:
            tech_map.setdefault(product.strip().lower(), (vendor, cpe_product))

    def tech_to_products(techs: list[str], ip: str, port: int) -> list[dict]:
        out = []
        for t in techs or []:
            name, _, ver = str(t).partition(":")
            key = name.strip().lower()
            hit = tech_map.get(key)
            if not hit:
                for k, v in tech_map.items():
                    if k and (k in key or key in k) and len(k) > 3:
                        hit = v
                        break
            if not hit:
                continue
            out.append({"product": name, "vendor": hit[0], "cpe_product": hit[1],
                        "version": ver.strip(), "ip": ip, "port": port,
                        "evidence": f"технологии httpx: {t}"})
        return out

    httpx_products: list[dict] = []
    for (ip, port), r in probe_results.items():
        if r.get("from") == "httpx" and r.get("tech"):
            httpx_products += tech_to_products(r["tech"], ip, port)
    for info in httpx_products:
        disp = info["product"] + (f" {info['version']}" if info["version"] else "")
        assets.append({"kind": "tech", "value": disp, "meta": {"ip": info["ip"], "порт": info["port"],
                                                              "источник": info["evidence"]}})
        edges.append({"src": f"{info['ip']}:{info['port']}", "dst": info["product"], "rel": "работает на"})
        key = (info["vendor"], info["cpe_product"], info["version"], info["ip"], info["port"])
        products.setdefault(key, dict(info))

    for (ip, port), r in probe_results.items():
        if r.get("from") == "httpx":
            continue  # технологии httpx уже разобраны выше
        if r.get("error"):
            continue
        ctx = {"port": port, "headers": r.get("headers", {}), "server": r.get("server", ""),
               "title": r.get("title", ""), "html": r.get("body_snippet", "")}
        if r.get("tls"):
            assets.append({"kind": "cert", "value": r["tls"].get("subject_cn") or f"{ip}:{port}",
                           "meta": {"issuer": r["tls"].get("issuer_o") or r["tls"].get("issuer_cn"),
                                    "not_after": r["tls"].get("not_after"), "ip": ip}})
        try:
            fps = identify.fingerprint(ctx)
        except Exception:
            fps = []
        for fp in fps:
            disp = fp.get("product", "") + (f" {fp['version']}" if fp.get("version") else "")
            assets.append({"kind": "tech", "value": disp, "meta": {"ip": ip, "порт": port,
                                                                   "источник": fp.get("evidence", "")}})
            edges.append({"src": f"{ip}:{port}", "dst": fp["product"], "rel": "работает на"})
            if not fp.get("vendor") or not fp.get("cpe_product"):
                continue
            key = (fp["vendor"], fp["cpe_product"], fp.get("version", ""), ip, port)
            products.setdefault(key, {"product": fp["product"], "vendor": fp["vendor"],
                                      "cpe_product": fp["cpe_product"],
                                      "version": fp.get("version", ""), "ip": ip, "port": port,
                                      "evidence": fp.get("evidence", "")})
    _log(scan_id, f"Опознано продуктов: {len(products)}")
    return products, tech_map


def stage_active_checks(L, all_ips, assets, edges, host_to_ips, ip_ports, probe_results, scan_id):
    # ---------------------------------------------------- 5б. активная проверка
    nuclei_findings: list[dict] = []
    active_used: dict = {}
    operation_settings = _operation_settings(L)
    if L.get("active_scan") and active is not None:
        tools = active.available(settings=operation_settings)
        if tools["ports_ready"] or tools["ready"]:
            store.scan_progress(scan_id, "6/10 — активные проверки (порты, шаблоны)", 62)
            _log(scan_id, "АКТИВНЫЙ ЭТАП: порты (naabu) + проверки уязвимостей (nuclei). "
                          "Исключены агрессивные категории шаблонов (dos, fuzz, intrusive), "
                          "заданы лимиты скорости и времени.")
            # 1) порты
            if tools["ports_ready"]:
                for ip in all_ips[:L["max_active_targets"]]:
                    try:
                        # скорость не задаём: её берёт из профиля сам port_scan.
                        # Раньше здесь стояло 500, и это молча перебивало профиль.
                        ports = (engines.port_scan(
                                     ip, top_ports=int(_setting(L, "ASM_NAABU_TOP_PORTS", "1000")),
                                     timeout=int(_setting(L, "ASM_NAABU_TIMEOUT", "240")),
                                     settings=operation_settings,
                                 ) if engines else active.scan_ports(
                                     ip, top_ports=int(_setting(L, "ASM_NAABU_TOP_PORTS", "1000")),
                                     timeout=int(_setting(L, "ASM_NAABU_TIMEOUT", "240")),
                                     settings=operation_settings,
                                 ))
                    except Exception as e:
                        _log(scan_id, f"  naabu {ip}: ошибка {e}")
                        continue
                    ok, why = active.ports_plausible(ports, int(_setting(L, "ASM_NAABU_TOP_PORTS", "1000")))
                    if not ok:
                        _log(scan_id, f"  naabu {ip}: {why}")
                        ports = []
                    if ports:
                        active_used["ports"] = True
                        known = set(ip_ports.get(ip, []))
                        fresh = [p for p in ports if p not in known]
                        ip_ports[ip] = sorted(known | set(ports))
                        _log(scan_id, f"  naabu {ip}: открытых портов {len(ports)}"
                                      + (f", новых для индекса {len(fresh)}: {fresh[:12]}" if fresh else ""))
                        for p in fresh:
                            svc = identify.PORT_SERVICES.get(p, "?")
                            assets.append({"kind": "service", "value": f"{ip}:{p}",
                                           "meta": {"service": svc, "источник": "активное сканирование (naabu)"}})
                            edges.append({"src": ip, "dst": f"{ip}:{p}", "rel": "порт открыт",
                                          "meta": {"service": svc}})

            # 2) проверки уязвимостей по шаблонам
            if tools["ready"]:
                urls: list[str] = []
                for (ip, port), r in probe_results.items():
                    if r.get("status") and not r.get("error"):
                        scheme = "https" if port in (443, 8443, 9443) else "http"
                        urls.append(f"{scheme}://{ip}:{port}" if port not in (80, 443) else f"{scheme}://{ip}")
                for ip in all_ips[:L["max_active_targets"]]:
                    for h in [x for x, ips in host_to_ips.items() if ip in ips][:3]:
                        urls.append(f"https://{h}")
                        urls.append(f"http://{h}")
                urls = list(dict.fromkeys(urls))[:60]
                if urls:
                    profile_tags = (tools.get("profile") or {}).get("nuclei_tags")
                    if not profile_tags:
                        profile_tags = _setting(L, "ASM_NUCLEI_TAGS", None) or \
                            ("cve,exposure,misconfig,takeover,ssl,tech")
                    _log(scan_id, f"  nuclei: проверяем {len(urls)} адресов; шаблоны: "
                                  f"{profile_tags}; исключены проверки учётных данных и агрессивные категории")
                    try:
                        raw = (engines.vuln_scan(
                                   urls, timeout=int(_setting(L, "ASM_NUCLEI_TIMEOUT", "900")),
                                   settings=operation_settings,
                               ) if engines else active.scan_urls(
                                   urls, timeout=int(_setting(L, "ASM_NUCLEI_TIMEOUT", "900")),
                                   settings=operation_settings,
                               ))
                    except Exception as e:
                        raw = []
                        _log(scan_id, f"  nuclei: ошибка {e}")
                    # дедуп по (шаблон, адрес)
                    seen_tpl = set()
                    for r in raw:
                        k = (r["template_id"], r["matched_at"], r.get("matcher"))
                        if k in seen_tpl:
                            continue
                        seen_tpl.add(k)
                        nuclei_findings.append(r)
                    active_used["nuclei"] = True
                    active_used["urls"] = len(urls)
                    _log(scan_id, f"  nuclei: находок {len(nuclei_findings)}")
        else:
            _log(scan_id, "Активный этап пропущен: движки naabu/nuclei не найдены "
                          "(установка: bash bin/install-tools.sh). Пассивный анализ выполнен полностью.")
    else:
        _log(scan_id, "Активный этап отключён — выполнен только пассивный анализ.")
    return active_used, nuclei_findings


def stage_cve(L, all_ips, ip_cpes, ip_index_cves, ip_ports, products, raw_cve, scan_id):
    # ---------------------------------------------------- 6. CVE
    store.scan_progress(scan_id, "7/10 — сопоставление с базами уязвимостей (NVD/KEV/EPSS)", 72)
    _log(scan_id, "NVD: 1 запрос на продукт-версию, лимит 5 запросов/30 сек без ключа "
                  "(NVD_API_KEY ускоряет в 10 раз). Повторный анализ — из кэша.")

    cpe_jobs: list[tuple[str, str, str, str, str, str]] = []  # cpe23, display, ip, port, evidence, version
    seen_cpe: set[str] = set()

    # (A) CPE из публичного индекса — уже с версиями
    for ip in all_ips:
        for uri in ip_cpes.get(ip, []):
            cpe23 = cve.cpe23_from_cpe_uri(uri)
            if not cpe23 or cpe23 in seen_cpe:
                continue
            seen_cpe.add(cpe23)
            disp, _, _ = _pretty_cpe(uri)
            ver = cpe_version(uri)
            # порт берём только тот, что реально открыт и соответствует продукту
            port = identify.port_for_product(uri, ip_ports.get(ip, []))
            cpe_jobs.append((cpe23, disp, ip, port, f"CPE из публичного индекса: {uri}", ver))

    # (B) продукты, опознанные нашей пробой
    for (vendor, cpe_product, version, ip, port), info in products.items():
        cpe23 = cve.cpe23_from_cpe_uri(f"cpe:/a:{vendor}:{cpe_product}:{version}") if version \
            else f"cpe:2.3:a:{vendor}:{cpe_product}:*:*:*:*:*:*:*:*"
        if not version or cpe23 in seen_cpe:
            continue
        seen_cpe.add(cpe23)
        cpe_jobs.append((cpe23, f"{info['product']} {version}".strip(), ip, port,
                         info.get("evidence", ""), version))

    if len(cpe_jobs) > L["max_cpes"]:
        _log(scan_id, f"Лимит: обогащаем {L['max_cpes']} продуктов из {len(cpe_jobs)}")
        cpe_jobs = cpe_jobs[:L["max_cpes"]]

    def cve_lookup(job):
        cpe23, disp, ip, port, ev, ver = job
        try:
            got = cve.cves_for_cpe23(cpe23)
        except Exception as e:
            return job, [], str(e)
        return job, got, ""

    with ThreadPoolExecutor(max_workers=2) as ex:  # 2 потока * лимитер = мягко к NVD
        futs = [ex.submit(cve_lookup, j) for j in cpe_jobs]
        for f in as_completed(futs):
            job, got, err = f.result()
            cpe23, disp, ip, port, ev, ver = job
            if err:
                _log(scan_id, f"  {disp}: ошибка NVD ({err})")
            if got:
                _log(scan_id, f"  {disp} @ {ip}: {len(got)} CVE по версии {ver}")
            for g in got:
                g.update({"ip": ip, "port": port, "product": disp, "version": ver, "evidence": ev})
                raw_cve.append(g)
            # локальные правила для высокосигнальных версий
            for c in cve.curated_for(cpe23.split(":")[3], cpe23.split(":")[4], ver):
                if c["cve"] not in {g["cve_id"] for g in got}:
                    raw_cve.append({"cve_id": c["cve"], "cvss": c["cvss"], "severity": "CRITICAL",
                                    "vector": "", "description": c["note"], "published": "",
                                    "url": f"https://nvd.nist.gov/vuln/detail/{c['cve']}",
                                    "source": "curated", "ip": ip, "port": port, "product": disp,
                                    "version": ver, "evidence": ev})

    # (C) CVE из публичного индекса без версий — берём только те, что в KEV
    store.scan_progress(scan_id, "7/10 — проверка по CISA KEV", 78)
    index_cve_ids = sorted({c for ids in ip_index_cves.values() for c in ids})
    kev = cve.kev_lookup(index_cve_ids)
    for ip, ids in ip_index_cves.items():
        web_port = next((p for p in (443, 80, 8080, 8443) if p in ip_ports.get(ip, [])), None)
        for cid in ids:
            if cid in kev:
                raw_cve.append({"cve_id": cid, "cvss": None, "severity": "CRITICAL", "vector": "",
                                "description": "Уязвимость присутствует в публичном индексе баннеров "
                                               "и одновременно в CISA KEV (эксплуатация фиксируется).",
                                "url": f"https://nvd.nist.gov/vuln/detail/{cid}", "published": "",
                                "source": "internetdb+kev", "ip": ip, "port": web_port,
                                "product": "", "version": "", "evidence": "публичный индекс баннеров"})
    _log(scan_id, f"Связок CVE-объект до агрегации: {len(raw_cve)}")
    return cpe_jobs, seen_cpe


def stage_nmap_products(cpe_jobs, nmap_products, seen_cpe, tech_map):
    # --- продукты из nmap -sV: та же цепочка CPE -> NVD, что и у веб-технологий
    for info in nmap_products:
        prod = info["product"]
        ver = info.get("version") or ""
        vendor = cpe_product = ""
        key = prod.strip().lower()
        if key in tech_map:
            vendor, cpe_product = tech_map[key]
        else:
            for k, v in tech_map.items():
                if k and len(k) > 3 and (k in key or key in k):
                    vendor, cpe_product = v
                    break
        version = ver
        if not (vendor and cpe_product):
            cpe_uri = ""
            for c in info.get("cpe") or []:
                if c.startswith("cpe:/") or c.startswith("cpe:2.3:"):
                    cpe_uri = c
                    break
            if cpe_uri:
                cpe23 = cve.cpe23_from_cpe_uri(cpe_uri)
                if cpe23 and cpe23 not in seen_cpe:
                    seen_cpe.add(cpe23)
                    cpe_jobs.append((cpe23, prod, info["ip"], info.get("port"),
                                     f"nmap -sV определил CPE: {cpe_uri}", cpe_version(cpe_uri) if hasattr(cve, "cpe23_from_cpe_uri") else version))
                    continue
            continue
        if not version:
            continue
        cpe23 = cve.cpe23_from_cpe_uri(f"cpe:/a:{vendor}:{cpe_product}:{version}")
        if cpe23 in seen_cpe:
            continue
        seen_cpe.add(cpe23)
        cpe_jobs.append((cpe23, prod + " " + version, info["ip"], info.get("port"),
                         info.get("evidence", "nmap -sV"), version))


def stage_nuclei_findings(findings, nuclei_findings):
    # --- находки активных проверок (nuclei): подтверждённые проблемы
    for n in nuclei_findings:
        cve_ids = n.get("cve_ids") or []
        primary = cve_ids[0] if cve_ids else None
        kev_info = cve.kev_lookup([primary]) if primary else {}
        epss_val = cve.epss_lookup([primary]).get(primary) if primary else None
        vkev = "vkev" in [str(t).lower() for t in (n.get("tags") or [])]
        if vkev and not (primary in kev_info if primary else False):
            kev_info = dict(kev_info or {})
            kev_info[primary or n.get("template_id", "vkev")] = {
                "name": "Отмечено как эксплуатируемое в атаках (VulnCheck KEV, метка шаблона vkev)"}
        matched = n.get("matched_at") or n.get("host") or ""
        host, port = matched, None
        m = re.match(r"^(?:[a-z]+://)?([^/:]+)(?::(\d+))?", matched or "")
        if m:
            host = m.group(1)
            if m.group(2):
                port = int(m.group(2))
            elif matched.startswith("https"):
                port = 443
            elif matched.startswith("http"):
                port = 80
        if port is None and str(n.get("type") or "").lower() in ("network", "javascript"):
            try:
                port = int((n.get("raw") or {}).get("port") or 0) or None
            except Exception:
                port = None
        f = {
            "asset": matched or host,
            "ip": host,
            "port": port,
            "service": identify.PORT_SERVICES.get(port) if port else None,
            "product": None,
            "version": None,
            "cve_id": primary,
            "cvss": n.get("cvss"),
            "severity": n["severity"].upper(),
            "epss": epss_val,
            "kev": (primary in kev_info) if primary else bool(vkev),
            "kev_info": kev_info.get(primary or n.get("template_id", "vkev"), {}),
            "source_kind": "nuclei",
            "template_id": n.get("template_id"),
            "tags": n.get("tags"),
            "title": f"{n['name']}",
            "evidence": {
                "тип проверки": "активная проверка по шаблону nuclei (подтверждено ответом сервера)",
                "шаблон": n.get("template_id", ""),
                "адрес": matched,
                "категории": ", ".join(n.get("tags") or []),
                "описание": (n.get("description") or "")[:600],
                "что найдено": ", ".join(n.get("extracted") or [])[:300],
                "CWE": ", ".join(n.get("cwe") or []) if isinstance(n.get("cwe"), list) else str(n.get("cwe") or ""),
                "рекомендация авторов шаблона": (n.get("remediation") or "")[:400],
            },
        }
        findings.append(score.score_finding(f))


def stage_tool_findings(engine_findings, findings, scan_id):
    # --- находки движков арсенала (сертификаты, чувствительные адреса, скрытые пути)
    #
    # trivy и osv-scanner проверяют одни и те же lock-файлы и выдают одну и ту же
    # CVE по одному и тому же пакету. Без склейки в отчёте получаются две строки
    # об одной проблеме — а заказчик читает расхождение в количестве находок как
    # невнимательность. Совпадение при этом не выбрасываем молча: факт, что
    # проблему независимо подтвердили два сканера, повышает доверие к ней,
    # поэтому источник-подтверждение сохраняется в доказательствах.
    merged_ef, dupes = merge_engine_findings(engine_findings)

    for f in merged_ef:
        f.setdefault("evidence", {})
        f["evidence"].setdefault("источник", "движки арсенала (tlsx / katana / gau / ffuf)")
        findings.append(score.score_finding(f))

    if engine_findings:
        _log(scan_id, f"Дополнительные находки движков: {len(merged_ef)} "
                      f"(сертификаты, чувствительные адреса, скрытые пути)"
                      + (f"; склеено дублей между сканерами: {dupes}" if dupes else ""))


def stage_asset_criticality(findings, scan_id):
    # --- критичность активов из реестра заказчика (SSVC-подобный контекст)
    registry = store.registry_all()
    if registry:
        raised = 0
        for f in findings:
            keys = [f.get("asset") or "", (f.get("asset") or "").split(" (")[0],
                    (f.get("asset") or "").rsplit(":", 1)[0], f.get("ip") or ""]
            for k in keys:
                r = registry.get(k)
                if r and r.get("criticality"):
                    before = f.get("priority")
                    score.apply_criticality(f, r["criticality"])
                    if f.get("priority") != before:
                        raised += 1
                    break
        if raised:
            _log(scan_id, f"Реестр заказчика: приоритет изменён у {raised} находок")


def stage_remediation(findings):
    # --- к каждой находке прикладываем «как закрыть» (по-русски, с командами).
    # Если движок уже дал точный совет (например «обновить minimist до 1.2.6» или
    # «отозвать ключ»), он идёт первым пунктом, а общая база его дополняет.
    for f in findings:
        try:
            adv = remediate.advice(f)
        except Exception:
            adv = {"класс": "", "пункты": [], "команды": []}
        specific = f.get("fix")
        if isinstance(specific, str) and specific.strip():
            text = specific.strip()
            points = [text] + [p for p in (adv.get("пункты") or []) if p != text]
            adv = {**adv, "пункты": points[:9],
                   "класс": (adv.get("класс") or "") + (" · по данным движка" if adv.get("класс") else "")}
        f["fix"] = adv

    findings.sort(key=lambda x: (score.PRIORITY_ORDER.get(x.get("priority"), 9), -(x.get("score") or 0)))


def stage_changes(assets, findings, scan_id, tgt):
    # ---------------------------------------------------- 8. изменения
    store.scan_progress(scan_id, "9/10 — сравнение с предыдущим анализом", 93)
    prev_row = store.last_done_scan(tgt["id"], before_id=scan_id)
    prev = None
    if prev_row:
        prev = {"scan_id": prev_row["id"], "assets": store.scan_assets(prev_row["id"]),
                "findings": store.scan_findings(prev_row["id"])}
    cur = {"scan_id": scan_id, "assets": assets, "findings": findings}
    diffs = diff_scans(prev, cur)
    return cur, diffs, prev


def stage_history(all_ips, findings, host_to_ips, prev, scan_id):
    # --- сквозная история: что новое, что тянется, что закрылось
    prev_findings_all = list((prev or {}).get("findings") or [])
    prev_map: dict[tuple, dict] = {}
    for p in prev_findings_all:
        k = ((p.get("cve_id") or p.get("template_id") or p.get("title") or "")[:120], p.get("ip") or "")
        prev_map[k] = p
    scanned_hosts = set(all_ips) | set(host_to_ips.keys())
    for f in findings:
        f["evidence_hash"] = hashlib.sha1(json.dumps(f.get("evidence", {}), sort_keys=True,
                                                    ensure_ascii=False).encode("utf-8")).hexdigest()[:12]
        k = ((f.get("cve_id") or f.get("template_id") or f.get("title") or "")[:120], f.get("ip") or "")
        p = prev_map.get(k)
        if p:
            f["first_seen_scan"] = p.get("first_seen_scan") or p.get("scan_id")
            f["last_seen_scan"] = scan_id
            if p.get("status") in ("false", "accepted", "confirmed"):
                f["status"] = p["status"]
                f["status_note"] = p.get("status_note") or ""
            if p.get("owner"):
                f["owner"] = p["owner"]
        else:
            f["first_seen_scan"] = scan_id
            f["last_seen_scan"] = scan_id
    # закрылось само: находка была открыта, хост проверяли, находки больше нет
    auto_fixed = 0
    cur_keys = {((f.get("cve_id") or f.get("template_id") or f.get("title") or "")[:120], f.get("ip") or "")
                for f in findings}
    for p in prev_findings_all:
        k = ((p.get("cve_id") or p.get("template_id") or p.get("title") or "")[:120], p.get("ip") or "")
        if k in cur_keys or p.get("status") not in ("open", "confirmed"):
            continue
        if (p.get("ip") or "") in scanned_hosts and p.get("ip"):
            if store.set_finding_status(p["id"], "fixed", "закрыто по повторному анализу"):
                auto_fixed += 1
    if auto_fixed:
        _log(scan_id, f"Автоматически помечено закрытыми: {auto_fixed}")
    return auto_fixed


def stage_analytics(active_used, all_ips, assets, auto_fixed, cpe_jobs, cur, diffs, edges, engine_counts, engine_findings, est_sources, estate_warn, findings, ip_meta, ip_ports, products, related, scan_id, src_counts, src_errors, subs, tgt):
    # ---------------------------------------------------- 9. аналитика
    store.scan_progress(scan_id, "10/10 — аналитика", 97)
    report_data = ai.build(cur, tgt, assets, findings, ip_meta, diffs)

    store.save_assets(scan_id, assets)
    store.save_edges(scan_id, edges)
    store.save_findings(scan_id, findings)
    summ = score.summarize(findings)
    stats = {
        "assets": len(assets), "ips": len(all_ips), "subdomains": len(subs),
        "services": sum(len(v) for v in ip_ports.values()), "findings": len(findings),
        "priority": summ["counts"], "kev": summ["kev"], "report": report_data,
        "ip_meta": ip_meta, "diffs": diffs, "open_ports": sorted({p for v in ip_ports.values() for p in v}),
        "estate_sources": est_sources, "estate_warn": estate_warn, "auto_fixed": auto_fixed,
        "sources": src_counts, "source_errors": src_errors, "related_domains": related[:40],
        "engines": engine_counts, "engine_findings": len(engine_findings),
        "active": active_used, "cpe_tasks": len(cpe_jobs), "products": [{"product": v["product"], "version": v.get("version"),
                                                  "ip": v["ip"], "port": v["port"]}
                                                 for v in list(products.values())[:40]],
    }
    store.scan_finish(scan_id, "done", stats=stats)
    try:
        notify.notify_scan_finished(scan_id)
    except Exception as e:  # noqa: BLE001
        _log(scan_id, f"Уведомление не отправлено: {e}")
    if engine_counts:
        _log(scan_id, "Движки арсенала: " + ", ".join(f"{k}: {v}" for k, v in sorted(engine_counts.items())))
    _log(scan_id, f"Готово. Цифровых следов: {len(assets)}, находок: {len(findings)} "
                  f"(P0: {summ['counts']['P0']}, P1: {summ['counts']['P1']})")
