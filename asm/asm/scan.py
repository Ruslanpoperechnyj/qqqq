"""
Конвейер анализа. Здесь собирается всё вместе:

  1. Discover   — CT-логи -> поддомены (пассивно, объект не трогаем)
  2. Resolve    — DNS -> IP, группировка по подсетям
  3. Enrich IP  — InternetDB (открытые порты/CPE/CVE), RIPEstat (ASN/провайдер/страна)
  4. Probe      — лёгкая HTTP/TLS-проба по веб-портам (только периметр заказчика)
  5. Identify   — заголовки/meta/баннеры -> продукт+версия -> CPE
  6. CVE        — CPE-версия -> NVD (CVSS) + CISA KEV + FIRST EPSS
  7. Score      — приоритет защиты (P0..P3), агрегация по продукту
  8. Diff       — сравнение с прошлым анализом (мониторинг изменений)
  9. Report     — аналитика «Oracle» (правила + опционально LLM)
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

from .scan_helpers import NOISE, _interesting, _is_ip, _log, _pretty_cpe, cpe_version, diff_scans
from .stages import stage_active_checks, stage_analytics, stage_asset_criticality, stage_changes, stage_crawl_archives, stage_cve, stage_discovery_sources, stage_enrich_ip, stage_enrich_scoring, stage_expand_by_ip, stage_history, stage_identify, stage_live_fingerprints, stage_nikto, stage_nmap_products, stage_nuclei_findings, stage_org_nets, stage_probe_gap_fill, stage_probe_light, stage_remediation, stage_resolve_hosts, stage_reverse_ip, stage_secrets_code, stage_service_versions, stage_testssl, stage_tlsx_certs, stage_tool_findings, stage_wapiti, stage_web_httpx
from . import sources, store
from .settings import Settings, ScanSettings, use_settings
from .contracts import Asset, Finding, ProbeResult, ScanContext, StageResult, StageStatus

try:  # лучший бесплатный арсенал ИБ (nuclei, httpx, subfinder, naabu, tlsx, katana, ...)
    from . import engines
except Exception:  # noqa: BLE001 — без арсенала работает встроенный пассивный контур
    engines = None  # type: ignore

try:
    from . import active
except Exception:  # активный модуль опционален
    active = None  # type: ignore

# Compatibility constant for code which still imports scan.DEFAULTS. Unlike the
# former object, it contains schema defaults only; effective runtime settings are
# now captured explicitly when a scan is submitted or run.
DEFAULTS = ScanSettings().to_legacy_dict()


def _setting_for_scan(L: dict, name: str, default):
    settings = L.get("__settings__") if isinstance(L, dict) else None
    if settings is not None:
        getter = getattr(settings, "get", None)
        return getter(name, default) if callable(getter) else default
    return os.environ.get(name, default)


def run(scan_id: int, limits: dict | None = None, *,
        settings: Settings | None = None) -> None:
    """Запустить scan с неизменяемым snapshot конфигурации.

    ``limits`` сохраняет legacy-поведение для CLI/web callers и прочих полей,
    которые ещё не вошли в typed schema. Переданный Settings имеет приоритет
    как базовая конфигурация; при его отсутствии env читается здесь, а не при
    импорте модуля.
    """
    store.scan_mark_pid(scan_id)          # «паспорт процесса»: по нему видно, жив ли скан
    try:
        if settings is None:
            effective = Settings.from_environment_snapshot(os.environ)
        elif isinstance(settings, Settings):
            effective = settings
        else:
            raise TypeError("settings должен быть объектом Settings")
        L = effective.scan.to_legacy_dict()
        # Per-run snapshot is explicit input for all migrated stages/engines.
        L["__settings__"] = effective
        if limits:
            # None means "not supplied". False and zero are intentional per-scan
            # overrides (the web UI uses False to turn off active checks); dropping
            # them would silently restore a more permissive mode preset.
            L.update({k: v for k, v in limits.items() if v is not None})
        with use_settings(effective):
            _run(scan_id, L)
    except Exception as e:  # noqa: BLE001
        store.scan_log(scan_id, "ОШИБКА: " + str(e))
        store.scan_log(scan_id, traceback.format_exc()[-2000:])
        store.scan_finish(scan_id, "error", error=str(e))
    finally:
        store.scan_clear_pid(scan_id)


def _run_stage(ctx: ScanContext, name: str, fn, *args, skip_reason: str = "",
               partial_issues: tuple[str, ...] = (), **kwargs):
    """Call a legacy stage behind a typed, lossless result boundary.

    Exceptions are recorded as failed and re-raised unchanged; an explicit
    ``StageResult.failed`` is likewise fatal. Thus the envelope cannot turn an
    error into empty/successful output. A skipped
    legacy branch may still need to compute its compatibility return shape for
    the following stage; in that case the shape is retained in ``ctx.values``
    while the typed status correctly remains ``not_run``.
    """
    try:
        value = fn(*args, **kwargs)
    except Exception as exc:
        ctx.values[name] = None
        ctx.record_stage(name, StageResult.failed(type(exc).__name__))
        raise
    if isinstance(value, StageResult):
        ctx.record_stage(name, value)
        ctx.values[name] = value.value
        if value.status is StageStatus.FAILED:
            # A typed failure is still a failure boundary; do not let the caller
            # mistake its optional/empty value for successful stage output.
            raise RuntimeError(f"stage {name} returned a failed result")
        return value.value
    ctx.values[name] = value
    if skip_reason:
        result = StageResult.not_run(reason=skip_reason)
    elif partial_issues:
        result = StageResult.partial(value, issues=partial_issues)
    else:
        result = StageResult.ok(value)
    ctx.record_stage(name, result)
    return value


def _run(scan_id: int, L: dict) -> ScanContext:
    sc = store.scan(scan_id)
    tgt = store.target(sc["target_id"])
    if not tgt:
        raise RuntimeError("scan target is missing")
    root = str(tgt["value"])
    is_ip = tgt["kind"] == "ip"

    # One typed context owns the operation's mutable state. Normal scan entry
    # always carries a frozen Settings snapshot; a compatibility _run caller
    # without one gets a schema-default context but keeps legacy consumers on
    # their established environment path.
    operation_settings = L.get("__settings__")
    context_settings = operation_settings if isinstance(operation_settings, Settings) else Settings()
    ctx = ScanContext(
        scan_id=scan_id, target=dict(tgt), root=root, is_ip=is_ip,
        settings=context_settings,
    )
    assets = ctx.assets
    edges = ctx.edges
    ip_meta = ctx.ip_meta
    raw_cve = ctx.raw_cve
    engine_counts = ctx.engine_counts       # вклад движков арсенала
    engine_findings = ctx.engine_findings   # находки движков
    engines_status = ctx.engines_status
    ctx.values["limits"] = {k: v for k, v in L.items() if k != "__settings__"}

    # Явный профиль (pentest/full) поднимает скорости выше щадящих — пусть это
    # будет видно в журнале, а не выяснится из логов движков постфактум.
    if engines is not None:
        _profile_note = engines.profile_note(settings=operation_settings)
        if _profile_note:
            _log(scan_id, _profile_note)
    if engines and L.get("engines"):
        try:
            engines_status.update(engines.available(settings=operation_settings))
            ctx.values["engines_status"] = engines_status
            ctx.record_stage("engine_inventory", StageResult.ok(engines_status))
        except Exception as exc:
            engines_status.clear()
            ctx.record_stage("engine_inventory", StageResult.failed(type(exc).__name__))
    else:
        ctx.record_stage("engine_inventory", StageResult.not_run(reason="движки отключены"))

    discovery = _run_stage(
        ctx, "discovery_sources", stage_discovery_sources,
        L=L, assets=assets, edges=edges, engine_counts=engine_counts,
        is_ip=is_ip, root=root, scan_id=scan_id,
        skip_reason="для IP-цели доменная разведка не применяется" if is_ip else "",
    )
    name_src, src_counts, src_errors, subs = discovery
    if src_errors and not is_ip:
        ctx.record_stage("discovery_sources", StageResult.partial(
            discovery, issues=tuple(f"source:{name}" for name in sorted(src_errors)[:20])))

    expanded = _run_stage(
        ctx, "expand_by_ip", stage_expand_by_ip,
        L=L, assets=assets, edges=edges, is_ip=is_ip, name_src=name_src,
        root=root, scan_id=scan_id, src_counts=src_counts, src_errors=src_errors,
        subs=subs,
        skip_reason="расширение организации выключено" if not L.get("estate") else "",
    )
    est_sources, hosts, subs, estate_warn = expanded
    all_ips, host_to_ips = _run_stage(
        ctx, "resolve_hosts", stage_resolve_hosts,
        L=L, assets=assets, edges=edges, hosts=hosts, is_ip=is_ip,
        root=root, scan_id=scan_id,
    )
    reverse_on = bool(all_ips and "ipthc" in sources._enabled_ids(settings=operation_settings))
    related = _run_stage(
        ctx, "reverse_ip", stage_reverse_ip,
        L=L, all_ips=all_ips, assets=assets, edges=edges,
        est_sources=est_sources, host_to_ips=host_to_ips, name_src=name_src,
        root=root, scan_id=scan_id,
        skip_reason="нет IP-адресов или источник ip.thc.org выключен" if not reverse_on else "",
    )
    all_ips, estate_warn = _run_stage(
        ctx, "org_networks", stage_org_nets,
        L=L, assets=assets, edges=edges, is_ip=is_ip, root=root,
        scan_id=scan_id, all_ips=all_ips, estate_warn=estate_warn,
        skip_reason=("расширение по сетям ASN выключено" if not L.get("estate_asn")
                     else "нет отвечающих IP-адресов" if not all_ips else ""),
    )
    ip_cpes, ip_index_cves, ip_ports = _run_stage(
        ctx, "ip_enrichment", stage_enrich_ip,
        L=L, all_ips=all_ips, assets=assets, edges=edges, ip_meta=ip_meta,
        scan_id=scan_id,
        skip_reason="нет отвечающих IP-адресов" if not all_ips else "",
    )
    nmap_enabled = bool(engines and L.get("engines") and all_ips
                        and engines_status.get("nmap", {}).get("installed"))
    nmap_products = _run_stage(
        ctx, "service_versions", stage_service_versions,
        L=L, all_ips=all_ips, assets=assets, edges=edges,
        engine_counts=engine_counts, engines_status=engines_status,
        ip_ports=ip_ports, is_ip=is_ip, scan_id=scan_id,
        skip_reason="nmap выключен или не установлен" if not nmap_enabled else "",
    )
    probe_results, probes = _run_stage(
        ctx, "probe_plan", stage_probe_light,
        L=L, all_ips=all_ips, host_to_ips=host_to_ips, ip_ports=ip_ports,
        root=root, scan_id=scan_id,
    )
    _run_stage(
        ctx, "web_httpx", stage_web_httpx,
        engine_counts=engine_counts, engines_status=engines_status, hosts=hosts,
        probe_results=probe_results, scan_id=scan_id,
        settings=operation_settings,
        skip_reason=("httpx выключен или не установлен" if not engines_status.get("httpx", {}).get("installed")
                     else "нет хостов для httpx" if not hosts else ""),
    )
    _run_stage(
        ctx, "probe_gap_fill", stage_probe_gap_fill,
        L=L, engine_counts=engine_counts, probe_results=probe_results,
        probes=probes, scan_id=scan_id,
    )
    # Lossless contract adapter at the HTTP/TLS boundary: stage code and stored
    # payloads continue to use ordinary dictionaries.
    try:
        for key, payload in tuple(probe_results.items()):
            probe_results[key] = ProbeResult.from_legacy(payload).to_legacy()
    except Exception as exc:
        ctx.record_stage("probe_result_adapter", StageResult.failed(type(exc).__name__))
        raise
    else:
        ctx.record_stage("probe_result_adapter", StageResult.ok({"count": len(probe_results)}))
    ctx.values["probe_results"] = probe_results
    _run_stage(ctx, "live_fingerprints", stage_live_fingerprints,
               assets=assets, edges=edges, probe_results=probe_results)
    products, tech_map = _run_stage(
        ctx, "identify", stage_identify,
        assets=assets, edges=edges, probe_results=probe_results, scan_id=scan_id,
    )
    live_candidates = [row.get("url") for row in probe_results.values()
                       if row.get("url") and not row.get("error")]
    crawl_enabled = bool(engines and L.get("engines") and L.get("engine_crawl")
                         and live_candidates)
    live_urls = _run_stage(
        ctx, "crawl_archives", stage_crawl_archives,
        L=L, assets=assets, edges=edges, engine_counts=engine_counts,
        engine_findings=engine_findings, engines_status=engines_status,
        is_ip=is_ip, probe_results=probe_results, root=root, scan_id=scan_id,
        skip_reason="обход и архивы выключены или нет доступных веб-адресов" if not crawl_enabled else "",
    )
    tlsx_enabled = bool(engines and L.get("engines")
                        and engines_status.get("tlsx", {}).get("installed"))
    _run_stage(
        ctx, "tlsx_certs", stage_tlsx_certs,
        L=L, assets=assets, edges=edges, engine_counts=engine_counts,
        engine_findings=engine_findings, engines_status=engines_status,
        hosts=hosts, name_src=name_src, root=root, scan_id=scan_id,
        skip_reason="tlsx выключен или не установлен" if not tlsx_enabled else "",
    )
    nikto_enabled = bool(
        engines and L.get("engines") and engines_status.get("nikto", {}).get("installed")
        and _setting_for_scan(L, "ASM_NIKTO", "1") not in ("0", "false", "no")
        and live_urls
    )
    web_futures, web_pool = _run_stage(
        ctx, "nikto", stage_nikto,
        L=L, engine_counts=engine_counts, engine_findings=engine_findings,
        engines_status=engines_status, live_urls=live_urls, scan_id=scan_id,
        skip_reason="nikto выключен, не установлен или нет веб-адресов" if not nikto_enabled else "",
    )
    # Secret/code scanner implementation and secret value paths are expressly
    # left on their legacy route under the operator's Stage 4 waiver.
    _run_stage(
        ctx, "secrets_code", stage_secrets_code,
        L=L, engine_counts=engine_counts, engine_findings=engine_findings,
        engines_status=engines_status, scan_id=scan_id, tgt=tgt,
        sensitive=locals().get("sensitive", ()),
        skip_reason="движки выключены" if not L.get("engines") else "",
    )
    wapiti_enabled = bool(engines and L.get("engines")
                         and engines_status.get("wapiti", {}).get("installed")
                         and _setting_for_scan(L, "ASM_WAPITI", "1") not in ("0", "false", "no")
                         and live_urls)
    _run_stage(
        ctx, "wapiti", stage_wapiti,
        L=L, engine_counts=engine_counts, engine_findings=engine_findings,
        engines_status=engines_status, live_urls=live_urls, scan_id=scan_id,
        web_futures=web_futures, web_pool=web_pool,
        skip_reason="wapiti выключен, не установлен или нет веб-адресов" if not wapiti_enabled else "",
    )
    has_https_urls = any(re.match(r"https://[^/]+", url or "") for url in live_urls)
    testssl_enabled = bool(
        engines and L.get("engines") and engines_status.get("testssl", {}).get("installed")
        and _setting_for_scan(L, "ASM_TESTSSL", "1") not in ("0", "false", "no")
        and has_https_urls and int(_setting_for_scan(L, "ASM_TESTSSL_HOSTS", "2")) > 0
    )
    _run_stage(
        ctx, "testssl", stage_testssl,
        L=L, engine_counts=engine_counts, engine_findings=engine_findings,
        engines_status=engines_status, live_urls=live_urls, scan_id=scan_id,
        skip_reason="testssl выключен, не установлен или нет веб-адресов" if not testssl_enabled else "",
    )
    active_enabled = bool(L.get("active_scan") and active is not None)
    active_used, nuclei_findings = _run_stage(
        ctx, "active_checks", stage_active_checks,
        L=L, all_ips=all_ips, assets=assets, edges=edges,
        host_to_ips=host_to_ips, ip_ports=ip_ports,
        probe_results=probe_results, scan_id=scan_id,
        skip_reason="активные проверки выключены" if not active_enabled else "",
    )
    cpe_jobs, seen_cpe = _run_stage(
        ctx, "cve_matching", stage_cve,
        L=L, all_ips=all_ips, ip_cpes=ip_cpes, ip_index_cves=ip_index_cves,
        ip_ports=ip_ports, products=products, raw_cve=raw_cve, scan_id=scan_id,
    )
    findings = _run_stage(
        ctx, "enrich_scoring", stage_enrich_scoring,
        ip_ports=ip_ports, raw_cve=raw_cve, scan_id=scan_id,
    )
    _run_stage(ctx, "nmap_products", stage_nmap_products,
               cpe_jobs=cpe_jobs, nmap_products=nmap_products,
               seen_cpe=seen_cpe, tech_map=tech_map)
    _run_stage(ctx, "nuclei_findings", stage_nuclei_findings,
               findings=findings, nuclei_findings=nuclei_findings)
    _run_stage(ctx, "tool_findings", stage_tool_findings,
               engine_findings=engine_findings, findings=findings, scan_id=scan_id)
    _run_stage(ctx, "asset_criticality", stage_asset_criticality,
               findings=findings, scan_id=scan_id)
    _run_stage(ctx, "remediation", stage_remediation, findings=findings)
    cur, diffs, prev = _run_stage(
        ctx, "changes", stage_changes,
        assets=assets, findings=findings, scan_id=scan_id, tgt=tgt,
    )
    auto_fixed = _run_stage(
        ctx, "history", stage_history,
        all_ips=all_ips, findings=findings, host_to_ips=host_to_ips,
        prev=prev, scan_id=scan_id,
    )
    # Domain adapters validate the payloads at the persistence boundary while
    # preserving every legacy field, including provider-specific extensions.
    try:
        assets[:] = [Asset.from_legacy(item).to_legacy() for item in assets]
        findings[:] = [Finding.from_legacy(item).to_legacy() for item in findings]
    except Exception as exc:
        ctx.record_stage("legacy_payload_adapters", StageResult.failed(type(exc).__name__))
        raise
    else:
        ctx.record_stage("legacy_payload_adapters", StageResult.ok({
            "assets": len(assets), "findings": len(findings),
        }))
    _run_stage(
        ctx, "analytics_persistence", stage_analytics,
        active_used=active_used, all_ips=all_ips, assets=assets,
        auto_fixed=auto_fixed, cpe_jobs=cpe_jobs, cur=cur, diffs=diffs,
        edges=edges, engine_counts=engine_counts, engine_findings=engine_findings,
        est_sources=est_sources, estate_warn=estate_warn, findings=findings,
        ip_meta=ip_meta, ip_ports=ip_ports, products=products, related=related,
        scan_id=scan_id, src_counts=src_counts, src_errors=src_errors,
        subs=subs, tgt=tgt,
    )
    ctx.values["completed"] = True
    return ctx
