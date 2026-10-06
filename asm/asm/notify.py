# -*- coding: utf-8 -*-
"""Уведомления о завершённом анализе: Telegram или webhook.

Настраивается переменными окружения (по умолчанию выключено — ничего наружу не уходит):
    ASM_TG_TOKEN   — токен бота Telegram
    ASM_TG_CHAT    — чат/канал, куда писать
    ASM_WEBHOOK_URL — либо обычный webhook: туда уйдёт POST с JSON

Отправка — «best effort»: сбой уведомления не влияет на результат анализа.
"""
from __future__ import annotations

import json
import os
import urllib.request

from . import store


def enabled() -> bool:
    return bool((os.environ.get("ASM_TG_TOKEN") and os.environ.get("ASM_TG_CHAT"))
                or os.environ.get("ASM_WEBHOOK_URL"))


def scan_text(sid: int) -> str:
    sc = dict(store.scan(sid) or {})
    tgt = dict(store.target(sc.get("target_id")) or {})
    fs = store.scan_findings(sid)
    st = json.loads(sc.get("stats") or "{}")
    diffs = st.get("diffs") or {}
    p = {k: sum(1 for f in fs if f.get("priority") == k) for k in ("P0", "P1", "P2", "P3")}
    new = len(diffs.get("new_findings") or []) if not diffs.get("first_scan") else len(fs)
    fixed = len(diffs.get("fixed_findings") or []) if not diffs.get("first_scan") else 0
    top = [f for f in fs if f.get("priority") == "P0"][:3]
    lines = [
        f"Анализ периметра завершён: {tgt.get('value','')} (скан №{sid})",
        f"Находки: {len(fs)} · P0 {p['P0']} · P1 {p['P1']} · P2 {p['P2']} · P3 {p['P3']}",
        f"Новых: {new} · закрыто с прошлого раза: {fixed}",
    ]
    for f in top:
        lines.append(f"• {f.get('title','')[:110]}")
    if not top:
        lines.append("Критичных (P0) проблем нет.")
    return "\n".join(lines)


def send(text: str) -> tuple[bool, str]:
    token, chat = os.environ.get("ASM_TG_TOKEN", ""), os.environ.get("ASM_TG_CHAT", "")
    hook = os.environ.get("ASM_WEBHOOK_URL", "")
    try:
        if token and chat:
            data = json.dumps({"chat_id": chat, "text": text, "disable_web_page_preview": True},
                              ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage",
                                         data=data, headers={"Content-Type": "application/json"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=20) as r:
                return True, f"telegram: {r.status}"
        if hook:
            data = json.dumps({"text": text}, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(hook, data=data, headers={"Content-Type": "application/json"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=20) as r:
                return True, f"webhook: {r.status}"
        return False, "не настроено (ASM_TG_TOKEN/ASM_TG_CHAT или ASM_WEBHOOK_URL)"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def notify_scan_finished(sid: int) -> None:
    if not enabled():
        return
    ok, info = send(scan_text(sid))
    store.audit("notify", {"scan_id": sid, "ok": ok, "info": info})
