# tools/seed-hard.py — восстанавливает стенд «сложной задачи» для проверки ответов модели.
#
# Зачем: ответ модели на knowledge/prompts/hard-task.md проверяется командой
#     python3 app.py --set ASM_DB=data/hard-task.sqlite agent check 1 --file <ответ>
# Для этого нужна база с одной целью, одним сканом (22 дня назад) и кэшем NVD/KEV/EPSS
# по двум версиям: СУП-Панель 2.4.1 (CVE-2026-1188 — применима) и Jetty 9.4.51
# (CVE-2026-2044 — НЕ применима, уязвимы <= 9.4.50). Сеть при проверке не нужна.
#
# Запуск:  python3 tools/seed-hard.py            → data/hard-task.sqlite (перезапишет)
#          ASM_DB=/tmp/x.sqlite python3 tools/seed-hard.py
#
# База крошечная (~160 КБ) и лежит в рабочей копии, так что проверка ответа
# работает без восстановления. Скрипт нужен, если файл потерян или испорчен.
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DB = Path(os.environ.get("ASM_DB") or (ROOT / "data" / "hard-task.sqlite"))
if DB.exists():
    DB.unlink()
    print(f"старая база удалена: {DB}")
DB.parent.mkdir(parents=True, exist_ok=True)
os.environ["ASM_DB"] = str(DB)

from asm import agent, store  # noqa: E402  (после правки ASM_DB — так и задумано)

store.connect()
tid = store.add_target("panel.example", "Заказчик", "договор 9/2026")
sid = agent.open_session(tid, "Оператор", "сложная задача — стенд для проверки ответов модели")
scan_id = store.new_scan(tid)
store.save_findings(scan_id, [
    {"asset": "panel.example", "ip": "10.20.4.11", "port": 8080, "service": "http",
     "product": "СУП-Панель", "version": "2.4.1", "severity": "critical",
     "title": "СУП-Панель 2.4.1 — обход аутентификации по отчёту сканера",
     "source_kind": "nuclei"},
    {"asset": "panel.example", "ip": "10.20.4.11", "port": 8080, "service": "http",
     "product": "Jetty", "version": "9.4.51", "severity": "high",
     "title": "Jetty 9.4.51 (бэкенд панели)", "source_kind": "http"},
])
store.scan_finish(scan_id, "done")
old = (datetime.now(timezone.utc) - timedelta(days=22)).isoformat(timespec="seconds")
store.ex("UPDATE scans SET started_at=?, finished_at=? WHERE id=?", (old, old, scan_id))

# То, что конвейер уже спрашивал у NVD по этим версиям (кэш, без сети):
store.cache_put("nvd:cpe23:cpe:2.3:a:atlasops:sup_panel:2.4.1:*:*:*:*:*:*:*", {"vulnerabilities": [{"cve": {
    "id": "CVE-2026-1188", "published": "2026-04-02T00:00:00.000",
    "configurations": [{"nodes": [{"cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:atlasops:sup_panel:*:*:*:*:*:*:*:*",
        "versionEndIncluding": "2.4.1"}]}]}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]})
store.cache_put("nvd:cpe23:cpe:2.3:a:eclipse:jetty:9.4.51:*:*:*:*:*:*:*", {"vulnerabilities": [{"cve": {
    "id": "CVE-2026-2044", "published": "2026-05-11T00:00:00.000",
    "configurations": [{"nodes": [{"cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:eclipse:jetty:*:*:*:*:*:*:*:*",
        "versionEndIncluding": "9.4.50"}]}]}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]})
store.cache_put("kev:index", {"CVE-2026-1188": {"name": "atlasops", "ransomware": "Known"}})
store.cache_put("epss:CVE-2026-1188", 0.72)

print(f"готово: {DB}")
print(f"цель {tid}, сессия {sid}, скан {scan_id}")
print("дальше:  python3 app.py --set ASM_DB=" + str(DB) + " agent facts 1")
