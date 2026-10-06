#!/usr/bin/env python3
"""Сравнить планы и время ключевых SQLite-запросов до/после schema v2 indexes.

Работает только во временной БД. Для каждого размера создаёт синтетические данные,
снимает baseline с набором индексов до v2, применяет штатную миграцию и сверяет
результаты запросов побайтно по значениям. Никаких сетевых вызовов нет.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEGACY_INDEXES = (
    "CREATE INDEX idx_agent_steps_session ON agent_steps(session_id)",
    "CREATE INDEX idx_handover_placed_session ON handover_placed(session_id)",
    "CREATE INDEX idx_agent_plans_session ON agent_plans(session_id)",
    "CREATE INDEX idx_agent_notes_session ON agent_notes(session_id)",
    "CREATE INDEX idx_agent_chat_session ON agent_chat(session_id)",
    "CREATE INDEX idx_attachments_target ON attachments(target_id)",
    "CREATE INDEX idx_assets_scan ON assets(scan_id)",
    "CREATE INDEX idx_edges_scan ON edges(scan_id)",
    "CREATE INDEX idx_findings_scan ON findings(scan_id)",
)


def _query_specs(size: int) -> dict[str, tuple[str, tuple[Any, ...]]]:
    session_id = 1
    scan_id = 1
    cve_id = f"CVE-{max(1, size // 2):08d}"
    return {
        "scans_by_target": (
            "SELECT id, target_id FROM scans WHERE target_id=? ORDER BY id DESC", (1,)),
        "last_done_scan": (
            "SELECT id, status FROM scans WHERE target_id=? AND status='done' "
            "ORDER BY id DESC LIMIT 1", (1,)),
        "stale_scans": (
            "SELECT id FROM scans WHERE status='running'", ()),
        "findings_by_scan_score": (
            "SELECT id, score FROM findings WHERE scan_id=? ORDER BY score DESC", (scan_id,)),
        "pending_steps_by_sequence": (
            "SELECT id, seq FROM agent_steps WHERE session_id=? AND status=? ORDER BY seq",
            (session_id, "proposed")),
        "all_agent_steps_by_sequence": (
            "SELECT id, seq FROM agent_steps WHERE session_id=? ORDER BY seq",
            (session_id,)),
        "chat_history": (
            "SELECT id, role FROM chats WHERE scan_id=? AND element=? ORDER BY id DESC LIMIT ?",
            (scan_id, "main", 40)),
        "views_for_scan": (
            "SELECT id FROM views WHERE scan_id=? ORDER BY id DESC", (scan_id,)),
        "open_agent_sessions": (
            "SELECT s.id, t.value FROM agent_sessions s "
            "LEFT JOIN targets t ON t.id=s.target_id "
            "WHERE s.status='open' ORDER BY s.id DESC LIMIT 50", ()),
        "kb_refinement_lookup": (
            "SELECT id FROM kb_refinements WHERE cve_id=? AND part=? AND vendor=? "
            "AND product=? AND v_start=? AND v_end=?",
            (cve_id, "a", "vendor", "product", "1.0", "2.0")),
    }


def _insert_rows(conn: sqlite3.Connection, size: int) -> None:
    conn.executemany(
        "INSERT INTO targets(id,value,kind,client,auth_ref) VALUES(?,?,?,?,?)",
        [(i, f"target-{i}", "domain", "synthetic", "benchmark") for i in range(1, 101)])
    conn.executemany(
        "INSERT INTO scans(id,target_id,started_at,status) VALUES(?,?,?,?)",
        ((i, 1 + (i - 1) % 100, "2026-01-01",
          "running" if i % 1000 == 0 else "done") for i in range(1, size + 1)))
    conn.executemany(
        "INSERT INTO findings(id,scan_id,score,title) VALUES(?,?,?,?)",
        ((i, 1 + (i - 1) % 100, float(i), f"finding-{i}")
         for i in range(1, size * 2 + 1)))
    conn.executemany(
        "INSERT INTO agent_sessions(id,target_id,status) VALUES(?,?,?)",
        ((i, 1 + (i - 1) % 100, "open" if i % 100 == 0 else "closed")
         for i in range(1, size + 1)))
    conn.executemany(
        "INSERT INTO agent_steps(id,session_id,seq,action_id,cls,status) "
        "VALUES(?,?,?,?,?,?)",
        ((i, 1 + (i - 1) % 100, i, f"action-{i}", "read",
          "proposed" if i % 3 == 0 else "done") for i in range(1, size * 2 + 1)))
    conn.executemany(
        "INSERT INTO chats(id,scan_id,element,role,content) VALUES(?,?,?,?,?)",
        ((i, 1 + (i - 1) % 100, "main" if i % 2 == 1 else "detail", "user", f"chat-{i}")
         for i in range(1, size * 2 + 1)))
    conn.executemany(
        "INSERT INTO views(id,scan_id,name,state) VALUES(?,?,?,?)",
        ((i, 1 + (i - 1) % 100, f"view-{i}", "{}") for i in range(1, size * 2 + 1)))
    conn.executemany(
        "INSERT INTO kb_refinements(id,cve_id,part,vendor,product,v_start,v_end) "
        "VALUES(?,?,?,?,?,?,?)",
        ((i, f"CVE-{i:08d}", "a", "vendor", "product", "1.0", "2.0")
         for i in range(1, size + 1)))
    conn.commit()


def _explain(conn: sqlite3.Connection, sql: str, args: tuple[Any, ...]) -> str:
    return " | ".join(str(row[3]) for row in conn.execute("EXPLAIN QUERY PLAN " + sql, args))


def _results(conn: sqlite3.Connection, specs: dict[str, tuple[str, tuple[Any, ...]]]
             ) -> dict[str, list[tuple]]:
    return {name: [tuple(row) for row in conn.execute(sql, args)]
            for name, (sql, args) in specs.items()}


def _storage_pages(conn: sqlite3.Connection) -> dict[str, int]:
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    free_pages = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    return {
        "page_count": page_count,
        "page_size_bytes": page_size,
        "allocated_bytes": page_count * page_size,
        "free_pages": free_pages,
    }


def _measure(conn: sqlite3.Connection, specs: dict[str, tuple[str, tuple[Any, ...]]],
             repeat: int) -> dict[str, dict]:
    measured: dict[str, dict] = {}
    for name, (sql, args) in specs.items():
        samples: list[float] = []
        row_count = 0
        for _ in range(repeat + 1):
            started = time.perf_counter()
            rows = conn.execute(sql, args).fetchall()
            elapsed = time.perf_counter() - started
            row_count = len(rows)
            samples.append(elapsed)  # first pass warms SQLite's page cache
        # Exclude the first of repeat+1 executions as a warm-up.
        measured[name] = {
            "runs": repeat,
            "p50_ms": round(statistics.median(samples[1:]) * 1000, 3),
            "rows": row_count,
            "plan": _explain(conn, sql, args),
        }
    return measured


def _run_case(store, size: int, repeat: int, root: Path) -> dict:
    db_path = root / f"index-{size}.sqlite"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        store._initialize_schema(conn)

        # Recreate the deployed pre-v2 index set after initializing canonical columns.
        index_names = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL").fetchall()]
        for name in index_names:
            conn.execute(f'DROP INDEX "{name}"')
        for ddl in LEGACY_INDEXES:
            conn.execute(ddl)
        conn.execute("PRAGMA user_version = 1")
        _insert_rows(conn, size)
        conn.execute("ANALYZE")

        specs = _query_specs(size)
        storage_before = _storage_pages(conn)
        before_rows = _results(conn, specs)
        before = _measure(conn, specs, repeat)

        # The standard versioned path performs the v1 -> v2 index migration.
        store._initialize_schema(conn)
        conn.execute("ANALYZE")
        storage_after = _storage_pages(conn)
        after_rows = _results(conn, specs)
        if after_rows != before_rows:
            raise AssertionError(f"size {size}: query rows changed after index migration")
        after = _measure(conn, specs, repeat)
        return {
            "size": size, "rows_equal": True,
            "storage_before": storage_before, "storage_after": storage_after,
            "before": before, "after": after,
        }
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[1000, 10000, 100000])
    parser.add_argument("--repeat", type=int, default=5, help="measured runs after warm-up")
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    args = parser.parse_args(argv)
    if args.repeat < 1 or any(size < 1 for size in args.sizes):
        parser.error("--repeat and every --sizes value must be positive")

    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from asm import store

    with tempfile.TemporaryDirectory(prefix="asm-store-index-bench-") as tmp:
        cases = [_run_case(store, size, args.repeat, Path(tmp)) for size in args.sizes]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "platform": platform.platform(),
        "database": "temporary SQLite file per size; removed after run",
        "method": "legacy-index baseline vs standard schema-v2 migration; warm p50; exact result equality",
        "repeat": args.repeat,
        "cases": cases,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
