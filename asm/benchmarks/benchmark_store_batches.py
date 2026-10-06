#!/usr/bin/env python3
"""Synthetic, isolated benchmark for ASM's SQLite result-write APIs.

Example (from the project root):
    python3 benchmarks/benchmark_store_batches.py \
        --sizes 1000 10000 100000 --repeat 3 --label baseline \
        --output benchmarks/results/store-batch-baseline.json

Only generated `.invalid` hostnames and synthetic findings are written. Every
iteration gets a fresh SQLite file in a TemporaryDirectory; ASM_DB is set before
importing asm.store and restored before exit. No network or scanner is used.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


def percentile_nearest_rank(values: list[float], percentile: float) -> float:
    """Deterministic nearest-rank percentile, including for small sample counts."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def assets(n: int) -> list[dict]:
    return [
        {"kind": "host", "value": f"host-{i}.bench.invalid",
         "meta": {"index": i, "source": "synthetic-benchmark"}}
        for i in range(n)
    ]


def edges(n: int) -> list[dict]:
    return [
        {"src": f"host-{i}.bench.invalid", "dst": f"service-{i}.bench.invalid:443",
         "rel": "exposes", "meta": {"index": i, "port": 443}}
        for i in range(n)
    ]


def findings(n: int) -> list[dict]:
    return [
        {"asset": f"host-{i}.bench.invalid", "ip": "198.51.100.10", "port": 443,
         "service": "https", "product": "synthetic-server", "version": "1.0",
         "severity": "medium", "priority": "P2", "score": float(i % 100),
         "title": f"Synthetic configuration finding {i}",
         "rationale": "Generated solely for a local database benchmark.",
         "evidence": {"index": i, "fixture": "benchmark"},
         "fix": {"класс": "configuration", "шаг": "synthetic"},
         "source_kind": "benchmark", "status": "open"}
        for i in range(n)
    ]


def count_commits(conn, operation: Callable[[], None]) -> tuple[float, int]:
    commits = 0

    def trace(statement: str) -> None:
        nonlocal commits
        first = statement.strip().split(None, 1)
        if first and first[0].upper() == "COMMIT":
            commits += 1

    conn.set_trace_callback(trace)
    started = time.perf_counter()
    try:
        operation()
    finally:
        elapsed = time.perf_counter() - started
        conn.set_trace_callback(None)
    return elapsed, commits


def close_store_connection(store) -> None:
    """Закрыть соединение текущего benchmark-потока между БД."""
    store.close_current()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int,
                        default=[1000, 10000, 100000], help="rows per save API")
    parser.add_argument("--repeat", type=int, default=3, help="fresh-database runs per size")
    parser.add_argument("--label", default="run", help="baseline/after or other comparison label")
    parser.add_argument("--output", type=Path, help="optional JSON result path")
    args = parser.parse_args(argv)
    if args.repeat < 1 or any(size < 1 for size in args.sizes):
        parser.error("--repeat and every --sizes value must be positive")

    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    prior_asm_db = os.environ.get("ASM_DB")
    samples: list[dict] = []
    fts_available: bool | None = None
    with tempfile.TemporaryDirectory(prefix="asm-store-bench-") as tmp:
        first_db = Path(tmp) / "bootstrap.sqlite"
        os.environ["ASM_DB"] = str(first_db)
        try:
            from asm import store

            if Path(store.DB_PATH).resolve() != first_db.resolve():
                raise RuntimeError("benchmark refused: store.DB_PATH is not the temporary DB")

            api_specs = (
                ("assets", assets, store.save_assets, "assets"),
                ("edges", edges, store.save_edges, "edges"),
                ("findings", findings, store.save_findings, "findings"),
            )
            for size in args.sizes:
                for repeat in range(args.repeat):
                    close_store_connection(store)
                    db_path = Path(tmp) / f"case-{size}-{repeat}.sqlite"
                    store.DB_PATH = str(db_path)
                    target_id = store.add_target("benchmark.invalid", "synthetic", "local benchmark")
                    scan_id = store.new_scan(target_id)
                    has_fts = store._fts_ready()
                    if fts_available is None:
                        fts_available = has_fts
                    elif fts_available != has_fts:
                        raise RuntimeError("FTS5 availability changed between benchmark runs")
                    conn = store.connect()

                    for api_name, make_rows, save, table in api_specs:
                        rows = make_rows(size)  # preparation is intentionally outside the timer
                        elapsed, commits = count_commits(conn, lambda: save(scan_id, rows))
                        actual = conn.execute(
                            f"SELECT count(*) FROM {table} WHERE scan_id=?", (scan_id,)
                        ).fetchone()[0]
                        if actual != size:
                            raise AssertionError(
                                f"{api_name}: expected {size} rows, observed {actual}"
                            )
                        if api_name == "findings" and has_fts:
                            indexed = conn.execute(
                                "SELECT count(*) FROM findings_fts x JOIN findings f "
                                "ON f.id=x.rowid WHERE f.scan_id=?", (scan_id,)
                            ).fetchone()[0]
                            if indexed != size:
                                raise AssertionError(
                                    f"findings FTS: expected {size} rows, observed {indexed}"
                                )
                        samples.append({
                            "label": args.label, "size": size, "repeat": repeat + 1,
                            "api": api_name, "seconds": elapsed, "commits": commits,
                            "rows": actual, "fts5": has_fts if api_name == "findings" else None,
                        })
                        del rows
                    close_store_connection(store)
        finally:
            # Never leave a handle open while TemporaryDirectory removes its files.
            try:
                try:
                    close_store_connection(store)
                except (UnboundLocalError, NameError):
                    pass
            finally:
                if prior_asm_db is None:
                    os.environ.pop("ASM_DB", None)
                else:
                    os.environ["ASM_DB"] = prior_asm_db

    summary: dict[str, dict] = {}
    for size in args.sizes:
        per_size: dict[str, dict] = {}
        for api_name, *_ in api_specs:
            vals = [s["seconds"] for s in samples
                    if s["size"] == size and s["api"] == api_name]
            commits = sorted({s["commits"] for s in samples
                              if s["size"] == size and s["api"] == api_name})
            per_size[api_name] = {
                "runs": len(vals),
                "p50_ms": round(statistics.median(vals) * 1000, 3),
                "p95_ms_nearest_rank": round(percentile_nearest_rank(vals, 0.95) * 1000, 3),
                "commit_counts": commits,
            }
        summary[str(size)] = per_size

    report = {
        "label": args.label,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "sqlite": __import__("sqlite3").sqlite_version,
        "platform": platform.platform(),
        "database": "fresh SQLite file per run in a removed TemporaryDirectory",
        "fts5_available": fts_available,
        "sizes": summary,
        "samples": samples,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())