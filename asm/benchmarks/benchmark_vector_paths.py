#!/usr/bin/env python3
"""Profile the current cross-scan vector-memory paths in an isolated SQLite DB.

Example (from the project root):
    python3 benchmarks/benchmark_vector_paths.py \
        --sizes 1000 10000 100000 --repeat 3 --output \
        benchmarks/results/vector-path-baseline.json

The benchmark creates only synthetic `.bench.invalid` data. Each size runs in a
fresh subprocess and TemporaryDirectory so peak RSS is attributable to that
case and an inherited ASM_DB is never opened. No scanner, network, model, or
external vector extension is used. A deterministic 16-dimensional fixture
keeps the 100k case below the sandbox memory ceiling; this is a path/overhead
baseline, not a claim about production latency or full-dimension memory use.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import sqlite3
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Any

DIM_DEFAULT = 16
INDEX_METHOD = "benchmark-deterministic-v1"


def percentile_nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _peak_rss_bytes() -> int | None:
    try:
        import resource
        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # Linux/BSD report KiB; macOS reports bytes. Windows has no resource module.
        return value if sys.platform == "darwin" else value * 1024
    except (ImportError, AttributeError, OSError, ValueError):
        return None


def _vector_index(text: str, dim: int) -> int:
    low = (text or "").lower()
    if "directory" in low or "catalog" in low or "каталог" in low:
        return 0
    if "tls" in low:
        return 1 % dim
    return 2 % dim


def _vector_blob(text: str, dim: int) -> bytes:
    values = [0.0] * dim
    values[_vector_index(text, dim)] = 1.0
    return struct.pack(f"<{dim}f", *values)


def _seed_database(store, vector, size: int, dim: int) -> tuple[int, int]:
    conn = store.connect()
    scan_count = min(size, 100, max(2, size // 10))
    targets = (
        (i, f"target-{i}.bench.invalid", "domain", f"Synthetic client {i}", "benchmark")
        for i in range(1, scan_count + 1)
    )
    conn.executemany(
        "INSERT INTO targets(id,value,kind,client,auth_ref) VALUES(?,?,?,?,?)", targets)
    conn.executemany(
        "INSERT INTO scans(id,target_id,started_at,finished_at,status) VALUES(?,?,?,?,?)",
        ((i, i, "2026-01-01T00:00:00+00:00", "2026-01-01T00:01:00+00:00", "done")
         for i in range(1, scan_count + 1)))

    per_scan = (size + scan_count - 1) // scan_count

    def finding_rows():
        for fid in range(1, size + 1):
            scan_id = min(scan_count, 1 + (fid - 1) // per_scan)
            local_id = fid - 1 - (scan_id - 1) * per_scan
            cohort = "open directory" if local_id % 2 == 0 else "outdated tls"
            title = (f"Open directory on synthetic asset {fid}" if local_id % 2 == 0
                     else f"Outdated TLS on synthetic asset {fid}")
            priority = "P0" if local_id == 0 else ("P1" if local_id < 4 else "P2")
            status = ("false" if local_id == 0 else "fixed" if local_id == 1 else "open")
            evidence = json.dumps(
                {"cohort": cohort, "local": local_id, "fixture": "vector-benchmark"},
                ensure_ascii=False, separators=(",", ":"))
            yield (fid, scan_id, f"host-{fid}.bench.invalid", "synthetic-server", "https",
                   priority, float(size - fid), title,
                   "Generated only for a local performance benchmark.", evidence,
                   "{}", "benchmark", "configuration", status)

    conn.executemany(
        "INSERT INTO findings(id,scan_id,asset,product,service,priority,score,title,"
        "rationale,evidence,fix,source_kind,kind,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        finding_rows())

    # Prime the vector tables with deterministic rows so measured calls exercise
    # the existing read/rank path rather than spending time embedding the corpus.
    vector._ensure_meta(conn)
    vector._ensure_tables(conn, dim)

    def metadata_rows():
        cursor = conn.execute(
            "SELECT id,scan_id,title,product,service,asset,evidence FROM findings ORDER BY id")
        for fid, scan_id, title, product, service, asset, evidence in cursor:
            finding = {
                "title": title, "product": product, "service": service, "asset": asset,
                "evidence": json.loads(evidence or "{}"),
            }
            text = vector._text_full(finding)
            yield (int(fid), int(scan_id), dim, vector._text_hash(text), INDEX_METHOD)

    conn.executemany(
        "INSERT INTO sem_meta(finding_id,scan_id,dim,text_hash,how) VALUES(?,?,?,?,?)",
        metadata_rows())

    def vector_rows():
        cursor = conn.execute(
            "SELECT id,scan_id,title FROM findings ORDER BY id")
        for fid, scan_id, title in cursor:
            yield (int(scan_id), int(fid), dim, "", _vector_blob(title, dim))

    conn.executemany(
        "INSERT INTO sem(scan_id,finding_id,dim,text,vec) VALUES(?,?,?,?,?)", vector_rows())
    conn.commit()
    return scan_count, per_scan


def _instrumented_call(vector, operation: Callable[[], Any]) -> tuple[Any, dict[str, int]]:
    counts = {
        "all_findings_calls": 0,
        "all_findings_rows": 0,
        "vectors_cached_calls": 0,
        "vectors_cached_candidate_ids": 0,
        "read_stored_calls": 0,
        "read_stored_vector_rows": 0,
    }
    originals = {
        "all": vector._all_findings,
        "cached": vector._vectors_cached,
        "stored": vector._read_stored,
    }

    def all_findings():
        counts["all_findings_calls"] += 1
        result = originals["all"]()
        counts["all_findings_rows"] += len(result)
        return result

    def vectors_cached(findings):
        counts["vectors_cached_calls"] += 1
        counts["vectors_cached_candidate_ids"] += len(findings)
        return originals["cached"](findings)

    def read_stored(conn):
        counts["read_stored_calls"] += 1
        result = originals["stored"](conn)
        counts["read_stored_vector_rows"] += len(result[0])
        return result

    vector._all_findings = all_findings
    vector._vectors_cached = vectors_cached
    vector._read_stored = read_stored
    try:
        return operation(), counts
    finally:
        vector._all_findings = originals["all"]
        vector._vectors_cached = originals["cached"]
        vector._read_stored = originals["stored"]


def _search_signature(result: dict) -> list[dict]:
    return [
        {"finding_id": int(row["finding"]["id"]), "score": row["score"],
         "words": row["words"], "client": row["client"]}
        for row in result.get("results", [])
    ]


def _notes_signature(result: list[dict]) -> list[dict]:
    return [
        {"finding_id": int(note["finding_id"]),
         "hits": [{"scan_id": int(hit["scan_id"]), "title": hit["title"],
                   "score": hit["score"], "client": hit["client"],
                   "status": hit["status"]} for hit in note.get("hits", [])]}
        for note in result
    ]


def _measure_path(vector, name: str, operation: Callable[[], Any],
                  signature: Callable[[Any], Any], repeat: int) -> dict:
    warm_result, warm_counts = _instrumented_call(vector, operation)
    expected = signature(warm_result)
    del warm_result

    samples: list[float] = []
    first_counts: dict[str, int] | None = None
    for _ in range(repeat):
        started = time.perf_counter()
        result, counts = _instrumented_call(vector, operation)
        samples.append(time.perf_counter() - started)
        current = signature(result)
        if current != expected:
            raise AssertionError(f"{name}: ordered result signature changed between runs")
        if first_counts is None:
            first_counts = counts
        del result

    return {
        "warmup": 1,
        "runs": repeat,
        "p50_ms": round(statistics.median(samples) * 1000, 3),
        "p95_ms_nearest_rank": round(percentile_nearest_rank(samples, 0.95) * 1000, 3),
        "results_stable_across_runs": True,
        "per_measured_call_counts": first_counts or warm_counts,
        "ordered_result_signature": expected,
    }


def _worker(size: int, repeat: int, dim: int) -> dict:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    with tempfile.TemporaryDirectory(prefix=f"asm-vector-bench-{size}-") as tmp:
        os.environ["ASM_DB"] = str(Path(tmp) / "vector.sqlite")
        from asm import store, vector

        # The benchmark must never invoke a local model or depend on sqlite-vec.
        old_embed = vector.embed
        old_how_key = vector._how_key
        old_vec_loader = vector._load_vec_ext

        def benchmark_embed(texts: list[str]) -> tuple[list[list[float]], str]:
            vectors = []
            for text in texts:
                values = [0.0] * dim
                values[_vector_index(text, dim)] = 1.0
                vectors.append(values)
            return vectors, INDEX_METHOD

        vector.embed = benchmark_embed
        vector._how_key = lambda: INDEX_METHOD
        vector._load_vec_ext = lambda _conn: False
        try:
            scan_count, per_scan = _seed_database(store, vector, size, dim)
            database_bytes = os.path.getsize(os.environ["ASM_DB"])
            rss_before = _peak_rss_bytes()
            search_path = _measure_path(
                vector, "search_all",
                lambda: vector.search_all("open directory", k=12),
                _search_signature, repeat)
            notes_path = _measure_path(
                vector, "notes_for_scan",
                lambda: vector.notes_for_scan(1, limit=4, per_finding=2),
                _notes_signature, repeat)
            rss_after = _peak_rss_bytes()
        finally:
            vector.embed = old_embed
            vector._how_key = old_how_key
            vector._load_vec_ext = old_vec_loader
            store.close_all()

        rss_delta = (max(0, rss_after - rss_before)
                     if rss_before is not None and rss_after is not None else None)
        return {
            "findings": size,
            "scans": scan_count,
            "targets": scan_count,
            "findings_per_scan_approx": per_scan,
            "embedding_dimension": dim,
            "database_bytes": database_bytes,
            "search_all": search_path,
            "notes_for_scan": notes_path,
            "peak_rss_before_mib": round(rss_before / (1024 * 1024), 2)
            if rss_before is not None else None,
            "peak_rss_after_mib": round(rss_after / (1024 * 1024), 2)
            if rss_after is not None else None,
            "peak_rss_delta_mib": round(rss_delta / (1024 * 1024), 2)
            if rss_delta is not None else None,
            "temporary_database_removed": True,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[1000, 10000, 100000])
    parser.add_argument("--repeat", type=int, default=3,
                        help="timed runs after one warm-up; p95 uses nearest rank")
    parser.add_argument("--dim", type=int, default=DIM_DEFAULT,
                        help="synthetic vector dimension (default: 16 to bound memory)")
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    parser.add_argument("--worker-size", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.repeat < 1 or args.dim < 2 or any(size < 2 for size in args.sizes):
        parser.error("--repeat must be positive; --dim and every size must be at least 2")

    if args.worker_size is not None:
        print(json.dumps(_worker(args.worker_size, args.repeat, args.dim), ensure_ascii=False))
        return 0

    project_root = Path(__file__).resolve().parents[1]
    cases = []
    for size in args.sizes:
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--worker-size", str(size),
             "--repeat", str(args.repeat), "--dim", str(args.dim)],
            cwd=project_root, check=True, capture_output=True, text=True)
        cases.append(json.loads(completed.stdout))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "platform": platform.platform(),
        "database": "fresh SQLite file in a per-size subprocess TemporaryDirectory",
        "isolation": "ASM_DB overridden before importing asm; inherited database is not opened",
        "network_scanner_model": "none; deterministic embed and fallback SQLite vector table only",
        "method": ("one warm-up plus timed calls; p50 median; p95 nearest-rank; "
                   "ordered result signatures checked for repeatability; resource peak RSS "
                   "measured over the combined search_all then notes_for_scan sequence"),
        "peak_rss_scope": ("per-size process delta after both paths; not attributed to one "
                           "function individually"),
        "repeat": args.repeat,
        "embedding_dimension": args.dim,
        "dimension_caveat": ("Synthetic compact dimension chosen to safely run 100k findings "
                              "within the sandbox; memory is not representative of 384D vectors."),
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
