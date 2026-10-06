#!/usr/bin/env python3
"""Read-only disk-budget check for the ASM shelf.

This script never downloads or executes a tool. It sums regular-file logical
sizes under the selected roots, deduplicates overlapping roots and hardlinks,
and compares the result with the approved 225 decimal GB cap in
``data/tool_shelf_225gb.json``. Dynamic VM/Docker storage outside the project
must be passed explicitly with ``--root``.

Windows (PowerShell):
    py -3 bin\\check_shelf.py --root "$env:USERPROFILE\\VirtualBox VMs"

Git Bash:
    python3 bin/check_shelf.py --root "$HOME/VirtualBox VMs"
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data" / "tool_shelf_225gb.json"


def _file_key(path: Path, st: os.stat_result) -> tuple:
    """Identity for hardlink/path de-duplication on Windows and POSIX."""
    if getattr(st, "st_ino", 0):
        return ("inode", st.st_dev, st.st_ino)
    return ("path", os.path.normcase(os.path.abspath(os.fspath(path))))


def _files_under(path: Path) -> Iterable[Path]:
    """Yield regular files without following directory symlinks."""
    try:
        st = path.lstat()
    except OSError:
        return
    if path.is_symlink():
        return
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        return
    for current, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
        for name in files:
            candidate = Path(current) / name
            if candidate.is_symlink():
                continue
            yield candidate


def measure_roots(paths: list[tuple[str, Path]]) -> dict:
    """Measure regular files; overlapping roots and hardlinks count once."""
    seen: set[tuple] = set()
    entries: list[dict] = []
    total = 0
    file_count = 0
    errors: list[str] = []
    for label, root in paths:
        root = root.expanduser()
        if not root.exists():
            entries.append({"name": label, "path": str(root), "exists": False,
                            "bytes": 0, "files": 0})
            continue
        subtotal = 0
        subfiles = 0
        for path in _files_under(root):
            try:
                st = path.stat(follow_symlinks=False)
            except OSError as exc:
                errors.append(f"{path}: {exc}")
                continue
            if not path.is_file():
                continue
            key = _file_key(path, st)
            if key in seen:
                continue
            seen.add(key)
            size = max(0, int(st.st_size))
            subtotal += size
            subfiles += 1
        total += subtotal
        file_count += subfiles
        entries.append({"name": label, "path": str(root), "exists": True,
                        "bytes": subtotal, "files": subfiles})
    return {"total_bytes": total, "file_count": file_count,
            "roots": entries, "errors": errors}


def _human_bytes(value: int) -> str:
    gb = value / 1_000_000_000
    gib = value / (1024 ** 3)
    return f"{gb:,.2f} GB ({gib:,.2f} GiB)"


def load_manifest() -> dict:
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"не читается манифест {MANIFEST}: {exc}") from exc
    capacity = data.get("capacity") or {}
    limit = capacity.get("limit_bytes")
    if not isinstance(limit, int) or limit <= 0:
        raise RuntimeError("в манифесте нет корректного capacity.limit_bytes")
    return data


def default_roots(data: dict) -> list[tuple[str, Path]]:
    """Resolve declared defaults and environment overrides, without shell use."""
    out: list[tuple[str, Path]] = [("проект ASM", ROOT)]
    for item in data.get("storage_roots") or []:
        env = item.get("env")
        default = item.get("default_path")
        if not default or default == "operator-selected":
            continue
        value = os.environ.get(env, "") if env else ""
        candidate = Path(value).expanduser() if value else Path(default)
        if not candidate.is_absolute():
            candidate = ROOT / candidate
        # The project root already contains the default build/tools, model, and
        # wordlist paths. Add only environment overrides outside that tree.
        try:
            candidate.resolve().relative_to(ROOT.resolve())
            inside_project = True
        except (OSError, ValueError):
            inside_project = False
        if not inside_project:
            out.append((item.get("id") or "external", candidate))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", default=[], metavar="PATH",
                        help="additional VM, Docker, model, or external tool-storage root; repeatable")
    parser.add_argument("--expected-gb", type=float, default=0.0, metavar="GB",
                        help="planned addition; fail if it would exceed 225 GB or target-volume free space")
    parser.add_argument("--target", default=str(ROOT), metavar="PATH",
                        help="volume/path where the planned addition would be stored (default: project root)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)
    if args.expected_gb < 0:
        parser.error("--expected-gb must be non-negative")
    try:
        data = load_manifest()
    except RuntimeError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1

    paths = default_roots(data)
    for n, value in enumerate(args.root, start=1):
        paths.append((f"дополнительный корень {n}", Path(value)))
    measured = measure_roots(paths)
    limit = data["capacity"]["limit_bytes"]
    expected_bytes = int(args.expected_gb * 1_000_000_000)
    projected = measured["total_bytes"] + expected_bytes
    target = Path(args.target).expanduser()
    if not target.is_absolute():
        target = Path.cwd() / target
    probe = target
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        target_free = shutil.disk_usage(probe).free
        free_error = ""
    except OSError as exc:
        target_free = None
        free_error = str(exc)
    target_has_space = (target_free is not None and target_free >= expected_bytes)
    target_space_unverified = expected_bytes > 0 and target_free is None
    insufficient_free_space = expected_bytes > 0 and not target_has_space
    result = {
        "limit_bytes": limit,
        "used_bytes": measured["total_bytes"],
        "expected_addition_bytes": expected_bytes,
        "projected_bytes": projected,
        "remaining_bytes": max(0, limit - projected),
        "over_limit": projected > limit,
        "target_path": str(target),
        "target_volume_probe": str(probe),
        "target_free_bytes": target_free,
        "target_has_space_for_expected_addition": target_has_space,
        "target_space_unverified": target_space_unverified,
        "insufficient_free_space": insufficient_free_space,
        "target_free_error": free_error,
        "file_count": measured["file_count"],
        "roots": measured["roots"],
        "errors": measured["errors"],
        "measurement": "regular-file logical sizes; overlapping roots/hardlinks counted once; symlinks not followed",
        "caveat": "VM and Docker data outside listed roots are not discovered automatically; pass their storage paths with --root."
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("Проверка полки ASM (только чтение; программы не запускаются)")
        for item in result["roots"]:
            state = "есть" if item["exists"] else "нет"
            print(f"  {state:3}  {item['name']}: {item['path']} — "
                  f"{_human_bytes(item['bytes'])}, файлов: {item['files']}")
        print(f"Итого: {_human_bytes(result['used_bytes'])} из "
              f"{_human_bytes(limit)}; остаток после плана: {_human_bytes(result['remaining_bytes'])}")
        if expected_bytes:
            print(f"Планируемое добавление: {_human_bytes(expected_bytes)}; "
                  f"после него: {_human_bytes(projected)}")
            if target_free is None:
                print("СТОП: свободное место на целевом томе проверить не удалось: " + free_error)
            else:
                print(f"Свободно на целевом томе ({probe}): {_human_bytes(target_free)}")
                if insufficient_free_space:
                    print("СТОП: запрошенный пакет не помещается на целевой том.")
        print("Учёт: перекрывающиеся пути и hardlinks считаются один раз; "
              "symlink не обходятся.")
        print("ПРИМЕЧАНИЕ: пути VM/Docker вне перечисленных корней не обнаруживаются; "
              "передайте их через --root.")
        if measured["errors"]:
            print(f"Предупреждений чтения: {len(measured['errors'])}")
            for error in measured["errors"][:5]:
                print("  · " + error)
        print("ПРЕДУПРЕЖДЕНИЕ: слабый словарь weakpass_2a исключён и скриптом не ищется.")
    if result["over_limit"]:
        return 2
    if insufficient_free_space:
        return 3
    if measured["errors"] or target_space_unverified:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
