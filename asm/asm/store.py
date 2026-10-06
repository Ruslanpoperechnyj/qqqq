"""
Хранилище: SQLite + кэш внешних API + журнал аудита.

Идея 1:1 как в оригинале: сначала собираем и КЭШИРУЕМ «цифровые следы»,
потом анализ идёт за секунды, потому что данные уже под рукой.
"""
from __future__ import annotations

import atexit
import itertools
import json
import os
import re
import sqlite3
import threading
import weakref
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from .settings import current_settings

DB_PATH = os.environ.get("ASM_DB", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "asm.sqlite"))
SCHEMA_VERSION = 2

# Один sqlite3.Connection принадлежит одному потоку. Глобальная блокировка
# координирует инициализацию схемы и DDL FTS, но не оборачивает обычные запросы.
_lock = threading.RLock()
_conn_local = threading.local()
_connections_lock = threading.Lock()
_connections: dict[int, tuple[sqlite3.Connection, weakref.finalize]] = {}
_connection_ids = itertools.count(1)
_schema_paths: set[str] = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  value TEXT NOT NULL,
  kind TEXT NOT NULL,
  client TEXT NOT NULL,
  auth_ref TEXT NOT NULL,
  auth_date TEXT,
  note TEXT,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL,
  started_at TEXT, finished_at TEXT,
  status TEXT DEFAULT 'running',
  progress TEXT, log TEXT, error TEXT, stats TEXT
);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER, kind TEXT, value TEXT, meta TEXT
);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER, src TEXT, dst TEXT, rel TEXT, meta TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER, asset TEXT, ip TEXT, port INTEGER, service TEXT,
  product TEXT, version TEXT,
  cve_id TEXT, cvss REAL, severity TEXT, epss REAL, kev INTEGER DEFAULT 0,
  priority TEXT, score REAL, title TEXT, rationale TEXT, evidence TEXT,
  fix TEXT, fix_class TEXT, source_kind TEXT, kind TEXT
);
CREATE TABLE IF NOT EXISTS cache (
  key TEXT PRIMARY KEY, payload TEXT, fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS registry (
  value TEXT PRIMARY KEY, kind TEXT, criticality TEXT, exposure TEXT, owner TEXT,
  tags TEXT, note TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, element TEXT,
  role TEXT, content TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS schedule (
  target_id INTEGER PRIMARY KEY, interval_hours INTEGER DEFAULT 24, enabled INTEGER DEFAULT 1,
  last_run TEXT, next_run TEXT
);
CREATE TABLE IF NOT EXISTS views (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, name TEXT, state TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS layout (
  scan_id INTEGER, node TEXT, x REAL, y REAL, PRIMARY KEY(scan_id, node)
);
CREATE TABLE IF NOT EXISTS kv (
  k TEXT PRIMARY KEY, v TEXT
);
CREATE TABLE IF NOT EXISTS kb_refinements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL, part TEXT DEFAULT 'a', vendor TEXT, product TEXT NOT NULL,
  v_start TEXT, v_end TEXT, note TEXT, operator TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS agent_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL, operator TEXT, note TEXT,
  status TEXT DEFAULT 'open', created_at TEXT, closed_at TEXT,
  deadline TEXT, stopped_by TEXT, stop_note TEXT
);
CREATE TABLE IF NOT EXISTS agent_steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL, seq INTEGER,
  action_id TEXT NOT NULL, cls TEXT NOT NULL,
  title TEXT, params TEXT, rationale TEXT, risk TEXT,
  reversible INTEGER DEFAULT 1,
  status TEXT DEFAULT 'proposed',
  decided_by TEXT, decided_at TEXT, decision_note TEXT,
  started_at TEXT, finished_at TEXT, result TEXT, error TEXT
);
-- Пакет передачи доступа. Колонки под секрет здесь НЕТ и не должно быть:
-- не «мы не сохраняем», а «сохранить некуда». Пароль, ключ и хеш передаются
-- лично, а этот документ остаётся у заказчика на годы.
CREATE TABLE IF NOT EXISTS handover_access (
  session_id INTEGER PRIMARY KEY,
  account TEXT, privilege TEXT, host TEXT, method TEXT, verify TEXT, note TEXT,
  created_at TEXT, updated_at TEXT
);
-- Что перенесено на объект. Без этого списка уборка после работ держится
-- на памяти, а через два месяца работы по объекту память подводит.
CREATE TABLE IF NOT EXISTS handover_placed (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,
  file TEXT NOT NULL, host TEXT, path TEXT, note TEXT,
  placed_at TEXT, removed INTEGER DEFAULT 0, removed_at TEXT
);
-- Журнал планов: чем планировали и что предложили. Нужен не для отчётности,
-- а для сравнения: план модели и план правил лежат рядом, и видно, что именно
-- добавила модель. Без этого «модель планирует лучше» проверить нечем.
CREATE TABLE IF NOT EXISTS agent_plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL, source TEXT NOT NULL,
  note TEXT, plan TEXT, created_at TEXT
);
-- Память решений сессии. Не «история ради истории»: без неё модель в новом
-- круге не знает, что оператор уже запретил или решил, и предлагает это снова.
-- Здесь же живут цели словами заказчика и запреты («эту панель не трогать»).
CREATE TABLE IF NOT EXISTS agent_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,
  kind TEXT NOT NULL, source TEXT, text TEXT, created_at TEXT
);
-- Диалог сессии. Не «чат ради чата»: без истории разговор начинается заново
-- каждый раз, а решения (что решили, чем обосновали) теряются между кругами.
-- kind: "оператор" | "агент" | "инструмент" | "шаг" — в ленте это разные вещи.
CREATE TABLE IF NOT EXISTS agent_chat (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,
  role TEXT NOT NULL, kind TEXT, text TEXT, meta TEXT, created_at TEXT
);
-- Бюджет работ: сколько объект может выдержать и сколько нам нужно. Живёт
-- рядом с сессией, меняется сам (супервизор) в записанных границах, и каждое
-- изменение причины словами — в журнале. Колонки цифр и основание отдельно:
-- через неделю «почему стояло 18 шума» иначе не восстановить.
CREATE TABLE IF NOT EXISTS agent_budget (
  session_id INTEGER PRIMARY KEY,
  hosts INTEGER, steps_per_hour INTEGER, noise_per_hour INTEGER, files_at_once INTEGER,
  bounds TEXT, usage TEXT, why TEXT, note TEXT, updated_at TEXT
);
-- Вложения: файлы и фото объекта. Лежат у цели, а не в общем каталоге: забрать
-- их (отдать через пакет передачи или показать в отчёте) можно только вместе
-- с объектом, случайно не приложишь.
CREATE TABLE IF NOT EXISTS attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL, session_id INTEGER DEFAULT 0,
  name TEXT NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL,
  size INTEGER DEFAULT 0, sha256 TEXT DEFAULT '', note TEXT, created_at TEXT
);
"""


# --- характер находки
# `source_kind` отвечает на вопрос «кто нашёл» (nuclei, tls, secret, code), и он
# бывает пустым: находка из ассетов или ручная. Для отчёта и фильтров нужен
# ответ на другой вопрос — «что это по существу»: уязвимость, конфигурация,
# открытый наружу сервис, секрет в файле, проблема в коде или в зависимостях.
KIND_BY_SOURCE = {
    "nuclei": "vulnerability", "engine": "vulnerability", "wapiti": "vulnerability",
    "cve": "vulnerability", "tls": "configuration", "exposure": "exposure",
    "secret": "secret", "code": "code", "sast": "code",
    "deps": "dependencies", "image": "dependencies", "iac": "configuration",
}
KIND_LABELS = {
    "vulnerability": "уязвимости", "configuration": "конфигурация",
    "exposure": "открытые наружу сервисы", "secret": "секреты в файлах",
    "code": "код приложения", "dependencies": "зависимости и образы",
    "other": "прочее",
}


def finding_kind(f: dict) -> str:
    """Характер находки: что это по существу, а не чем найдено."""
    kind = str(f.get("kind") or "").strip()
    if kind:
        return kind
    return KIND_BY_SOURCE.get(str(f.get("source_kind") or "").strip(), "other")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _schema_key(path: str) -> str | None:
    # `:memory:` создаёт отдельную схему на соединение — её нельзя кэшировать по пути.
    return None if path == ":memory:" else os.path.abspath(path)


def _read_schema_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _initialize_schema(conn: sqlite3.Connection) -> None:
    """Создать базовые таблицы и применить последовательные schema migrations."""
    version = _read_schema_version(conn)
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"База имеет schema version {version}, приложение поддерживает только "
            f"{SCHEMA_VERSION}; откат версии схемы запрещён"
        )

    # executescript сам управляет транзакцией здесь; явная граница не оставляет
    # частично созданный базовый набор таблиц при DDL-ошибке.
    try:
        conn.executescript("BEGIN IMMEDIATE;\n" + SCHEMA + "\nCOMMIT;")
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise
    _apply_schema_migrations(conn)


def _close_registered_connection(token: int) -> None:
    with _connections_lock:
        entry = _connections.pop(token, None)
    if entry is not None:
        conn, _ = entry
        try:
            conn.close()
        except sqlite3.Error:
            pass


def close_current() -> None:
    """Закрыть соединение потока, если он больше не обслуживает работу."""
    state = getattr(_conn_local, "state", None)
    if state is None:
        return
    try:
        state["finalizer"].detach()
    finally:
        try:
            del _conn_local.state
        except AttributeError:
            pass
        _close_registered_connection(state["token"])


def close_all() -> None:
    """Закрыть все зарегистрированные соединения при остановке/в тестовой уборке.

    Вызывать после остановки рабочих потоков; SQLite connections созданы с
    `check_same_thread=False`, чтобы shutdown мог закрыть и их владельцев.
    """
    with _connections_lock:
        entries = list(_connections.values())
        _connections.clear()
    try:
        del _conn_local.state
    except AttributeError:
        pass
    for conn, finalizer in entries:
        finalizer.detach()
        try:
            conn.close()
        except sqlite3.Error:
            pass


def connect() -> sqlite3.Connection:
    """Соединение SQLite, принадлежащее текущему потоку.

    Повторный вызов в потоке возвращает тот же handle; другой поток получает
    свой. Глобальный lock используется только при первом создании схемы.
    """
    path = DB_PATH
    key = _schema_key(path)
    state = getattr(_conn_local, "state", None)
    if state is not None and state["path"] != path:
        close_current()
        state = None
    if state is not None:
        return state["conn"]

    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        with _lock:
            if key is None or key not in _schema_paths:
                _initialize_schema(conn)
                if key is not None:
                    _schema_paths.add(key)
    except BaseException:
        conn.close()
        raise

    token = next(_connection_ids)
    finalizer = weakref.finalize(threading.current_thread(),
                                 _close_registered_connection, token)
    with _connections_lock:
        _connections[token] = (conn, finalizer)
    _conn_local.state = {"path": path, "conn": conn, "token": token,
                         "finalizer": finalizer}
    return conn


atexit.register(close_all)


def _backfill_kinds(conn: sqlite3.Connection) -> None:
    """Проставить характер находки там, где строка сохранена до этой колонки.

    Досчитываем один раз: строк без характера в базе быть не должно, иначе
    отчёт по характеру находок молча теряет старые данные.
    """
    rows = conn.execute("SELECT id, source_kind FROM findings "
                        "WHERE kind IS NULL OR kind = ''").fetchall()
    for r in rows:
        kind = KIND_BY_SOURCE.get(str(r["source_kind"] or "").strip(), "other")
        conn.execute("UPDATE findings SET kind=? WHERE id=?", (kind, r["id"]))


def _migration_v1_add_legacy_columns(conn: sqlite3.Connection) -> None:
    """Добавить поля, появившиеся после ранних баз, и один раз досчитать kind."""
    additions = (
        # score belongs to the original findings shape and is also required by
        # the v2 read-path index; keep partial pre-versioned databases usable.
        ("findings", "score", "REAL"),
        ("findings", "status", "TEXT DEFAULT 'open'"),
        ("findings", "status_note", "TEXT"),
        ("findings", "owner", "TEXT"),
        ("findings", "first_seen_scan", "INTEGER"),
        ("findings", "last_seen_scan", "INTEGER"),
        ("findings", "evidence_hash", "TEXT"),
        ("assets", "source", "TEXT"),
        ("findings", "fix", "TEXT"),
        ("findings", "fix_class", "TEXT"),
        ("findings", "source_kind", "TEXT"),
        ("findings", "kind", "TEXT"),
        ("targets", "materials", "TEXT"),
        ("agent_sessions", "deadline", "TEXT"),
        ("agent_sessions", "stopped_by", "TEXT"),
        ("agent_sessions", "stop_note", "TEXT"),
    )
    columns_by_table: dict[str, set[str]] = {}
    for table, column, definition in additions:
        columns = columns_by_table.get(table)
        if columns is None:
            columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
            if not columns:
                raise RuntimeError(f"schema migration expected table {table!r}")
            columns_by_table[table] = columns
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            columns.add(column)
    _backfill_kinds(conn)


def _migration_v2_query_indexes(conn: sqlite3.Connection) -> None:
    """Пересоздать индексы по подтверждённым EXPLAIN-планам."""
    index_names = (
        # Убираем прежние single-column индексы, заменённые составными.
        "idx_agent_steps_session",
        "idx_agent_steps_session_seq",
        "idx_agent_steps_session_status_seq",
        "idx_handover_placed_session",
        "idx_agent_plans_session",
        "idx_agent_notes_session",
        "idx_agent_chat_session",
        "idx_attachments_target",
        "idx_assets_scan",
        "idx_edges_scan",
        "idx_findings_scan",
        "idx_scans_target_id_desc",
        "idx_scans_status",
        "idx_findings_scan_score",
        "idx_chats_scan_element_id_desc",
        "idx_views_scan_id_desc",
        "idx_agent_sessions_status_id_desc",
        "idx_kb_refinements_signature",
    )
    for name in index_names:
        conn.execute(f'DROP INDEX IF EXISTS "{name}"')

    indexes = (
        "CREATE INDEX idx_agent_steps_session_seq ON agent_steps(session_id, seq)",
        "CREATE INDEX idx_agent_steps_session_status_seq "
        "ON agent_steps(session_id, status, seq)",
        "CREATE INDEX idx_handover_placed_session ON handover_placed(session_id)",
        "CREATE INDEX idx_agent_plans_session ON agent_plans(session_id)",
        "CREATE INDEX idx_agent_notes_session ON agent_notes(session_id)",
        "CREATE INDEX idx_agent_chat_session ON agent_chat(session_id)",
        "CREATE INDEX idx_attachments_target ON attachments(target_id)",
        "CREATE INDEX idx_assets_scan ON assets(scan_id)",
        "CREATE INDEX idx_edges_scan ON edges(scan_id)",
        "CREATE INDEX idx_findings_scan ON findings(scan_id)",
        "CREATE INDEX idx_scans_target_id_desc ON scans(target_id, id DESC)",
        "CREATE INDEX idx_scans_status ON scans(status)",
        "CREATE INDEX idx_findings_scan_score ON findings(scan_id, score DESC)",
        "CREATE INDEX idx_chats_scan_element_id_desc "
        "ON chats(scan_id, element, id DESC)",
        "CREATE INDEX idx_views_scan_id_desc ON views(scan_id, id DESC)",
        "CREATE INDEX idx_agent_sessions_status_id_desc "
        "ON agent_sessions(status, id DESC)",
        "CREATE INDEX idx_kb_refinements_signature "
        "ON kb_refinements(cve_id, part, vendor, product, v_start, v_end)",
    )
    for ddl in indexes:
        conn.execute(ddl)


_SCHEMA_MIGRATIONS = {
    1: _migration_v1_add_legacy_columns,
    2: _migration_v2_query_indexes,
}


def _apply_schema_migrations(conn: sqlite3.Connection) -> None:
    version = _read_schema_version(conn)
    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"База имеет schema version {version}, приложение поддерживает только "
            f"{SCHEMA_VERSION}; обновите приложение"
        )
    while version < SCHEMA_VERSION:
        next_version = version + 1
        migration = _SCHEMA_MIGRATIONS.get(next_version)
        if migration is None:
            raise RuntimeError(f"для schema version {next_version} нет миграции")
        conn.execute("BEGIN IMMEDIATE")
        try:
            locked_version = _read_schema_version(conn)
            if locked_version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"База имеет schema version {locked_version}, приложение "
                    f"поддерживает только {SCHEMA_VERSION}"
                )
            if locked_version >= next_version:
                conn.commit()  # другой процесс успел применить эту миграцию
                version = locked_version
                continue
            if locked_version != version:
                raise RuntimeError(
                    f"schema version изменилась с {version} на {locked_version} "
                    "во время миграции"
                )
            migration(conn)
            conn.execute(f"PRAGMA user_version = {next_version}")
            conn.commit()
            version = next_version
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise


def q(sql: str, args: Iterable = ()) -> list[sqlite3.Row]:

    return connect().execute(sql, tuple(args)).fetchall()


def one(sql: str, args: Iterable = ()):
    rows = q(sql, args)
    return rows[0] if rows else None


def ex(sql: str, args: Iterable = ()) -> int:
    c = connect()
    cur = c.execute(sql, tuple(args))
    c.commit()
    return cur.lastrowid


# ---------------------------------------------------------------- кэш API
def cache_get(key: str, ttl_sec: int):
    row = one("SELECT payload, fetched_at FROM cache WHERE key=?", (key,))
    if not row:
        return None
    try:
        ts = datetime.fromisoformat(row["fetched_at"])
    except Exception:
        return None
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    if age > ttl_sec:
        return None
    try:
        return json.loads(row["payload"])
    except Exception:
        return None


def cache_peek(key: str) -> dict | None:
    """Запись кэша вместе с датой получения — без срока годности.

    `cache_get` на просроченной записи возвращает None, и по нему нельзя
    отличить «мы этого не знаем» от «знали, но давно». Слою сверки сведений
    (`facts`) это различие нужно каждый день: первое честно даёт вердикт
    «не подтверждено», второе — «данные устарели, обновить». Поэтому здесь
    кэш читается сырым, а срок годности решает вызывающий.
    """
    row = one("SELECT payload, fetched_at FROM cache WHERE key=?", (key,))
    if not row:
        return None
    try:
        payload = json.loads(row["payload"])
    except Exception:
        payload = None
    return {"payload": payload, "fetched_at": row["fetched_at"] or ""}


def cache_put(key: str, payload: Any) -> None:
    ex(
        "INSERT INTO cache(key, payload, fetched_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET payload=excluded.payload, fetched_at=excluded.fetched_at",
        (key, json.dumps(payload, ensure_ascii=False), now()),
    )


def cache_drop(key_prefix: str) -> None:
    ex("DELETE FROM cache WHERE key LIKE ?", (key_prefix + "%",))


# ---------------------------------------------------------------- аудит
def audit(action: str, detail: Any) -> None:
    ex("INSERT INTO audit(ts, action, detail) VALUES(?,?,?)",
       (now(), action, json.dumps(detail, ensure_ascii=False)))


# ---------------------------------------------------------------- targets / scans
def add_target(value: str, client: str, auth_ref: str, auth_date: str = "", note: str = "") -> int:
    value = value.strip().lower().rstrip(".")
    kind = "ip" if value.replace(".", "").isdigit() else "domain"
    tid = ex(
        "INSERT INTO targets(value, kind, client, auth_ref, auth_date, note, created_at) VALUES(?,?,?,?,?,?,?)",
        (value, kind, client, auth_ref, auth_date, note, now()),
    )
    audit("target_added", {"target": value, "client": client, "auth_ref": auth_ref})
    return tid


def target(tid: int):
    return one("SELECT * FROM targets WHERE id=?", (tid,))


def targets() -> list[sqlite3.Row]:
    return q("SELECT * FROM targets ORDER BY id DESC")


def set_materials(tid: int, materials: dict) -> None:
    """Материалы заказчика для проверки кода: репозиторий, каталог, образ контейнера."""
    clean = {k: str(v).strip() for k, v in (materials or {}).items() if str(v or "").strip()}
    ex("UPDATE targets SET materials=? WHERE id=?", (json.dumps(clean, ensure_ascii=False) if clean else None, tid))
    audit("materials_set", {"target_id": tid, "materials": clean})


def target_materials(tid: int) -> dict:
    row = one("SELECT materials FROM targets WHERE id=?", (tid,))
    if not row or not row["materials"]:
        return {}
    try:
        data = json.loads(row["materials"])
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


PID_DIR = os.path.join(os.path.dirname(DB_PATH), "build", "scan-pids")


def _pid_file(sid: int) -> str:
    return os.path.join(PID_DIR, f"{sid}.pid")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def scan_mark_pid(sid: int) -> None:
    """Записать «паспорт процесса» скана. Для скана, запущенного из панели, это процесс панели:
    если панель перезапустят, паспорт останется от мёртвого процесса — что и нужно."""
    try:
        os.makedirs(PID_DIR, exist_ok=True)
        with open(_pid_file(sid), "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))
    except OSError:
        pass


def scan_clear_pid(sid: int) -> None:
    try:
        os.remove(_pid_file(sid))
    except OSError:
        pass


def mark_stale_scans() -> list[int]:
    """Пометить прерванными только те сканы, чей процесс ДЕЙСТВИТЕЛЬНО мёртв.

    Раньше здесь помечались все сканы в статусе «идёт» — и живой скан, запущенный в фоне,
    обрывался панелью на старте. Теперь проверяем «паспорт процесса»: если процесс жив,
    скан продолжается; если паспорта нет вовсе (старые записи) — считаем прерванным."""
    db = connect()
    rows = [dict(r) for r in db.execute("SELECT id FROM scans WHERE status='running'")]
    ids = []
    for r in rows:
        pf = _pid_file(r["id"])
        if os.path.exists(pf):
            try:
                with open(pf, encoding="utf-8") as fh:   # иначе дескриптор течёт (ResourceWarning)
                    pid = int(fh.read().strip() or "0")
            except (OSError, ValueError):
                pid = 0
            if pid and _alive(pid):
                continue          # скан идёт прямо сейчас — не трогаем
        ids.append(r["id"])
        db.execute("UPDATE scans SET status='interrupted', finished_at=? WHERE id=?",
                   (now(), r["id"]))
        scan_log(r["id"], "скан прерван: процесс не пережил перезапуск (запустите заново)")
        try:
            os.remove(pf)
        except OSError:
            pass
    if ids:
        db.commit()
    return ids


def new_scan(target_id: int) -> int:
    return ex("INSERT INTO scans(target_id, started_at, status, progress, log) VALUES(?,?,?,?,?)",
              (target_id, now(), "running", "старт", ""))


def scan(sid: int):
    return one("SELECT * FROM scans WHERE id=?", (sid,))


def scans(target_id: int) -> list[sqlite3.Row]:
    return q("SELECT * FROM scans WHERE target_id=? ORDER BY id DESC", (target_id,))


def last_done_scan(target_id: int, before_id: int | None = None):
    if before_id:
        return one("SELECT * FROM scans WHERE target_id=? AND status='done' AND id<? ORDER BY id DESC LIMIT 1",
                   (target_id, before_id))
    return one("SELECT * FROM scans WHERE target_id=? AND status='done' ORDER BY id DESC LIMIT 1", (target_id,))


def scan_log(sid: int, line: str) -> None:
    row = one("SELECT log FROM scans WHERE id=?", (sid,))
    prev = (row["log"] or "") if row else ""
    ex("UPDATE scans SET log=?, progress=? WHERE id=?", ((prev + line + "\n")[-20000:], line, sid))


def scan_progress(sid: int, text: str, pct: int | None = None) -> None:
    payload = json.dumps({"text": text, "pct": pct}, ensure_ascii=False) if pct is not None else text
    ex("UPDATE scans SET progress=? WHERE id=?", (payload, sid))


def scan_progress_value(sid: int) -> dict:
    row = scan(sid)
    raw = (dict(row).get("progress") if row else "") or ""
    try:
        d = json.loads(raw)
        if isinstance(d, dict):
            return d
    except Exception:
        pass
    return {"text": raw, "pct": None}


def scan_finish(sid: int, status: str, stats: dict | None = None, error: str = "") -> None:
    ex("UPDATE scans SET finished_at=?, status=?, stats=?, error=?, progress=? WHERE id=?",
       (now(), status, json.dumps(stats or {}, ensure_ascii=False), error,
        "готово" if status == "done" else "ошибка", sid))


# ---------------------------------------------------------------- запись результата
@contextmanager
def _batch_transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """Атомарная граница одной пачки; не фиксирует чужую внешнюю транзакцию.

    В обычном случае берём SQLite write-lock до чтения/записи и делаем ровно
    один commit. Если вызывающий уже открыл транзакцию на соединении своего
    потока, используем savepoint: ошибка откатит пачку, не затрагивая его работу.
    """
    nested = conn.in_transaction
    savepoint = "asm_result_batch"
    if nested:
        conn.execute(f"SAVEPOINT {savepoint}")
    else:
        conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        if nested:
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        else:
            conn.commit()
    except BaseException:
        try:
            if nested:
                conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            else:
                conn.rollback()
        except BaseException as rollback_error:
            raise RuntimeError("ошибка пакетной записи; rollback тоже не удался, "
                               "состояние соединения не подтверждено") from rollback_error
        raise


def _executemany(sql: str, rows: Iterable[tuple]) -> None:
    """Выполнить непустую пачку на соединении текущего потока."""
    conn = connect()
    with _batch_transaction(conn):
        conn.executemany(sql, rows)


def save_assets(sid: int, assets: list[dict]) -> None:
    if not assets:
        return
    rows = (
        (sid, asset["kind"], asset["value"],
         json.dumps(asset.get("meta", {}), ensure_ascii=False))
        for asset in assets
    )
    _executemany("INSERT INTO assets(scan_id, kind, value, meta) VALUES(?,?,?,?)", rows)


def save_edges(sid: int, edges: list[dict]) -> None:
    if not edges:
        return
    rows = (
        (sid, edge["src"], edge["dst"], edge["rel"],
         json.dumps(edge.get("meta", {}), ensure_ascii=False))
        for edge in edges
    )
    _executemany("INSERT INTO edges(scan_id, src, dst, rel, meta) VALUES(?,?,?,?,?)", rows)


def save_findings(sid: int, findings: list[dict]) -> None:
    if not findings:
        return

    sql = """INSERT INTO findings(scan_id, asset, ip, port, service, product, version, cve_id,
             cvss, severity, epss, kev, priority, score, title, rationale, evidence,
             fix, fix_class, source_kind, kind, status, status_note, owner,
             first_seen_scan, last_seen_scan, evidence_hash)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

    def row_values(finding: dict) -> tuple:
        fix = finding.get("fix") or {}
        return (
            sid, finding.get("asset"), finding.get("ip"), finding.get("port"),
            finding.get("service"), finding.get("product"), finding.get("version"),
            finding.get("cve_id"), finding.get("cvss"), finding.get("severity"),
            finding.get("epss"), 1 if finding.get("kev") else 0,
            finding.get("priority"), finding.get("score"), finding.get("title"),
            finding.get("rationale"), json.dumps(finding.get("evidence", {}), ensure_ascii=False),
            json.dumps(finding.get("fix", {}), ensure_ascii=False), fix.get("класс", ""),
            finding.get("source_kind"), finding_kind(finding), finding.get("status") or "open",
            finding.get("status_note") or "", finding.get("owner") or "",
            finding.get("first_seen_scan") or sid, finding.get("last_seen_scan") or sid,
            finding.get("evidence_hash") or "",
        )

    rows = (row_values(finding) for finding in findings)
    conn = connect()
    fts = _fts_ready()
    with _batch_transaction(conn):
        first_id = None
        if fts:
            first_id = int(conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM findings"
            ).fetchone()[0])
        conn.executemany(sql, rows)

        if fts:
            inserted_ids = [int(row[0]) for row in conn.execute(
                "SELECT id FROM findings WHERE scan_id=? AND id>? ORDER BY id",
                (sid, first_id),
            )]
            if len(inserted_ids) != len(findings):
                raise RuntimeError("не удалось однозначно связать находки с FTS-строками")
            fts_rows = (
                (rid, finding.get("title") or "", finding.get("product") or "",
                 finding.get("cve_id") or "", finding.get("asset") or "")
                for rid, finding in zip(inserted_ids, findings)
            )
            conn.executemany(
                "INSERT INTO findings_fts(rowid, title, product, cve_id, asset) "
                "VALUES(?,?,?,?,?)", fts_rows
            )


def scan_assets(sid: int) -> list[dict]:
    return [{"kind": r["kind"], "value": r["value"], "meta": json.loads(r["meta"] or "{}")}
            for r in q("SELECT * FROM assets WHERE scan_id=?", (sid,))]


def scan_edges(sid: int) -> list[dict]:
    return [{"src": r["src"], "dst": r["dst"], "rel": r["rel"], "meta": json.loads(r["meta"] or "{}")}
            for r in q("SELECT * FROM edges WHERE scan_id=?", (sid,))]


def scan_findings(sid: int) -> list[dict]:
    out = []
    for r in q("SELECT * FROM findings WHERE scan_id=? ORDER BY score DESC", (sid,)):
        d = dict(r)
        d["evidence"] = json.loads(d.get("evidence") or "{}")
        try:
            d["fix"] = json.loads(d.get("fix") or "{}")
        except Exception:
            d["fix"] = {}
        out.append(d)
    return out


def all_targets_simple() -> list[dict]:
    return [dict(r) for r in targets()]


# ---------------------------------------------------------------- реестр активов
def registry_get(value: str) -> dict:
    r = one("SELECT * FROM registry WHERE value=?", (value,))
    return dict(r) if r else {}


def registry_all() -> dict:
    return {r["value"]: dict(r) for r in q("SELECT * FROM registry")}


def registry_set(value: str, kind: str = "", criticality: str = "", exposure: str = "",
                 owner: str = "", tags: str = "", note: str = "") -> None:
    ex("""INSERT INTO registry(value, kind, criticality, exposure, owner, tags, note, updated_at)
          VALUES(?,?,?,?,?,?,?,?)
          ON CONFLICT(value) DO UPDATE SET kind=excluded.kind, criticality=excluded.criticality,
            exposure=excluded.exposure, owner=excluded.owner, tags=excluded.tags,
            note=excluded.note, updated_at=excluded.updated_at""",
       (value, kind, criticality, exposure, owner, tags, note, now()))


def registry_critical() -> dict:
    """Карта «адрес/имя → критичность» для приоритизации."""
    out = {}
    for r in q("SELECT * FROM registry"):
        d = dict(r)
        for key in (d["value"],):
            out[key] = d
    return out


# ---------------------------------------------------------------- статусы находок
VALID_STATUS = ("open", "confirmed", "false", "accepted", "fixed")
STATUS_RU = {"open": "открыто", "confirmed": "подтверждено", "false": "ложное срабатывание",
             "accepted": "принято в риск", "fixed": "закрыто"}


def set_finding_status(fid: int, status: str, note: str = "", owner: str = "") -> bool:
    if status not in VALID_STATUS:
        return False
    ex("UPDATE findings SET status=?, status_note=?, owner=? WHERE id=?",
       (status, note, owner, fid))
    if status == "false":
        _learn_false_positive(fid, note=note, operator=owner)
    return True


def _learn_false_positive(fid: int, *, note: str = "", operator: str = "") -> None:
    """Пометка «ложное срабатывание» сразу попадает в память уточнений.

    Отдельный `kb learn` после каждого аудита никто не запускает, и память не
    накапливается — а именно она убирает повторный разбор одних и тех же
    срабатываний на следующем объекте.

    Сбой запоминания не отменяет пометку: оператор сказал «не верю» про
    находку, и это решение первично. Поэтому всё обёрнуто и глотается.

    Отключается `--set ASM_AUTO_LEARN=0`, если хочется сначала посмотреть
    список (`kb learn --dry-run`) и записать выборочно.
    """
    settings = current_settings()
    auto_learn = (settings.get("ASM_AUTO_LEARN", "1") if settings is not None
                  else os.environ.get("ASM_AUTO_LEARN", "1"))
    if str(auto_learn).strip().lower() in ("0", "false", "no"):
        return
    try:
        from . import knowledge
        knowledge.refinement_from_finding(fid, note=note, operator=operator)
    except Exception:
        pass


def finding(fid: int) -> dict:
    r = one("SELECT * FROM findings WHERE id=?", (fid,))
    if not r:
        return {}
    d = dict(r)
    try:
        d["evidence"] = json.loads(d.get("evidence") or "{}")
        d["fix"] = json.loads(d.get("fix") or "{}")
    except Exception:
        d["evidence"], d["fix"] = {}, {}
    return d


# ---------------------------------------------------------------- закладка графа
def layout_save(sid: int, positions: dict[str, tuple]) -> None:
    for node, (x, y) in positions.items():
        ex("INSERT INTO layout(scan_id, node, x, y) VALUES(?,?,?,?) "
           "ON CONFLICT(scan_id, node) DO UPDATE SET x=excluded.x, y=excluded.y",
           (sid, node, float(x), float(y)))


def layout_get(sid: int) -> dict:
    return {r["node"]: {"x": r["x"], "y": r["y"]} for r in q("SELECT * FROM layout WHERE scan_id=?", (sid,))}


# ---------------------------------------------------------------- чаты
def chat_save(sid: int, element: str, role: str, content: str) -> int:
    return ex("INSERT INTO chats(scan_id, element, role, content, ts) VALUES(?,?,?,?,?)",
              (sid, element, role, content[:20000], now()))


def chat_history(sid: int, element: str, limit: int = 20) -> list[dict]:
    rows = q("SELECT role, content FROM chats WHERE scan_id=? AND element=? ORDER BY id DESC LIMIT ?",
             (sid, element, limit))
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]


# ---------------------------------------------------------------- расписание
def schedule_set(target_id: int, interval_hours: int, enabled: bool = True) -> None:
    ex("INSERT INTO schedule(target_id, interval_hours, enabled, next_run) VALUES(?,?,?,?) "
       "ON CONFLICT(target_id) DO UPDATE SET interval_hours=excluded.interval_hours, "
       "enabled=excluded.enabled, next_run=excluded.next_run",
       (target_id, interval_hours, 1 if enabled else 0, now()))


def schedule_all() -> list[dict]:
    return [dict(r) for r in q("SELECT * FROM schedule")]


def schedule_get(target_id: int) -> dict:
    r = one("SELECT * FROM schedule WHERE target_id=?", (target_id,))
    return dict(r) if r else {}


def schedule_touch(target_id: int, next_run: str) -> None:
    ex("UPDATE schedule SET last_run=?, next_run=? WHERE target_id=?", (now(), next_run, target_id))


# ---------------------------------------------------------------- поиск по находкам
def _fts_ready() -> bool:
    """Подготовить FTS5, если текущая сборка SQLite его поддерживает.

    Используем соединение текущего потока под общей DDL-блокировкой, чтобы два
    потока одновременно не создавали таблицу. Не используем `ex()`: его
    безусловный commit зафиксировал бы транзакцию вызывающего кода.
    """
    with _lock:
        conn = connect()
        try:
            conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts "
                         "USING fts5(title, product, cve_id, asset)")
            return True
        except sqlite3.OperationalError as exc:
            if "no such module: fts5" not in str(exc).casefold():
                raise
            return False


def search_findings(sid: int, text: str, limit: int = 60) -> list[dict]:
    """Поиск: сначала полнотекстовый (FTS5), при отсутствии — по подстроке."""
    text = (text or "").strip()
    if not text:
        return []
    if _fts_ready():
        tokens = [t for t in re.split(r"\W+", text) if len(t) > 1][:6]
        if tokens:
            match = " AND ".join(f'"{t}"*' for t in tokens)
            rows = q("""SELECT f.id, f.priority, f.score, f.title, f.asset, f.ip, f.port,
                               f.cve_id, f.status
                        FROM findings_fts x JOIN findings f ON f.id = x.rowid
                        WHERE f.scan_id=? AND findings_fts MATCH ?
                        ORDER BY f.score DESC LIMIT ?""", (sid, match, limit))
            if rows:
                return [dict(r) for r in rows]
    like = f"%{text}%"
    rows = q("""SELECT id, priority, score, title, asset, ip, port, cve_id, status
                FROM findings WHERE scan_id=? AND (title LIKE ? OR asset LIKE ? OR ip LIKE ?
                OR cve_id LIKE ? OR product LIKE ? OR service LIKE ?)
                ORDER BY score DESC LIMIT ?""",
             (sid, like, like, like, like, like, like, limit))
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- виды графа
def view_save(sid: int, name: str, state: str) -> int:
    return ex("INSERT INTO views(scan_id, name, state, created_at) VALUES(?,?,?,?)",
              (sid, name[:60], state, now()))


def views_list(sid: int) -> list[dict]:
    return [dict(r) for r in q("SELECT * FROM views WHERE scan_id=? ORDER BY id DESC", (sid,))]


def view_delete(vid: int) -> None:
    ex("DELETE FROM views WHERE id=?", (vid,))


# ---------------------------------------------------------------- агент
# Агент не выполняет действия сам: шаг создаётся в статусе proposed и ждёт
# явного решения человека. Автоодобрения по таймауту нет ни в каком виде.
AGENT_PROPOSED = "proposed"
AGENT_APPROVED = "approved"
AGENT_REJECTED = "rejected"
AGENT_EXECUTED = "executed"
AGENT_FAILED = "failed"
AGENT_HANDOFF = "handoff"

# Терминальные состояния сессии. Отдельно от 'closed', потому что причина
# завершения важна для отчёта: закрыл оператор, нажал стоп или вышло окно.
AGENT_STOPPED = "stopped_by_operator"
AGENT_EXPIRED = "expired"


def kv_get(k: str, default: str = "") -> str:
    """Значение из kv. Пустая строка и отсутствие ключа — одно и то же.

    Через kv хранится и режим работ (`mode.py`): он должен жить между
    запусками, а переменные окружения в шелле не сохраняются.
    """
    row = one("SELECT v FROM kv WHERE k=?", (k,))
    return str(row["v"]) if row and row["v"] is not None else default


def kv_set(k: str, v: str) -> None:
    ex("INSERT INTO kv(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
       (k, str(v)))


def kv_del(k: str) -> None:
    ex("DELETE FROM kv WHERE k=?", (k,))


def halt_set(on: bool, reason: str = "") -> None:
    """Глобальный флаг остановки.

    Хранится в базе, а не в памяти процесса: кнопку нажимают в веб-интерфейсе,
    а скан может идти из CLI в другом терминале. Флаг в памяти одного процесса
    второй не увидел бы, и «одно нажатие останавливает всё» не работало бы.
    """
    payload = json.dumps({"on": bool(on), "reason": reason, "at": now()},
                         ensure_ascii=False)
    ex("INSERT INTO kv(k, v) VALUES('halted', ?) "
       "ON CONFLICT(k) DO UPDATE SET v = excluded.v", (payload,))


def halt_active() -> bool:
    """Установлен ли глобальный флаг остановки. Молчит при любой ошибке —
    лучше не запустить движок, чем запустить его после остановки."""
    row = one("SELECT v FROM kv WHERE k='halted'")
    if not row:
        return False
    try:
        return bool(json.loads(row["v"]).get("on"))
    except Exception:
        return False


def halt_info() -> dict:
    row = one("SELECT v FROM kv WHERE k='halted'")
    if not row:
        return {"on": False}
    try:
        return json.loads(row["v"])
    except Exception:
        return {"on": False}


def agent_open(target_id: int, operator: str = "", note: str = "",
               deadline: str = "") -> int:
    sid = ex("INSERT INTO agent_sessions(target_id, operator, note, status,"
             " created_at, deadline) VALUES(?,?,?,?,?,?)",
             (target_id, operator, note, "open", now(), deadline or None))
    audit("agent_session_opened", {"session": sid, "target_id": target_id,
                                   "operator": operator, "note": note,
                                   "deadline": deadline or None})
    return sid


def agent_sessions(only_open: bool = True) -> list[dict]:
    """Сессии агента — для панели в веб-интерфейсе.

    Возвращаются и закрытые: в панели нужно видеть, что работа по объекту
    окончена, а не только то, что открыто сейчас.
    """
    sql = ("SELECT s.*, t.value AS target FROM agent_sessions s"
           " LEFT JOIN targets t ON t.id = s.target_id")
    if only_open:
        sql += " WHERE s.status = 'open'"
    sql += " ORDER BY s.id DESC LIMIT 50"
    return [dict(r) for r in q(sql)]


def agent_session(session_id: int):
    return one("SELECT * FROM agent_sessions WHERE id=?", (session_id,))


def agent_close(session_id: int) -> None:
    ex("UPDATE agent_sessions SET status='closed', closed_at=? WHERE id=?",
       (now(), session_id))
    audit("agent_session_closed", {"session": session_id})


def agent_set_deadline(session_id: int, deadline: str) -> None:
    """Жёсткий срок, после которого агент отказывается делать что-либо сам.

    Нужен как страховка от того, что оператора не окажется за клавиатурой,
    когда окно работ закроется. Продолжение работ после окна — это уже
    нарушение договора, а не его исполнение.
    """
    ex("UPDATE agent_sessions SET deadline=? WHERE id=?", (deadline, session_id))
    audit("agent_deadline_set", {"session": session_id, "deadline": deadline})


def agent_expired(session_id: int) -> bool:
    """Прошёл ли срок сессии. Формат дат ISO 8601 UTC, сравнение строковое."""
    s = one("SELECT deadline FROM agent_sessions WHERE id=?", (session_id,))
    if not s or not s["deadline"]:
        return False
    return str(s["deadline"]) < now()


def agent_stop(session_id: int, operator: str = "", note: str = "",
               killed: int = 0) -> bool:
    """Остановить сессию: состояние stopped_by_operator, дальше ничего не выполняется.

    killed — сколько деревьев процессов было убито. Пишется в аудит: оператор
    должен видеть, что остановка действительно сработала, а не только выставила
    флаг в базе.
    """
    s = one("SELECT status FROM agent_sessions WHERE id=?", (session_id,))
    if not s:
        return False
    ex("UPDATE agent_sessions SET status=?, closed_at=?, stopped_by=?, stop_note=?"
       " WHERE id=?", (AGENT_STOPPED, now(), operator, note, session_id))
    # шаги, которые ждали подтверждения, гасим: одобрение, выданное до стопа,
    # не должно переживать сам стоп
    ex("UPDATE agent_steps SET status=?, decision_note=? "
       "WHERE session_id=? AND status IN (?,?)",
       (AGENT_REJECTED, "отменено остановкой сессии", session_id,
        AGENT_PROPOSED, AGENT_APPROVED))
    audit("agent_session_stopped", {"session": session_id, "operator": operator,
                                    "note": note, "killed_processes": killed})
    return True


def agent_propose(session_id: int, action_id: str, cls: str, title: str, *,
                  params: dict | None = None, rationale: str = "", risk: str = "",
                  reversible: bool = True) -> int:
    """Шаг в очередь на подтверждение. Выполнен не будет, пока его не одобрят."""
    seq = one("SELECT COUNT(*) n FROM agent_steps WHERE session_id=?", (session_id,))["n"] + 1
    sid = ex("INSERT INTO agent_steps(session_id, seq, action_id, cls, title, params,"
             " rationale, risk, reversible, status) VALUES(?,?,?,?,?,?,?,?,?,?)",
             (session_id, seq, action_id, cls, title,
              json.dumps(params or {}, ensure_ascii=False), rationale, risk,
              1 if reversible else 0, AGENT_PROPOSED))
    audit("agent_step_proposed", {"session": session_id, "step": sid, "action": action_id,
                                  "class": cls, "reversible": reversible})
    return sid


def agent_pending(session_id: int) -> list[dict]:
    return [dict(r) for r in q(
        "SELECT * FROM agent_steps WHERE session_id=? AND status=? ORDER BY seq",
        (session_id, AGENT_PROPOSED))]


def agent_step(step_id: int):
    return one("SELECT * FROM agent_steps WHERE id=?", (step_id,))


def agent_steps(session_id: int) -> list[dict]:
    return [dict(r) for r in q(
        "SELECT * FROM agent_steps WHERE session_id=? ORDER BY seq", (session_id,))]


def agent_decide(step_id: int, approve: bool, operator: str = "", note: str = "",
                 remember: bool = True) -> bool:
    """Явное решение человека. Отклонённый шаг повторно не одобряется.

    remember=False ставит автопилот: своё автоодобрение чтения он отмечает
    одной записью на круг, а не по шагу. Иначе память сессии заполняется
    машинными отметками, и решение оператора («эту панель не трогать»)
    вытесняется из подсказки модели первой же пачкой рекогносцировки.
    """
    st = agent_step(step_id)
    if not st or st["status"] != AGENT_PROPOSED:
        return False
    # Решение человека становится памятью сессии. Без этого в следующем круге
    # модель не знает, что этот шаг уже отклонён и почему, и предлагает его
    # снова — а оператор второй раз объясняет то же самое.
    if remember:
        agent_note(st["session_id"], NOTE_DECISION,
               f"{'одобрен' if approve else 'отклонён'} шаг {st['action_id']}"
                   f" ({st['title']}): {note or 'без примечания'}",
                   source=operator or "оператор")
    ex("UPDATE agent_steps SET status=?, decided_by=?, decided_at=?, decision_note=?"
       " WHERE id=?",
       (AGENT_APPROVED if approve else AGENT_REJECTED, operator, now(), note, step_id))
    audit("agent_step_approved" if approve else "agent_step_rejected",
          {"step": step_id, "action": st["action_id"], "operator": operator, "note": note})
    return True


def agent_mark_running(step_id: int) -> None:
    ex("UPDATE agent_steps SET status=?, started_at=? WHERE id=?",
       (AGENT_EXECUTED, now(), step_id))


def agent_mark_result(step_id: int, ok: bool, result: str = "", error: str = "",
                      handoff: bool = False) -> None:
    status = AGENT_HANDOFF if handoff else (AGENT_EXECUTED if ok else AGENT_FAILED)
    ex("UPDATE agent_steps SET status=?, finished_at=?, result=?, error=? WHERE id=?",
       (status, now(), result[:4000], error[:2000], step_id))
    audit("agent_step_finished", {"step": step_id, "status": status, "error": error[:200]})



def agent_plan_save(session_id: int, source: str, plan: dict, note: str = "") -> int:
    """Записать план в журнал (source: model | rules). Ничего не выполняет."""
    return ex("INSERT INTO agent_plans(session_id, source, note, plan, created_at)"
              " VALUES(?,?,?,?,?)",
              (session_id, source, note[:400],
               json.dumps(plan or {}, ensure_ascii=False), now()))


def agent_plan_rows(session_id: int, limit: int = 6) -> list[dict]:
    """Последние планы: свежие сверху. plan отдаётся разобранным."""
    out = []
    for r in q("SELECT * FROM agent_plans WHERE session_id=? ORDER BY id DESC LIMIT ?",
               (session_id, limit)):
        d = dict(r)
        try:
            d["plan"] = json.loads(d.get("plan") or "{}")
        except Exception:  # noqa: BLE001 — испорченная запись не должна ломать показ
            d["plan"] = {}
        out.append(d)
    return out


def agent_last_plan(session_id: int, source: str) -> dict | None:
    rows = agent_plan_rows(session_id, limit=20)
    for r in rows:
        if r["source"] == source:
            return r
    return None

NOTE_GOAL, NOTE_BAN, NOTE_DECISION, NOTE_QUESTION, NOTE_EVENT = (
    "goal", "ban", "decision", "question", "event")
NOTE_KIND_TITLE = {
    NOTE_GOAL: "цель", NOTE_BAN: "запрет", NOTE_DECISION: "решение",
    NOTE_QUESTION: "открытый вопрос", NOTE_EVENT: "событие",
}


def note_kind(text: str) -> str:
    """Какой это вид записи. Разбор по словам — нарочно простой и объяснимый.

    Отнесение к «запрету» или «решению» меняет то, как запись попадёт в
    подсказку модели, поэтому оператор всегда может сказать вид явно.
    """
    t = (text or "").lower()
    if any(w in t for w in ("нельзя", "не трогай", "запрещ", "не делай", "не надо",
                            "исключено", "не подход")):
        return NOTE_BAN
    if any(w in t for w in ("решено", "решили", "делаем", "согласован", "одобрен",
                            "договорились", "принято", "подтвержд")):
        return NOTE_DECISION
    if any(w in t for w in ("цель", "задача проекта", "нужно получить", "итог работ")):
        return NOTE_GOAL
    if t.rstrip().endswith("?"):
        return NOTE_QUESTION
    return NOTE_EVENT


def agent_note(session_id: int, kind: str, text: str, source: str = "operator") -> int:
    """Записать в память сессии. Возвращает номер записи."""
    kind = kind if kind in NOTE_KIND_TITLE else note_kind(text)
    return ex("INSERT INTO agent_notes(session_id, kind, source, text, created_at)"
              " VALUES(?,?,?,?,?)", (session_id, kind, source, text[:2000], now()))


def agent_notes(session_id: int, limit: int = 40, kinds: Iterable | None = None) -> list[dict]:
    """Последние записи сессии в прямом порядке: сначала старое, свежее — в конце."""
    if kinds:
        ks = [str(k) for k in kinds]
        ph = ",".join("?" for _ in ks)
        rows = q(f"SELECT * FROM agent_notes WHERE session_id=? AND kind IN ({ph})"
                 " ORDER BY id DESC LIMIT ?", (session_id, *ks, limit))
    else:
        rows = q("SELECT * FROM agent_notes WHERE session_id=? ORDER BY id DESC LIMIT ?",
                 (session_id, limit))
    return [dict(r) for r in reversed(list(rows))]


def agent_chat_add(session_id: int, role: str, text: str, kind: str = "",
                   meta: dict | None = None) -> int:
    """Записать реплику диалога. Пустые не пишем: пустая строка в ленте —
    это «тишина вместо результата», тот же дефект, что и везде."""
    t = (text or "").strip()
    if not t:
        return 0
    return ex("INSERT INTO agent_chat(session_id, role, kind, text, meta, created_at) "
              "VALUES (?,?,?,?,?,?)",
              (session_id, role, kind or role, t,
               json.dumps(meta or {}, ensure_ascii=False), now()))


def agent_chat(session_id: int, limit: int = 40, after_id: int = 0) -> list[dict]:
    """История диалога — от старых к новым, чтобы читать как разговор."""
    rows = q("SELECT * FROM agent_chat WHERE session_id=? AND id>? "
             "ORDER BY id DESC LIMIT ?", (session_id, after_id, limit))
    return [dict(r) for r in reversed(rows)]


def attachments(target_id: int) -> list[dict]:
    return [dict(r) for r in q("SELECT * FROM attachments WHERE target_id=? "
                               "ORDER BY id DESC", (target_id,))]


def attachment(aid: int) -> dict | None:
    r = one("SELECT * FROM attachments WHERE id=?", (aid,))
    return dict(r) if r else None


def attachment_add(target_id: int, name: str, path: str, kind: str,
                   size: int = 0, sha256: str = "", note: str = "",
                   session_id: int = 0) -> int:
    return ex("INSERT INTO attachments(target_id, session_id, name, path, kind, size, "
              "sha256, note, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
              (target_id, session_id, name, path, kind, size, sha256, note, now()))


def attachment_drop(aid: int) -> bool:
    return ex("DELETE FROM attachments WHERE id=?", (aid,)) > 0


def agent_last_approved_action(session_id: int) -> str:
    r = one("SELECT action_id FROM agent_steps WHERE session_id=? AND status IN (?,?,?)"
            " ORDER BY seq DESC LIMIT 1",
            (session_id, AGENT_EXECUTED, AGENT_HANDOFF, AGENT_FAILED))
    return (r["action_id"] if r else "")
