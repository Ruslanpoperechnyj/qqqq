"""
Поиск по смыслу (М5 из ТЗ) — без облака и без ключей.

Задача: аудитор помнит «где-то было что-то про открытый каталог», а не точное слово
из базы. Обычный поиск по словам такое не находит. Здесь два уровня:

  1) Векторное хранилище. Если доступно расширение sqlite-vec — векторы лежат в
     виртуальной таблице vec0 (быстро даже на сотнях тысяч находок). Если расширения
     нет — считаем косинус в Python: работает всегда, медленнее на очень больших объёмах.
  2) Модель представления текста. Если установлен fastembed (локальная модель ONNX,
     например BAAI/bge-m3 или intfloat/multilingual-e5-small) — берём её. Если нет —
     работаем на собственной хеш-векторизации n-грамм: без зависимостей и без интернета,
     качество ниже, но поиск по смыслу ближних формулировок работает.

Всё локально: наружу ни один запрос не уходит.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import math
import os
import re
import sqlite3
import struct
import threading

from . import store
from .settings import current_settings

DIM = int(os.environ.get("ASM_VECTOR_DIM", "384"))
MODEL_NAME = os.environ.get("ASM_EMBED_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")

_lock = threading.RLock()
_model = None
_model_tried = False
_model_key = None
_model_dim = None
_vec_ext = None
_vec_tried = False

_WORD = re.compile(r"[0-9a-zA-Zа-яёА-ЯЁ_]{2,}")


def _setting_value(name: str, default=None):
    settings = current_settings()
    if settings is not None:
        return settings.get(name, default)
    return os.environ.get(name, default)


def _dimension() -> int:
    return int(_setting_value("ASM_VECTOR_DIM", DIM))


def _model_name() -> str:
    return str(_setting_value("ASM_EMBED_MODEL", MODEL_NAME))


# --------------------------------------------------------------- модели текста
def _memory_gb() -> float:
    """Сколько памяти реально доступно: тяжёлую модель грузим только если хватает."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024 / 1024
    except Exception:
        pass
    return 99.0


def _load_model():
    """Локальная модель (fastembed) из snapshot; при её смене кэшируется новый экземпляр."""
    global _model, _model_tried, _model_key, _model_dim
    model_name = _model_name()
    mode = str(_setting_value("ASM_EMBED", "auto") or "auto").strip().lower()
    min_gb = float(_setting_value("ASM_EMBED_MIN_GB", 1.5) or 0)
    if mode in ("0", "off", "none"):
        return None
    key = (model_name, mode, min_gb)
    with _lock:
        if _model_tried and _model_key == key:
            return _model
        _model_key = key
        _model_tried = True
        _model = None
        _model_dim = None
        if mode not in ("1", "on", "force") and _memory_gb() < min_gb:
            # на слабой машине (или в тесном контейнере) модель не грузим, чтобы не уронить панель
            return None
        try:
            from fastembed import TextEmbedding  # type: ignore
            _model = TextEmbedding(model_name=model_name)
        except Exception:
            _model = None
        return _model


def _vector_dimension() -> int:
    """Размерность фактически выбранного векторизатора для snapshot операции."""
    global _model_dim
    model = _load_model()
    if model is None:
        return _dimension()
    with _lock:
        if _model is model and _model_dim:
            return int(_model_dim)
    try:
        sample = next(iter(model.embed(["asm dimension probe"])))
        dim = len(sample)
    except Exception:
        return _dimension()
    if dim > 0:
        with _lock:
            if _model is model:
                _model_dim = int(dim)
        return int(dim)
    return _dimension()


def _hashed_vector(text: str) -> list[float]:
    """Своя векторизация: слова + 3-граммы символов, хеш -> номер измерения.

    Так «открытый каталог» и «listing directory» окажутся рядом лишь частично, зато
    «каталог /catalog/» и «открыт каталог» — точно рядом. Никаких зависимостей.
    """
    low = (text or "").lower().replace("ё", "е")
    words = _WORD.findall(low)
    dim = _dimension()
    vec = [0.0] * dim
    def add(token: str, weight: float) -> None:
        h = int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")
        vec[h % dim] += weight
        vec[(h >> 17) % dim] += weight * 0.5
    for w in words:
        add(w, 1.0)
        for i in range(0, max(0, len(w) - 2)):
            add(w[i:i + 3], 0.35)
    for a, b in zip(words, words[1:]):          # устойчивые пары слов
        add(a + " " + b, 0.6)
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def embed(texts: list[str]) -> tuple[list[list[float]], str]:
    """Векторы текстов + название способа («модель» или «своя векторизация»)."""
    texts = [t or "" for t in texts]
    model_name = _model_name()
    model = _load_model()
    if model is not None:
        try:
            vecs = [_unit(list(map(float, v))) for v in model.embed(texts)]
            if vecs:
                global _model_dim
                with _lock:
                    if _model is model:
                        _model_dim = len(vecs[0])
            return vecs, f"модель {model_name}"
        except Exception:
            pass
    return [_hashed_vector(t) for t in texts], "встроенная векторизация n-грамм (модель не найдена)"


def _unit(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


# ------------------------------------------------------------- хранилище sqlite
def _load_vec_ext(conn: sqlite3.Connection) -> bool:
    """Пробуем подключить sqlite-vec к этому соединению.

    Расширение регистрируется в КАЖДОМ соединении отдельно, а помнили мы только
    сам факт «расширение есть»: второе соединение (новый запуск, тесты, смена
    базы) считало себя готовым, лезло в таблицу `vec0` и получало «no such
    module: vec0». С установленным sqlite-vec это ломало поиск по смыслу.
    Теперь готовность спрашивается у самого соединения.
    """
    global _vec_ext, _vec_tried
    with _lock:
        if _vec_ext is not None:
            try:
                conn.execute("SELECT vec_version()").fetchone()
                return True
            except Exception:
                pass          # это другое соединение — расширения в нём ещё нет
        if _vec_ext is None and _vec_tried:
            return False
        if _vec_ext is None:
            _vec_tried = True
        try:
            # расширение ставится вместе с арсеналом (build/tools/pylibs) и в системный
            # python не попадает — добавляем его каталог в путь поиска сами
            import sys as _sys
            for cand in (_setting_value("ASM_PYLIBS", None),
                         os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                      "build", "tools", "pylibs")):
                if cand and os.path.isdir(cand) and cand not in _sys.path:
                    _sys.path.insert(0, cand)
            import sqlite_vec  # type: ignore
        except Exception:
            _vec_ext = None
            return False
        try:
            conn.enable_load_extension(True)
            sqlite_vec.load(conn)
            conn.enable_load_extension(False)
            conn.execute("SELECT vec_version()").fetchone()
            _vec_ext = sqlite_vec
        except Exception:
            # модуль импортируется, но подключить к соединению не удалось —
            # работаем честным медленным путём, а не падаем
            return False
        return True


def backend() -> str:
    """Что реально используется сейчас — для честной подписи в интерфейсе."""
    db = store.connect()
    vec = "sqlite-vec" if _load_vec_ext(db) else "косинус в Python"
    model = ("модель " + _model_name() if _load_model() is not None
             else "встроенная векторизация n-грамм")
    return f"{vec} · {model}"


# индекс приходится пересобирать только при смене модели/метрики — сообщаем об этом наверх,
# чтобы это не выглядело как «поиск по смыслу вдруг перестал находить»
REINDEX_NEEDED = False


def _how_key() -> str:
    """Способ расчёта векторов — часть их личности, а не подробность.

    Вектор от модели и вектор от n-грамм несравнимы: если способ сменился,
    старый индекс надо пересчитать, иначе поиск начнёт «находить» по мусору.
    """
    model = _load_model()
    base = ("модель " + _model_name()) if model is not None else "n-граммы"
    return f"{base} · dim={_vector_dimension()}"


def _text_hash(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", "replace")).hexdigest()


def _ensure_meta(conn: sqlite3.Connection) -> None:
    # Metadata tables can be reached from several worker threads on first use.
    with _lock:
        conn.execute("CREATE TABLE IF NOT EXISTS sem_meta(finding_id INTEGER PRIMARY KEY,"
                     " scan_id INTEGER, dim INTEGER, text_hash TEXT, how TEXT)")
        conn.execute("CREATE INDEX IF NOT EXISTS sem_meta_scan_idx ON sem_meta(scan_id)")


def _ensure_tables(conn: sqlite3.Connection, dim: int) -> bool:
    """Готовит таблицу векторов. Удаляет её ТОЛЬКО если старая сделана не так, как нужно
    (другая метрика или другая размерность модели) — иначе индекс обнулялся бы при каждом
    обращении к поиску."""
    global REINDEX_NEEDED
    if _load_vec_ext(conn):
        row = conn.execute("SELECT sql FROM sqlite_master WHERE name='sem'").fetchone()
        sql = (row[0] if row else "") or ""
        if row:
            m = re.search(r"float\[(\d+)\]", sql)
            wrong_metric = "distance_metric=cosine" not in sql
            wrong_dim = bool(m) and int(m.group(1)) != dim
            if wrong_metric or wrong_dim:
                had = conn.execute("SELECT count(*) FROM sem").fetchone()[0]
                conn.execute("DROP TABLE IF EXISTS sem")
                if had:
                    REINDEX_NEEDED = True
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS sem USING vec0(scan_id integer, "
                     f"finding_id integer, embedding float[{dim}] distance_metric=cosine)")
        return True
    # без расширения: если в базе осталась таблица прошлой версии (vec0), прочитать её
    # всё равно нельзя — пересоздаём обычную; индекс воспроизводим и пересоберётся сам
    row = conn.execute("SELECT sql FROM sqlite_master WHERE name='sem'").fetchone()
    if row and "vec0" in (row[0] or ""):
        conn.execute("DROP TABLE IF EXISTS sem")
    conn.execute("CREATE TABLE IF NOT EXISTS sem(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,"
                 " finding_id INTEGER, dim INTEGER, text TEXT, vec BLOB)")
    conn.execute("CREATE INDEX IF NOT EXISTS sem_finding_idx ON sem(finding_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS sem_scan_idx ON sem(scan_id)")
    return False


def _stored_dimension(conn: sqlite3.Connection) -> int:
    """Определить dimension индексированной строки без чтения всего vector корпуса."""
    try:
        if _load_vec_ext(conn):
            row = conn.execute("SELECT embedding FROM sem LIMIT 1").fetchone()
            return len(bytes(row[0])) // 4 if row and row[0] is not None else 0
        row = conn.execute("SELECT dim FROM sem LIMIT 1").fetchone()
        return int(row[0] or 0) if row else 0
    except (sqlite3.Error, TypeError, ValueError, OverflowError):
        # Пустая/несовместимая таблица будет подготовлена ниже; размерность
        # нового индекса в таком случае спросим у текущего векторизатора.
        return 0


def _read_stored(conn: sqlite3.Connection) -> tuple[dict[int, list[float]], dict[int, int]]:
    """Что уже лежит в индексе: (id находки → вектор, id находки → rowid строки).

    Второе нужно не для красоты: в `vec0` удаление по столбцу-метаданным — это
    полный проход по таблице (1,6 с на 200 строк при пяти тысячах в индексе),
    а удаление по rowid мгновенное. Поэтому мы его запоминаем.
    """
    vecs: dict[int, list[float]] = {}
    rowids: dict[int, int] = {}
    try:
        if _load_vec_ext(conn):
            for rid, fid, blob in conn.execute(
                    "SELECT rowid, finding_id, embedding FROM sem").fetchall():
                b = bytes(blob)
                fid = int(fid)
                vecs[fid] = list(struct.unpack(f"<{len(b) // 4}f", b))
                rowids[fid] = int(rid)
        else:
            for rid, fid, dim, blob in conn.execute(
                    "SELECT id, finding_id, dim, vec FROM sem").fetchall():
                fid = int(fid)
                vecs[fid] = list(struct.unpack(f"<{int(dim)}f", bytes(blob)))
                rowids[fid] = int(rid)
    except Exception:
        return {}, {}
    return vecs, rowids


def _vectors_cached(findings: dict[int, dict]) -> dict[int, list[float]]:
    """Векторы находок — из индекса, а не пересчётом на каждый запрос.

    Раньше память между объектами (`search_all`) считала векторы всех находок
    заново при каждом вопросе: при 5 000 находок это 1,9 секунды из 2,2 секунд
    запроса, а с настоящей моделью было бы в десятки раз хуже. Индекс для этого
    и существует — здесь он наконец используется, причём пересчитываются только
    новые или изменившиеся записи.
    """
    if not findings:
        return {}
    conn = store.connect()
    texts = {int(fid): _text_full(f) for fid, f in findings.items()}
    how = _how_key()
    hashes = {fid: _text_hash(t) for fid, t in texts.items()}

    _ensure_meta(conn)
    meta: dict[int, tuple[str, str]] = {}
    try:
        for fid, h, w in conn.execute("SELECT finding_id, text_hash, how FROM sem_meta"):
            meta[int(fid)] = (str(h or ""), str(w or ""))
    except sqlite3.OperationalError:
        meta = {}

    # Не распаковывать все BLOB ради одного dim: сначала спросить размерность
    # одной строки, подготовить таблицу (она может быть пересоздана), затем
    # материализовать stored map единственным полным чтением.
    dim = _vector_dimension() or _stored_dimension(conn)
    with _lock:
        use_vec = _ensure_tables(conn, dim)
        stored, rowids = _read_stored(conn)

        def need_ids() -> list[int]:
            return [fid for fid in texts
                    if fid not in stored or
                    meta.get(fid, ("", "")) != (hashes[fid], how)]

        todo = need_ids()
        if todo:
            vecs, _ = embed([texts[fid] for fid in todo])
            _ensure_meta(conn)
            for fid, vec in zip(todo, vecs):
                # без vec0 строки нумеруются AUTOINCREMENT, и `rowid=fid` попадал в ЧУЖУЮ
                # запись (или в только что вставленную на прошлом шаге) — часть находок
                # молча выпадала из памяти. Здесь удаляем по finding_id, он проиндексирован.
                if use_vec:
                    conn.execute("DELETE FROM sem WHERE rowid=?", (rowids.get(fid, fid),))
                    conn.execute("INSERT INTO sem(rowid, scan_id, finding_id, embedding)"
                                 " VALUES(?,?,?,?)",
                                 (fid, findings[fid].get("scan_id"), fid,
                                  _vec_ext.serialize_float32(vec)))
                else:
                    conn.execute("DELETE FROM sem WHERE finding_id=?", (fid,))
                    conn.execute("INSERT INTO sem(scan_id, finding_id, dim, text, vec)"
                                 " VALUES(?,?,?,?,?)",
                                 (findings[fid].get("scan_id"), fid, dim, "",
                                  struct.pack(f"<{dim}f", *vec)))
                conn.execute("INSERT INTO sem_meta(finding_id, scan_id, dim, text_hash, how)"
                             " VALUES(?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET"
                             " scan_id=excluded.scan_id, dim=excluded.dim,"
                             " text_hash=excluded.text_hash, how=excluded.how",
                             (fid, findings[fid].get("scan_id"), dim, hashes[fid], how))
            conn.commit()
            stored, rowids = _read_stored(conn)
    return {fid: stored[fid] for fid in texts if fid in stored}


def index_scan(scan_id: int) -> dict:
    """Пересчитать векторы находок одного анализа."""
    findings = store.scan_findings(scan_id)
    if not findings:
        return {"indexed": 0, "backend": backend()}
    vecs, how = embed([_text_full(f) for f in findings])
    how_key = _how_key()
    dim = len(vecs[0]) if vecs else _vector_dimension()
    conn = store.connect()
    with _lock:
        # сперва готовим таблицу (здесь же подключается расширение), и только потом чистим
        # прошлый индекс: если удалять до этого, хранилище может ещё не уметь читать vec0,
        # удаление молча не сработает — и векторы задублируются
        use_vec = _ensure_tables(conn, dim)
        _ensure_meta(conn)
        # Чистим прошлый индекс этого скана по rowid: удаление по столбцу в vec0 —
        # это полный проход по таблице, и на больших базах он занимает секунды.
        _, old_rows = _read_stored(conn)
        try:
            ids = [int(r[0]) for r in conn.execute(
                "SELECT finding_id FROM sem_meta WHERE scan_id=?", (scan_id,)).fetchall()]
        except sqlite3.OperationalError:
            ids = []
        for fid in ids:
            if use_vec:
                conn.execute("DELETE FROM sem WHERE rowid=?", (old_rows.get(fid, fid),))
            else:
                conn.execute("DELETE FROM sem WHERE finding_id=?", (fid,))
            conn.execute("DELETE FROM sem_meta WHERE finding_id=?", (fid,))
        for f, vec in zip(findings, vecs):
            if use_vec:
                conn.execute("INSERT INTO sem(rowid, scan_id, finding_id, embedding)"
                             " VALUES(?,?,?,?)",
                             (f["id"], scan_id, f["id"], _vec_ext.serialize_float32(vec)))
            else:
                conn.execute("INSERT INTO sem(scan_id, finding_id, dim, text, vec) VALUES(?,?,?,?,?)",
                             (scan_id, f["id"], dim, "", struct.pack(f"<{dim}f", *vec)))
            conn.execute("INSERT INTO sem_meta(finding_id, scan_id, dim, text_hash, how)"
                         " VALUES(?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET"
                         " scan_id=excluded.scan_id, dim=excluded.dim,"
                         " text_hash=excluded.text_hash, how=excluded.how",
                         (f["id"], scan_id, dim, _text_hash(_text_full(f)), how_key))
        conn.commit()
    return {"indexed": len(findings), "backend": how, "dim": dim}


# ------------------------------------------------------------------- сам поиск
def _cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def search(scan_id: int, query: str, k: int = 12) -> dict:
    """Смысловой поиск по находкам анализа. Пусто в индексе — индексируем на месте."""
    query = (query or "").strip()
    if not query:
        return {"query": query, "results": [], "backend": backend()}
    conn = store.connect()
    findings = {f["id"]: f for f in store.scan_findings(scan_id)}
    if not findings:
        return {"query": query, "results": [], "backend": backend()}
    try:
        have = conn.execute("SELECT COUNT(*) FROM sem WHERE scan_id=?", (scan_id,)).fetchone()[0]
    except sqlite3.OperationalError:
        have = 0
    if not have:
        index_scan(scan_id)
    qvec, how = embed([query])
    qvec = qvec[0]
    scored: list[tuple[float, int]] = []
    with _lock:
        try:
            if _load_vec_ext(conn):
                rows = conn.execute(
                    "SELECT finding_id, distance FROM sem WHERE scan_id=? AND embedding MATCH ? "
                    "ORDER BY distance LIMIT ?",
                    (scan_id, _vec_ext.serialize_float32(qvec), k * 3)).fetchall()
                scored = [(1.0 - float(r[1]), int(r[0])) for r in rows]
            else:
                rows = conn.execute("SELECT finding_id, dim, vec FROM sem WHERE scan_id=?",
                                    (scan_id,)).fetchall()
                for fid, dim, blob in rows:
                    vec = list(struct.unpack(f"<{dim}f", blob))
                    scored.append((_cosine(qvec, vec), int(fid)))
        except Exception:
            scored = []
    if not scored:                      # хранилище не завелось — считаем на месте, честно и не быстро
        vecs, how = embed([_text_of(findings[fid]) for fid in findings])
        for (fid, _), vec in zip(findings.items(), vecs):
            scored.append((_cosine(qvec, vec), fid))
    scored.sort(reverse=True)
    words = set(_WORD.findall(query.lower()))
    # признак «работает настоящая модель»: по строке способа видно и «модель …», и
    # «…(модель не найдена)» — поэтому проверяем именно название модели
    has_model = (_model_name() in how) and ("не найдена" not in how)
    out = []
    for score, fid in scored[:k * 3]:
        f = findings.get(fid)
        if not f:
            continue
        blob = json_dumps(f).lower()
        hits = sum(1 for w in words if w in blob)
        if has_model:       # есть настоящая модель: смысл главный, совпадение слов — уточнение
            final = float(score) + 0.08 * hits
        else:               # без модели: опираемся на слова, вектор — лишь добавка
            final = 0.25 * float(score) + float(hits)
        out.append({"finding": f, "score": round(final, 4), "words": hits,
                    "why": ("совпадают слова и смысл" if (hits and has_model) else
                            ("совпадают слова" if hits else "совпадает смысл")),
                    "title": f.get("title"), "priority": f.get("priority")})
    out.sort(key=lambda r: r["score"], reverse=True)
    return {"query": query, "results": out[:k], "backend": how, "indexed": len(findings),
            "mode": "смысловой поиск (модель)" if has_model else "поиск по словам (модель не установлена)"}


def _text_of(f: dict) -> str:
    return " ".join(str(f.get(k) or "") for k in ("title", "product", "service", "asset"))


def _text_full(f: dict) -> str:
    """Текст находки для векторизации.

    Один и тот же построитель используется и при индексации, и в запасном пути
    поиска. Если бы они считали по-разному, оценка в запасном пути не
    соответствовала бы тому, что лежит в индексе, и результаты плавали бы
    в зависимости от того, завелось расширение sqlite-vec или нет.
    """
    parts = [str(f.get("title") or ""), str(f.get("product") or ""),
             str(f.get("service") or ""), str(f.get("asset") or "")]
    ev = f.get("evidence") or {}
    if isinstance(ev, dict):
        parts += [str(v) for v in list(ev.values())[:6]]
    return " ".join(x for x in parts if x)[:1500]


# ------------------------------------------------- четвёртый слой: память между объектами
_STATUS_RU = {"false": "ложное срабатывание", "fixed": "исправлено",
              "accepted": "принят риск", "open": "открыта"}


def _all_findings() -> dict[int, dict]:
    """Все находки всех анализов, с указанием скана и заказчика."""
    out: dict[int, dict] = {}
    try:
        rows = store.q(
            "SELECT f.*, s.target_id AS _target_id, s.started_at AS _started_at, "
            "       t.value AS _target, t.client AS _client "
            "FROM findings f JOIN scans s ON s.id = f.scan_id "
            "LEFT JOIN targets t ON t.id = s.target_id "
            "ORDER BY f.id")
    except Exception:
        return out
    for r in rows:
        d = dict(r)
        try:
            d["evidence"] = json.loads(d.get("evidence") or "{}")
        except Exception:
            d["evidence"] = {}
        out[d["id"]] = d
    return out


def index_all(*, force: bool = False) -> dict:
    """Индексировать все анализы сразу.

    По одному скану индекс собирается в `index_scan`, но память между объектами
    работает только тогда, когда в индексе есть всё: вопрос «встречалось ли это
    раньше» нельзя ответить по базе, где лежит один анализ.

    Сканы без находок индексировать нечего; они не должны снова попадать в
    очередь при каждом вызове. Без `force` также пропускаются сканы, которые
    уже в индексе — пересчёт всех анализов на каждое обращение был бы медленным.
    """
    conn = store.connect()
    try:
        have = {int(r[0]) for r in
                conn.execute("SELECT DISTINCT scan_id FROM sem").fetchall()}
    except sqlite3.OperationalError:
        have = set()
    all_sids = [int(r[0]) for
                r in conn.execute("SELECT id FROM scans ORDER BY id").fetchall()]
    sids = [int(r[0]) for r in conn.execute(
        "SELECT DISTINCT f.scan_id FROM findings f JOIN scans s ON s.id=f.scan_id "
        "ORDER BY f.scan_id").fetchall()]
    todo = sids if force else [x for x in sids if x not in have]
    total, how = 0, backend()
    for sid in todo:
        res = index_scan(sid)
        total += int(res.get("indexed") or 0)
        how = res.get("backend") or how
    return {"indexed": total, "scans": len(todo), "scans_total": len(all_sids),
            "skipped": len(all_sids) - len(todo), "backend": how}


def _search_candidates(query: str, k: int, findings: dict[int, dict],
                       vec_map: dict[int, list[float]] | None = None) -> dict:
    """Ранжировать выбранный корпус; vec_map позволяет переиспользовать индекс.

    Для обычного поиска вектора загружаются здесь. Пакетные callers могут
    подготовить vec_map один раз и задать несколько queries к тому же snapshot
    без повторного чтения SQLite.
    """
    qvec, how = embed([query])
    qvec = qvec[0]
    if vec_map is None:
        vec_map = _vectors_cached(findings)
    words = set(_WORD.findall(query.lower()))
    has_model = (_model_name() in how) and ("не найдена" not in how)

    def scored_items():
        for position, fid in enumerate(findings):
            f = findings[fid]
            vec = vec_map.get(int(fid)) or [0.0] * len(qvec)
            # JSON вычисляется один раз на finding/query, не на каждое слово.
            blob = json_dumps(f).lower() if words else ""
            hits = sum(1 for word in words if word in blob)
            cosine = _cosine(qvec, vec)
            final = (float(cosine) + 0.08 * hits if has_model else
                     0.25 * float(cosine) + float(hits))
            yield position, {
                "finding": f, "score": round(final, 4), "words": hits,
                "title": f.get("title"), "priority": f.get("priority"),
                "scan_id": f.get("scan_id"), "target": f.get("_target") or "",
                "client": f.get("_client") or "", "started_at": f.get("_started_at") or "",
                "status": f.get("status") or "open",
                "status_ru": _STATUS_RU.get(f.get("status") or "open", f.get("status") or "открыта"),
                "why": ("совпадают слова и смысл" if (hits and has_model) else
                        ("совпадают слова" if hits else "совпадает смысл")),
            }

    # search_all обычно просит k≪N. Держим только top-k вместо N готовых
    # словарей. Входной sequence index воспроизводит stable-sort tie order.
    if 0 < k < len(findings):
        best: list[tuple[float, int, dict]] = []
        for position, item in scored_items():
            score_value = item["score"]
            if math.isnan(score_value):
                # NaN не задаёт total ordering для heap; редкий повреждённый
                # vector сохраняет прежнее поведение Python stable sort.
                out = [candidate for _, candidate in scored_items()]
                out.sort(key=lambda result: result["score"], reverse=True)
                break
            entry = (score_value, -position, item)
            if len(best) < k:
                heapq.heappush(best, entry)
            elif entry > best[0]:
                heapq.heapreplace(best, entry)
        else:
            best.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
            out = [entry[2] for entry in best]
    else:
        out = [item for _, item in scored_items()]
        out.sort(key=lambda result: result["score"], reverse=True)

    return {"query": query, "results": out[:k], "backend": how,
            "searched": len(findings),
            "mode": "смысловой поиск по всем объектам (модель)" if has_model
                    else "поиск по словам по всем объектам (модель не установлена)"}


def search_all(query: str, k: int = 12, *, exclude_scan: int = 0,
               target_id: int = 0) -> dict:
    """Смысловой поиск по всем анализам: что похожего уже встречалось.

    Именно этого не хватало для памяти между объектами — `search()` отвечает
    только в пределах одного анализа.

    `exclude_scan` убирает текущий анализ: искать «видел ли я такое» в том же
    скане, где находка и так есть, смысла нет.
    """
    query = (query or "").strip()
    if not query:
        return {"query": query, "results": [], "backend": backend(), "mode": ""}
    findings = _all_findings()
    if exclude_scan:
        findings = {i: f for i, f in findings.items() if f.get("scan_id") != exclude_scan}
    if target_id:
        findings = {i: f for i, f in findings.items() if f.get("_target_id") == target_id}
    if not findings:
        return {"query": query, "results": [], "backend": backend(),
                "mode": "в базе нет находок"}
    return _search_candidates(query, k, findings)


def _annotate_similar(mine: dict, results: list[dict], k: int) -> list[dict]:
    """Добавить к прошлым находкам пометки, которые помогают принять решение."""
    out = []
    for item in results:
        finding = item["finding"]
        note = "та же CVE" if (finding.get("cve_id") or "") and \
            finding.get("cve_id") == mine.get("cve_id") else ""
        if note and (finding.get("product") or "") and \
                finding.get("product") == mine.get("product"):
            note += ", тот же продукт"
        item["note"] = note
        out.append(item)
    return out[:k]


def notes_for_scan(scan_id: int, *, limit: int = 4, per_finding: int = 2) -> list[dict]:
    """Что из этого анализа уже встречалось на других объектах и чем кончилось.

    Вынесено сюда, а не в `agent.py`: поиск грузит локальную модель эмбеддингов,
    а агент по устройству не обращается к моделям вовсе — иначе нельзя
    утверждать, что решение принимает оператор, а не модель.

    Берутся только находки с приоритетом P0/P1: перебирать все подряд смысла
    нет, а подсказка на сотню строк не читается. Корпус и vector map берутся
    одним snapshot, потому что все queries относятся к одному scan_id.
    """
    out: list[dict] = []
    scan_findings = store.scan_findings(scan_id)
    findings = [f for f in scan_findings
                if (f.get("priority") or "") in ("P0", "P1")]
    if not findings:
        findings = scan_findings[:limit]
    findings = findings[:limit]
    if not findings:
        return out

    candidates = {fid: finding for fid, finding in _all_findings().items()
                  if finding.get("scan_id") != int(scan_id)}
    if not candidates:
        return out
    queries = [(mine, _text_full(mine).strip()) for mine in findings]
    queries = [(mine, query) for mine, query in queries if query]
    if not queries:
        return out
    vec_map = _vectors_cached(candidates)

    for mine, query in queries:
        res = _search_candidates(query, per_finding + 1, candidates, vec_map)
        hits = _annotate_similar(mine, res.get("results", []), per_finding)
        if not hits:
            continue
        out.append({
            "finding_id": int(mine["id"]),
            "title": mine.get("title") or "",
            "priority": mine.get("priority") or "",
            "hits": [{
                "score": hit["score"], "scan_id": hit["scan_id"],
                "client": hit.get("client") or "", "target": hit.get("target") or "",
                "title": hit.get("title") or "", "status": hit.get("status") or "open",
                "status_ru": hit.get("status_ru") or "", "note": hit.get("note") or "",
            } for hit in hits],
        })
    return out


def similar(finding_id: int, k: int = 8) -> dict:
    """Чем эта находка похожа на то, что уже было на других объектах.

    Это и есть рабочий вопрос памяти: не «что ещё похоже по тексту», а
    «разбирался ли я с этим раньше и чем кончилось». Поэтому в результат
    попадает вывод по прошлой находке — ложное срабатывание, исправлено,
    принят риск, — а не только заголовок.
    """
    mine = store.finding(finding_id)
    if not mine:
        return {"results": [], "finding": {}, "backend": backend()}
    res = search_all(_text_full(mine), k=k + 1, exclude_scan=int(mine.get("scan_id") or 0))
    out = _annotate_similar(mine, res.get("results", []), k)
    return {"finding": mine, "results": out, "backend": res.get("backend"),
            "mode": res.get("mode"), "searched": res.get("searched", 0)}


def json_dumps(obj) -> str:
    import json
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)


def status() -> dict:
    """Состояние смыслового поиска — для интерфейса и документов."""
    info = {"backend": backend(), "dim": _vector_dimension(), "model": _model_name(),
            "sqlite_vec": bool(_load_vec_ext(store.connect())), "fastembed": _load_model() is not None}
    try:
        info["indexed"] = store.connect().execute("SELECT COUNT(*) FROM sem").fetchone()[0]
    except Exception:
        info["indexed"] = 0
    return info
