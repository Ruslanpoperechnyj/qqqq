"""Веб-сервер и API дашборда (только стандартная библиотека Python)."""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import aiagent, collect, drafts, graphpaths, mode as modemod, report, scan as scanmod, sources, store
from .settings import Settings, SettingsError, project_explicit_environment, use_settings

try:
    from . import vector as vecmod
except Exception:  # noqa: BLE001
    vecmod = None  # type: ignore

HERE = os.path.dirname(os.path.abspath(__file__))
UI = os.path.join(os.path.dirname(HERE), "ui", "index.html")
_MODE_ENV_KEYS = frozenset(key for preset in modemod.PRESETS.values() for key in preset)


def _explicit_config_snapshot(values: Mapping[str, object] | None = None) -> dict[str, object]:
    """Project explicit non-secret scan and mode env before legacy injection."""
    source = os.environ if values is None else values
    return project_explicit_environment(source, additional_keys=_MODE_ENV_KEYS)


def _scan_settings_snapshot(
    explicit_environment: Mapping[str, object] | None = None,
) -> Settings:
    """Собрать settings для нового worker; mode читается на границе операции."""
    explicit = (explicit_environment if explicit_environment is not None
                else _explicit_config_snapshot())
    _, mode_values = modemod.stored_preset(store)
    return Settings.from_environment_snapshot(explicit, mode_values=mode_values)


def _json(handler, obj, code=200):
    body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _text(handler, body: str, ctype="text/plain; charset=utf-8", code=200, filename: str | None = None):
    data = body.encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    if filename:
        handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.end_headers()
    handler.wfile.write(data)


def _bytes(handler, data: bytes, ctype="application/octet-stream", filename: str | None = None):
    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    if filename:
        handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.end_headers()
    handler.wfile.write(data)


def _sse(handler, chunks):
    """Поток Server-Sent Events (chunked): токены ИИ приходят по мере генерации."""
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
    handler.send_header("Cache-Control", "no-cache")
    handler.send_header("X-Accel-Buffering", "no")
    handler.send_header("Transfer-Encoding", "chunked")
    handler.end_headers()
    try:
        for chunk in chunks:
            if not chunk:
                continue
            handler.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
            handler.wfile.flush()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try:
            handler.wfile.write(b"0\r\n\r\n")
            handler.wfile.flush()
        except Exception:  # noqa: BLE001
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ASM/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # тише в консоли
        if os.environ.get("ASM_VERBOSE"):
            super().log_message(fmt, *args)

    # ------------------------------------------------------------ helpers
    def _settings_for_new_scan(self) -> Settings:
        server = getattr(self, "server", None)
        explicit = getattr(server, "asm_explicit_config_environment", None)
        return _scan_settings_snapshot(explicit)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
        except Exception:
            return {}

    def _target_row(self, t) -> dict:
        d = dict(t)
        scs = store.scans(t["id"])
        d["scans"] = [{"id": s["id"], "status": s["status"], "started_at": s["started_at"],
                       "finished_at": s["finished_at"], "progress": s["progress"]} for s in scs]
        d["last_scan"] = scs[0]["id"] if scs else None
        try:
            d["materials"] = store.target_materials(t["id"])
        except Exception:
            d["materials"] = {}
        return d

    # ------------------------------------------------------------ routing
    def do_GET(self):
        try:
            request_settings = self._settings_for_new_scan()
            settings_context = use_settings(request_settings)
            settings_context.__enter__()
        except Exception as e:  # noqa: BLE001 — без значений конфигурации
            return _json(self, {"error": f"{type(e).__name__}: {e}"}, 500)
        try:
            # Parse inside the protected Settings scope too: malformed absolute
            # request targets can make urlparse raise before the cleanup finally.
            u = urllib.parse.urlparse(self.path)
            p = u.path
            if p in ("/", "/index.html"):
                if os.path.exists(UI):
                    return _text(self, open(UI, encoding="utf-8").read(), "text/html; charset=utf-8")
                return _text(self, "<h1>UI не найден</h1>", "text/html; charset=utf-8", 500)

            if p in ("/chat", "/chat/"):
                fp = os.path.join(os.path.dirname(UI), "chat.html")
                if os.path.exists(fp):
                    with open(fp, encoding="utf-8") as f:
                        return _text(self, f.read(), "text/html; charset=utf-8")
                return _text(self, "<h1>чат не найден (ui/chat.html)</h1>",
                             "text/html; charset=utf-8", 500)

            if p == "/api/chat/status":
                from . import chat as chatmod
                sessions = []
                for se in store.agent_sessions(only_open=True):
                    t = store.target(se["target_id"])
                    sessions.append({"id": se["id"], "target_id": se["target_id"],
                                     "target": (t["value"] if t else "?"),
                                     "client": (t["client"] if t else ""),
                                     "auth_ref": (t["auth_ref"] if t else ""),
                                     "status": se["status"], "deadline": se.get("deadline") or ""})
                return _json(self, {"chat": chatmod.status(), "sessions": sessions,
                                    "tools": {k: {"kind": v["kind"], "about": v["about"]}
                                              for k, v in chatmod.TOOLS.items()}})

            if p == "/api/chat/history":
                from . import chat as chatmod
                qs = urllib.parse.parse_qs(u.query)
                sid = int((qs.get("session") or ["0"])[0] or 0)
                if not sid:
                    return _json(self, {"error": "нужен session"}, 400)
                return _json(self, {"messages": chatmod.history(sid)})

            if p == "/api/chat/ctx":
                from . import objmap
                qs = urllib.parse.parse_qs(u.query)
                sid = int((qs.get("session") or ["0"])[0] or 0)
                sess = store.agent_session(sid) if sid else None
                if not sess:
                    return _json(self, {"error": f"сессии {sid} нет"}, 404)
                t = store.target(sess["target_id"])
                out = {"target": dict(t) if t else {}, "notes": store.agent_notes(sid, limit=12),
                       "attachments": store.attachments(sess["target_id"]), "map": ""}
                try:
                    m = objmap.build(session_id=sid)
                    if m.get("ok"):
                        out["map"] = objmap.text(m, limit=2600)
                except Exception as e:  # noqa: BLE001
                    out["map"] = f"карта недоступна: {type(e).__name__}"
                return _json(self, out)

            if p == "/api/chat/steps":
                from . import agent as agmod
                qs = urllib.parse.parse_qs(u.query)
                sid = int((qs.get("session") or ["0"])[0] or 0)
                if not sid:
                    return _json(self, {"error": "нужен session"}, 400)
                steps = []
                for st in store.agent_steps(sid):
                    try:
                        g = agmod.gate_step(st["id"], sess=store.agent_session(sid))
                        internal = st["action_id"] in getattr(agmod, "INTERNAL_IDS", ())
                    except Exception as e:  # noqa: BLE001
                        g = {"action": "allow", "note": f"проверка недоступна: {type(e).__name__}"}
                        internal = False
                    steps.append({"id": st["id"], "seq": st["seq"], "cls": st["cls"],
                                  "title": st["title"], "status": st["status"],
                                  "action_id": st["action_id"], "internal": bool(internal),
                                  "rationale": st["rationale"], "risk": st["risk"],
                                  "gate": g.get("action"), "gate_note": g.get("note") or "",
                                  "decided_by": st.get("decided_by") or "",
                                  "result": (st.get("result") or "")[:600]})
                from . import engines as engmod
                return _json(self, {"steps": steps, "halted": engmod.halt_state()})

            if p == "/api/attachments":
                qs = urllib.parse.parse_qs(u.query)
                tid = int((qs.get("target") or ["0"])[0] or 0)
                if not tid:
                    return _json(self, {"error": "нужен target"}, 400)
                return _json(self, {"attachments": store.attachments(tid)})

            if p.startswith("/vendor/"):
                # локальные копии библиотек интерфейса (без внешних CDN: работает и без интернета)
                name = os.path.basename(p)
                fp = os.path.join(os.path.dirname(UI), "vendor", name)
                if os.path.exists(fp) and name.endswith(".js"):
                    return _text(self, open(fp, encoding="utf-8").read(),
                                 "application/javascript; charset=utf-8")
                return _text(self, "нет такого файла", "text/plain; charset=utf-8", 404)

            if p == "/api/targets":
                return _json(self, [_self_target_row(t) for t in store.targets()])

            if p == "/api/audit":
                return _json(self, [dict(r) for r in store.q("SELECT * FROM audit ORDER BY id DESC LIMIT 200")])

            if p.startswith("/api/scan/"):
                parts = p.strip("/").split("/")
                sid = int(parts[2])
                sc = store.scan(sid)
                if not sc:
                    return _json(self, {"error": "скан не найден"}, 404)
                tail = parts[3] if len(parts) > 3 else ""
                if not tail:
                    st = json.loads(sc["stats"] or "{}")
                    return _json(self, {
                        "id": sid, "status": sc["status"], "progress": sc["progress"],
                        "started_at": sc["started_at"], "finished_at": sc["finished_at"],
                        "log": sc["log"], "error": sc["error"], "stats": st,
                        "target": dict(store.target(sc["target_id"])),
                        "findings_count": len(store.scan_findings(sid)),
                    })
                if tail == "findings":
                    qq = urllib.parse.parse_qs(u.query)
                    status = (qq.get("status", [""])[0] or "").strip()
                    priority = (qq.get("priority", [""])[0] or "").strip()
                    text = (qq.get("q", [""])[0] or "").strip()
                    rows = store.scan_findings(sid)
                    if status:
                        wanted = set(status.split(","))
                        rows = [f for f in rows if (f.get("status") or "open") in wanted]
                    if priority:
                        rows = [f for f in rows if f.get("priority") in set(priority.split(","))]
                    if text:
                        low = text.lower()
                        rows = [f for f in rows
                                if low in json.dumps({k: f.get(k) for k in
                                                      ("title", "asset", "ip", "cve_id", "product")},
                                                     ensure_ascii=False).lower()]
                    return _json(self, rows)
                if tail == "progress":
                    return _json(self, {"progress": store.scan_progress_value(sid),
                                        "status": sc["status"], "error": sc["error"]})
                if tail == "search":
                    qq = urllib.parse.parse_qs(u.query)
                    return _json(self, store.search_findings(sid, (qq.get("q", [""])[0] or "").strip()))
                if tail == "paths":
                    return _json(self, graphpaths.attack_paths(store.scan_assets(sid),
                                                               store.scan_edges(sid),
                                                               store.scan_findings(sid)))
                if tail == "views":
                    return _json(self, store.views_list(sid))
                if tail == "summary":
                    return _text(self, aiagent.summary_markdown(sid), "text/markdown; charset=utf-8")
                if tail == "assets":
                    return _json(self, store.scan_assets(sid))
                if tail == "graph":
                    assets = store.scan_assets(sid)
                    edges = store.scan_edges(sid)
                    kinds = sorted({a["kind"] for a in assets})
                    layout = store.layout_get(sid)
                    return _json(self, {"nodes": assets, "edges": edges, "kinds": kinds,
                                        "layout": layout})
                if tail == "drafts":
                    fs = store.scan_findings(sid)
                    made = drafts.drafts_for_scan(fs)
                    folder = drafts.write_drafts(sid, made) if made else ""
                    return _json(self, {"count": len(made), "folder": folder,
                                        "items": [{k: v for k, v in d.items() if k != "yaml"} | {"yaml": d["yaml"]}
                                                  for d in made],
                                        "как_запускать": "nuclei -validate -t *.yaml, затем "
                                                         "nuclei -t *.yaml -u https://ваш-сайт"})
                if tail == "drafts.zip":
                    fs = store.scan_findings(sid)
                    made = drafts.drafts_for_scan(fs)
                    data = drafts.zip_bytes(sid, made)
                    return _bytes(self, data, "application/zip", f"asm-drafts-scan-{sid}.zip")
                if tail == "semantic":
                    q = urllib.parse.parse_qs(u.query).get("q", [""])[0]
                    if vecmod is None:
                        return _json(self, {"error": "модуль смыслового поиска недоступен"}, 500)
                    res = vecmod.search(sid, q, k=int(urllib.parse.parse_qs(u.query).get("k", ["12"])[0]))
                    return _json(self, {**res, "backend": vecmod.backend()})
                if tail == "index":
                    if vecmod is None:
                        return _json(self, {"error": "модуль смыслового поиска недоступен"}, 500)
                    return _json(self, vecmod.index_scan(sid))
                if tail == "node":
                    q = urllib.parse.parse_qs(u.query)
                    element = {"type": q.get("type", ["asset"])[0],
                               "value": q.get("value", [""])[0],
                               "id": q.get("id", [""])[0],
                               "port": q.get("port", [""])[0]}
                    return _json(self, aiagent.context_for(sid, element))
                if tail == "report":
                    fmt = urllib.parse.parse_qs(u.query).get("fmt", ["md"])[0]
                    if fmt == "json":
                        return _text(self, report.json_report(sid), "application/json; charset=utf-8",
                                     filename=f"asm-report-{sid}.json")
                    if fmt == "csv":
                        return _text(self, "\ufeff" + report.csv_report(sid), "text/csv; charset=utf-8",
                                     filename=f"asm-report-{sid}.csv")
                    return _text(self, report.markdown(sid), "text/markdown; charset=utf-8",
                                 filename=f"asm-report-{sid}.md")

            if p == "/api/ai/status":
                return _json(self, aiagent.status())

            if p == "/api/registry":
                return _json(self, store.registry_all())

            if p == "/api/schedule":
                return _json(self, store.schedule_all())

            if p == "/api/ai/history":
                qq = urllib.parse.parse_qs(u.query)
                sid = int(qq.get("scan_id", ["0"])[0] or 0)
                el = qq.get("element", [""])[0]
                return _json(self, store.chat_history(sid, el) if sid and el else [])

            if p == "/api/health":
                return _json(self, {"ok": True})

            if p == "/api/vector":
                if vecmod is None:
                    return _json(self, {"доступно": False})
                return _json(self, {**vecmod.status(), "доступно": True})

            if p == "/api/engines":
                # арсенал: что установлено, версии, роль каждого движка
                try:
                    from . import engines as eng
                    st = eng.available()
                    installed = sum(1 for k, v in st.items() if isinstance(v, dict) and v.get("installed"))
                    total = sum(1 for k, v in st.items() if isinstance(v, dict) and "installed" in v and v.get("id"))
                    return _json(self, {"engines": [v for v in st.values() if isinstance(v, dict) and v.get("id")],
                                        "installed": installed, "total": total,
                                        "templates": st["nuclei"]["templates"] if isinstance(st.get("nuclei"), dict) else 0,
                                        "wordlists": st.get("wordlists", {}).get("files", []),
                                        "banned": sorted(eng.BANNED_TAGS)})
                except Exception as e:  # noqa: BLE001
                    return _json(self, {"error": f"арсенал недоступен: {e}", "engines": []})

            if p == "/api/agent/state":
                from . import engines
                procs = []
                for pr in engines.running():
                    procs.append({"pid": pr.pid,
                                  "cmd": " ".join(pr.args)[:200] if pr.args else ""})
                return _json(self, {"stopped": engines.halt_state(),
                                    "running": procs})

            if p == "/api/agent/plan":
                # Панель шагов агента. Одобрение и запуск остаются решениями
                # человека, но принимать их из терминала, пока смотришь в
                # дашборд, — лишнее трение: именно на нём и ломается контроль,
                # потому что начинают одобрять «пачкой», не читая.
                from . import agent as agmod
                from . import engines as engmod
                qs = urllib.parse.parse_qs(u.query)
                sid = int((qs.get("session") or ["0"])[0] or 0)
                sessions = store.agent_sessions()
                if not sid and sessions:
                    sid = sessions[0]["id"]
                sess = store.agent_session(sid) if sid else None
                if sid and sess is None:
                    return _json(self, {"error": f"сессии {sid} нет"}, 404)
                steps = []
                for st in (store.agent_steps(sid) if sid else []):
                    d = dict(st)
                    try:
                        d["params"] = json.loads(st["params"] or "{}")
                    except Exception:
                        d["params"] = {}
                    # Описание шага отдаём тем же текстом, что и в терминале:
                    # два разных описания одного шага разошлись бы.
                    try:
                        d["describe"] = agmod.describe(st)
                    except Exception:
                        d["describe"] = ""
                    # Ворота показываются рядом с шагом: оператор должен
                    # видеть, чем платит, ДО нажатия «одобрить».
                    try:
                        from . import gate as gmod
                        g = agmod.gate_step(st["id"])
                        d["gate"] = {"action": g["action"], "note": g["note"],
                                     "findings": g["findings"],
                                     "text": gmod.describe(g)}
                    except Exception as e:  # noqa: BLE001
                        d["gate"] = {"action": "allow", "note": f"проверка недоступна: {e}",
                                     "findings": [], "text": ""}
                    # Внутренний ли шаг: панель по этому признаку спрашивает
                    # пароль перед отправкой и по-другому подписывает шаг.
                    d["internal"] = st["action_id"] in getattr(agmod, "INTERNAL_IDS", ())
                    steps.append(d)
                # Сверенные сведения рядом с планом. Оператор должен видеть не
                # только «что предложено», но и «на каких сведениях это
                # построено»: в прогоне №1 план был дисциплинированным, а
                # ошибка — в применимости уязвимости, и поймать её глазами
                # можно было только увидев диапазон версий.
                facts_view: dict = {}
                if sid:
                    try:
                        from . import facts as fmod
                        sh = fmod.sheet_for_session(sid)
                        if sh.get("scan_id"):
                            facts_view = {"scan": sh.get("scan") or {},
                                          "lines": sh.get("lines") or [],
                                          "unverified": sh.get("unverified") or [],
                                          "mode": sh.get("mode") or ""}
                    except Exception:  # noqa: BLE001 — панель обязана открыться
                        facts_view = {}
                # Карта объекта: тот же сбор, что идёт модели в подсказку и в
                # документ передачи. Оператор видит стадию, поверхность и где
                # мы стоим, а схему (mermaid) можно целиком вставить в отчёт.
                obj_map: dict = {}
                if sid:
                    try:
                        from . import objmap
                        om = objmap.build(session_id=sid)
                        if om.get("ok"):
                            obj_map = {"text": objmap.text(om, limit=4000),
                                       "mermaid": objmap.mermaid(om),
                                       "stage": om.get("stage_title") or ""}
                    except Exception:  # noqa: BLE001 — панель важнее приложения
                        obj_map = {}
                return _json(self, {
                    "session": sid,
                    "session_row": dict(sess) if sess else None,
                    "sessions": sessions,
                    "steps": steps,
                    "halted": engmod.halt_state(),
                    "notes": store.agent_notes(sid, limit=50) if sid else [],
                    "facts": facts_view,
                    "objmap": obj_map,
                })

            if p == "/api/agent/gate":
                from . import agent as agmod
                from . import gate as gmod
                qs = urllib.parse.parse_qs(u.query)
                step_id = int((qs.get("step") or ["0"])[0] or 0)
                if not step_id or store.agent_step(step_id) is None:
                    return _json(self, {"error": f"шага {step_id} нет"}, 404)
                g = agmod.gate_step(step_id)
                return _json(self, {**g, "text": gmod.describe(g)})

            if p == "/api/agent/notes":
                qs = urllib.parse.parse_qs(u.query)
                sid = int((qs.get("session") or ["0"])[0] or 0)
                if sid and store.agent_session(sid) is None:
                    return _json(self, {"error": f"сессии {sid} нет"}, 404)
                rows = store.agent_notes(sid, limit=200) if sid else []
                for r in rows:
                    r["kind_title"] = store.NOTE_KIND_TITLE.get(r["kind"], r["kind"])
                return _json(self, {"session": sid, "notes": rows,
                                    "kinds": [{"id": k, "title": v}
                                              for k, v in store.NOTE_KIND_TITLE.items()]})

            if p == "/api/sources":
                # справочник источников разведки + что включено сейчас + вклад прошлого анализа
                cat = sources.sources_catalog()
                try:
                    rows = store.q("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
                    if rows:
                        sid_last = rows[0]["id"]
                        st = json.loads(store.scan(sid_last)["stats"] or "{}")
                        cat["last_scan"] = {"id": sid_last,
                                            "sources": st.get("sources") or {},
                                            "errors": st.get("source_errors") or {},
                                            "related": (st.get("related_domains") or [])[:12]}
                except Exception:
                    pass
                return _json(self, cat)

            return _json(self, {"error": "не найдено"}, 404)
        except Exception as e:  # noqa: BLE001
            return _json(self, {"error": f"{type(e).__name__}: {e}"}, 500)
        finally:
            settings_context.__exit__(None, None, None)

    def do_POST(self):
        try:
            request_settings = self._settings_for_new_scan()
            settings_context = use_settings(request_settings)
            settings_context.__enter__()
        except Exception as e:  # noqa: BLE001 — без значений конфигурации
            return _json(self, {"error": f"{type(e).__name__}: {e}"}, 500)
        try:
            # Keep URL parsing under the same finally-protected operation context.
            u = urllib.parse.urlparse(self.path)
            p = u.path
            b = self._body()
            if p == "/api/targets":
                value = (b.get("value") or "").strip()
                client = (b.get("client") or "").strip()
                auth_ref = (b.get("auth_ref") or "").strip()
                if not value or not client or not auth_ref:
                    return _json(self, {"error": "Нужны: объект анализа, заказчик и основание "
                                                 "(договор/письмо-разрешение). Это не формальность — "
                                                 "именно это отделяет аудит от статьи 272 УК РФ."}, 400)
                tid = store.add_target(value, client, auth_ref, b.get("auth_date") or "", b.get("note") or "")
                return _json(self, self._target_row(store.target(tid)))

            if p == "/api/scan":
                tid = int(b.get("target_id"))
                t = store.target(tid)
                if not t:
                    return _json(self, {"error": "цель не найдена"}, 404)
                try:
                    scan_settings = request_settings
                except SettingsError as e:
                    return _json(self, {"error": f"ошибка настроек scan: {e}"}, 400)
                sid = store.new_scan(tid)
                store.audit("scan_started", {"target": t["value"], "scan_id": sid,
                                             "client": t["client"], "auth_ref": t["auth_ref"]})
                lim = {k: v for k, v in (b.get("limits") or {}).items() if v is not None}
                # материалы заказчика (код, репозиторий, образ) хранятся у цели и подставляются сами
                try:
                    mats = store.target_materials(tid)
                except Exception:
                    mats = {}
                if mats.get("repo"):
                    lim.setdefault("code_repo", mats["repo"])
                if mats.get("code_path"):
                    lim.setdefault("code_path", mats["code_path"])
                if mats.get("image"):
                    lim.setdefault("image", mats["image"])
                threading.Thread(target=scanmod.run, args=(sid, lim),
                                 kwargs={"settings": scan_settings}, daemon=True).start()
                return _json(self, {"scan_id": sid, "status": "running"})

            if p.startswith("/api/target/") and p.endswith("/materials"):
                tid = int(p.strip("/").split("/")[2])
                if not store.target(tid):
                    return _json(self, {"error": "цель не найдена"}, 404)
                mats = {"repo": b.get("repo") or "", "code_path": b.get("code_path") or "",
                        "image": b.get("image") or ""}
                store.set_materials(tid, mats)
                return _json(self, {"ok": True, "materials": store.target_materials(tid)})

            if p.startswith("/api/findings/") and p.endswith("/status"):
                fid = int(p.strip("/").split("/")[2])
                st = (b.get("status") or "").strip()
                if not store.set_finding_status(fid, st, b.get("note") or "", b.get("owner") or ""):
                    return _json(self, {"error": "недопустимый статус", "можно": list(store.VALID_STATUS)}, 400)
                return _json(self, {"ok": True, "finding": store.finding(fid)})

            if p == "/api/registry":
                value = (b.get("value") or "").strip()
                if not value:
                    return _json(self, {"error": "нужно значение актива"}, 400)
                store.registry_set(value, b.get("kind") or "", b.get("criticality") or "",
                                   b.get("exposure") or "", b.get("owner") or "",
                                   b.get("tags") or "", b.get("note") or "")
                return _json(self, {"ok": True, "registry": store.registry_get(value)})

            if p == "/api/agent/stop":
                from . import engines
                sid = int(b.get("session") or 0)
                sess = store.agent_session(sid) if sid else None
                if sid and sess is None:
                    return _json(self, {"error": f"сессии {sid} нет"}, 404)
                # Процессы убиваем ДО записи в базу. Если запись упадёт,
                # воздействие на объект всё равно должно прекратиться —
                # порядок здесь принципиален.
                killed = engines.stop_all(b.get("note") or "остановка из веб-интерфейса")
                if sess is not None:
                    store.agent_stop(sid, b.get("operator") or "", b.get("note") or "", killed)
                left = engines.stop_survivors()
                return _json(self, {"ok": True, "killed": killed,
                                    "survivors": left,
                                    "stopped": engines.halt_state(),
                                    "session": sid or None})

            if p == "/api/attach":
                import base64 as b64
                from . import chat as chatmod
                tid = int(b.get("target") or 0)
                if not tid or not store.target(tid):
                    return _json(self, {"error": "не названа цель"}, 400)
                name = str(b.get("name") or "файл")[:160]
                blob = b.get("b64") or ""
                if not blob:
                    return _json(self, {"error": "пустой файл"}, 400)
                try:
                    data = b64.b64decode(blob)
                except Exception:  # noqa: BLE001
                    return _json(self, {"error": "файл не разобран (base64)"}, 400)
                if len(data) > 25 * 1024 * 1024:
                    return _json(self, {"error": "файл больше 25 МБ — принесите меньший"}, 400)
                import tempfile
                tmp = os.path.join(tempfile.mkdtemp(), name)
                with open(tmp, "wb") as f:
                    f.write(data)
                r = chatmod.save_attachment(tid, tmp, session_id=int(b.get("session") or 0),
                                            name=name, note=str(b.get("note") or "")[:200])
                return _json(self, r, 200 if r.get("ok") else 400)

            if p == "/api/chat/send":
                from . import chat as chatmod
                sid = int(b.get("session") or 0)
                text = str(b.get("text") or "")
                attach = [int(x) for x in (b.get("attach") or []) if str(x).isdigit()]
                model_choice = str(b.get("model") or "local")[:40]
                effort = str(b.get("effort") or "")[:20]
                if not sid:
                    return _json(self, {"error": "нужен session"}, 400)
                queue: "list[dict]" = []
                done = threading.Event()

                def worker():
                    try:
                        with use_settings(request_settings):
                            chatmod.ask(sid, text, attach=attach, model_choice=model_choice,
                                        effort=effort or None, emit=queue.append)
                    except Exception as e:  # noqa: BLE001 — причина, а не тишина
                        queue.append({"type": "error",
                                      "text": f"сбой чата: {type(e).__name__}: {e}"})
                    finally:
                        done.set()

                threading.Thread(target=worker, daemon=True).start()

                def gen():
                    while True:
                        while queue:
                            ev = queue.pop(0)
                            yield ("data: " + json.dumps(ev, ensure_ascii=False) + "\n\n").encode()
                        if done.is_set() and not queue:
                            break
                        time.sleep(0.05)

                return _sse(self, gen())

            if p == "/api/agent/decide":
                from . import agent as agmod
                try:
                    step_id = int(b.get("step") or 0)
                except (TypeError, ValueError):
                    step_id = 0
                st = store.agent_step(step_id) if step_id else None
                if st is None:
                    return _json(self, {"error": f"шага {step_id} нет"}, 404)
                if st["status"] != store.AGENT_PROPOSED:
                    # Повторное решение не принимается: иначе отклонённый шаг
                    # можно было бы «дожать» второй кнопкой.
                    return _json(self, {"error": f"шаг {step_id} уже решён"
                                                 f" ({st['status']})"}, 409)
                approve = bool(b.get("approve"))
                ok = store.agent_decide(step_id, approve, b.get("operator") or "веб-интерфейс",
                                        b.get("note") or "")
                if not ok:
                    return _json(self, {"error": "решение не принято"}, 409)
                return _json(self, {"ok": True, "step": dict(store.agent_step(step_id)),
                                    "approved": approve})

            if p == "/api/agent/run":
                from . import agent as agmod
                from . import engines
                sid = int(b.get("session") or 0)
                sess = store.agent_session(sid) if sid else None
                if sid and sess is None:
                    return _json(self, {"error": f"сессии {sid} нет"}, 404)
                results, done = [], 0
                # Пароль доступа приходит с этим запросом и живёт только в памяти
                # процесса: ни в базу, ни в журнал он не попадает (см. transport.py).
                secret = str(b.get("secret") or "")
                for st in (store.agent_steps(sid) if sid else []):
                    # Выполняются только шаги, одобренные человеком: решение —
                    # единственное, что переводит шаг в это состояние.
                    if st["status"] != store.AGENT_APPROVED:
                        continue
                    res = agmod.execute(st["id"], secret=secret)
                    done += 1
                    results.append({
                        "step": st["id"], "action_id": st["action_id"],
                        "ok": bool(res.get("ok")),
                        "inward": bool(res.get("inward")),
                        "reason": res.get("reason") or "",
                        "count": res.get("count"),
                        "handoff": bool(res.get("handoff")),
                        "internal": bool(res.get("internal")),
                        "result": res.get("result") or "",
                    })
                return _json(self, {"executed": done, "results": results,
                                    "halted": engines.halt_state(),
                                    "survivors": engines.stop_survivors()})

            if p == "/api/agent/note":
                sid = int(b.get("session") or 0)
                text = (b.get("text") or "").strip()
                if not sid or store.agent_session(sid) is None:
                    return _json(self, {"error": f"сессии {sid} нет"}, 404)
                if not text:
                    return _json(self, {"error": "пустая запись — записывать нечего"}, 400)
                kind = (b.get("kind") or "").strip() or store.note_kind(text)
                nid = store.agent_note(sid, kind, text,
                                       source=b.get("operator") or "панель")
                rows = store.agent_notes(sid, limit=1)
                return _json(self, {"ok": True, "id": nid,
                                    "kind": kind,
                                    "kind_title": store.NOTE_KIND_TITLE.get(kind, kind),
                                    "note": rows[-1] if rows else None})

            if p == "/api/agent/plan_next":
                # Планировщик из панели: строит план и ставит законную часть в
                # очередь. Ничего не выполняется — каждый шаг ждёт решения.
                from . import planner as pmod
                sid = int(b.get("session") or 0)
                if not sid or store.agent_session(sid) is None:
                    return _json(self, {"error": f"сессии {sid} нет"}, 404)
                res = pmod.plan_and_apply(sid, int(b.get("scan") or 0) or None,
                                          explicit_mode=b.get("planner") or "",
                                          limit=int(b.get("limit") or 6))
                return _json(self, {
                    "ok": True, "mode": res.get("mode"),
                    "queued": res.get("queued") or [],
                    "skipped": res.get("skipped") or [],
                    "warnings": res.get("warnings") or [],
                    "model": {k: v for k, v in (res.get("model") or {}).items()
                              if k != "hints"},
                    "rules": res.get("rules"),
                })

            if p == "/api/agent/autopilot":
                # Автопилот из панели: те же остановки, что и в терминале.
                from . import planner as pmod
                sid = int(b.get("session") or 0)
                if not sid or store.agent_session(sid) is None:
                    return _json(self, {"error": f"сессии {sid} нет"}, 404)
                rec = pmod.autopilot(sid,
                                     rounds=int(b.get("rounds") or 3),
                                     approve=(b.get("approve") or "none"),
                                     scan_id=int(b.get("scan") or 0) or None,
                                     limit=int(b.get("limit") or 4),
                                     planner_mode=b.get("planner") or "",
                                     operator=b.get("operator") or "панель")
                return _json(self, {"ok": True, "protocol": pmod.render_autopilot(rec),
                                    "stopped": rec.get("stopped"),
                                    "waiting": rec.get("waiting") or []})

            if p.startswith("/api/scan/") and p.endswith("/layout"):
                parts = p.strip("/").split("/")
                sid = int(parts[2])
                store.layout_save(sid, b.get("positions") or {})
                return _json(self, {"ok": True})

            if p.startswith("/api/scan/") and p.endswith("/recheck"):
                parts = p.strip("/").split("/")
                sid = int(parts[2])
                host = (b.get("host") or "").strip()
                port = int(b.get("port") or 0)
                if not host or not port:
                    return _json(self, {"error": "нужны host и port"}, 400)
                # проверяем только то, что уже входит в этот анализ (своя инфраструктура)
                known = {a["value"] for a in store.scan_assets(sid)} | {f.get("ip") for f in store.scan_findings(sid)}
                host_key = host.split(" (")[0]
                base_ip = host_key.rsplit(":", 1)[0]
                if host_key not in known and base_ip not in known:
                    return _json(self, {"error": "этот адрес не входит в текущий анализ"}, 400)
                result = {"host": host, "port": port}
                try:
                    result["tcp_open"] = collect.tcp_open(base_ip, port)
                except Exception as e:  # noqa: BLE001
                    result["tcp_open"] = None
                    result["tcp_error"] = str(e)
                try:
                    scheme = "https" if port in (443, 8443, 9443) else "http"
                    pr = collect.http_probe(base_ip, port, scheme, settings=request_settings)
                    result["probe"] = {k: pr.get(k) for k in
                                       ("status", "server", "title", "error", "tls")}
                except Exception as e:  # noqa: BLE001
                    result["probe_error"] = str(e)
                store.audit("recheck", {"scan_id": sid, **result})
                return _json(self, result)

            if p.startswith("/api/scan/") and p.endswith("/views"):
                parts = p.strip("/").split("/")
                sid = int(parts[2])
                name = (b.get("name") or "вид").strip()
                state = json.dumps(b.get("state") or {}, ensure_ascii=False)
                vid = store.view_save(sid, name, state)
                return _json(self, {"ok": True, "id": vid, "views": store.views_list(sid)})

            if p.startswith("/api/views/") and p.endswith("/delete"):
                vid = int(p.strip("/").split("/")[2])
                store.view_delete(vid)
                return _json(self, {"ok": True})

            if p == "/api/ai/triage":
                sid = int(b.get("scan_id") or 0)
                fid = int(b.get("finding_id") or 0)
                if not sid or not fid:
                    return _json(self, {"error": "нужны scan_id и finding_id"}, 400)
                if not aiagent.rate_ok():
                    return _json(self, {"error": "слишком много запросов — подождите минуту"}, 429)
                return _sse(self, aiagent.triage_stream(sid, fid))

            if p == "/api/schedule":
                tid = int(b.get("target_id") or 0)
                hours = int(b.get("interval_hours") or 24)
                if not tid:
                    return _json(self, {"error": "нужен target_id"}, 400)
                store.schedule_set(tid, max(1, hours), bool(b.get("enabled", True)))
                return _json(self, {"ok": True, "schedule": store.schedule_get(tid)})

            if p == "/api/ai/chat":
                sid = int(b.get("scan_id") or 0)
                element = b.get("element") or {}
                history = b.get("history") or []
                question = (b.get("question") or "").strip()
                if not question:
                    return _json(self, {"error": "пустой вопрос"}, 400)
                return _sse(self, aiagent.chat_stream(sid, element, history, question))

            if p == "/api/cache/clear":
                store.cache_drop("nvd:")
                return _json(self, {"ok": True})

            return _json(self, {"error": "не найдено"}, 404)
        except Exception as e:  # noqa: BLE001
            return _json(self, {"error": f"{type(e).__name__}: {e}"}, 500)
        finally:
            settings_context.__exit__(None, None, None)


def _self_target_row(t) -> dict:
    d = dict(t)
    scs = store.scans(t["id"])
    d["scans"] = [{"id": s["id"], "status": s["status"], "started_at": s["started_at"],
                   "finished_at": s["finished_at"], "progress": s["progress"]} for s in scs]
    d["last_scan"] = scs[0]["id"] if scs else None
    return d


def _scheduler_loop(explicit_environment: Mapping[str, object] | None = None) -> None:
    """Раз в 5 минут проверяет расписание и запускает сканы, которым пора."""
    import datetime as _dt
    while True:
        try:
            now = _dt.datetime.now()
            for row in store.schedule_all():
                if not row.get("enabled"):
                    continue
                nxt = row.get("next_run") or ""
                try:
                    due = _dt.datetime.fromisoformat(nxt) <= now if nxt else True
                except Exception:
                    due = True
                if not due:
                    continue
                tid = row["target_id"]
                t = store.target(tid)
                if not t:
                    continue
                scan_settings = _scan_settings_snapshot(explicit_environment)
                sid = store.new_scan(tid)
                store.audit("scheduled_scan", {"target": t["value"], "scan_id": sid,
                                               "interval_hours": row.get("interval_hours")})
                threading.Thread(target=scanmod.run, args=(sid, {}),
                                 kwargs={"settings": scan_settings}, daemon=True).start()
                store.schedule_touch(tid, (now + _dt.timedelta(hours=int(row.get("interval_hours") or 24))).isoformat(timespec="seconds"))
                print(f"[планировщик] запущен скан №{sid} по расписанию: {t['value']}")
        except Exception as e:  # noqa: BLE001
            print(f"[планировщик] ошибка: {e}")
        time.sleep(300)


def serve(
    host: str = "0.0.0.0",
    port: int | None = None,
    *,
    explicit_environment: Mapping[str, object] | None = None,
) -> None:
    port = int(port or os.environ.get("ASM_PORT", "8000"))
    explicit_snapshot = _explicit_config_snapshot(explicit_environment)
    store.connect()
    try:
        srv = ThreadingHTTPServer((host, port), Handler)
    except OSError as e:
        # Занятый порт — самая частая осечка при первом запуске (особенно на
        # Windows, где его держит прежняя панель). Стек здесь ничего не
        # объясняет, а подсказка объясняет всё.
        print(f"панель не запустилась: {e}", file=sys.stderr, flush=True)
        print(f"  порт {port} занят — закройте прежнюю панель или выберите "
              f"другой: python3 app.py serve --port {port + 1}", file=sys.stderr,
              flush=True)
        return
    srv.daemon_threads = True
    srv.asm_explicit_config_environment = explicit_snapshot
    threading.Thread(target=_scheduler_loop, args=(explicit_snapshot,), daemon=True).start()
    shown = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    # flush: адрес должен быть виден сразу и при перенаправлении вывода в файл
    print(f"ASM дашборд: http://{shown}:{port}", flush=True)
    if shown != host:
        print(f"  слушает на всех интерфейсах ({host}); "
              f"с других машин — по IP этого компьютера", flush=True)
    if os.name == "nt":
        print("  Windows: если система спросит про брандмауэр — разрешите для "
              "частных сетей; закрыть панель — Ctrl+C", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("остановлено")
