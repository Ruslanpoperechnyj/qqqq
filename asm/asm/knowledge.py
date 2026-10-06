# -*- coding: utf-8 -*-
"""База знаний: плейбуки, память уточнений, шаблоны доказательств.

Зачем это отдельным модулем. Инструмент собирает данные хорошо, но решение
«что делать дальше» каждый раз принималось заново — оператором или правилным
каталогом без контекста. База знаний хранит накопленный опыт рядом с данными,
а не в голове и не в правках кода.

Три слоя:

1. **Плейбуки** — «наблюдается такая-то технология → вот упорядоченная цепочка
   действий агента». Лежат отдельными файлами, чтобы их можно было править и
   дописывать без правки кода. Каждый шаг плейбука обязан существовать в
   каталоге агента: плейбук предлагает последовательность, но не изобретает
   новые действия и ничего не выполняет сам.

2. **Память уточнений** — когда оператор помечает находку как ложное
   срабатывание, уточнённый диапазон версий запоминается в базе, и в следующих
   аудитах та же CVE по тому же продукту уже не всплывает. Раньше словарь
   `REFINED_RANGES` правили руками прямо в `cve.py`, то есть память жила в коде
   и терялась при обновлении сборки.

3. **Шаблоны доказательств** — что именно приложить к находке каждого класса,
   чтобы заказчик мог воспроизвести результат и чтобы отчёт выдержал проверку.

4. **Поиск по смыслу между объектами** — «встречалось ли это раньше и чем
   кончилось». Живёт в `vector.py` (`search_all`, `similar`, `notes_for_scan`),
   здесь не дублируется. В CLI — команда `memory`.

Правило, общее для всех слоёв: **отсутствие данных не должно выглядеть
как пустой результат.** Если плейбуки не загрузились, об этом сообщается явно,
а не возвращается тихий пустой список.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Iterable

from . import store
from .settings import current_settings

# Каталоги -------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

#: Где лежат плейбуки. Переопределяется ASM_KB_DIR.
KB_DIR = os.environ.get("ASM_KB_DIR") or os.path.join(_ROOT, "knowledge")
PLAYBOOKS_DIR = os.path.join(KB_DIR, "playbooks")


def _playbooks_dir() -> str:
    settings = current_settings()
    configured = (settings.get("ASM_KB_DIR", None) if settings is not None
                  else os.environ.get("ASM_KB_DIR"))
    if configured:
        return os.path.join(str(configured), "playbooks")
    # Preserve the public legacy constant as an injectable default for tests/plugins.
    return PLAYBOOKS_DIR


#: Действия, которые плейбук предлагать не вправе никогда — они либо
#: необратимы, либо выходят за границу «получили доступ и остановились».
# Шаги, которые плейбук предлагать не может. Помимо получения доступа это
# вся внутренняя работа: она делается ПОСЛЕ входа, а вход даёт человек.
# Плейбук, предложивший такой шаг, выглядел бы как план на пустом месте.
# --- схема плейбука
# Неизвестный ключ в плейбуке — это опечатка, а не запас на будущее: `mtch`
# вместо `match` или `stpes` вместо `steps` не падает, а просто никогда не
# срабатывает. В разгар аудита это выглядит как «инструмент ничего не предложил»,
# и разбираться в этом некогда. Поэтому набор ключей закрыт.
PLAYBOOK_KEYS = frozenset({"id", "title", "note", "match", "steps", "_file"})
MATCH_KEYS = frozenset({"port", "service", "product", "banner"})
STEP_KEYS = frozenset({"action", "why"})
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


FORBIDDEN_IN_PLAYBOOK = frozenset({
    "handoff_access",
    "inside_whoami", "inside_privileges", "inside_processes",
    "inside_ad_collect", "inside_tunnel", "inside_next_host",
})


# ---------------------------------------------------------------- плейбуки
def _yaml_available():
    try:
        import yaml  # noqa: F401
        return True
    except Exception:
        return False


def _read_one(path: str) -> tuple[Any, str]:
    """Прочитать один файл плейбука. Возвращает (данные, текст ошибки)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as e:
        return None, f"не читается: {e}"
    name = os.path.basename(path)
    if name.endswith((".yaml", ".yml")):
        try:
            import yaml
        except Exception:
            return None, ("нужен PyYAML (pip install pyyaml), либо переименуйте "
                          "файл в .json — формат поддерживается без зависимостей")
        try:
            return yaml.safe_load(raw), ""
        except Exception as e:  # noqa: BLE001
            return None, f"разбор YAML не удался: {e}"
    try:
        return json.loads(raw), ""
    except Exception as e:  # noqa: BLE001
        return None, f"разбор JSON не удался: {e}"


def validate_playbook(pb: Any, *, known_actions: Iterable[str] = ()) -> list[str]:
    """Проверить плейбук. Возвращает список замечаний; пустой — всё в порядке.

    Проверка строгая намеренно: плейбук, который ссылается на несуществующее
    действие, молча не сработает в разгар аудита, и разбираться в этом будет
    некогда.
    """
    errs: list[str] = []
    if not isinstance(pb, dict):
        return ["ожидается словарь, получен " + type(pb).__name__]
    pid = str(pb.get("id") or "").strip()
    if not pid:
        errs.append("нет id")
    elif not _ID_RE.match(pid):
        errs.append(f"id «{pid}»: допустимы строчные латинские буквы, цифры, «-» и «_»")
    if not str(pb.get("title") or "").strip():
        errs.append("нет title")
    unknown = sorted(set(pb) - PLAYBOOK_KEYS)
    if unknown:
        errs.append("неизвестные поля: " + ", ".join(unknown) +
                    " — опечатка в имени поля не падает, а просто не работает")
    match = pb.get("match")
    if not isinstance(match, dict) or not match:
        errs.append("нет match или он пустой — плейбук никогда не сработает")
    else:
        if not any(k in match for k in MATCH_KEYS):
            errs.append("match должен содержать хотя бы одно из: port, service, product, banner")
        bad = sorted(set(match) - MATCH_KEYS)
        if bad:
            errs.append("неизвестные условия match: " + ", ".join(bad))
        errs.extend(_check_match_types(match))
    steps = pb.get("steps")
    if not isinstance(steps, list) or not steps:
        errs.append("нет steps или он пустой")
    else:
        known = set(known_actions)
        for i, st in enumerate(steps):
            if not isinstance(st, dict):
                errs.append(f"шаг {i + 1}: ожидается словарь")
                continue
            extra = sorted(set(st) - STEP_KEYS)
            if extra:
                errs.append(f"шаг {i + 1}: неизвестные поля: " + ", ".join(extra))
            if not str(st.get("why") or "").strip():
                errs.append(f"шаг {i + 1}: нет why — оператор не сможет оценить, "
                            f"зачем шаг и чем он рискует")
            act = str(st.get("action") or "").strip()
            if not act:
                errs.append(f"шаг {i + 1}: нет action")
                continue
            if act in FORBIDDEN_IN_PLAYBOOK:
                errs.append(f"шаг {i + 1}: действие «{act}» в плейбуке запрещено — "
                            f"получение доступа всегда решает оператор, не шаблон")
            if known and act not in known:
                errs.append(f"шаг {i + 1}: неизвестное действие «{act}»")
    return errs


def _check_match_types(match: dict) -> list[str]:
    """Условия срабатывания обязаны быть того типа, с которым их сравнивают.

    `port: "443"` совпадёт случайно (код приводит к int), а `port: [http]`
    не совпадёт никогда — и это будет молчаливый отказ, а не ошибка.
    """
    errs: list[str] = []
    if "port" in match:
        want = match["port"] if isinstance(match["port"], list) else [match["port"]]
        for v in want:
            if not (isinstance(v, int) and not isinstance(v, bool)) and not (
                    isinstance(v, str) and v.strip().isdigit()):
                errs.append(f"match.port: «{v}» — ожидается номер порта")
    for key in ("service", "product", "banner"):
        if key not in match:
            continue
        want = match[key] if isinstance(match[key], list) else [match[key]]
        for v in want:
            if not isinstance(v, str) or not v.strip():
                errs.append(f"match.{key}: «{v}» — ожидается непустая строка")
    return errs


def load_playbooks(*, known_actions: Iterable[str] = ()) -> tuple[list[dict], list[str]]:
    """Загрузить все плейбуки из каталога.

    Возвращает (плейбуки, предупреждения). Предупреждения надо показывать
    оператору: плейбук, который не загрузился из-за опечатки, выглядит как
    «инструмент ничего не предложил», и причину без этого сообщения не найти.
    """
    warns: list[str] = []
    out: list[dict] = []
    playbooks_dir = _playbooks_dir()
    if not os.path.isdir(playbooks_dir):
        return out, [f"каталога плейбуков нет: {playbooks_dir}"]
    try:
        names = sorted(os.listdir(playbooks_dir))
    except OSError as e:
        return out, [f"каталог плейбуков не читается: {e}"]
    for name in names:
        if not name.endswith((".yaml", ".yml", ".json")):
            continue
        path = os.path.join(playbooks_dir, name)
        data, err = _read_one(path)
        if err:
            warns.append(f"{name}: {err}")
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            errs = validate_playbook(item, known_actions=known_actions)
            if errs:
                warns.append(f"{name}: " + "; ".join(errs))
                continue
            item["_file"] = name
            out.append(item)
    seen: dict[str, str] = {}
    for item in out:
        pid = str(item.get("id") or "")
        if pid in seen:
            warns.append(f"{item.get('_file')}: id «{pid}» уже занят файлом {seen[pid]} — "
                         f"два плейбука с одним id неразличимы в журнале и в панели")
        else:
            seen[pid] = str(item.get("_file") or "")
    if not out and not warns:
        warns.append("в каталоге плейбуков нет ни одного файла .yaml/.json")
    return out, warns


def _match_one(pb: dict, *, ports: set, services: set, products: set,
               banners: list[str]) -> bool:
    m = pb.get("match") or {}
    if "port" in m:
        want = m["port"]
        want = {int(p) for p in want} if isinstance(want, list) else {int(want)}
        if not (want & ports):
            return False
    if "service" in m:
        want = m["service"]
        want = [want] if isinstance(want, str) else list(want)
        if not {str(w).casefold() for w in want} & services:
            return False
    if "product" in m:
        want = m["product"]
        want = [want] if isinstance(want, str) else list(want)
        if not {str(w).casefold() for w in want} & products:
            return False
    if "banner" in m:
        want = m["banner"]
        want = [want] if isinstance(want, str) else list(want)
        blob = " ".join(banners).casefold()
        if not any(str(w).casefold() in blob for w in want):
            return False
    return True


def match_playbooks(*, ports: Iterable[int] = (), services: Iterable[str] = (),
                    products: Iterable[str] = (), banners: Iterable[str] = (),
                    known_actions: Iterable[str] = ()) -> tuple[list[dict], list[str]]:
    """Подобрать плейбуки под то, что реально observed на цели.

    Совпадение по любому из признаков; чем больше совпало, тем выше плейбук
    в выдаче — иначе список всегда в алфавитном порядке и самый точный
    плейбук тонет среди общих.
    """
    pbs, warns = load_playbooks(known_actions=known_actions)
    ports_s = {int(p) for p in ports if p}
    services_s = {str(s).casefold() for s in services if s}
    products_s = {str(p).casefold() for p in products if p}
    banners_l = [str(b) for b in banners if b]

    hit: list[tuple[int, dict]] = []
    for pb in pbs:
        m = pb.get("match") or {}
        score = 0
        if "port" in m:
            want = m["port"]
            want = {int(p) for p in want} if isinstance(want, list) else {int(want)}
            score += 2 if (want & ports_s) else 0
        if "service" in m:
            want = m["service"]
            want = [want] if isinstance(want, str) else list(want)
            score += 1 if ({str(w).casefold() for w in want} & services_s) else 0
        if "product" in m:
            want = m["product"]
            want = [want] if isinstance(want, str) else list(want)
            score += 3 if ({str(w).casefold() for w in want} & products_s) else 0
        if "banner" in m:
            want = m["banner"]
            want = [want] if isinstance(want, str) else list(want)
            blob = " ".join(banners_l).casefold()
            score += 2 if any(str(w).casefold() in blob for w in want) else 0
        # признак заявлен, но не совпал — плейбук не подходит вовсе
        declared = sum(1 for k in ("port", "service", "product", "banner") if k in m)
        if declared and score == 0:
            continue
        if not declared:
            continue
        if not _match_one(pb, ports=ports_s, services=services_s,
                          products=products_s, banners=banners_l):
            continue
        hit.append((score, pb))
    hit.sort(key=lambda t: (-t[0], str(t[1].get("id"))))
    return [pb for _, pb in hit], warns


# ------------------------------------------------------- память уточнений
_REF_CACHE: dict | None = None


def refinements(*, refresh: bool = False) -> dict[str, list[tuple[str, str, str, str, str]]]:
    """Уточнённые диапазоны версий: встроенные + накопленные в базе.

    Возвращает **список правил на каждую CVE**, а не одно. Одна и та же CVE
    регулярно приходит на несколько продуктов (openssl и zlib в одном образе,
    один пакет в двух сервисах), и словарь по одному ключу молча затирал
    предыдущее правило последним. Затёртое правило исчезало без следа: ни
    увидеть, ни вернуть.

    Накопленные правила дополняют встроенные — оператор на объекте знает больше,
    чем автор инструмента.

    Результат кэшируется: `_refine()` вызывается на каждую пару CVE-хост,
    и запрос в базу на каждый вызов заметно замедлил бы анализ. После
    добавления или удаления уточнения кэш сбрасывается сам.
    """
    global _REF_CACHE
    if _REF_CACHE is not None and not refresh:
        return _REF_CACHE
    from . import cve
    out: dict[str, list[tuple[str, str, str, str, str]]] = {}
    for cid, rule in (cve.REFINED_RANGES or {}).items():
        out[str(cid).upper()] = [tuple(rule)]
    try:
        rows = store.q("SELECT cve_id, part, vendor, product, v_start, v_end "
                       "FROM kb_refinements ORDER BY id")
    except Exception:
        # таблицы ещё нет (старая база) — работаем на встроенных
        _REF_CACHE = out
        return out
    for r in rows:
        out.setdefault(str(r["cve_id"]).upper(), []).append(
            (r["part"] or "a", r["vendor"] or "", r["product"] or "",
             r["v_start"] or "", r["v_end"] or ""))
    _REF_CACHE = out
    return out


def refinement_rows() -> list[dict]:
    """Все накопленные уточнения как есть — для просмотра и удаления.

    `refinements()` сводит их в правила для фильтра и теряет id, примечание
    и автора. Без этого списка уточнение невозможно ни осмотреть, ни отменить,
    а отменять придётся: ошибочное правило прячет настоящую находку во всех
    следующих аудитах.
    """
    try:
        return [dict(r) for r in store.q(
            "SELECT id, cve_id, part, vendor, product, v_start, v_end, note, "
            "operator, created_at FROM kb_refinements ORDER BY id")]
    except Exception:
        return []


def forget_refinement(rid: int, *, operator: str = "") -> bool:
    """Убрать уточнение по номеру. Возвращает False, если такого нет."""
    row = store.one("SELECT * FROM kb_refinements WHERE id=?", (rid,))
    if not row:
        return False
    d = dict(row)
    store.ex("DELETE FROM kb_refinements WHERE id=?", (rid,))
    store.audit("kb_refinement_forgotten",
                {"id": rid, "cve_id": d.get("cve_id"), "product": d.get("product"),
                 "v_start": d.get("v_start"), "v_end": d.get("v_end"),
                 "operator": operator})
    refinements(refresh=True)
    return True


def add_refinement(cve_id: str, *, part: str = "a", vendor: str = "", product: str = "",
                   v_start: str = "", v_end: str = "", note: str = "",
                   operator: str = "") -> bool:
    """Запомнить уточнение. Без продукта или без границ запоминать нечего."""
    cid = str(cve_id or "").strip().upper()
    if not cid or not product:
        return False
    if not v_start and not v_end:
        return False
    # Повторная пометка той же находки не должна плодить одинаковые правила:
    # на фильтр это не влияет, но список становится нечитаемым, а лишнее
    # правило потом приходится искать, чтобы отменить.
    dup = store.one("SELECT id FROM kb_refinements WHERE cve_id=? AND part=? "
                    "AND vendor=? AND product=? AND v_start=? AND v_end=?",
                    (cid, part or "a", vendor, product, v_start, v_end))
    if dup:
        return True
    store.ex("""INSERT INTO kb_refinements(cve_id, part, vendor, product, v_start,
                    v_end, note, operator, created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
             (cid, part or "a", vendor, product, v_start, v_end, note, operator,
              store.now()))
    store.audit("kb_refinement_added", {"cve_id": cid, "product": product,
                                        "v_start": v_start, "v_end": v_end,
                                        "operator": operator, "note": note})
    refinements(refresh=True)
    return True


def refinement_from_finding(fid: int, *, note: str = "", operator: str = "") -> bool:
    """Сделать уточнение из находки, помеченной как ложное срабатывание.

    Это и есть замкнутый контур памяти: оператор один раз сказал «не верю»,
    и в следующих аудитах та же связка CVE+продукт+версия не всплывает.
    """
    f = store.finding(fid)
    if not f:
        return False
    if f.get("status") != "false":
        return False
    cve_id = f.get("cve_id") or ""
    ev = f.get("evidence") or {}
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:
            ev = {}
    product = (f.get("product") or ev.get("пакет") or ev.get("cpe_product") or "").strip()
    version = (f.get("version") or ev.get("установлено") or "").strip()
    if not cve_id or not product or not version:
        return False
    vendor = (ev.get("vendor") or ev.get("поставщик") or "").strip()
    # «установлено X, исправлено в Y» -> диапазон [X, Y)
    fixed = (ev.get("исправлено в") or "").strip()
    v_end = fixed if fixed and fixed != "исправления нет" else ""
    return add_refinement(cve_id, vendor=vendor, product=product,
                          v_start=version, v_end=v_end,
                          note=note or f.get("status_note") or "", operator=operator)


def learn_from_scan(scan_id: int, *, operator: str = "", dry_run: bool = False) -> dict:
    """Пройти по находкам скана и запомнить уточнения по всем ложным срабатываниям.

    По одной находке это делается через refinement_from_finding, но после
    аудита их десятки — перебирать вручную никто не будет, и память просто
    не накопится.

    dry_run=True ничего не пишет: показывает, что было бы запомнено. Это нужно,
    потому что уточнение подавляет находку во всех следующих аудитах, и
    ошибочное уточнение дороже пропущенного.
    """
    made: list[dict] = []
    skipped: list[dict] = []
    for f in store.scan_findings(scan_id):
        if f.get("status") != "false":
            continue
        fid = f.get("id")
        if dry_run:
            ev = f.get("evidence") or {}
            if isinstance(ev, str):
                try:
                    ev = json.loads(ev)
                except Exception:
                    ev = {}
            product = (f.get("product") or ev.get("пакет") or "").strip()
            version = (f.get("version") or ev.get("установлено") or "").strip()
            entry = {"cve_id": f.get("cve_id") or "", "product": product,
                     "version": version, "находка": fid}
            if f.get("cve_id") and product and version:
                made.append(entry)
            else:
                entry["причина"] = "нет CVE, продукта или версии"
                skipped.append(entry)
            continue
        ok = refinement_from_finding(fid, note=f.get("status_note") or "",
                                     operator=operator)
        entry = {"cve_id": f.get("cve_id") or "", "product": f.get("product") or "",
                 "version": f.get("version") or "", "находка": fid}
        (made if ok else skipped).append(entry)
        if not ok:
            entry["причина"] = "нет CVE, продукта или версии"
    return {"запомнено": made, "пропущено": skipped}


# --------------------------------------------- шаблоны доказательств
#: Что приложить к находке, чтобы её можно было воспроизвести и оспорить.
#: Без этого отчёт читается как утверждение, а не как результат.
EVIDENCE_TEMPLATES: dict[str, dict] = {
    "observe": {
        "название": "Пассивное наблюдение",
        "объект не затронут": True,
        "что приложить": [
            "источник данных (название сервиса, дата и время запроса)",
            "запрос дословно, как он уходил",
            "ответ дословно, без сокращений",
        ],
        "что НЕ делать": [
            "не отправлять запросы объекту — этап пассивный",
            "не дописывать от себя то, чего нет в ответе",
        ],
    },
    "probe": {
        "название": "Проба на чтение",
        "объект не затронут": True,
        "что приложить": [
            "полная команда с флагами",
            "исходный вывод инструмента",
            "отметка времени по UTC",
            "адрес и порт, куда уходил запрос",
        ],
        "что НЕ делать": [
            "не менять состояние объекта",
            "не повторять проверку многократно без нужды",
        ],
    },
    "impact": {
        "название": "Воздействие",
        "объект не затронут": False,
        "что приложить": [
            "одобрение оператора: кто, когда, каким решением (ссылка на аудит)",
            "полная команда с флагами",
            "исходный вывод, включая признаки успеха",
            "отметка времени по UTC и адрес с портом",
            "что именно изменилось на объекте и как это откатить",
            "подтверждение, что данные не читались и не выгружались",
        ],
        "что НЕ делать": [
            "не выполнять без письменного одобрения",
            "не извлекать содержимое баз и файлов — только факт доступа",
            "не оставлять за собой изменений без записи о них",
        ],
    },
    "handoff_access": {
        "название": "Передача доступа",
        "объект не затронут": False,
        "что приложить": [
            "учётная запись и уровень привилегий (без самого секрета)",
            "способ получения — цепочка шагов со ссылками на аудит",
            "команды воспроизведения",
            "отметка времени по UTC",
            "явная запись: данные не читались, не копировались, не изменялись",
            "список того, что осталось на объекте и требует уборки",
        ],
        "что НЕ делать": [
            "не сохранять секрет в базе или отчёте — он показывается один раз",
            "не продолжать работу после получения доступа",
        ],
    },
}


def evidence_template(cls: str) -> dict:
    """Шаблон доказательств для класса действия. Неизвестный класс — не молчим."""
    t = EVIDENCE_TEMPLATES.get(cls)
    if t:
        return t
    return {"название": f"неизвестный класс «{cls}»",
            "предупреждение": "для этого класса шаблона нет — состав доказательств "
                              "нужно согласовать отдельно",
            "что приложить": list(EVIDENCE_TEMPLATES["probe"]["что приложить"])}


def status() -> dict:
    """Сводка для диагностики: что загрузилось и что нет."""
    try:
        from . import agent
        actions = {a["id"] for a in agent.catalog()}
    except Exception:
        actions = set()
    pbs, warns = load_playbooks(known_actions=actions)
    try:
        n_ref = store.q("SELECT COUNT(*) AS n FROM kb_refinements")[0]["n"]
    except Exception:
        n_ref = None
    from . import cve
    return {"каталог": _playbooks_dir(),
            "плейбуков загружено": len(pbs),
            "предупреждений": warns,
            "yaml доступен": _yaml_available(),
            "уточнений в базе": n_ref,
            "уточнений всего (с встроенными)": len(refinements()) if n_ref is not None
            else len(cve.REFINED_RANGES),
            "классов доказательств": len(EVIDENCE_TEMPLATES)}
