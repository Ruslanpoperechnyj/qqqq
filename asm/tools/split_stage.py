#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Вынос этапа конвейера из общей простыни в отдельную функцию — с проверкой.

Зачем. `asm/scan.py` был одной функцией `_run` на полторы тысячи строк с
двадцатью девятью этапами подряд. Читать её было нельзя, а значит нельзя было и
править без риска: любой сдвиг в середине задевал всё ниже.

Как. Тело этапа переносится **дословно**: не переписывается и не «улучшается».
Всё, что этап читает, приходит параметрами; что переприсваивает — возвращается
наружу. Именно поэтому перенос можно механизировать, а результат — проверить
машиной, а не глазами.

Две команды:

    python3 tools/split_stage.py audit
        Ищет имена, которые функция читает раньше, чем привязывает: после
        переноса такое имя становится локальным и падение случается там, где в
        конвейере значение уже было. Запускать после каждого выноса.

    python3 tools/split_stage.py take "7. обогащение" stage_enrich_scoring
        Сухой прогон: печатает строки, параметры, возвраты и то, что получится.
        С ключом `--apply` записывает — но только если сверка дерева разбора
        прошла. Проверка идёт ДО записи: иначе на диске остаётся правка,
        которая проверку не прошла (так однажды и вышло).

Что проверять после выноса (все четыре, иначе это не проверка):

    1. сверка дерева разбора — тело функции совпадает с блоком дословно;
    2. сверка строковых констант — ни одно сообщение и ни одна подсказка
       не потерялись (сдвиг отступов портит многострочный текст молча);
    3. дифференциальный прогон — одинаковые заглушки движков дают одинаковое
       состояние базы у старого и нового конвейера, и не на одной
       конфигурации, а на матрице: движки, реестр, активные проверки,
       глубокие пути, анализ кода, образ;
    4. полный набор тестов — `python3 -m unittest discover -s tests`.

Эталон «до» удобно держать скомпилированной копией прежнего `scan.py`
(например `asm/scan_before.pyc`, загружается как `asm.scan_before`): тогда
старый и новый конвейер можно прогнать в одном процессе на одних заглушках.
"""
from __future__ import annotations

import ast
import builtins
import io
import pathlib
import re
import sys
import tokenize

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCAN = ROOT / "asm" / "scan.py"
STAGES = ROOT / "asm" / "stages.py"
HELPERS = ROOT / "asm" / "scan_helpers.py"


def bound_names(node) -> set[str]:
    """Все имена, привязываемые внутри блока.

    Обязательно учитывать то, что привязывает не через Name/Store: import,
    `except ... as x`, `with ... as x`, цели for, переменные включений и
    вложенные def. Первая версия анализатора этого не видела и предлагала
    параметрами имена, которые блок сам и создаёт — то есть вынос упал бы
    на вызове с NameError.
    """
    out: set[str] = set()
    for x in ast.walk(node):
        if isinstance(x, ast.Name) and isinstance(x.ctx, (ast.Store, ast.Del)):
            out.add(x.id)
        elif isinstance(x, (ast.Import, ast.ImportFrom)):
            for a in x.names:
                out.add((a.asname or a.name).split(".")[0])
        elif isinstance(x, ast.ExceptHandler) and x.name:
            out.add(x.name)
        elif isinstance(x, ast.arg):
            out.add(x.arg)
        elif isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(x.name)
    return out


def loaded_names(node) -> set[str]:
    return {x.id for x in ast.walk(node)
            if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}


def module_level(tree) -> set[str]:
    """Имена уровня модуля.

    Идём и в `try:`/`if:` на уровне модуля: именно так в scan.py объявлен
    `engines` (`try: from . import engines ... except: engines = None`).
    Первая версия смотрела только на прямые инструкции модуля и объявляла
    `engines` свободным именем этапа, то есть предлагала передавать его
    параметром.
    """
    out: set[str] = set()

    def deep(stmts) -> None:
        for n in stmts:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(n.name)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    out.add((a.asname or a.name).split(".")[0])
            elif isinstance(n, ast.Assign):
                for t in ast.walk(n):
                    if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store):
                        out.add(t.id)
            elif isinstance(n, (ast.Try, ast.If, ast.With)):
                deep(n.body)
                deep(getattr(n, "orelse", []) or [])
                deep(getattr(n, "finalbody", []) or [])
                for h in getattr(n, "handlers", []) or []:
                    deep(h.body)

    deep(tree.body)
    return out


class _Flow(ast.NodeVisitor):
    """return/break/continue, которые НЕ принадлежат блоку.

    Вложенные функции пропускаем целиком: `return` внутри них возвращает
    управление им, а не из конвейера. Первая версия обходила дерево вручную и
    засчитывала такие `return` за выход из этапа — из-за чего вынос самого
    большого этапа был объявлен невозможным на пустом месте.
    """

    def __init__(self) -> None:
        self.bad: list[str] = []
        self.loop = 0

    def visit_FunctionDef(self, node):        # noqa: N802
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):             # noqa: N802
        return

    def visit_ClassDef(self, node):           # noqa: N802
        return

    def _loop(self, node):
        self.visit(node.iter if hasattr(node, "iter") else node.test)
        self.loop += 1
        for st in node.body:
            self.visit(st)
        self.loop -= 1
        for st in node.orelse:
            self.visit(st)

    visit_For = _loop
    visit_AsyncFor = _loop
    visit_While = _loop

    def visit_Return(self, node):             # noqa: N802
        self.bad.append(f"return@{node.lineno}")

    def visit_Break(self, node):              # noqa: N802
        if self.loop == 0:
            self.bad.append(f"break@{node.lineno}")

    def visit_Continue(self, node):           # noqa: N802
        if self.loop == 0:
            self.bad.append(f"continue@{node.lineno}")


def flow_breaks(node) -> list[str]:
    f = _Flow()
    for st in node.body:
        f.visit(st)
    return f.bad


def dedent_block(chunk: str) -> str:
    """Снять четыре пробела отступа, не тронув содержимое многострочных строк.

    Обычный сдвиг всех строк портит текст внутри тройных кавычек: отступ там —
    часть строки, а не разметка. Поломка выглядит безобидно (сообщение в
    журнале чуть съезжает), и заметить её можно только сверкой.
    """
    lines = chunk.splitlines()
    inside: set[int] = set()
    try:
        for t in tokenize.generate_tokens(io.StringIO(chunk).readline):
            if t.type == tokenize.STRING and t.end[0] > t.start[0]:
                inside.update(range(t.start[0] + 1, t.end[0] + 1))
    except Exception:  # noqa: BLE001 — разбор не удался: снимем отступ как раньше
        pass
    out = []
    for i, x in enumerate(lines, 1):
        if i in inside:
            out.append(x)
        else:
            out.append(x[4:] if x.startswith("    ") else x)
    return "\n".join(out)


def unconditional_before(run, block_start: int) -> set[str]:
    """Имена, привязанные до этапа безусловно.

    Считаем только инструкции верхнего уровня: присваивание внутри `if` или
    `try` может не выполниться, и тогда имя к моменту этапа не привязано.
    Ровно на этом ловится `sensitive`: оно привязывается под условием, а этап
    секретов идёт при другом — и прежний код ловил там NameError.
    """
    out: set[str] = {a.arg for a in run.args.args}     # параметры самой _run
    for st in run.body:
        if getattr(st, "lineno", 0) >= block_start:
            break
        if isinstance(st, (ast.If, ast.Try, ast.While, ast.For, ast.AsyncFor)):
            continue                     # условно: не считаем
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(st.name)
            continue
        out |= bound_names(st)
    return out


def markers(lines: list[str], run) -> list[tuple[int, str]]:
    """Границы этапов: комментарии-разделители и уже сделанные вызовы.

    Вызовы тоже границы: без этого строка вызова попадала в блок следующего
    этапа, и он «затягивал» чужой вызов внутрь себя — тот начинал выполняться
    не в том месте, а на пустых данных проверка такого не видит.
    """
    out = []
    for i, l in enumerate(lines, 1):
        if i < run.lineno or i > run.end_lineno:
            continue
        st = l.strip()
        if st.startswith("# ") and "---" in st and len(st) > 20:
            out.append((i, st.lstrip("#- ").strip()))
        elif re.match(r"^[a-z_]\w*(, [a-z_]\w*)* = stage_\w+\(|^stage_\w+\(", st):
            out.append((i, "__call__"))
    return out


def take(title_prefix: str, func_name: str, apply: bool) -> int:
    src = SCAN.read_text(encoding="utf-8")
    lines = src.splitlines()
    tree = ast.parse(src)
    run = [n for n in tree.body if getattr(n, "name", "") == "_run"][0]
    mods = module_level(tree)
    # Блок уезжает в stages.py, поэтому именами уровня модуля для него
    # становятся и то, что объявлено там (и в scan_helpers.py) — иначе
    # инструмент требовал бы параметром то, что там уже есть.
    landed = module_level(ast.parse(STAGES.read_text(encoding="utf-8"))) if STAGES.exists() else set()
    if HELPERS.exists():
        landed |= module_level(ast.parse(HELPERS.read_text(encoding="utf-8")))

    marks = markers(lines, run)
    idx = [k for k, (_, t) in enumerate(marks) if t.startswith(title_prefix)]
    if len(idx) != 1:
        print(f"не нашёл однозначно этап по «{title_prefix}»", file=sys.stderr)
        return 2
    k = idx[0]
    ln, title = marks[k]
    end = marks[k + 1][0] - 1 if k + 1 < len(marks) else run.end_lineno
    chunk = "\n".join(lines[ln - 1:end])
    dedented = dedent_block(chunk)

    block = ast.parse("def _s():\n" + "\n".join(
        ("    " + x) if x.strip() else x for x in chunk.splitlines())).body[0]

    why = flow_breaks(block)
    if why:
        print("вынос запрещён: меняется поток управления "
              f"({', '.join(why)}) — это уже переписывание логики, а не перенос")
        return 3

    used, written = loaded_names(block), bound_names(block)
    free = sorted(n for n in used - written
                  if n not in mods and n not in landed and not hasattr(builtins, n))

    # Имя, которое блок читает раньше, чем привязывает, обязано приходить
    # параметром: в функции оно станет локальным и чтение упадёт. Так были
    # найдены `subs` (в этапе расширения по адресу) и `estate_warn`.
    tail_src = "\n".join(("    " + x) if x.strip() else x
                         for x in lines[end:run.end_lineno])
    first_event: dict[str, str] = {}
    if tail_src.strip():
        tail_fn = ast.parse("def _t():\n" + tail_src).body[0]
        for st in tail_fn.body:
            # `x += ...` — это и чтение, и запись: цель читается до записи.
            if isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
                first_event.setdefault(st.target.id, "read")
            for x in ast.walk(st):
                # Сначала чтения этой инструкции, потом то, что она привязывает:
                # `except ... as e:` пишет в e, и это не «чтение старого».
                if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load) \
                        and x.id not in bound_names(st):
                    first_event.setdefault(x.id, "read")
            for nm in bound_names(st):
                first_event.setdefault(nm, "write")

    sure = unconditional_before(run, ln)
    reads_before_write = sorted(
        n for n in written & used
        if n not in sure and _read_before_write(block, n))
    optional = [n for n in free if n not in sure]
    returns = sorted(n for n in written if first_event.get(n) == "read")
    returns = [n for n in returns if n not in _imported(block) and n not in _nested(block)]
    free = sorted(set(free) | set(reads_before_write))

    print(f"этап: {title}")
    print(f"строки: {ln}-{end} ({end - ln + 1} строк)")
    print(f"параметры: {', '.join(free) or '—'}")
    if reads_before_write:
        print(f"читается раньше привязки, приходит параметром: "
              f"{', '.join(reads_before_write)}")
    print(f"вернуть наружу: {', '.join(returns) or '—'}")
    if optional:
        print(f"может быть не привязано (передаём пустое): {', '.join(optional)}")

    body_src = "\n".join(("    " + x) if x.strip() else x for x in dedented.splitlines())
    # Параметры со значением по умолчанию обязаны идти последними: иначе
    # «non-default argument follows default argument» — синтаксическая ошибка.
    ordered = [n for n in free if n not in optional] + [n for n in free if n in optional]
    sig = ", ".join(f"{n}=()" if n in optional else n for n in ordered)
    # Без возвратов return не добавляем: лишняя `return None` ломает сверку
    # дерева разбора с вырезанным блоком (и была бы правкой внутри тела).
    ret = f"    return {', '.join(returns)}" if returns else ""
    func = f"def {func_name}({sig}):\n{body_src}\n" + (ret + "\n" if ret else "")
    # Для необязательных имён передаём пустое значение: прежний код на этом
    # месте ловил NameError и подставлял пусто — результат тот же, но без
    # исключения.
    call_args = ", ".join(
        (f'{n}=locals().get("{n}", ())' if n in optional else f"{n}={n}") for n in ordered)
    call = (f"    {', '.join(returns)} = {func_name}({call_args})\n" if returns
            else f"    {func_name}({call_args})\n")

    # Сверка ДО записи: тело новой функции обязано совпасть с вырезанным блоком
    # по дереву разбора, инструкция в инструкцию. Проверять после записи —
    # значит оставлять записанным то, что проверку не прошло.
    new_fn = ast.parse("def _s():\n" + body_src + ("\n" + ret if ret else "")).body[0]
    if ret:
        new_fn.body = new_fn.body[:-1]        # строку возврата добавили мы сами
    same = ast.dump(ast.Module(body=new_fn.body, type_ignores=[])) == ast.dump(
        ast.Module(body=block.body, type_ignores=[]))
    print("сверка дерева разбора:", "совпадает" if same else "РАСХОЖДЕНИЕ")

    if apply:
        if not same:
            print("не применяю: тело не совпадает с блоком")
            return 4
        print("\n--- применяю ---")
        print(f"stages.py: добавляю {func_name} ({len(func.splitlines())} строк)")
        print(f"scan.py:   на месте строк {ln}-{end} будет вызов")
        old = STAGES.read_text(encoding="utf-8") if STAGES.exists() else ""
        if func_name not in old:
            STAGES.write_text(old.rstrip("\n") + "\n\n\n" + func + "\n", encoding="utf-8")
        new_lines = lines[:ln - 1] + [call.rstrip("\n")] + lines[end:]
        SCAN.write_text("\n".join(new_lines) + ("\n" if src.endswith("\n") else ""),
                        encoding="utf-8")
        _register_import(func_name)
        print("готово")
    else:
        print("\n--- как будет выглядеть (первые 12 строк функции) ---")
        print("\n".join(func.splitlines()[:12]))
        print("--- вызов вместо блока ---")
        print(call.rstrip())
    return 0


def _scan_seq(stmts, name: str, bound: bool) -> bool:
    """Есть ли чтение имени раньше, чем оно привязано.

    Идём по инструкциям в порядке выполнения: у цикла сначала считается
    выражение, потом привязывается переменная, потом выполняется тело; у
    условия — сначала условие; у `try` — тело, затем обработчики (привязывая
    имя исключения). Вложенные функции и включения — отдельные области
    видимости, их чтения сюда не относятся.
    """
    for st in stmts:
        if isinstance(st, (ast.For, ast.AsyncFor)):
            if _reads_outside(st.iter, name) and not bound:
                return True
            inner = bound or any(isinstance(x, ast.Name) and x.id == name
                                 for x in ast.walk(st.target))
            if _scan_seq(st.body, name, inner) or _scan_seq(st.orelse, name, bound):
                return True
        elif isinstance(st, ast.While):
            if _reads_outside(st.test, name) and not bound:
                return True
            if _scan_seq(st.body, name, bound) or _scan_seq(st.orelse, name, bound):
                return True
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for it in st.items:
                if _reads_outside(it.context_expr, name) and not bound:
                    return True
            inner = bound or any(
                it.optional_vars is not None
                and any(isinstance(x, ast.Name) and x.id == name
                        for x in ast.walk(it.optional_vars))
                for it in st.items)
            if _scan_seq(st.body, name, inner):
                return True
        elif isinstance(st, ast.If):
            if _reads_outside(st.test, name) and not bound:
                return True
            if _scan_seq(st.body, name, bound) or _scan_seq(st.orelse, name, bound):
                return True
        elif isinstance(st, ast.Try):
            if _scan_seq(st.body, name, bound):
                return True
            for h in st.handlers:
                if _reads_outside(h.type, name) and not bound:
                    return True
                if _scan_seq(h.body, name, bound or h.name == name):
                    return True
            if _scan_seq(st.orelse, name, bound) or _scan_seq(st.finalbody, name, bound):
                return True
        else:
            if _reads_outside(st, name) and not bound:
                return True
            if _binds_here(st, name):
                bound = True
            continue
        # Привязка внутри условия или обработчика считается состоявшейся только
        # тогда, когда она есть во всех ветках: `try: x = ... except: x = []`
        # привязывает x всегда, а `if flag: x = ...` — нет.
        if _guaranteed_binds(st, name):
            bound = True
    return False


def _guaranteed_binds(st, name: str) -> bool:
    """Привязывает ли инструкция имя при любом ходе выполнения."""
    if isinstance(st, ast.Try):
        if _guaranteed_binds_seq(st.body, name):
            return True
        return bool(st.handlers) and all(_guaranteed_binds_seq(h.body, name)
                                        for h in st.handlers)
    if isinstance(st, ast.If):
        return bool(st.orelse) and _guaranteed_binds_seq(st.body, name) \
            and _guaranteed_binds_seq(st.orelse, name)
    if isinstance(st, (ast.For, ast.AsyncFor, ast.While)):
        return False                     # цикл может не выполниться ни разу
    if isinstance(st, (ast.With, ast.AsyncWith)):
        return _guaranteed_binds_seq(st.body, name) or any(
            it.optional_vars is not None
            and any(isinstance(x, ast.Name) and x.id == name
                    for x in ast.walk(it.optional_vars))
            for it in st.items)
    return _binds_here(st, name)


def _guaranteed_binds_seq(stmts, name: str) -> bool:
    return any(_guaranteed_binds(st, name) for st in stmts)


class _Skipper(ast.NodeVisitor):
    """Ищет чтения имени, не заходя в чужие области видимости."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.found = False
        self.assigned = False

    def visit_Name(self, node):               # noqa: N802
        if node.id != self.name:
            return
        if isinstance(node.ctx, ast.Load):
            self.found = True
        else:
            self.assigned = True

    def visit_FunctionDef(self, node):        # noqa: N802
        return                                 # своя область видимости

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):             # noqa: N802
        return

    def visit_ListComp(self, node):           # noqa: N802
        return

    visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp


def _peek(node, name: str) -> tuple[bool, bool]:
    if node is None:
        return False, False
    v = _Skipper(name)
    v.visit(node)
    return v.found, v.assigned


def _reads_outside(node, name: str) -> bool:
    return _peek(node, name)[0]


def _binds_here(st, name: str) -> bool:
    """Привязывает ли простая инструкция имя (включая `x += ...`: она и читает)."""
    if isinstance(st, ast.AugAssign):
        return any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(st.target))
    if isinstance(st, (ast.Assign, ast.AnnAssign)):
        return _peek(getattr(st, "target", None) or
                     ast.Tuple(elts=[t for t in st.targets], ctx=ast.Store()), name)[1]
    if isinstance(st, (ast.Import, ast.ImportFrom)):
        return any((a.asname or a.name).split(".")[0] == name for a in st.names)
    if isinstance(st, ast.Delete):
        return False
    if isinstance(st, ast.Expr):
        return False
    # всё остальное, что привязывает имя, но не является простой инструкцией
    return _peek(st, name)[1]


def _read_before_write(block, name: str) -> bool:
    """Читается ли имя в блоке раньше, чем привязывается безусловно."""
    return _scan_seq(block.body, name, False)


def _imported(block) -> set[str]:
    out: set[str] = set()
    for x in ast.walk(block):
        if isinstance(x, (ast.Import, ast.ImportFrom)):
            for a in x.names:
                out.add((a.asname or a.name).split(".")[0])
    return out


def _nested(block) -> set[str]:
    return {x.name for x in block.body
            if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _register_import(func_name: str) -> None:
    """Дописать вынесенную функцию в импорт scan.py."""
    text = SCAN.read_text(encoding="utf-8")
    m = re.search(r"^from \.stages import ([^\n]*)$", text, re.M)
    names = sorted(set((m.group(1).split(", ") if m else [])) | {func_name})
    line = "from .stages import " + ", ".join(names)
    if m:
        text = text[:m.start()] + line + text[m.end():]
    else:
        text = text.replace("from . import store\n", line + "\nfrom . import store\n", 1)
    SCAN.write_text(text, encoding="utf-8")
    print(f"scan.py: импорт обновлён — {line}")


def audit() -> int:
    """Имена, которые этап читает раньше, чем привязывает (после переноса —
    локальные: чтение падает там, где в конвейере значение уже было)."""
    tree = ast.parse(STAGES.read_text(encoding="utf-8"))
    scan_src = SCAN.read_text(encoding="utf-8")
    run = [n for n in ast.parse(scan_src).body if getattr(n, "name", "") == "_run"][0]
    lines = scan_src.splitlines()
    call_line: dict[str, int] = {}
    for i, l in enumerate(lines, 1):
        if "stage_" not in l:
            continue
        try:
            st = ast.parse(l.strip()).body[0]
        except SyntaxError:
            continue
        for x in ast.walk(st):
            if isinstance(x, ast.Call) and getattr(x.func, "id", "").startswith("stage_"):
                call_line[x.func.id] = i

    total = 0
    for fn in [n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name.startswith("stage_")]:
        params = {a.arg for a in fn.args.args}
        inner = _inner_scopes(fn)
        locals_ = _locals(fn) - params
        bad = []
        for n in sorted(locals_):
            if _read_before_write(fn, n):
                bad.append(n)
        if not bad:
            continue
        total += len(bad)
        # Имена вложенных функций (их параметры, локальные, цели включений) —
        # не наши: внутри своей области они привязаны. Отделяем их, чтобы
        # список был коротким и его читали.
        real = [n for n in bad if n not in inner]
        noise = [n for n in bad if n in inner]
        where = call_line.get(fn.name)
        sure = unconditional_before(run, where) if where else set()
        passed = [n for n in real if n in sure]
        print(f"  {fn.name} (вызов, строка {where}): "
              + (f"параметрами — {', '.join(passed)}" if passed else "ничего не нужно")
              + (f" | не привязано в конвейере до вызова: "
                 f"{', '.join(n for n in real if n not in sure)}"
                 if [n for n in real if n not in sure] else "")
              + (f" | внутри вложенных областей: {', '.join(noise)}" if noise else ""))
    print(f"  подозрительных имён: {total}")
    return 0


def _locals(fn) -> set[str]:
    """Имена, которые Python считает локальными для функции.

    Цели включений и аргументы вложенных функций сюда не входят: у них своя
    область видимости.
    """
    out: set[str] = set()

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):     # noqa: N802
            out.add(node.name)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):        # noqa: N802
            out.add(node.name)

        def visit_Lambda(self, node):          # noqa: N802
            return

        def visit_Name(self, node):            # noqa: N802
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                out.add(node.id)

        def visit_Import(self, node):          # noqa: N802
            for a in node.names:
                out.add((a.asname or a.name).split(".")[0])

        visit_ImportFrom = visit_Import

        def visit_ExceptHandler(self, node):   # noqa: N802
            if node.name:
                out.add(node.name)
            self.generic_visit(node)

        def visit_ListComp(self, node):        # noqa: N802
            return

        visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

    v = V()
    for st in fn.body:
        v.visit(st)
    return out


def _inner_scopes(fn) -> set[str]:
    """Имена, привязанные внутри вложенных функций и включений."""
    out: set[str] = set()
    for node in ast.walk(fn):
        if node is fn:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            out |= {a.arg for a in node.args.args} | {
                a.arg for a in getattr(node.args, "posonlyargs", [])}
            out |= {a.arg for a in node.args.kwonlyargs}
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.add(node.name)
                body = node.body
            else:
                body = [node.body]
            for st in body:
                for x in ast.walk(st):
                    if isinstance(x, ast.Name) and isinstance(x.ctx, (ast.Store, ast.Del)):
                        out.add(x.id)
        elif isinstance(node, ast.comprehension):
            for x in ast.walk(node.target):
                if isinstance(x, ast.Name):
                    out.add(x.id)
    return out


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--apply"]
    if not args:
        print(__doc__.strip().split("Две команды")[0])
        return 2
    if args[0] == "audit":
        return audit()
    if args[0] == "take":
        if len(args) < 3:
            print("нужно: take \"<этап>\" <имя_функции> [--apply]", file=sys.stderr)
            return 2
        return take(args[1], args[2], "--apply" in sys.argv)
    print(f"неизвестная команда: {args[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
