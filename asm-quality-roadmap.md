# ASM — план доведения качества до проверяемых 10/10

**Цель:** не сделать «большой рефакторинг», а закрывать пункты последовательно, маленькими изменениями, с доказуемым критерием готовности на каждый пункт.  
**Текущий режим:** план исполняется последовательно, один пункт за раз. Этапы 2.1–2.3 и vector 3.1–3.4 выполнены на Linux sandbox. В этапе 4.1 выполнены A/B/C1/C2 для scan/mode boundary; C3 — read-only inventory оставшихся mode consumers. Immutable `Settings` передаётся scan workers; CLI/web/scheduler включают preset mapping, с порядком defaults < mode < environment, а явные shell/`--set` остаются сильнее preset. Полный suite — **564/564**; существующие mode/profile/stealth/planner/agent-gating tests после inventory — **70/70**. Import purity ещё не достигнута: engines/active/transport и другие consumers остаются на прежнем пути; `load_into_env`/`mode.apply` сохранены для env compatibility. `--set`, `--settings`, model/transport и secret-related code не менялись. Этап 4.1 не принят. Следующий кодовый шаг — отдельная миграция одного оставшегося non-scan consumer с сохранением его safety gates; legacy adapter не удалять до переноса соответствующих consumers. Windows/production performance и полная независимость тестов остаются открытыми.

### Журнал приёмки

- **Пункт 1 — безопасная тестовая БД и утечки фикстур: принят.** `tests/test_core.py` принудительно направляет тестовый набор в уникальную `TemporaryDirectory` и останавливается до записи, если `store.DB_PATH` не совпадает с ней; установлен `atexit` cleanup. Один незакрывавшийся monkeypatch восстановлен в `finally`. Закрыты SQLite-соединения vector/legacy-тестов; ручная фикстура дерева процессов теперь закрывает потоки и удаляет `Popen` из реестра. Проверка с `ASM_DB`, указывающим на реальную sentinel SQLite-БД: она осталась побайтно неизменной, временная директория suite удалена; тогда прошло **517/517**, **0 `ResourceWarning`**.
- **Пункт 2.1 — пакетная запись assets/edges/findings и FTS: принят.** В `asm/store.py` добавлены `executemany`, одна атомарная транзакция на непустую пачку, savepoint для уже открытой транзакции и согласованная запись findings+FTS. Пустые пачки не создают таблиц; ошибка FTS не оставляет finding без индекса. 13 изолированных регрессионных тестов покрывают commit count, ошибки до/во время COMMIT, rollback, nested transactions, fallback и FTS rowid.
- **Измерение пункта 2.1:** воспроизводимый скрипт `benchmarks/benchmark_store_batches.py`; сводка — `benchmarks/results/store-batch-report.md`, исходные результаты — `store-batch-baseline.json` и `store-batch-batched.json`. На Linux/Python 3.13.14/SQLite 3.46.1, по 3 повтора: при 100k строк p50 улучшился **8.60× assets**, **8.06× edges**, **7.47× findings+FTS**; commit count сократился с 100k/100k/200k до **одного на API**. Это микробенчмарк sandbox, не обещание абсолютной скорости на Windows.
- **Проверка после пункта 2.1 (исторический запуск до этапа 2.2):** полный suite — **530/530**, **0 `ResourceWarning`**; унаследованная sentinel SQLite-БД осталась побайтно неизменной, временная директория удалена.
- **Пункт 2.2 — модель конкурентного доступа, принята для Linux sandbox; проверка Windows ожидает:** выбран отдельный `sqlite3.Connection` на поток. В `asm/store.py` глобальное соединение заменено на thread-local state; добавлены регистрация соединений, `close_current`, `close_all` и cleanup по завершении потока. `q`, `ex`, пакетные writers, `mark_stale_scans` и vector-пути получают handle только через `store.connect()`; `check_same_thread=False` оставлен лишь для централизованного закрытия после остановки потоков. WAL и настройка busy timeout не менялись.
- **Регрессия/проверка 2.2:** до рефакторинга два из трёх новых characterization-тестов воспроизводили общий handle и dirty read; шесть параллельных batch-writers сохраняли все 180 строк. После изменений целевой класс — **17/17**, полный discovery — **534/534**, **0 `ResourceWarning`**. Запуск с унаследованной sentinel-БД: sentinel не изменился, временные каталоги тестов удалены. Benchmark smoke 1k assets/edges/findings сохранил точное число строк и по одному commit на API.
- **Пункт 2.3 — миграции и индексы, приняты на Linux sandbox:** схема версионирована через `PRAGMA user_version` (текущая версия 2). v1 идемпотентно добавляет отсутствующие legacy-колонки и досчитывает `kind`; v2 атомарно заменяет/создаёт индексы. Будущая версия БД отклоняется до DDL. `OperationalError` миграций больше не проглатывается; FTS fallback срабатывает только для известного `no such module: fts5`, остальные ошибки доходят до вызывающего кода.
- **EXPLAIN и индексы 2.3:** подтверждены планы для scans по target/status, findings по scan+score, agent steps по session/seq и session/status/seq, chat history, views, открытых agent sessions и dedupe lookup `kb_refinements`. Дополнительно добавлены `sem_meta(scan_id)` и `sem(scan_id)` для vector fallback. Регрессионные проверки сверяют результаты до/после миграции и подтверждают запланированные индексы/отсутствие временной сортировки.
- **Benchmark 2.3:** `benchmarks/benchmark_store_indexes.py`, результаты — `benchmarks/results/store-index-report.md` и `.json`. На 1k/10k/100k, 5 warm runs, результирующие кортежи до/после точно совпали. На 100k базовых строк: scans-by-target **6.81×**, stale-scan sweep **103.86×**, findings-by-score **2.60×**, pending steps **5.85×**, views **7.30×**; измеренная площадь БД выросла на **22,761,472 байта**. Это warm-cache Linux microbenchmark; write-latency и production workloads отдельно не измерялись. Повторный batch benchmark после v2 — `benchmarks/results/store-batch-schema-v2.json`, один commit на API.
- **Проверка этапа 2.3:** полный discovery — **541/541**, **0 `ResourceWarning`**; при унаследованной sentinel-БД она не изменилась, тестовые temp-каталоги удалены. Статический runtime-поиск: единственный `sqlite3.connect` в `asm` — внутри `store.connect()`; общего `_conn` нет.
- **Ограничения этапа 2.3:** всё ещё проверено только на Linux/Python 3.13.14/SQLite 3.46.1; Windows, межпроцессная contention-нагрузка и write-overhead новых индексов не подтверждены. WAL/busy timeout не менялись. Изоляция тестов действует на запуск suite, но независимость каждого теста/случайный параллельный порядок не доказаны. Windows-проверку SQLite оставить отдельным acceptance gate.
- **Этап 3.1 — baseline vector memory paths, выполнен:** benchmark `benchmarks/benchmark_vector_paths.py`, результаты `benchmarks/results/vector-path-baseline.md` и `.json`. На 100k synthetic findings `search_all()` p50/p95 — 4,335.874/4,796.243 ms; `notes_for_scan(limit=4)` — 48,347.058/48,467.306 ms; совместный RSS peak delta двух путей — 486.66 MiB при тестовых векторах 16D (не атрибутирован отдельной функции). Один `search_all()` вызывает `_all_findings` 1× и `_read_stored` 2× (2N векторов); один `notes_for_scan()` повторяет полный поиск 4× и декодирует 8N строк (800k на корпусе 100k). Benchmark работает на изолированной временной БД; sentinel SHA не изменился, временные каталоги удалены. Краткие p95 из трёх наблюдений и 16D размерность — явные ограничения; это не Windows/production прогноз.
- **Ranking characterization:** fixed-corpus golden test сверяет точный `(score, finding_id)`; reference test сверяет ID/порядок и tie stability. Batch-vs-individual `similar()` test сравнивает полную структуру подсказок; counter tests проверяют один corpus snapshot, один vector map и одну JSON-сериализацию на finding/query. Cross-target и `target_id` tests сохранены.
- **Этап 3.2 — пакетный vector path, реализован на Linux:** `notes_for_scan()` теперь один раз читает общий corpus/vector map и повторно использует их для выбранных findings; `_search_candidates()` и `_annotate_similar()` сохраняют общий scorer/annotation. JSON находится и сериализуется один раз на finding/query, а не один раз на query word. На 100k `notes_for_scan(limit=4)` p50/p95 снизился с 48,347/48,467 ms до 9,537/9,782 ms (**5.07× / 4.95×**), ordered signatures до baseline совпали для 1k/10k/100k. Для batch-пути corpus reads: 4→1, vector-cache calls: 4→1, decoded vector rows: 8N→2N. Совместный RSS peak delta 486.66→487.04 MiB (+0.38 MiB, несущественно в этом замере); 16D caveat остаётся. `search_all()` p50 на 100k практически без изменения — 4,336→4,406 ms.
- **Проверки 3.2:** `TestVectorSearch` + `TestCrossScanMemory` прошли 20/20 даже при обратном порядке классов; это выявило и устранило один конкретный fixture leak: sentinel `sem(scan_id=NULL)` теперь удаляется в `finally`. Полный suite — **543/543**, 0 `ResourceWarning`; inherited sentinel БД не изменилась, temp-каталоги удалены. Полная независимость всех тестов/случайный порядок всё ещё не доказаны.
- **Benchmark post-change:** `benchmarks/results/vector-path-notes-batch.md` и `.json`; baseline 3.1 сохранён отдельно как `vector-path-baseline.md/.json`. Три замера; p95 при малом числе повторов — только ориентир; Windows/production не подтверждены.
- **Этап 3.3 — single-read warm vector cache, выполнен:** `_stored_dimension()` получает dim из одной fallback/vec0 строки (`LIMIT 1`); после `_ensure_tables()` полный `_read_stored()` выполняется один раз. На 100k `search_all()` p50/p95 — 3,993/4,050 ms (было 4,406/4,424 ms после 3.2); batch notes — 9,129/9,201 ms (было 9,537/9,782 ms). Ordered signatures точно совпали. Совместный RSS peak delta снизился 487.04→405.92 MiB. Post-commit read при фактической переиндексации остаётся; устранён duplicate pass на warm path.
- **Проверки 3.3:** тест тёплого кэша подтверждает один полный read и точное равенство vector map; обратный порядок vector classes — 21/21; полный suite — **544/544**, 0 `ResourceWarning`; sentinel DB не изменилась, temp-каталоги удалены.
- **Benchmark 3.3:** `benchmarks/results/vector-path-single-read.md/.json`; 16D synthetic Linux corpus, 1k/10k/100k, три warm observations; RSS — совместный пик двух путей, p95 ориентировочный.
- **Этап 3.4 — bounded top-k, выполнен:** при `0 < k < N` `_search_candidates()` теперь удерживает не более `k` готовых result dict вместо списка на `N`, сохраняя округлённый score и стабильный tie order; NaN использует прежний stable-sort fallback. Scorer-only tracemalloc на 100k снизился с **49.21 MiB до 0.01 MiB** временных Python allocations. Все ordered signatures точно совпали с 3.3 и baseline 3.1 на 1k/10k/100k. На 100k p50 против 3.3 ниже на 3.3% для `search_all()` и 12.4% для `notes_for_scan()` по трём повторам; это не гарантия причинного speedup. Joint RSS high-water практически плоский: 405.92→405.87 MiB, поэтому process-RSS improvement не заявляется. Детали — `benchmarks/results/vector-path-topk.md/.json`.
- **Проверки 3.4:** regression test на tie order/NaN; vector/cross-target классы — **22/22**; полный suite — **545/545**, 0 `ResourceWarning`; inherited sentinel DB не изменилась, временные каталоги удалены; `py_compile` OK. Cross-target behavior и `target_id` filter проходят существующие тесты.
- **Ограничения 3.4:** benchmark выполнен на Linux, synthetic 16D; Windows, production/384D и полная независимость тестов остаются открытыми. ANN не обоснован.
- **Этап 4.1A — pure scan Settings schema:** создан `asm/settings.py` с frozen `Settings`/`ScanSettings`, strict parsing по явным mappings, precedence `mode < environment < CLI` и без чтения/изменения `os.environ`. Все 18 defaults точно совпали с прежними defaults в чистом subprocess.
- **Этап 4.1B — передача snapshot в scan:** `scan.run(..., settings=...)` принимает immutable `Settings`; CLI, API web-scan и scheduler строят snapshot до запуска worker. Legacy callers без `settings` читают явный env snapshot в момент вызова; `scan.DEFAULTS` сохранён как static schema-defaults mapping. `limits` dict и его прежнее truthy merge (включая игнорирование 0/False) оставлены для совместимости.
- **Этап 4.1C1 — pure mode preset mapping:** `mode.preset_values(name)` возвращает копию preset без env/DB side effects; `mode.stored_preset(st)` возвращает сохранённое имя и mapping без изменения окружения. `load_into_env()` теперь использует этот mapping как legacy adapter, сохраняя `setdefault`; `mode.apply()` сохраняет прежний behavior.
- **Этап 4.1C2 — mode mapping подключён к typed scan resolver:** `Settings.from_environment_snapshot()` проецирует только известные scan env keys отдельно из preset и environment mappings; чужие домены preset не попадают в строгий scan parser. CLI, web API и scheduler вызывают `stored_preset()` при сборке каждого snapshot. Приоритет typed sources: defaults < mode < environment; `--set` остаётся явной environment-установкой до legacy mode adapter и не меняет приоритет.
- **Проверки 4.1 A/B/C1/C2:** settings/mode-mapping tests — **19/19**; полный suite — **564/564**, 0 `ResourceWarning`; inherited sentinel DB SHA совпал (`b95a122d…498d184`), новые suite temp-каталоги отсутствуют; `py_compile` OK. Проверены default equality, mode/env precedence, фильтрация чужих ключей, повторное получение preset на новых web snapshots, AST wiring CLI/web/scheduler, отсутствие env mutation в mapping API и прежние mode tests.
- **Этап 4.1C3 — read-only inventory mode consumers:** сопоставлены 6 preset keys и их consumers/timing. `ASM_ACTIVE_SCAN` и `ASM_FFUF` уже входят в typed scan schema; `ASM_PROFILE`, `ASM_PLANNER`, `ASM_STEALTH` и `ASM_QUEUE_IMPACT` остаются вне неё. Отмечены high-risk profile/egress gates и два runtime parser-а `ASM_QUEUE_IMPACT`; существующие профильные/режимные классы — **70/70**. В C3 runtime code не менялся.
- **Границы и следующий этап:** 4.1 не завершён. Typed resolver охватывает scan-domain; `load_into_env`/`mode.apply` продолжают менять env ради не перенесённых consumers. `engines`/`active`/transport и другие modules сохраняют env-read path; `--set`, `--settings`, model/transport и secret code не менялись. Следующий кодовый шаг — миграция одного отдельного non-scan consumer с тестированием его safety gates; legacy adapter не удалять до подтверждённого переноса import-time consumers.

## Что в этой работе означает «10/10»

Абсолютный ноль дефектов обещать нельзя. Для каждого пункта «10/10» означает одновременно:

1. исправлена указанная причина, а не только симптом;
2. контракт явно записан в типе/API/документации;
3. есть регрессионный тест, который падает на старом поведении и проходит на новом;
4. тест изолирован от рабочей БД, сети и установленных внешних инструментов;
5. отрицательный/ошибочный результат нельзя спутать с «пусто/успешно»;
6. если пункт про производительность — есть воспроизводимый benchmark, размер входа и сравнение до/после;
7. статический повторный обзор не находит побочного обхода через fallback/CLI/UI.

Ни один пункт не закрывается одной правкой без проверки соседних путей.

## Рабочий протокол

- Один issue за раз; небольшие отдельные изменения, без «переписать всё за раз».
- Перед новым изменением — зафиксировать baseline и критерий приёмки; после — показать конкретные файлы/строки/результаты.
- Любой повторный запуск suite обязан использовать уникальную временную SQLite-БД; перед изменениями harness проверять защиту через унаследованный `ASM_DB` sentinel. Рабочую БД не подставлять ни при каких тестах.
- Динамические проверки — только на временной/изолированной SQLite-БД, без сети и без внешних движков.
- Никаких сканов объектов, скачиваний/установок инструментов или обращения к облачной модели без отдельного решения.
- Если исправление изменяет политику (например, общая память между объектами, режимы или внешние запросы), сначала документировать выбранное поведение, затем кодировать его.

---

## Этап 0. Защитить процесс работы

### 0.1. Защитить тестовую среду от рабочей `ASM_DB`
**Причина:** `tests/test_core.py:21` использует `os.environ.setdefault`; существующая переменная окружения имеет приоритет, затем тесты создают данные в выбранной БД.

**Изменение:** каждый test run получает уникальную временную БД принудительно; suite отказывается стартовать, если БД не в temp-каталоге; гарантированное закрытие/удаление в `tearDownModule` или отдельном subprocess.

**Приёмка 10/10:** при `ASM_DB`, указывающей на sentinel-базу с хешем/счётчиками, запуск тестов не открывает и не меняет её; temp-база удаляется даже при падении теста; два прогона не разделяют состояние.

### 0.2. Изолировать тесты друг от друга
**Причина:** общая БД используется между тестами; `test_execution_is_not_repeatable` оставляет monkeypatch для `dnsx_resolve` и `tool_path`.

**Изменение:** пер-test fixtures или транзакционные rollback; все глобальные подмены через контекстный `patch`; отдельные тесты параллельного исполнения.

**Приёмка 10/10:** каждый тест проходит отдельно и при случайном порядке; изменённые функции/окружение восстановлены после успеха и исключения; нет зависимости от данных, оставленных другим классом.

---

## Этап 1. Снять release-blockers безопасности и целостности

Эти пункты ставятся перед общей перестройкой архитектуры, потому что дальнейшие тесты и сканирования не должны опираться на неверные ограничения.

### 1.1. Панель: bind, auth и ограничения API
- loopback по умолчанию; удалённый bind только после явного выбора.
- аутентификация/авторизация для всех API, CSRF-защита, лимит размера тела до чтения.
- разделение read-only и управляющих маршрутов.
- тесты на unauth GET/POST, размер тела и отсутствие действия при отказе.

### 1.2. Scope и egress — единый enforcement
- проверять исходный target, разрешённые IP, PTR/SAN/ASN-расширения и каждый redirect непосредственно перед соединением.
- boundary-correct DNS suffix; неизвестное/непроверенное назначение блокировать.
- `ASM_ACTIVE_SCAN=0` должен запрещать все активные стадии, а не одну ветку.
- режим `vpn/require` обязан проверять реальный маршрут и запрещать незащищённый egress/raw sockets/subprocess.

**Приёмка 10/10:** табличные тесты на in-scope/out-of-scope IPv4/IPv6, CNAME, redirects, SAN и raw socket; каждый вариант либо разрешён с доказанным маршрутом, либо заблокирован до отправки пакета.

### 1.3. Очередь агента, одобрение и стоп
- атомарный переход `proposed -> approved/rejected -> running` с compare-and-swap.
- один execution ID на разрешённый шаг; повторный запрос идемпотентен.
- единый preflight/бюджет перед всеми ветками, в том числе internal transport; ошибка budget не разрешает исполнение.
- STOP управляет process groups/job objects, ждёт дерева процессов и честно сообщает survivors.

**Приёмка 10/10:** конкурентные тесты approve/reject/run/stop; ровно один внешний вызов; отказ/остановка не оставляет живой дочерний процесс.

### 1.4. Устранить ввод/рендеринг, способный менять действие
- UI: DOM API и event listeners вместо данных внутри inline JS/HTML.
- endpoint целей: строгая валидация типов/длины; безопасный вывод всех недоверенных полей.
- URL fetch: только допустимые публичные назначения либо явный scope; повторная валидация redirect.
- тесты на hostile strings, DNS/IP redirects и malformed requests.

### 1.5. Удаление/выполнение в вспомогательных скриптах
- `seed-hard.py` не удаляет путь из внешнего `ASM_DB`.
- диагностика не удаляет/не заменяет штатные бинарники и не вызывает installer неявно.
- `check-big.py` не исполняет произвольный код на host; тестовая проверка — AST/DSL или изолированная disposable VM.
- проверка CSV-формул перед экспортом.

---

## Этап 2. Закрыть крупнейшее узкое место — запись в SQLite

### 2.1. Пакетная запись
`save_assets`, `save_edges`, `save_findings` должны использовать `executemany` и одну транзакцию на пакет; FTS обновляется пакетом в той же транзакции.

### 2.2. Конкурентная модель БД
**Статус:** connection-per-thread реализован и принят на Linux sandbox; Windows acceptance остаётся открытым. Каждому потоку принадлежит thread-local `sqlite3.Connection`; SQLite сериализует записи. `q/ex`, batch helpers и прямые vector/scan SQL-пути работают через `store.connect()`. Закрытие: `close_current()` владельцем потока; `close_all()` только после остановки потоков/при shutdown. `check_same_thread=False` нужен для контролируемого закрытия зарегистрированных handle-ов и не означает совместное использование через store API.

WAL и явный busy timeout отложены до конкурентных тестов на целевой Windows-системе. Не менять их в рамках текущей Linux-проверки.

### 2.3. Миграции и индексы
**Статус:** реализовано и принято на Linux sandbox; фактическая Windows-проверка SQLite остаётся открытой.

`asm/store.py` использует `PRAGMA user_version`, текущая версия — 2. Миграция v1 добавляет отсутствующие legacy-колонки через `PRAGMA table_info` и выполняет backfill `kind`; v2 атомарно обновляет набор индексов. Каждая миграция выполняется в транзакции `BEGIN IMMEDIATE` и фиксирует версию только после успешного завершения. Неизвестная будущая версия отклоняется до изменения схемы. Вместо `except OperationalError: pass` ошибки миграции теперь приводят к rollback и возвращаются вызывающему коду. В FTS fallback известное отсутствие модуля распознаётся отдельно; lock/schema/query ошибки не маскируются.

По baseline `EXPLAIN QUERY PLAN` были добавлены индексы для: `scans(target_id,id DESC)` и `scans(status)`; `findings(scan_id,score DESC)`; `agent_steps(session_id,seq)` и `(session_id,status,seq)`; `chats(scan_id,element,id DESC)`; `views(scan_id,id DESC)`; `agent_sessions(status,id DESC)`; сигнатуры `kb_refinements`. Существующий индекс `findings(scan_id)` сохранён, поскольку обслуживает отдельные scan/id-пути. Индексы `sem_meta(scan_id)` и fallback `sem(scan_id)` создаются в vector subsystem.

Три migration-теста проверяют отказ для будущей версии, распространение SQL-ошибки с rollback и сохранение старого индекса при провале v2; plan-тест сверяет точные результаты до/после и выбранные индексы; отдельные тесты проверяют vector plans и FTS error handling.

**Benchmark:** `benchmarks/benchmark_store_indexes.py`; отчёт и сырые данные — `benchmarks/results/store-index-report.md` и `store-index-report.json`. На 1k/10k/100k результаты всех запросов точно совпали. На 100k базовых строк warm p50 улучшился в 6.81× для scans-by-target, 103.86× для stale-scan sweep, 2.60× для findings-by-score, 5.85× для pending steps, 7.30× для views и 538× для точного KB-lookup. Размер БД вырос на 22,761,472 байта. Write-latency overhead индексов отдельно не измерялся; это синтетический Linux result, не Windows/production гарантия.

**Приёмка:** полный suite после этапа — 541/541, 0 `ResourceWarning`; sentinel DB неизменна, временные каталоги удалены. Независимость каждого теста от общего временного корпуса не входит в это доказательство.

---

## Этап 3. Перестроить векторную память без потери рейтинга

**Статус:** пункты 3.1–3.4 реализованы и проверены на Linux sandbox; exact result signatures, ties, cross-target behavior и `target_id` filter сохранены. Bounded top-k прошёл целевой и полный suite. Windows/production performance и 384D vectors не подтверждены.

1. **Политика памяти:** cross-target поиск намеренный и проверен `TestCrossScanMemory.test_search_all_reaches_other_targets`; `test_target_filter_narrows_the_search` проверяет явный фильтр. Не сужать общий поиск без отдельного решения.
2. **Тёплый single-query cache — выполнено:** `_stored_dimension()` получает dimension одной строки, `_ensure_tables()` сначала решает судьбу schema, после чего `_read_stored()` делает один полный pass. `similar()` наследует этот path. При reindex после commit дополнительный read остаётся.
3. **Batch `notes_for_scan()` — выполнено:** один corpus и vector map на scan, JSON blob считается раз на finding/query. На 100k p50/p95 — 9.537/9.782 s против 48.347/48.467 s baseline (**5.07×/4.95×**); reads корпуса 4→1, vector map 4→1, vector rows 8N→2N.
4. **Общий warm path после 3.3:** на 100k direct `search_all()` p50/p95 3.993/4.050 s; совместный peak RSS delta двух путей 405.92 MiB против 486.66 MiB на baseline (около −16.6%). Синтетическая размерность 16D; это не оценка штатных 384D/model vectors.
5. **Bounded top-k — выполнено:** до изменения cProfile на 100k показывал `search_all()` 6.998 s под profiler; `_search_candidates()` 4.827 s cumulative / 0.592 s self-time, `_all_findings()` 2.101 s, `_vectors_cached()` 1.655 s, `json_dumps()` 1.334 s. Scorer-only `tracemalloc` peak временных Python allocations снизился с 49.21 MiB до 0.01 MiB после heap; полный корпус/vector map и точный O(N) scoring остаются. При равном округлённом score используется входная позиция для стабильного порядка; NaN включает старый stable-sort path.
6. **ANN только при обосновании:** пока не добавлять. Точные ordered signatures сохранены; измеренный scorer memory benefit достаточен для локального top-k, но профиль не показывает, что ANN нужен. Пересматривать только при отдельном workload benchmark и с точным fallback/characterization.

**Артефакты:** baseline — `benchmarks/results/vector-path-baseline.md/.json`; после batch — `vector-path-notes-batch.md/.json`; после single-read — `vector-path-single-read.md/.json`; после bounded top-k — `vector-path-topk.md/.json`. Benchmark на 1k/10k/100k, по 3 warm observations; p95 ориентировочный, RSS совместный для двух путей, Linux sandbox без сети/модели. Scorer-only `tracemalloc` измерялся отдельно после подготовки корпуса и vector map.

**Characterization и приёмка 3.4:** fixed golden order `(score, finding_id)`, reference ID/order/tie test, отдельный tie/NaN fallback regression, batch-vs-individual `similar()` equality, cross-target и `target_id` tests. Vector/cross-target классы после изменения — 22/22; полный suite — 545/545, 0 `ResourceWarning`, sentinel DB неизменна. Ordered signatures на 1k/10k/100k совпали с этапом 3.3 и baseline. Scorer-only peak Python allocations: 49.21→0.01 MiB; joint process RSS 405.92→405.87 MiB и не трактуется как измеримый RSS выигрыш.

**Открытые ограничения:** все vector measurements сделаны на Linux и synthetic 16D vectors; Windows, production corpus/384D, write/workload contention и полная randomized-order isolation не доказаны. Существующий `target_id` фильтр и cross-target search не менялись. Перед следующим source change сохранить точную сигнатуру, sentinel и полный suite.

---

## Этап 4. Ввести явные конфигурацию и типизированные контракты

### 4.1. Settings
**Статус: частично; A/B/C1/C2 и C3 inventory выполнены, полный этап не принят.** `asm/settings.py` задаёт immutable `Settings`/`ScanSettings`; `scan.run()` получает snapshot от CLI/web/scheduler. `scan.DEFAULTS` стал static compatibility mapping, legacy `limits` truthiness пока сохранён. CLI/web/scheduler builders включают `stored_preset()` как source ниже environment; `from_environment_snapshot()` проецирует только известные scan keys из preset и environment mappings. Приоритет typed scan sources: defaults < mode < environment; legacy `load_into_env()` и `mode.apply()` оставлены для ещё не мигрированных consumers. Карта оставшихся четырёх non-scan preset keys и их safety-sensitive consumers записана в `asm-settings-architecture-plan.md`.

Полный критерий этапа остаётся:
- общий композиционный корень с typed scan/model/transport settings и валидируемыми источниками;
- отсутствие import-time config reads у всей рабочей import graph и отсутствие глобальной env mutation;
- режим и CLI source precedence сохраняются без временной подмены `os.environ`;
- secrets не передаются через `--set` и не отображаются в диагностике. Secret-related code не менять без отдельного разрешения; это условие пока не закрыто.

Transitive `engines`/`active`/transport consumers, `--set`, `--settings`, model/transport и runtime `limits` typing не мигрированы. Полную import purity и Windows acceptance не заявлять.

### 4.2. Stage/agent contracts
- `ScanContext` вместо передачи 20+ независимых значений.
- `StageResult` со статусами `ok/partial/failed/not_run` и структурированными ошибками.
- доменные модели для Asset/Finding/ProbeResult/Step; schema validation на границах HTTP/LLM/DB.

**Приёмка 10/10:** импорт модулей не читает и не меняет process config; запуск теста может создать 2 независимых конфигурации в одном процессе; неверный тип/поле отклоняется на границе с диагностикой.

---

## Этап 5. Объединить policy и транспорт

- один адаптер для HTTP(S), redirects, TLS, proxy, body limits, timeout и error mapping.
- один источник scanner args/allowlist; fallback использует ту же policy, что основной engine.
- правила `active`, `safe/pentest/full`, egress, budget и scope не дублируются в CLI/UI/engine.
- ошибки не преобразуются в «пустой ответ» без статуса и причины.

**Приёмка 10/10:** контрактные тесты одинаковы для всех transport/engine paths; аудит фиксирует фактически использованные режимы; новые движки не могут добавиться без policy metadata и теста.

---

## Этап 6. Оптимизировать пайплайн только по профилю

1. Поставить таймеры по стадиям, DB, внешним источникам, сериализации и vector search.
2. Устранить повторные проходы по host/IP map там, где benchmark подтверждает цену; заранее строить обратные индексы `ip -> hosts`.
3. Параллелизм ограничить явным resource budget; не создавать worker pools для коротких операций без замера.
4. Batch/cache только с корректной invalidation и статусом freshness.

**Приёмка 10/10:** есть эталонные сценарии и воспроизводимые бенчмарки; p50/p95 и peak memory не регрессируют выше заранее согласованного порога; выводы основаны на измерениях, не на визуальном впечатлении.

---

## Этап 7. Разбить крупные модули малыми рефакторингами

Очередность: `store.py` (repository/migrations), `engines.py` (адаптеры/политики/процессы), `agent.py` (decision/execution), `web.py` (routes/services), `stages.py` (контексты и результаты), затем UI на отдельные модули.

Правило: сначала characterization tests, затем один перенос, затем сравнение поведения. Не переносить всю простыню автоматически и не менять бизнес-поведение одновременно с перемещением кода.

**Приёмка 10/10:** файлы имеют единую ответственность; публичные интерфейсы короткие и типизированные; зависимости направлены внутрь; новая стадия не требует изменения несвязанных модулей.

---

## Этап 8. Воспроизводимость и качество изменений

- добавить `pyproject.toml`, lockfile, версии поддерживаемого Python, Ruff/formatter/type checker и CI Windows/Linux.
- разделить `tests/test_core.py` по доменам; отключить сеть по умолчанию через fake transport.
- короткие ADR вместо датированных повествовательных комментариев; исправить недостоверные будущие даты.
- отдельно проводить security review, code-quality review и performance review, не заменяя одно другим.

**Приёмка 10/10:** clean checkout воспроизводимо собирается/проверяется в CI; два запуска дают один результат; все внешние инструменты подменены fake в unit suite; lint/type/test результаты приложены к каждой партии изменений.

---

## Порядок первой рабочей серии

1. Принудительная изоляция БД на test-run, cleanup и восстановление утекшего monkeypatch — **выполнено; 517/517 на первой приёмке**. Полная per-test isolation остаётся отдельным долгом.
2. Characterization/regression tests и пакетная транзакционная запись assets/edges/findings/FTS с benchmark — **выполнено; 530/530 на полной проверке**.
3. Connection-per-thread выбран и проверен конкурентными тестами на Linux; Windows-проверка остаётся незавершённой. WAL/busy timeout не включать до неё.
4. Этап 2.3 — schema migrations и EXPLAIN-driven indexes — выполнен на Linux; Windows/production acceptance остаётся открытым.
5. Этапы vector memory 3.1–3.4 завершены на Linux sandbox: batch reuse, single-read cache и bounded top-k; cross-target behavior и `target_id` filter сохранены, полный suite после 3.4 — 545/545. Windows/production performance остаются открытыми.
6. В этапе 4.1 выполнены A/B для scan Settings и C1 для чистого mode preset mapping; полный suite — 561/561. Следующий substep — подключить mode mapping к source resolver, сохраняя precedence и legacy env adapter. Секретные `--set`/`--settings` paths не менять без отдельного разрешения. ANN по-прежнему не обоснован.

Параллельно нельзя считать проект готовым к release, пока не закрыты auth/scope/egress/active-switch/XSS/unsafe-code execution/DB deletion пункты из предыдущего отчёта.
