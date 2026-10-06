# ASM — мастер-план этапа 4: конфигурация и типизированные контракты

**Назначение:** единый рабочий план Stage 4 по явному запросу оператора «делать весь этап, вопросы собрать заранее». После утверждения плана работа продолжается по нему без остановки после каждого внутреннего C/D-подшага.

## 1. Зафиксированные решения и границы

- Охват — весь раздел 4: **4.1 Settings/config + 4.2 Stage/Agent contracts**.
- Перевести все активные **несекретные** настройки и consumers: scan, engines/active, stealth policy (без изменения политики), planner/agent, model/transport, sources/runtime и связанные стадии.
- Источник mode перечитывается на каждой границе новой операции. Уже запущенная операция сохраняет собственный snapshot. В работающем web-процессе внешнее изменение mode должно влиять на следующий scan.
- Приоритет: defaults < сохранённый mode < явные shell/CLI environment < явный override операции. Значения, которые `load_into_env()` добавил только ради legacy consumers, не должны ошибочно считаться явным environment override для typed resolver.
- **Секретный carve-out по решению оператора:** `--set`, `--settings` и secret-related code не менять. Оператор разрешил принять Stage 4 при сохранении этого ограничения. В приёмке это документируется как явный waiver, а не как технически выполненный secret-safety gate. Реальные secret values не читать для аудита, не выводить в файлы/ответы и не использовать в тестах.
- Windows/PowerShell фактически не доступен. Оператор разрешил Linux-only acceptance; итог не выдавать за проверку Windows.
- Не менять policy safe/pentest/full, egress/VPN/stealth, scope, approvals, исполнение шагов, сетевую маршрутизацию, выбор провайдера, retry/timeout семантику либо сканирующие лимиты без characterization test, подтверждающего прежнее поведение.
- Не запускать внешние движки, настоящие сканы или сетевые обращения для config tests; использовать mocks, изолированную test DB и synthetic values.

## 2. Исходная точка

- Текущий baseline после C2: settings target tests **19/19**, полный suite **564/564**, 0 `ResourceWarning`; inherited sentinel SQLite SHA сохранился. C3 — read-only mode-consumer inventory; профильные characterization classes **70/70**.
- Нынешняя `ScanSettings` охватывает 18 полей; CLI/web/scheduler передают scan snapshot. `mode.stored_preset()` уже включён, но `load_into_env()` остаётся для legacy import-time consumers.
- Read-only AST inventory нашёл 128 уникальных статически заданных `ASM_*` имён в 160 literal access sites. Это нижняя граница: динамические ключи, `getattr`, `Path`/аргументы tools, non-ASM env и дополнительные consumer paths требуют отдельной классификации.
- В `--settings` остаётся существующая выдача ASM values, `--set` принимает произвольный `ASM_*`; эти маршруты остаются нетронутыми по explicit waiver.
- В `scan._run()` pipeline передаёт между стадиями много независимых локальных dict/list/values; `stage_analytics` имеет очень длинную сигнатуру; `StageResult` ещё отсутствует.

## 3. Целевая архитектура

### 3.1. Configuration root

- Нижний pure модуль `asm/settings.py` содержит frozen dataclasses и парсеры; не импортирует рабочие модули и не читает/меняет `os.environ`.
- Верхний composition root снимает только необходимые несекретные explicit environment keys до legacy mode injection; full environment values не копируются без необходимости.
- `Settings` группирует как минимум `scan`, `engines/active`, `stealth policy`, `planner/agent`, `sources/runtime`, `model` и `transport` non-secret values. Для секретных value flows оставляется существующий путь без изменений — исключение по waiver.
- Mode preset передаётся как отдельная lower-priority mapping. `load_into_env()` сохраняется до окончания миграции legacy consumers. Новый scan/agent operation получает отдельный immutable snapshot.
- Для child process передаётся только необходимый non-secret explicit config provenance; legacy-injected preset keys не должны маскировать новое значение mode.
- Defaults, input types, ranges, enum sets, `None`/unset, пустая строка, `0` и `False` специфицируются и characterization-тестируются. Ошибки называют ключ/источник, но не входное значение.

### 3.2. Stage / Agent contracts

- Новый pure `asm/contracts.py` (или эквивалентный нижний модуль) с frozen `ScanContext`, typed `StageResult` statuses `ok / partial / failed / not_run`, и доменными моделями для `Asset`, `Finding`, `ProbeResult`, `Step` по фактическим payload shapes.
- На внешних/хранимых границах оставить явные conversion adapters в прежние dict/JSON формы: не менять SQLite schema, HTTP API payloads, отчёты и audit events без отдельной characterization.
- У scan pipeline один контекст запуска; миграция стадий должна сохранять порядок, результаты, ошибки и текущий behavior. `StageResult` не может превращать ошибку в «пустой/успешный» результат.
- В agent planner/executor settings/config не могут разрешать исполнение: `agent.execute()` по-прежнему требует явного одобрения; internal actions остаются gated по записанному доступу.

## 4. План реализации

1. **Provenance-safe composition:** устранить конфликт между explicit env и значениями, внесёнными `load_into_env()`. Захватить explicit non-secret scan values до adapter; передать их одинаково в CLI, web API, scheduler и `--no-wait` child. Пере-read stored mode на границе каждой новой операции. Сохранить mode adapter.
2. **Полная карта non-secret consumers:** сопоставить key/type/default/domain/read time/consumer и существующий test; оставить secret-related paths за waiver. Обновить schema/coverage tests так, чтобы статические и динамические call sites были видимы.
3. **Typed config domains:** добавлять по domain с import-purity и precedence characterization. Мигрировать runtime consumers на explicit settings arguments; import-time consumers — только после characterization и с сохранением safety gates. Не менять `--set`/`--settings`/secret paths.
4. **Mode consumers:** интегрировать profile/planner/stealth/queue-impact в соответствующие typed groups и новые operation snapshots. Отдельно тестировать rate/tag policy, outward blocking, planner fallback, queue-vs-approval distinction.
5. **Model/transport non-secret config:** перенести non-secret base/model/style/timeout/transport decisions без выбора другого провайдера, endpoint, credentials flow, network route или retry semantics. Секретные values остаются в прежних consumers.
6. **Stage/Agent contracts:** определить модели по runtime shapes; перевести orchestration в `ScanContext`; мигрировать результаты стадий к `StageResult` с lossless adapters; agent planner remains proposal-only and execution gated.
7. **Regression/acceptance:** целевые tests после каждого group; затем полный discovery с inherited sentinel SHA check и отсутствием новых `ResourceWarning`; import-purity guards на мигрированных модулях; parallel snapshot independence; AST/coverage guard для active env call sites; docs/roadmap/review.
8. **Operator-waived gates:** секретная защита, `--set`/`--settings` hardening и Windows/PowerShell не заявлять как выполненные. Stage may be marked **accepted by operator with explicit waivers**, without claiming those checks passed.

## 5. Обязательные acceptance checks

- Точный порядок source precedence; свежий mode отражается в следующем web scan, уже запущенный snapshot не меняется.
- Immutable snapshots независимы между scans и одновременно работающими operation contexts; отсутствие новых config reads при импорте для migrated consumers.
- Safe/pentest/full tags, rates, active scan gates, stealth outward block/UA, planner fallback, queue impact, scope, budgets, approval/stop gates не регрессируют.
- `ScanContext`/`StageResult` и domain models валидируют boundary shapes и сохраняют compatibility payloads.
- Target suite и полный suite проходят на Linux sandbox; sentinel DB byte-identical, temporary DB dirs очищены, нет новых `ResourceWarning`.
- В итоговом статусе отдельно перечислить explicit secret/security waiver и отсутствие Windows acceptance.

## 6. Текущий ход работы

План создан перед реализацией согласно просьбе оператора. Следующий непосредственный кодовый пункт — provenance-safe snapshot для CLI/web/scheduler/child, затем расширение schema и typed boundaries. Stage 4 считается завершённым только после перечисленных checks либо после явного документирования waiver, согласованного оператором.
