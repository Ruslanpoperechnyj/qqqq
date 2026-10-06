# ASM — архитектурный план Settings / Config (этап 4.1)

**Статус:** архитектурный план; шаги A/B/C1/C2 выполнены для scan/mode boundary, этап 4.1 в целом не принят.  
**Основание:** `asm-quality-roadmap.md`, этап 4.1; `ПЛАН.md` §§17.1–17.2 и 25.3.  
**Инвентаризация:** read-only поиск по CLI, scan, mode и настройкам Python-модулей.  
**Реализация A/B/C1/C2:** добавлены immutable scan Settings и snapshot injection; CLI/web/scheduler передают сохранённый mode mapping в typed resolver с приоритетом environment выше mode. Legacy env adapter сохранён для ещё не мигрированных consumers. `--set`, `--settings`, model/transport и secret-related code не менялись.

## 1. Цель

Перейти от неявной конфигурации через глобальный `os.environ` и import-time константы к валидируемому неизменяемому снимку настроек, который создаётся на границе операции и передаётся явным зависимостям.

Целевой контракт:

- один верхнеуровневый `Settings`, состоящий из предметных групп `ScanSettings`, `ModelSettings`, `TransportSettings` и, при необходимости, отдельных runtime-настроек;
- построение из явно переданных источников, без чтения/записи process environment на импорте;
- настройки каждой операции неизменяемы после старта; два параллельных скана в одном процессе могут получить разные snapshots;
- ошибка неизвестного или неверно типизированного значения обнаруживается до запуска скана/движка и содержит имя настройки и причину, но не её потенциально чувствительное значение;
- текущие defaults, сохранённый режим и приоритет явных настроек не меняют поведение незаметно.

## 2. Что найдено в текущей реализации

1. `app.py` разбирает `--set` до импортов ASM и записывает пары прямо в `os.environ`. Допускается любое имя с префиксом `ASM_`; наличие поля в поддерживаемой схеме и его тип не проверяются. Тесты сейчас закрепляют это поведение, поэтому его нельзя менять молча.
2. Затем `_apply_mode_before_imports()` открывает SQLite и вызывает `mode.load_into_env()`. `asm/mode.py` применяет preset через `os.environ.setdefault()`. В `ПЛАН.md` §25.3 зафиксирован ожидаемый приоритет: явные настройки из shell/`--set` → сохранённый режим → defaults.
3. До шага B `asm/scan.py` строил `DEFAULTS` при импорте и немедленно разбирал числовые env-значения. Теперь `DEFAULTS` — static schema-defaults mapping, а `scan.run()` принимает `Settings` snapshot; legacy callers без него строят mapping snapshot во время вызова. `limits` merge всё ещё использует `if v`, поэтому legacy overrides на `False`/`0` по-прежнему пропускаются.
4. CLI, web API и scheduler создают отдельный snapshot перед прямым запуском/созданием worker; builder вызывает `stored_preset()` и передаёт mapping вместе с environment в typed resolver. `Settings.from_environment_snapshot()` проецирует только известные scan env keys для обоих sources; `scan.run()` получает typed object, а не строит его из глобального окружения. Тестовые/legacy callers могут пока вызывать функцию без `settings`.
5. Import-time env-зависимости есть не только в `scan.py`, но и в импортируемых путях `engines.py`, `active.py`, `stealth.py`, `transport.py`, `vector.py`, `sources.py`, `knowledge.py` и других модулях. `--settings` извлекает имена и defaults AST-поиском, но не является типизированной схемой и не проверяет диапазоны.
6. `app.py --settings` выводит текущие значения `ASM_*` без отдельного правила маскирования чувствительных имён. `--set` также принимает секретное имя, если оно начинается с `ASM_`. Реальные значения в ходе инвентаризации не запрашивались и не печатались.

## 3. Предлагаемая архитектура

### 3.1. Чистый модуль настроек

Создать `asm/settings.py` с типами данных и парсерами стандартной библиотеки; модуль не импортирует `store`, `mode`, `scan`, transport-клиенты и не читает `os.environ` при импорте.

Интерфейс сборки должен принимать mappings/явные источники, например:

```text
Settings.from_sources(
    defaults=..., mode_values=..., environment=..., cli_overrides=...
)
```

Сам `Settings.from_sources()` не читает глобальное окружение и ничего в нём не меняет. Composition root передаёт явные sources. Для текущего scan boundary `from_environment_snapshot()` принимает полную environment mapping (например, `os.environ`) и извлекает только известные scan keys, не обходя/копируя значения остальных доменов; это создаёт самостоятельный typed snapshot без необходимости копировать всю среду.

Модели — immutable dataclasses (`frozen=True`), с вложенными группами по назначению. Domain-код получает ровно нужную группу, а не читает глобальный env напрямую. `settings.py` остаётся нижним слоем без импорта рабочих модулей, чтобы не создать циклические зависимости.

### 3.2. Источники и приоритет

Сохранить уже задокументированное поведение §25.3 и текущее поведение CLI:

```text
built-in defaults < сохранённый preset режима < shell environment < --set / явный override операции
```

Повторяющиеся `--set` должны разрешаться в текущем порядке (последнее значение выигрывает), если это не будет отдельно изменено и задокументировано. Для web новый snapshot создаётся при постановке операции/скана; изменение конфигурации не меняет уже работающий scan. Разрешение режима должно возвращать mapping, а не выставлять preset в process environment.

Парсер различает «параметр не задан» и явные `False`/`0`/пустую строку. У каждой настройки должны быть описаны допустимые значения, default и поведение пустого значения; не вводить новые верхние лимиты без анализа существующей политики.

### 3.3. Постепенная миграция потребителей

Не заменять 112 имён одним массовым codemod. Сначала каталогизировать имена по доменам и контексту чтения: import-time, runtime, CLI, режим, секретный источник, внутренний compatibility alias. Затем переносить группы по одной, оставляя временный адаптер для ещё не мигрированных потребителей.

Для scan-пути все 18 defaults `ScanSettings` совпали с историческими defaults `scan.DEFAULTS` в чистом subprocess. В шаге B `scan.DEFAULTS` оставлен как static compatibility mapping; он больше не захватывает env при импорте. `scan.run()` получает `Settings` явно от CLI/web/scheduler; legacy callers без `settings` разбирают runtime snapshot при входе. Dict `limits` сохранён как adapter, включая текущее truthiness-поведение.

Отдельная работа остаётся открытой: определить и внедрить explicit semantics для `limits`-override `False`/`0` и типизацию HTTP/CLI-полей. Сейчас их прежнее отбрасывание сохранено, чтобы не смешивать config wiring с изменением внешнего поведения.

## 4. Этапы реализации

### Шаг A — схема и characterization (выполнен; consumers пока не мигрированы)

- Добавить чистые dataclasses и парсеры для несекретной `ScanSettings`; заложить composition root `Settings`, без массового подключения новых модулей.
- Значения передавать как mappings; никаких новых reads/writes `os.environ`.
- Зафиксировать defaults из `scan.DEFAULTS`, типы, допустимые bool-строки, диапазоны и особую семантику пустых значений.
- Существующий `--set`, режим, модель, транспорт, секретный раздел и их consumers не менять в этом коммите.

**Тесты:** два разных snapshots в одном процессе; входные mappings и `os.environ` не мутируются; invalid bool/int/range отклоняется с полезной диагностикой; все действующие defaults равны characterization fixtures; import чистого модуля не имеет side effects.

**Результат шага A (до B):** добавлены `asm/settings.py` и первичные тесты; тогда целевой класс прошёл 9/9, полный suite — 554/554. Все 18 defaults совпали с историческим `scan.DEFAULTS` в subprocess с очищенным `ASM_*` окружением. Runtime-поведение на шаге A ещё не менялось.

### Шаг B — явная передача в scan (выполнен с сохранением legacy adapter)

- CLI, web API и scheduler собирают snapshot до передачи работы через `stored_preset()` + explicit environment mapping; projection передаёт resolver только известные scan keys. Web config error возвращается до создания scan-записи.
- `scan.run(..., settings=Settings)` формирует stage `L` из snapshot; если `settings` не передан, legacy callers снимают environment snapshot в момент вызова.
- `scan.DEFAULTS` сохранён как mapping schema defaults, но перестал читать environment при импорте.
- Legacy `limits: dict` merge сохранён без переопределения `False`/`0`; эту семантику нельзя считать исправленной.
- Scoring, scope, active modes и последовательность стадий не менялись.

**Проверки B:** 14 settings tests проходят; проверены независимые Settings objects, builder parsing, runtime env fallback и `_run()` receives effective dictionary. AST regression test проверяет wiring CLI + два web Thread callers. Полный suite — 559/559, 0 `ResourceWarning`, sentinel DB unchanged. Реальное одновременное выполнение двух full scans не запускалось; cross-talk по нескольким реальным сканерам не объявляется закрытым.

### Шаг C1 — side-effect-free mode mapping (реализован; legacy adapter сохранён)

- `mode.preset_values(name)` возвращает копию preset для известного имени/alias; для неизвестного имени — пустой mapping.
- `mode.stored_preset(st=None)` читает сохранённое имя и выдаёт mapping, не меняя process environment.
- `mode.load_into_env()` строит применение из этой mapping-функции, но продолжает выставлять preset через `setdefault`; `mode.apply()` продолжает писать сохранённый режим и обновлять env для уже импортированных потребителей.
- Добавлены side-effect/copy tests; существующие mode behavior tests остаются acceptance gate.

**Результат 05.10.2026:** settings/mode mapping target tests — 16/16; полный suite — 561/561, 0 `ResourceWarning`; inherited sentinel неизменна. Это API foundation, не переключение application composition: source priority на runtime пока продолжает обеспечиваться старым env-путём.

### Шаг C2 — mode mapping в typed Settings resolver (выполнен; legacy adapter сохранён)

- `Settings.from_environment_snapshot(environment, mode_values=...)` проецирует известные scan env keys из обеих mapping-ов, затем применяет resolver precedence `defaults < mode < environment < CLI`. Полный mode preset содержит ключи других доменов, которые не передаются строгому scan parser; environment mapping читается только по точным scan key names.
- CLI snapshot builder (`app.py`) и общий web snapshot builder (используемый API и scheduler) вызывают `stored_preset()` заново на каждой границе scan snapshot. `--set` продолжает применяться до legacy mode adapter и остаётся в environment source выше mode; parser не менялся.
- `load_into_env()` и `mode.apply()` не удалялись/не переписывались сверх C1; они по-прежнему обслуживают consumers, которые читают env/import-time значения. Режимные `safe`/`combat` policies и gates не менялись.
- Secret-related code, `--settings`, model/transport и scan `limits` overrides этим шагом не затрагивались.

**Characterization и проверки C2:** settings suite — **19/19**; полный suite — **564/564**, 0 `ResourceWarning`; `py_compile` прошёл. Проверены env-over-mode, mode-over-default, фильтрация ключей других доменов, no-env-mutation у mapping helper, повторный вызов web builder с разными returned saved presets, AST wiring CLI/web/scheduler и прежние mode compatibility tests. Полный запуск получил inherited sentinel SHA `b95a122db2ca5a504db8d409484c96403b187d2c311bbd0a2e89513af498d184` до/после; новых `asm-tests-*` temp каталогов нет.

Это composition только для scan typed snapshot; оно не удаляет и не переводит legacy env adapters для остальных модулей.

### Шаг C3 — инвентаризация оставшихся mode consumers (выполнен; read-only)

Без runtime-изменений сопоставлены все шесть ключей `mode.PRESETS` с актуальными потребителями, моментом чтения и защитными регрессиями:

| Ключ | Scan typed schema | Текущие потребители/момент чтения | Риск и существующие проверки |
|---|---|---|---|
| `ASM_PROFILE` | нет | `asm.engines.PROFILE` при импорте; через `engines.PENTEST` влияет также на класс действий `asm.agent` | Высокий: risky-tag filters, скорость и профильные impact-классы; `TestProfiles`, `TestRateLimits`, `TestAgentGating.test_impact_class_follows_profile` |
| `ASM_PLANNER` | нет | `asm.planner.mode()` при каждом планировании; `asm.mode._model_state()` при проверке готовности | Выбор правил/model/both может вызвать модель; `TestPlanner.test_rules_mode_does_not_touch_the_model`, fallback tests и `TestMode.test_check_tells_apart_a_blocker_from_a_warning` |
| `ASM_STEALTH` | нет | `asm.stealth.MODE` при импорте; `asm.mode._stealth_state()` читает environment отдельно | Высокий: egress/proxy policy и отказ наружу; `TestStealth.test_require_mode_blocks_outward_without_proxy`, `TestMode.test_require_stealth_without_proxy_is_a_blocker` |
| `ASM_ACTIVE_SCAN` | да: `ScanSettings.active_scan` | typed scan `L` → `asm.stages.stage_active_checks()` | Stage пропускается при false; оба preset сейчас задают `1`; settings precedence tests |
| `ASM_FFUF` | да: `ScanSettings.deep_paths` | typed scan `L` → условный ffuf-этап в `stage_crawl_archives()` | Шумный этап включается только при true; оба preset сейчас задают `0`; settings precedence tests |
| `ASM_QUEUE_IMPACT` | нет | runtime readers `asm.agent._queue_impact()` и `asm.planner.queue_impact_enabled()` (два парсера одного значения) | Влияет на автодобавление impact-шагов в очередь, но не на одобрение/исполнение; `TestPlanner.test_queueing_impact_can_be_turned_off`, `test_impact_is_queued_but_never_runs_without_approval`, `TestAgentGating.test_step_is_not_executed_without_approval` |

Текущая разница preset-ов: `safe` → profile `safe`, planner `rules`, stealth `off`; `combat` → profile `pentest`, planner `both`, stealth `warn`. Оба включают active scan и очередь impact-шагов, оба оставляют FFUF выключенным. Ключи `ASM_PROFILE` и `ASM_STEALTH` связаны с высокорисковыми policy boundaries; их нельзя переносить простой заменой env-read без отдельного design/characterization. `ASM_QUEUE_IMPACT` дублирует bool parsing, но остаётся частью operator queue policy — одобрение `agent.execute()` не должно зависеть от неё.

**Проверка inventory:** существующие `TestMode`, `TestProfiles`, `TestStealth`, `TestRateLimits`, `TestPlanner` и `TestAgentGating` — **70/70**; это characterization существующего поведения, не подтверждение миграции этих consumers. C3 не менял код и не расширял typed schema.

### Более поздний composition этап

- Перевести mode с изменения `os.environ` на выдачу preset mapping после миграции import-time consumers.
- Сохранить PowerShell/Git Bash workflow из §17.1; изменения `--set` и `--settings` применяются только отдельным разрешённым scope.
- Незатронутые модули могут временно использовать legacy env compatibility path, но их статус должен быть явным.

### Шаг D — model и transport

- Переносить `ModelSettings` и `TransportSettings` отдельными малыми PR/этапами после scan.
- Не менять выбор провайдера, сетевой маршрут, VPN/proxy policy, auth, retry policy или разрешение на отправку данных как побочный эффект config refactor.
- Новые consumers получают snapshot явно; действующие секретные источники и secret flows остаются нетронутыми, пока оператор отдельно не разрешит соответствующую работу.

### Шаг E — реестр, `--settings` и завершение миграции

- После классификации всех активных env-настроек заменить AST-эвристику на метаданные типизированной схемы; временно сравнивать оба списка тестом покрытия.
- Не включать значения чувствительных полей в repr, CLI output, API, audit или ошибки.
- Применение `--set` к секретным именам и правила отображения секретов — отдельный защищённый scope: до явного разрешения оператора не менять secret-related code. Это не блокирует реализацию чистой scan-конфигурации, но остаётся открытым acceptance item 4.1.
- Удалять legacy env-адаптер только после подтверждённой миграции каждого активного consumer и отсутствия неучтённых ключей.

## 5. Acceptance gates

Этап 4.1 можно считать завершённым лишь после всех пунктов:

1. Для мигрированных модулей import не читает и не меняет env; для полного требования это проверено по всей рабочей import graph, включая scan/engine/transport consumers.
2. Два `Settings` в одном процессе и в параллельных операциях остаются независимыми; нет reload-ов модулей и временной подмены глобального env.
3. Defaults и precedence точно сверены с текущим контрактом режимов и CLI; invalid key/type/range не превращается в молчаливый default и блокирует операцию до внешнего действия.
4. `False`, `0`, unset и пустая строка имеют различимую, протестированную семантику.
5. Текущие cross-target, scope, safe/pentest/full, active-scan gates, VPN и operator-approval behavior не регрессируют.
6. Секретные значения не передаются через `--set`, не раскрываются в `--settings`, API, audit, repr и ошибки. Этот пункт требует отдельно разрешённого изменения secret-related code.
7. Полный suite запускается с inherited sentinel SQLite-БД, которая остаётся побайтно неизменной; нет новых предупреждений ресурсов. Сетевые обращения и внешние сканеры для config unit tests отсутствуют.
8. Windows/PowerShell acceptance проверяется оператором в его окружении; Linux sandbox не выдаётся за доказательство Windows-поведения.

## 6. Ограничения и открытые решения

- Сейчас известны многочисленные env consumers, но до реализации нужен полный классифицированный список: имя → тип → default → источник → домен → точка чтения → чувствительность → допустимые значения. Не принимать динамически сформированные ключи за подтверждённые поля без проверки call sites.
- `ASM_DB` нужен до подключения store и временной тестовой БД; его bootstrap-порядок следует проектировать отдельно, чтобы не открыть рабочую БД из тестов и не создать цикл `Settings ↔ store`.
- Web snapshot builder перечитывает `stored_preset()` для каждого нового scan, но `load_into_env()` при старте добавляет значения preset в process environment. Если другая CLI-процедура меняет сохранённый mode без вызова `mode.apply()` в том же web-процессе, эти старые env значения могут оказаться в слое environment выше нового preset. Сейчас оба preset задают одинаковые scan-значения (`ASM_ACTIVE_SCAN=1`, `ASM_FFUF=0`), но происхождение env ключей следует решить до добавления различающихся scan presets. Уже запущенный scan остаётся на своём snapshot.
- Существующий `--set` принимает неизвестные `ASM_*`; переход к строгой схеме способен обнаружить ранее молча принимаемые ключи. Миграционный тест должен инвентаризировать действующие обращения прежде, чем неизвестные ключи начнут отклоняться.
- Старые `ПЛАН.md` §§17.1–17.2 описывают исторический CLI-контракт «112 настроек» и AST-поиск. Новый typed registry должен обновить их только после принятия соответствующего кода, не задним числом.

## 7. Текущий статус и следующий кодовый шаг

A/B/C1/C2 выполнены для scan Settings: CLI/web/scheduler snapshot builders передают `stored_preset()` в typed resolver; environment имеет приоритет над mode, а `load_into_env()`/`mode.apply()` сохранены для legacy consumers. C3 — read-only inventory шести preset keys и их consumers — тоже выполнен; карта с timing, risk и regression tests приведена выше. По существующим профильным/режимным классам пройдено **70/70**.

Следующий плановый шаг — выбрать один non-scan consumer и мигрировать его отдельным подшагом, не трогая секретные значения. Приоритетные ограничения из C3: не менять `ASM_PROFILE` и `ASM_STEALTH` без отдельного сохранения safety/egress gates; не смешивать `ASM_QUEUE_IMPACT` с approve/execute policy. Также остаётся незакрытым различение shell/`--set` environment от legacy preset values после внешнего изменения режима в работающем web-процессе (текущие scan-поля в safe/combat одинаковы).

Этап 4.1 не принят: import graph вне scan всё ещё читает env; model/transport consumers, `limits` typing/False/0 semantics, полный settings registry, secret guard и Windows acceptance остаются открытыми.
