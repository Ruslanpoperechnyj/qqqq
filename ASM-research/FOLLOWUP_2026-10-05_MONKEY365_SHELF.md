# Дополнение: Monkey365 v1.0.0 и сверка полки 225 GB

**Дата:** 2026-10-05  
**Режим:** только чтение исходников и манифестов. Monkey365 и другие кандидаты не запускались и не импортировались; зависимости не устанавливались; tenant/API/цели не опрашивались. Программный код ASM не менялся.

## Краткий вывод

- **Monkey365 пока не подходит для unattended/read-only cloud-профиля.** В Azure Storage collector обнаружена выдача `listKeys` и создание чрезмерно широкого account SAS; на ошибочном HTTP-ответе SAS URL может попасть в verbose-лог. Это отдельный hard blocker для StorageAccounts collector.
- Registry `/tokens` проходит через **GET** и в просмотренном коде не найдено получения/генерации token password. Но ответ не проецируется на безопасный DTO: объект сохраняется как есть и попадает в raw export.
- Webhook-логгеры Slack/Teams отправляют форматированные сообщения на заданный URL без редактирования. В штатной конфигурации внешнего webhook нет. При `ExportTo HTML` конфигурация по умолчанию, напротив, включает GitHub API/jsDelivr-запросы и удалённые ресурсы.
- `SaveProject` сохраняет полный export object; общего redaction-этапа в просмотренной цепочке нет. Power BI runner объявляет `Timeout=30`, но это не hard deadline: внутренние wait-циклы повторяют таймаутные ожидания, не отменяя зависшую задачу.
- Реестры содержат **135 основных + 34 challenge-pass источника = 169 уникальных URL**. Это первичный обзор, а не полный source audit 169 материалов.
- Оценка полки **141 GB + резерв 84 GB** не подтверждает, что весь набор реально помещается: множество assets, runtime, VM/Docker/Windows footprints и свободное место на Windows-хосте не измерены. Выявлена ещё одна неотражённая в прежнем манифесте позиция — Wordlust; она записана как unresolved, не исключена и не включена в подсчёт.

## 1. Архив Monkey365

Файл: `candidates/archives/monkey365-v1.0.0.zip`  
Локальный размер: **5,190,112 байт**; SHA-256: `737ed9fa9b4c2a4c578669de534fc648f99a0f56af10ddab9a62b92b504c6b4e`. В `monkey365/monkey365.psd1` заявлена версия `1.0.0`. Upstream tag `v1.0.0` разрешён в commit `cecfcbe7e5fca891a9aae961369f927d3d9ed65d` ([tag ref](https://api.github.com/repos/silverhack/monkey365/git/ref/tags/v1.0.0)). Локальный ZIP не был побайтно сопоставлен с upstream tag archive; SHA — только проверка этой локальной копии, не upstream signature. Запись добавлена в `candidates/download_manifest.json`.

## 2. Остаточный статический review Monkey365

### 2.1 Azure Storage: listKeys и SAS — высокий риск

Цепочка: `collectors/azure/storage/storageaccounts/Get-MonkeyAZCloudStorageAccount.ps1` → `Get-MonkeyAzStorageAccountInfo.ps1` → `Get-MonkeyAzStorageAccountClassicDiagnosticSetting.ps1`.

- `Get-MonkeyAzStorageAccountInfo.ps1` вызывает classic-diagnostics helper отдельно для `file`, `queue`, `blob` и `table` (примерно строки 107–142). В helper `Get-MonkeyAzStorageAccountKey.ps1` вызывается **до** проверки наличия endpoint. Он делает `POST` к ARM resource `listKeys` и извлекает `key1` (строки 48–60). Поэтому на каждый обработанный storage account возможны до четырёх `listKeys`-запросов, в том числе когда конкретный service endpoint не используется.
- `Get-MonkeyAzStorageAccountClassicDiagnosticSetting.ps1` передаёт key в `Get-SASUri` и применяет созданный URL для `GET` service properties/diagnostics (строки 82–153). По умолчанию `Get-SASUri.ps1` подписывает SAS с `sp=rwdlacup`, `ss=bqtf`, `srt=sco`, IPv4-диапазоном `0.0.0.0-255.255.255.255` и сроком `UtcNow + 1 hour` (строки 56–72, 99–137). Это несоразмерно запросу только на чтение диагностических настроек: SAS в коде описывает гораздо более широкую возможность, чем необходимый GET.
- Ключ и SAS не присваиваются возвращаемому Storage DTO: helper возвращает разобранные значения logging/metrics, а не сам URL. Но `Invoke-ClientRequest.ps1` при неуспешном ответе делает `Write-Verbose` с `RequestUri.AbsoluteUri` (строки 211–215); SAS signature находится в query string. Если включены verbose/file logging или webhook-loggers, URL может попасть в журнал и дальше — в настроенный внешний логгер.
- Дополнительный дефект: в выборе endpoint для `queue`/`file` последующий отдельный `if ($Type -eq 'blob') ... else { table }` может перезаписать ранее выбранный endpoint таблицей. Это влияет на корректность classic-diagnostics сбора, но не устраняет `listKeys`.

**Решение для профиля:** `Get-MonkeyAZCloudStorageAccount` исключить из строгого read-only allowlist до source patch и повторного review. Минимум — убрать `listKeys`/SAS целиком, заменить на least-privilege read-only путь, не логировать URLs с query secrets и ограничить scope. Сейчас никаких таких запросов не выполнялось.

### 2.2 Azure Container Registry `/tokens`

`Get-MonkeyContainerRegistryToken.ps1` передаёт `Resource='/tokens'`, API version `2020-11-01-preview`, без `Method`; `Get-MonkeyAzObjectById.ps1` по умолчанию использует `GET` (default в параметре `Method`). `Get-MonkeyAzContainerRegistryInfo.ps1` помещает возвращённый объект прямо в `$newcrObject.tokens` (около строк 77–80), затем collector отдаёт весь registry object в `Data`.

В просмотренном архиве не найден вызов `listCredentials`, `generateCredentials` или `tokenPasswords`. Поэтому **получение token password этим конкретным путём не доказано**; виден GET token-resource data. Но ответ сохраняется без field projection/redaction, поэтому его метаданные нужно считать чувствительными и не пересылать наружу. Допуск возможен только после узкого allowlist конкретного GET и проверки схемы ответа/выходного DTO.

### 2.3 Egress логов и HTML-отчёта

| Триггер | Что делает код | Статус / ограничение |
|---|---|---|
| Slack/Teams logger | `Write-Slack.ps1` и `Write-Teams.ps1` отправляют `POST` на `Configuration.webHook`; `Get-FormattedMessage.ps1` форматирует `MessageData`/исключение/строку без редактирования. Валидатор webhook проверяет только наличие свойства, а не допустимый hostname. | **Условный egress**: в default `monkey365.config` внешнего webhook нет — `logging.default`/`logging.loggers` настроены на локальные file loggers. При добавлении Slack/Teams URL наружу уйдёт содержимое лог-записей. Не включать до destination allowlist и redaction. |
| HTML export | При `ExportTo HTML` дефолт `htmlReportFromCDN=true`, `assets.useLatestTag=true`, repo указывает на `silverhack/monkey365assets`. `Initialize-MonkeyHtml.ps1` получает latest tag/config через GitHub API и `cdn.jsdelivr.net`; `New-HTMLNavBar` вызывает GitHub API для данных repo и latest release. | **Egress по умолчанию для HTML-ветки**, не для JSON/CSV-only. Прямой upload findings на GitHub/jsDelivr в коде не найден; запросы раскрывают как минимум сетевой адрес/UA/время, а страница отчёта загружает удалённые ресурсы. Remote JS в контексте HTML-отчёта — отдельная supply-chain граница, так как скрипт страницы может читать DOM с findings. Для offline/анонимного режима — локальные pinned assets, отключённый CDN и блок внешнего egress. |
| Локальный HTML asset downloader | При `localHtmlReport.enabled=true` используется `Update-MonkeyAsset` с GitHub release/assets. | В конфигурации по умолчанию `localHtmlReport.enabled=false`; функция всё равно требует отдельного egress review, если будет включена. |
| Azure Storage SAS | При Storage collector SAS передаётся storage endpoint как query parameter; на non-success verbose path логирует полный request URL. | Условен выбором Storage collector и включённым логированием; возможен секрет в локальном/внешнем журнале. |

В проверенном logger/export пути не найден универсальный redaction-механизм. Точный риск лог-записи зависит от `WriteLog`/verbose-настроек и списка logger-конфигурации; штатный конфиг не содержит Slack/Teams webhook.

### 2.4 Сериализация и чувствительные поля

- `New-O365ExportObject.ps1` формирует `Output=$dataset`; для Azure добавляет также `$O365Object.all_resources`.
- При `-SaveProject` `Out-MonkeyData.ps1` передаёт полный `$MonkeyExportObject` в `Out-Gzip` и сохраняет его в `MonkeyJob/MonkeyOutput`; перед этой операцией общего field scrubber в просмотренной цепочке нет. Это raw, tenant-specific материал — хранить локально/ограниченно и не прикладывать к чату/модели/внешнему сервису.
- Обычный JSON/CSV/CLIXML/HTML export строится из `$matchedRules`, а не из всего raw object, но содержит findings/evidence и тоже требует локальной защиты. В проверенной цепочке `Export-MonkeyData` → `Invoke-MonkeyOutput` общего secret-redaction этапа не обнаружено.
- В Storage DTO извлечённый key и SAS намеренно не добавляются, но возможна утечка SAS в verbose log при HTTP ошибке. ACR `tokens`-объект, напротив, прикрепляется без фильтрации.

Это вывод только по указанным Storage/ACR/Logger/export путям, не утверждение о полном обзоре всех полей 100+ collectors.

### 2.5 Power BI polling и timeout

- `Invoke-MonkeyScanner.ps1` объявляет `Timeout=30`, но `Initialize-MonkeyScan.ps1` не принимает Timeout, а вызов `Invoke-MonkeyJob` в scanner не передаёт его. Параметр scanner не задаёт 30-секундный deadline.
- `Invoke-MonkeyJob.ps1` использует timeout по умолчанию 10 секунд как интервал ожидания (`Task.WaitAll(..., $Timeout)`); `Watch-MonkeyJob.ps1` после каждого интервала продолжает ждать, пока задачи не завершатся. `Invoke-MonkeyJob` также продолжает цикл, пока job остаётся Running. Это не hard deadline и не cancellation.
- `Invoke-MonkeyPowerBIScan.ps1` опрашивает статус с `Start-Sleep -Seconds 3` и продолжает, пока статус не равен `Succeeded`; длительность не ограничена, отдельного выхода по `Failed` в этом условии нет. Поэтому зависший `Running`/`Failed` может удерживать collector; внутренний wait-timeout его не прекращает.

**Решение для профиля:** не подключать как unattended collector до добавления абсолютного deadline, отмены/остановки дочерних jobs/runspaces и обработки `Failed`/таймаутов с тестом зависшего коллектора.

## 3. Сверка источников и кандидатов

- `/home/user/ASM-research/SOURCES_WORKING.csv`: **135 строк, 135 уникальных URL**, 132 внешних и 3 внутренних; все 135 датированы `2026-10-05`. В этом списке 15 вторичных материалов (видео/форумы/Reddit/статья/доклад), они являются контекстом, не source-code proof.
- `/home/user/ASM-research/CHALLENGE_SOURCES_2026-10-05.csv`: **34 дополнительных URL**, в основных 135 не дублируются. Итого в двух реестрах **169 строк и 169 уникальных URL**. Challenge-pass остаётся отдельным реестром.
- 135 источников — первичный обзор документов/репозиториев/релизов/лицензий; это не означает, что все 135 проектов прошли полный source/dependency/egress audit. В основном реестре 26 строк прямо помечают более глубокий source/code audit как deferred.
- `download_manifest.json` теперь содержит **12 записей: 9 сохранённых полных архивов и 3 ограниченных/неполных загрузки** (Maester, Prowler, ZAP); их source slices остаются в соответствующих manifests. SHA архивов — локальная целостность, не upstream signature.

## 4. Сверка полки 225 GB

`/home/user/asm/data/tool_shelf_225gb.json` остаётся **scope-инвентарём, не install manifest** и не разрешением на запуск. После сверки в нём явно записаны unresolved Wordlust и повторные ссылки на один и тот же физический артефакт:

- Структура манифеста: 19 core движков; ProjectDiscovery union 23 CLI (7 existing + 16 extra, плюс отдельный templates data item); внутренний AD/Linux arsenal 17 entries; research-candidates 19 entries; lab/runtime 10; models/wordlists 10 entries плюс unresolved Wordlust. `NetExec` повторно указан в research, но уже помечен reuse;

- **Wordlust:** упомянут в `ПЛАН.md §3.5`, но отсутствовал в прежнем tool-shelf manifest. Upstream repository page показывает только `LICENSE` и `README.md`, без tags/releases и файла wordlist; README называет целевой размер будущего файла около **50 GB**, не размер опубликованного asset, и описывает составление из leaked/cracked password lists. Следовательно, конкретного закреплённого файла, версии, фактического размера, checksum и полной lineage/license для итогового набора сейчас нет. Позиция **не исключена**, но записана как unresolved; в смету 141 GB не включена. Если появится одобренный файл порядка 50 GB, резерв 84 GB снизится примерно до 34 GB до учёта необмеренных Windows/VM/Docker/candidate assets. Источник: [frizb/Wordlust](https://github.com/frizb/Wordlust).
- **Двойные ссылки в scope:** BloodHound CE повторяется как внутренний AD-артефакт и контейнеры в lab/runtime; Greenbone CE повторяется как исследовательский кандидат и lab images/feeds; NetExec уже помечен как reuse. В manifest добавлены `same_artifact_as`/`count_once` для первых двух, чтобы не удваивать физический размер.
- **Оценка:** базовые известные ориентиры суммируются примерно в **141 GB**; optional CrackStation — ещё **4.2 GB**, не входит в base subtotal; расчётный остаток — **84 GB**. Это не измерение установленного набора и не доказательство fit. Полные версии/assets/hash/размеры для 16 дополнительных ProjectDiscovery CLI, cloud/AD кандидатов и dependencies, Windows media и фактических VM/Docker volumes не закреплены/не замерены.
- Scope ProjectDiscovery сохраняет объединение двух официальных каталогов: **23 CLI** (7 уже есть в ASM + 16 дополнительных). Это согласованный scope-перечень на дату обзора, не доказательство, что перечислены все существующие upstream repos/releases.
- `weakpass_2a` (~90 GB) остаётся явно исключённым, не скачивался и не добавлен в смету. CrackStation остаётся необязательным.
- Workspace не имеет доступа к пользовательскому Windows-диску. Поэтому физическое наличие файлов, фактический объём, свободное место и полный 225 GB preflight здесь **не проверены**. `bin/check_shelf.py` предназначен для локального read-only измерения с дополнительными `--root` для внешних VM/Docker storage; его запуск в Linux sandbox не был бы проверкой Windows-хоста.

## 5. Что сделано и что не сделано

Сделано: локальный архив Monkey365 зарегистрирован; выполнен targeted static review Storage/listKeys/SAS, ACR `/tokens`, log/webhook/HTML egress, export redaction и Power BI timeout; подтверждены количества source registries и отмечены незакрытые size/artifact gaps полки.

Не сделано: полный source audit всех Monkey365 collectors и всех 169 материалов; скачивание остальных 225 GB shelf items; установка/распаковка кандидатов или зависимостей; проверка Windows-хоста; запуск Monkey365 или tenant/API-запросы. До отдельного аудита/разрешения Monkey365 остаётся **static-shelf only**.
