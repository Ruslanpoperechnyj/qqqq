# Challenge-pass: добавочные кандидаты и перепроверка сильных финалистов

**Дата среза:** 2026-10-05.  
**Область:** локальные бесплатные инструменты для Entra/M365, Azure, AWS, GCP и internet ASM; без SaaS-платформ сканирования.  
**Статус:** обзор первичных страниц, release notes, лицензий и документации. Это не source-level аудит новых кандидатов и не разрешение на установку, tenant consent, выдачу ролей или запуск.

## Короткий вывод

Наиболее содержательные challengers к уже проверяемому набору:

1. **Monkey365** — самый прямой кандидат на усиление Entra/M365/Azure posture: новый стабильный `v1.0.0` (25 сентября 2026), отдельный набор из 100+ Entra checks, Apache-2.0, PowerShell-модуль позиционируется как self-contained. Автор заявляет, что инструмент читает настройки и не исправляет/не меняет cloud resources; это надо проверить по collectors, auth flow, сетевым вызовам и outputs.
2. **Steampipe + Powerpipe** — сильнейший локальный «конструктор» межоблачных read-only запросов и benchmark-дашбордов для AWS/Azure/GCP. Это не готовый сканер: пригодность зависит от точного allowlist provider plugins и конкретных Powerpipe mods/queries. Никаких Flowpipe-автоматизаций, произвольного `exec`-plugin или Turbot Pipes SaaS.
3. **Cartography** — сильный слой связей/графа для AWS, Azure, GCP и Entra, а не замена CSPM. `v0.141.0` выпущен 1 сентября, Apache-2.0; результаты записываются в Neo4j, поэтому только отдельная локальная база. В поддерживаемом наборе есть Secret Manager/Key Vault/Secrets Manager resource-модели; пока не проверено, исключаются ли значения секретов и как сериализуются чувствительные поля.
4. **ScubaGear** — лучший отдельный CISA-baseline challenger для M365, но не безусловно read-only по минимальным permissions: SharePoint требует `Sites.FullControl.All`, Power Platform — предварительную регистрацию service principal, Power BI — изменение tenant setting. Ограничивать продуктовый scope; не запускать setup/consent helpers.
5. **CloudSplaining** — активный upstream Salesforce, `0.9.1` (14 июня 2026) плюс свежие изменения в upstream; хорош как локальный анализ уже экспортированных AWS IAM policy JSON. В offline-file режиме можно не опрашивать аккаунт. Репозиторный LICENSE — BSD-3-Clause, а метаданные PyPI объявляют MIT: до юридической сверки считать каноничным LICENSE репозитория и зафиксировать расхождение.

**Не ставить в безопасный профиль сейчас:** CloudFox намеренно перечисляет секреты/содержимое переменных и сохраняет loot; BBOT даёт много новой внешней разведки, но пересекается с установленным набором ASM и требует по-модульного исключения активных/нежелательных действий. **Checkov** может дать добавку за счёт graph-based IaC checks, но `Trivy config` уже присутствует: условная опция для Terraform/IaC-heavy scope, не первый приоритет.

## Сопоставление с текущей ASM

В `STATUS_2026-10-05.md` подтверждено, что текущий ASM уже содержит `subfinder`, `amass`, `dnsx`, `naabu`, `httpx`, `tlsx`, `katana`, `nuclei`, `nmap` и другие сетевые движки; Trivy уже сканирует IaC-конфигурации. Prowler, Maester и AzureHound также уже проходили обзор/частичный source review. Поэтому новые кандидаты оцениваются по **добавочной**, а не номинальной широте:

| Измерение | Самый сильный challenger | Добавка | Предварительная оценка |
|---|---|---|---|
| Entra/M365/Azure posture | Monkey365; отдельно ScubaGear | Много готовых Microsoft checks/rulesets; CISA baseline mapping | Высокий приоритет source review; права, телеметрия, network egress и состав отчёта ещё не проверены |
| AWS/Azure/GCP custom checks | Steampipe + Powerpipe | SQL по live API и наборы compliance/security benchmark controls | Высокая гибкость, но это framework; каждую таблицу, plugin и mod надо разрешать отдельно |
| Cloud identity/asset relationships | Cartography | Единый локальный graph для нескольких провайдеров и Entra | Высокая уникальная добавка; нужен audit read permissions, секрет-содержащих полей, egress и DB writes |
| AWS IAM policy privileges | CloudSplaining | Least-privilege, risk categories и escalation-path review на policy JSON | Небольшой безопасный статический профиль возможен; только AWS и только локальные файлы до аудита |
| Internet ASM | BBOT | Широкая рекурсивная разведка, OSINT и event/module pipeline | Сильный самостоятельный инструмент, но большая функциональная и operational-overlap с текущими 19 engines |
| IaC | Checkov | Более глубокий набор Terraform graph checks | Дополнять только если реально важны cross-resource IaC rules; остальное частично перекрывается Trivy |
| Cloud attack-path enum | CloudFox | Очень практичная карта действий/доступов в AWS/GCP и частично Azure | Функционально силён, но не проходит текущий барьер secret handling/loot; не включать как есть |

## Кандидаты и ограничения

### Monkey365 — высокий приоритет

- Upstream: `silverhack/monkey365`; стабильный релиз `v1.0.0` от 2026-09-25, в release notes заявлены 100+ проверок Entra по app registrations, Conditional Access, enterprise apps, ролям и identity security. Последний видимый commit на 2026-09-28.
- Лицензия: Apache-2.0. Официальный README говорит, что runtime dependencies bundled и инструмент не требует Azure CLI/Az/Graph PowerShell SDK; заявлены M365, Entra ID и Azure, с HTML/JSON/CSV отчётами.
- Автор пишет, что Monkey365 читает configuration data и не исправляет/не меняет облачные ресурсы. Это заявление, а не source-level доказательство. Поддерживаются delegated и app-only auth; permissions зависят от workload. Итоговый отчёт содержит evidence и должен считаться чувствительным.
- **Следующий аудит:** закрепить commit/tag; проверить каждый разрешаемый collector и его HTTP method/API scopes, setup/consent helper, update/version/network telemetry, сериализуемые поля, локальные файлы и все egress destinations. Не устанавливать через Gallery и не подключать tenant до этого.

Источники: [upstream](https://github.com/silverhack/monkey365), [release v1.0.0](https://github.com/silverhack/monkey365/releases/tag/v1.0.0), [LICENSE](https://github.com/silverhack/monkey365/blob/main/LICENSE), [permissions docs](https://silverhack.github.io/monkey365/getting_started/permissions/).

### ScubaGear — высокий, но условный приоритет

- Официальный CISA-инструмент для оценки Microsoft 365 по SCuBA baselines; покрывает Entra, Security Suite, Exchange, Power BI, Power Platform, SharePoint и Teams. Релиз `v1.8.0` — 2026-05-07; основной репозиторий активен (видимый commit — 2026-10-02). Лицензия CC0.
- Non-interactive permission table — минимальный набор «чтобы читать конфигурацию», но содержит write-named privileges для SharePoint (`Sites.FullControl.All`) и Power Platform из-за ограничений underlying APIs; авторы утверждают, что ScubaGear их не использует. Это не соответствует строгому фильтру «только read-only» без отдельного исключения и разрешения.
- Для Power Platform нужна одноразовая регистрация service principal интерактивной admin-командой; для Power BI надо включить read-only Admin API setting в Power BI Admin portal. Оба — изменения конфигурации tenant. Не выполнять automated/manual setup, consent и role-grant helpers.
- **Следующий аудит:** source-level пройти только конкретные разрешаемые product modules, REST/Graph вызовы, dependency/update path и outputs. Поддержка части M365 не означает автоматически допустимость полного `Invoke-SCuBA`.

Источники: [upstream](https://github.com/cisagov/ScubaGear), [release v1.8.0](https://github.com/cisagov/ScubaGear/releases/tag/v1.8.0), [noninteractive permissions](https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md), [license](https://github.com/cisagov/ScubaGear/blob/main/LICENSE).

### Cartography — высокий приоритет для отдельного локального graph-layer

- Upstream `cartography-cncf/cartography`; последний проверенный release `0.141.0` от 2026-09-01, latest visible repo commit 2026-10-02. Apache-2.0.
- Официальное описание: сбор инфраструктурных assets и relationships в Neo4j; текущий каталог перечисляет AWS, Azure, GCP и Microsoft Entra, а также много не-cloud-платформ. Это не compliance scanner. В качестве результата потенциально создаётся чувствительная карта идентификаторов, ресурсов, связей и доступов.
- Поддерживаемые модули включают AWS Secrets Manager/Secret Versions, GCP Secret Manager и Azure Key Vault. В `cartography/data/permission_relationships.yaml` AWS `secretsmanager:GetSecretValue` отображается как связь `GET_SECRET`: это графирование **права principals читать секрет**, а не доказательство, что ingest получает payload. Точные API calls и сериализуемые поля самих Secret resources всё ещё нужно проверить. Graph sync пишет в базу: отдельная локальная Neo4j instance/DB, никогда не подключать client/prod graph и не делать reset/drop базы.
- **Следующий аудит:** сформировать жёсткий provider/module allowlist; проверить role scopes и SDK calls по AWS/Azure/GCP/Entra, secret-value endpoints/fields, локальные DB mutations, downloads/update/version checks и egress. Не разворачивать Neo4j и не импортировать реальные данные в ходе этого исследования.

Источники: [upstream](https://github.com/cartography-cncf/cartography), [release 0.141.0](https://github.com/cartography-cncf/cartography/releases/tag/0.141.0), [PyPI metadata](https://pypi.org/project/cartography/0.141.0/), [permission relationship map](https://github.com/cartography-cncf/cartography/blob/master/cartography/data/permission_relationships.yaml).

### Steampipe + Powerpipe — высокий потенциал, не turnkey scanner

- На срезе последних релизов: Steampipe `v2.4.7` и Powerpipe `v1.5.5`, оба от 2026-09-16. Лицензии обоих — AGPL-3.0. Powerpipe предназначен для dashboards и security/compliance benchmarks; доступны локальные benchmarks для AWS, Azure, GCP и других sources.
- Steampipe делает live API calls и по умолчанию держит результаты в ephemeral tables/caches пять минут; сам по себе заявлен как read-only SQL interface, без SQL write operations. Результаты можно экспортировать в CSV/JSON, а значит локальные exports всё равно чувствительны. Официальная FAQ подтверждает WSL 2.0 support.
- «Локальный» не означает «невидимый»: Graph/API requests видны Microsoft/AWS/GCP и оставляют audit events. Экосистема содержит plugins не только для облака, но и для arbitrary `exec`; Flowpipe может действовать на результаты, а Turbot Pipes — отдельный hosted service. Эти расширения и SaaS не входят в безопасную опцию.
- **Следующий аудит:** сначала выбрать и зафиксировать конкретные official AWS/Azure/GCP provider plugins, их versions и Powerpipe mods; проверить source tables/query API calls, plugin install/update egress, cache/export paths и локальный bind/service exposure. Исключить `exec`, mutating workflows, Flowpipe и Turbot Pipes.

Источники: [Steampipe FAQ](https://steampipe.io/docs/faq/overview), [Powerpipe docs](https://steampipe.io/docs/pipes-ecosystem/powerpipe), [Steampipe releases](https://github.com/turbot/steampipe/releases), [Powerpipe releases](https://github.com/turbot/powerpipe/releases), [Steampipe LICENSE](https://github.com/turbot/steampipe/blob/main/LICENSE), [Powerpipe LICENSE](https://github.com/turbot/powerpipe/blob/develop/LICENSE).

### CloudSplaining — отдельный AWS IAM-файловый анализатор

- Важно: upstream — **Salesforce**, не `devops-made-easy` fork. Официальный upstream выпустил `0.9.1` 2026-06-14; в репозитории есть более поздняя активность (commit виден 2026-10-03). Fork `devops-made-easy` не обновлялся с 2021 года — не брать его как источник.
- PyPI описывает инструмент как AWS IAM least-privilege analyzer с risk-prioritized HTML report; поддерживается анализ отдельного policy file, а не только live account inventory. Наиболее безопасный потенциальный режим для этой задачи — локально переданный уже собранный JSON без AWS credentials; это ещё не проверено в исходниках.
- **License mismatch:** PyPI metadata и upstream `pyproject.toml` указывают `MIT`, но upstream `LICENSE` содержит `BSD 3-Clause`. До официального разрешения расхождения учитывать более конкретный LICENSE-файл и вести неоднозначность в ведомости лицензий.
- **Следующий аудит:** подтвердить exact CLI path для offline file; убедиться в отсутствии обязательного network lookup/telemetry; проверить, какие policy/principal/ARN данные уходят в HTML/JSON output и зависимости. Не выбирать режим live account enumeration без permissions review.

Источники: [PyPI](https://pypi.org/project/cloudsplaining/), [upstream](https://github.com/salesforce/cloudsplaining), [release 0.9.1](https://github.com/salesforce/cloudsplaining/releases/tag/0.9.1), [upstream LICENSE](https://github.com/salesforce/cloudsplaining/blob/master/LICENSE), [stale fork](https://github.com/devops-made-easy/cloudsplaining).

### CloudFox — функционально сильный, по умолчанию отложить

- MIT, последняя проверенная версия `v2.0.5` (2026-05-26). Upstream ориентирован на situational awareness/attack-path discovery. Официальные материалы расходятся по support matrix/зрелости облаков; AWS выглядит наиболее зрелым, конкретный GCP/Azure scope надо проверять по версии и командам.
- Официальный README/wiki прямо описывают вывод секретов из EC2 user-data/service environment variables, AWS `secrets` command по Secrets Manager/SSM и loot-файлы с чувствительными stack parameters, connection strings и follow-up commands. То, что cloud principal может быть read-only, не предотвращает чтение или локальную запись секрет-содержащих данных.
- При текущем запрете на неконтролируемый доступ к секретам не допускать `all-checks` и `secrets`/`env-vars`/secret-bearing commands в профиль. Не скачивать/не запускать. Даже отдельный allowlisted набор потребовал бы source audit, доказательства sanitizer и письменного обоснования.

Источники: [upstream README](https://github.com/BishopFox/cloudfox), [official wiki](https://github.com/BishopFox/cloudfox/wiki), [releases](https://github.com/BishopFox/cloudfox/releases), [MIT license](https://github.com/BishopFox/cloudfox/blob/main/LICENSE).

### BBOT — сильный для internet ASM, но не первой очереди

- `v3.0.2` опубликован 2026-08-24; PyPI license expression — AGPL-3.0. Модульный recursive scanner, сильный как единый framework, но часть функций уже перекрывается набором `subfinder/amass/dnsx/httpx/nuclei/katana/nmap` и другими текущими движками.
- Наличие множества OSINT/scanning modules означает потенциальные внешние обращения и active probes; отдельные output modules умеют отправлять данные во внешние системы. «Поставить весь профиль» не подходит под scope/egress/anonymity ограничения. Обоснованно рассматривать только curated module allowlist, если сравнительное покрытие покажет существенный пробел.
- **Следующий шаг:** не включать в первый source-audit batch; при необходимости сравнить по точно выбранным passive modules, egress endpoints, active probes и output modules.

Источники: [upstream](https://github.com/blacklanternsecurity/bbot), [PyPI 3.0.2](https://pypi.org/project/bbot/), [release history](https://github.com/blacklanternsecurity/bbot/releases).

### Checkov — опция только для IaC-depth

- `3.3.21` выпущен 2026-09-30; Apache-2.0. Особенно интересны graph-based cross-resource IaC checks. Это может дать больше глубины по Terraform/CloudFormation связям, чем отдельная проверка ресурса.
- Текущая ASM уже использует Trivy для IaC/config, поэтому считать Checkov доказанно лучшим/нужным нельзя без сравнительного rule coverage. Если появится в shortlist — только локальные static IaC checks; не включать live credential/API validation, SaaS и secret verification до отдельного аудита.

Источники: [release 3.3.21](https://github.com/bridgecrewio/checkov/releases/tag/3.3.21), [PyPI/license](https://pypi.org/project/checkov/), [Palo Alto graph policy overview](https://www.paloaltonetworks.com/blog/cloud-security/checkov-upgrade-iac-security/).

## Предлагаемый порядок source-review

1. **Monkey365** — exact Microsoft scopes, collectors, network/telemetry, secret-adjacent output.
2. **Steampipe + Powerpipe** — только выбранные AWS/Azure/GCP plugins и один benchmark mod на старте; permissions/API methods, local cache/export и egress.
3. **Cartography** — provider/module-by-module permissions, secret payload/value handling, local Neo4j writes и data egress.
4. **ScubaGear** — product-by-product, без registration/consent/role-setting helpers; сверить фактические calls с таблицей permission.
5. **CloudSplaining** — только offline JSON mode; проверить сетевые обращения/HTML report/metadata.

Это очередь **исследования исходников**, не очередь установки или выполнения. Любые cloud API calls, даже read-only, будут отдельным операторским решением и создают следы на стороне провайдера.
