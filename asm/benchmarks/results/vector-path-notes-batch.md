# Этап 3.2 — пакетное переиспользование vector memory в `notes_for_scan()`

**Дата:** 05.10.2026  
**Код:** `asm/vector.py`; исходный контракт ранжирования сохранён. Полный diff не заменяет benchmark: ниже приведено сравнение с зафиксированным baseline этапа 3.1.

## Изменение

- Вынесен общий точный scorer `_search_candidates()`. `search_all()` продолжает выбирать тот же корпус и вызывает его один раз.
- `notes_for_scan()` теперь выбирает findings текущего scan, загружает cross-scan candidates один раз и строит vector map один раз, затем выполняет запросы для каждой подсказки поверх одного snapshot.
- Substring scoring сохранён, но сериализованный JSON finding теперь вычисляется **один раз на finding/query**, а не повторно для каждого слова запроса. Общий кэш строк не удерживается между queries, чтобы не увеличивать peak RAM.
- Выделен `_annotate_similar()`; `similar()` и batch notes используют одну и ту же логику пометки совпадений CVE/продукта.
- Cross-target поиск и явный `target_id` в `search_all()` не сужались.

## Результаты — baseline → после

Оба прогона: Linux sandbox, Python 3.13.14, SQLite 3.46.1, synthetic 16D vectors, отдельная temp-БД на размер, один warm-up + 3 замера. p50 — median; p95 — nearest-rank (при трёх наблюдениях равен максимуму выборки).

| Findings | `notes_for_scan()` p50 baseline → after | p50 speedup | p95 baseline → after | Совместный RSS peak delta baseline → after |
|---:|---:|---:|---:|---:|
| 1,000 | 525.009 → 100.743 ms | **5.21×** | 563.352 → 102.554 ms (**5.49×**) | 5.20 → 5.17 MiB |
| 10,000 | 4,632.314 → 974.854 ms | **4.75×** | 4,842.147 → 989.550 ms (**4.89×**) | 46.50 → 46.29 MiB |
| 100,000 | 48,347.058 → 9,537.393 ms | **5.07×** | 48,467.306 → 9,781.703 ms (**4.95×**) | 486.66 → 487.04 MiB |

Для прямого `search_all()` существенного изменения latency не видно: при 100k p50 — 4,335.874 → 4,405.524 ms (0.98× относительно baseline; шум трёх прогонов). Основной выигрыш относится к `notes_for_scan()`.

На 100k на один `notes_for_scan(limit=4)`:

| Счётчик | Baseline | После |
|---|---:|---:|
| Полных `_all_findings()` вызовов / прочитанных rows | 4 / 400,000 | 1 / 100,000 |
| `_vectors_cached()` вызовов | 4 | 1 |
| Полных `_read_stored()` вызовов | 8 | 2 |
| Декодированных vector rows | 800,000 (8N) | 200,000 (2N) |
| Candidate IDs, переданных кэшу | 396,000 | 99,000 |

Профиль `cProfile` на 10k в промежуточной версии после batch-reuse, но до устранения повторной JSON-сериализации, показал 475,200 `json_dumps()` вызовов и 7.872 s под профайлером. После переноса сериализации за цикл слов — 39,600 вызовов и 1.760 s. Это диагностический профилированный результат, не latency из таблицы; снижение вызовов — 12×.

## Проверки поведения и изоляции

- Для `search_all()` и `notes_for_scan()` упорядоченные signatures `(score, finding_id/client/status…)` точно совпали с сохранённым baseline на 1k/10k/100k.
- Fixed golden ranking, full reference ranking, batch-vs-individual `similar()` output и счётчики corpus/vector/JSON проходов — целевые проверки прошли.
- `TestVectorSearch` и `TestCrossScanMemory` были запущены подряд в обратном обычному порядке. Это выявило, что fallback regression test оставлял в общей test DB временную строку `sem(scan_id=NULL)`, из-за чего последующий `index_all()` падал на `int(None)`. Теперь fixture удаляет именно свою sentinel-строку в `finally`; обратный порядок прошёл **20/20**.
- Полный suite после изменений: **543/543**, **0 `ResourceWarning`**; inherited sentinel SQLite-БД не изменилась, временные каталоги suite удалены.

## Ограничения и следующий шаг

16D — безопасная компактная synthetic размерность, не профиль штатных 384D vectors или модели. RSS — high-water delta совместного worker-прогона `search_all()` затем `notes_for_scan()`, а не отдельный peak каждой функции. Три повтора дают только ориентировочную p95. Windows и production workload не проверялись.

`search_all()`/`similar()` всё ещё материализуют полный корпус и `_vectors_cached()` всё ещё декодирует vector index дважды на один запрос. Следующий небольшой пункт — устранить повторное чтение в single-query path, сохранив точный ranking, cross-target results и `target_id` filter.

Артефакты сравнения: `vector-path-baseline.json` — исходный baseline; `vector-path-notes-batch.json` — текущий post-change прогон.
