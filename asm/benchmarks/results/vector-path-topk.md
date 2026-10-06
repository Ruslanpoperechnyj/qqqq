# ASM vector path — bounded top-k (этап 3.4)

**Дата:** 05.10.2026  
**Реализация:** `asm/vector.py::_search_candidates()`  
**Raw benchmark:** `vector-path-topk.json`  
**Сравнение:** этап 3.3, `vector-path-single-read.json`

## Что изменено

Для `0 < k < N` scorer больше не создаёт список из `N` готовых result-dict перед тем, как вернуть первые `k`. Он потоково оценивает каждый finding и держит bounded min-heap из не более `k` элементов. Итоговый heap сортируется в прежнем порядке по округлённому score; входная позиция задаёт стабильный порядок при равных score. Если встречается NaN, heap не используется для неопределённого сравнения: выполняется прежний полный stable sort. Для `k <= 0` и `k >= N` остаётся полный путь.

Score, отображаемые поля, cross-target corpus и `target_id` filter не менялись. `TestVectorSearch` / `TestCrossScanMemory` продолжают проверять ranking, поиск между targets и явный target filter; добавлен regression test на tie order и NaN fallback.

## Профиль и временные аллокации

До оптимизации на синтетических 100k findings cProfile для `search_all()` показал 6.998 s под profiler; `_search_candidates()` занял 4.827 s cumulative и 0.592 s self-time, `_all_findings()` — 2.101 s, `_vectors_cached()` — 1.655 s, `json_dumps()` — 1.334 s. Это instrumented Linux profile, а не latency benchmark; он указывает, что полный sort не был единственным и очевидным CPU-hotspot. Top-k выбран прежде всего для сокращения временной памяти, без основания вводить ANN.

Scorer-only `tracemalloc` на 100k — corpus и vector map подготовлены до начала трассировки — измерил peak временных Python allocations **49.21 MiB до** и **0.01 MiB после** bounded heap. Это около 49.20 MiB меньше аллокаций внутри scorer. Это `tracemalloc` peak Python allocations, а не process RSS и не полный footprint findings/vector map.

## Benchmark после изменения

Linux x86_64, Python 3.13.14, SQLite 3.46.1; отдельная временная БД на размер, детерминированные synthetic 16D-вектора, один warm-up и три timed observations. p95 — nearest-rank по трём наблюдениям, только ориентир. Время в миллисекундах; RSS — joint high-water delta последовательности `search_all()` + `notes_for_scan()`, не scorer-only.

| Findings | `search_all()` p50 / p95 | `notes_for_scan(limit=4)` p50 / p95 | Joint RSS delta |
|---:|---:|---:|---:|
| 1,000 | 29.967 / 30.241 | 73.314 / 73.332 | 4.12 MiB |
| 10,000 | 347.585 / 349.610 | 840.204 / 847.644 | 38.49 MiB |
| 100,000 | 3,861.070 / 3,893.968 | 7,996.937 / 8,312.722 | 405.87 MiB |

На 100k против этапа 3.3 p50 стал ниже на **3.3%** у `search_all()` и **12.4%** у `notes_for_scan()`. Это направление замера по трём повторам, не доказательство причинного ускорения heap. Joint RSS практически не изменился: **405.92 → 405.87 MiB**; benchmark high-water включает corpus/vector map и не изолирует память scorer. Поэтому вывод о снижении process RSS не делается.

Упорядоченные result signatures `search_all()` и `notes_for_scan()` совпали **точно** с этапом 3.3 для 1k/10k/100k; они также совпали с этапом 3.1 baseline. `read_stored()` остаётся один раз на каждый измеренный путь. Сырые подписи, counters и environment записаны в `vector-path-topk.json`.

## Проверки и ограничения

- Целевые vector/cross-target тесты после изменения: **22/22**.
- Полный `unittest discover`: **545/545**, **0 `ResourceWarning`**.
- Проверка с унаследованной sentinel SQLite-БД: SHA256 до/после совпал; временные каталоги suite удалены.
- `python3 -m py_compile asm/vector.py tests/test_core.py`: OK.
- Размерность benchmark — 16D и среда — Linux sandbox; Windows, production corpus и штатные 384D vectors не проверены.
- Top-k ограничивает result-list allocations; чтение/материализация всего корпуса и точный scoring остаются O(N). Измерения не обосновывают ANN.
