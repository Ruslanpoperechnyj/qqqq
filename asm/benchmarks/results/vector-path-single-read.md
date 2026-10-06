# Этап 3.3 — убрать повторную десериализацию vector index

**Дата:** 05.10.2026  
**Файлы:** `asm/vector.py`, `tests/test_core.py`. `search_all()`/`similar()` ranking и схема хранилища не менялись.

## Изменение

`_vectors_cached()` раньше вызывал `_read_stored()` до `_ensure_tables()` (чтобы узнать dimension), затем читал все stored vectors ещё раз после подготовки таблицы. Теперь `_stored_dimension()` получает размерность одной строки через `LIMIT 1` — для fallback из `sem.dim`, для `sqlite-vec` из размера `embedding` blob. Затем `_ensure_tables()` может создать/пересоздать таблицу, и **после этого** один раз выполняется полный `_read_stored()`.

Если таблица пуста/несовместима, dimension по-прежнему запрашивается у текущего embedder; при переиндексации после `COMMIT` остаётся отдельное чтение для получения фактически записанных float32-векторов. Устранённый duplicate pass относится к обычному warm-cache запросу.

Добавлен тест: повторный тёплый `_vectors_cached()` возвращает тот же mapping и вызывает полный `_read_stored()` ровно один раз. Fallback table recreation, обновление изменённой находки, golden ranking и batch-vs-individual tests оставлены активными.

## Benchmark

Сравнение — с post-stage-3.2 JSON `vector-path-notes-batch.json`; одинаковый сценарий на synthetic corpus 1k/10k/100k, Python 3.13.14, SQLite 3.46.1, Linux sandbox, размерность 16, прогрев + 3 warm измерения. Все упорядоченные signatures `search_all()` и `notes_for_scan()` точно совпали с предыдущим результатом.

| Findings | `search_all()` p50 / p95, ms | `notes_for_scan(limit=4)` p50 / p95, ms | RSS delta обоих путей |
|---:|---:|---:|---:|
| 1,000 | 34.459 / 38.009 | 81.354 / 82.155 | 4.19 MiB |
| 10,000 | 382.246 / 445.224 | 886.707 / 903.580 | 38.77 MiB |
| 100,000 | 3,993.456 / 4,049.545 | 9,128.750 / 9,201.408 | 405.92 MiB |

Относительно stage 3.2 на 100k p50 улучшился в **1.10×** для прямого `search_all()` и **1.04×** для `notes_for_scan()`. Полное чтение vector index в одном warm вызове сократилось с 2N до N строк. Совместный RSS peak delta снизился с 487.04 до 405.92 MiB (−81.12 MiB, около 16.6%). Относительно исходного stage 3.1 baseline RSS 486.66 MiB — снижение около **16.6%**.

`notes_for_scan()` в целом ускорен с исходных 48.347 s до 9.129 s p50 (около **5.30×**). Прямой `search_all()` с 4.336 до 3.993 s — около **1.09×**.

## Проверки и ограничения

- `TestVectorSearch` + `TestCrossScanMemory`, в обратном порядке классов, прошли 21/21; warm vector map читает полную таблицу один раз.
- Счётчики benchmark: `search_all()` и batch `notes_for_scan()` — один full stored-vector read на тёплый path; exact result signatures неизменны.
- Benchmark использует synthetic deterministic 16D-векторы и измеряет совместный RSS прогон двух путей. Это не прогноз памяти для 384D/локальной модели; p95 из трёх повторов ориентировочный. Windows/production не проверялись.
- JSON с результатами: `benchmarks/results/vector-path-single-read.json`; предыдущая точка сравнения сохранена в `vector-path-notes-batch.json`.

**Следующий пункт:** проверить стоимость полного scoring и сортировки всех N результатов в `_search_candidates()`. Выбирать top-k/streaming только при exact ties/order comparison на golden corpus; не менять семантику cross-target и `target_id` фильтра.
