# SQLite batch-write benchmark: baseline vs batched

**Date:** 2026-10-05  
**Runtime:** Python 3.13.14, SQLite 3.46.1, Linux x86_64 sandbox; FTS5 available.  
**Method:** 3 independent runs for each size, each on a fresh temporary SQLite file. Synthetic `.invalid` data only; no network, scanner, or production database. Payload construction, schema setup, and target/scan creation are outside the timer; JSON conversion, inserts, and FTS row writes are inside. The FTS table is pre-created so this compares recurring save calls. Every resulting row count was checked. p50 is the median of 3 samples; p95 is nearest-rank and therefore the maximum of those 3 samples—not a production latency distribution.

| Rows per call | API | p50 baseline (ms) | p50 batched (ms) | p50 speedup | p95 baseline (ms) | p95 batched (ms) | Commits baseline → batched |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1,000 | assets | 60.038 | 7.437 | 8.07× | 60.156 | 7.618 | 1,000 → 1 |
| 1,000 | edges | 58.665 | 8.314 | 7.06× | 58.976 | 8.845 | 1,000 → 1 |
| 1,000 | findings + FTS | 179.271 | 25.904 | 6.92× | 179.903 | 43.398 | 2,000 → 1 |
| 10,000 | assets | 625.384 | 73.512 | 8.51× | 661.698 | 98.638 | 10,000 → 1 |
| 10,000 | edges | 647.394 | 74.994 | 8.63× | 662.925 | 75.009 | 10,000 → 1 |
| 10,000 | findings + FTS | 1,977.463 | 249.876 | 7.91× | 2,042.408 | 250.934 | 20,000 → 1 |
| 100,000 | assets | 6,464.705 | 752.111 | 8.60× | 6,494.473 | 752.286 | 100,000 → 1 |
| 100,000 | edges | 6,230.390 | 772.641 | 8.06× | 6,540.552 | 826.134 | 100,000 → 1 |
| 100,000 | findings + FTS | 19,819.604 | 2,652.151 | 7.47× | 20,289.435 | 2,691.906 | 200,000 → 1 |

The change meets the measured target on this host: all APIs now insert with `executemany`, and a non-empty batch is one atomic commit (or a savepoint inside an existing caller transaction). A failed row rolls back the whole batch; FTS row insertion errors propagate and roll back matching findings instead of silently leaving a partial index. Commit failure was also injected by holding a reader lock: the batch rolls back, leaves no transaction open, and the connection remains usable. Empty calls do no work. Finding IDs are captured while the write transaction holds SQLite's write lock, then indexed in FTS in that same transaction.

**Limits:** synthetic local microbenchmark, only 3 samples per point, Linux sandbox rather than the operator's Windows/Git Bash setup, no peak-RAM measurement and no production scan profile. These timings support the relative improvement here; they are not an absolute Windows performance promise. Raw samples and environment metadata are in `store-batch-baseline.json` and `store-batch-batched.json`; reproduction: `python3 benchmarks/benchmark_store_batches.py --sizes 1000 10000 100000 --repeat 3 --label <label> --output <path>`.
