# SQLite schema v2 indexes — controlled microbenchmark

**Environment:** Linux sandbox, Python 3.13.14, SQLite 3.46.1.  
**Reproduce:** `python3 benchmarks/benchmark_store_indexes.py --sizes 1000 10000 100000 --repeat 5 --output benchmarks/results/store-index-report.json`.

For each size, the script builds a fresh temporary DB, records the pre-v2 index set and query plans, applies the real versioned v1→v2 migration, then compares exact result tuples and warm p50 query times. All query results were identical at 1k, 10k and 100k. The JSON contains plans, row counts, storage pages, and measurements for every size.

At size 100k (200k rows each in findings, steps, chats and views):

| Query | Before p50, ms | After p50, ms | Relative change |
|---|---:|---:|---:|
| Scans by target, newest first | 3.302 | 0.485 | 6.81× faster |
| Running-scan sweep | 3.843 | 0.037 | 103.86× faster |
| Findings by scan, score order | 2.841 | 1.093 | 2.60× faster |
| Pending agent steps by sequence | 1.941 | 0.332 | 5.85× faster |
| All agent steps by sequence | 2.923 | 1.077 | 2.71× faster |
| Chat history | 0.135 | 0.035 | 3.86× faster |
| Views for a scan | 6.041 | 0.828 | 7.30× faster |
| Open agent sessions | 0.193 | 0.044 | 4.39× faster |
| Knowledge-base refinement lookup | 3.766 | 0.007 | 538× faster |
| Last completed scan | 0.011 | 0.007 | 1.57× faster |

The new plans use the intended composite indexes and avoid the previously observed full table scans or temporary sort B-trees. At 100k base rows the SQLite page count rose from 11,864 to 17,421 pages (**+22,761,472 allocated bytes**). This is the storage trade-off; write-latency overhead was not separately benchmarked. Timings are warm-cache synthetic results, not a Windows or production guarantee.

The dynamic vector fallback also now indexes `sem_meta(scan_id)` and `sem(scan_id)`; dedicated tests confirm both lookups use those indexes and preserve the expected rows. Those vector queries are not included in the timing table above.
