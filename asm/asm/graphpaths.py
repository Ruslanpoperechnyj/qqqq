# -*- coding: utf-8 -*-
"""Пути до риска: кратчайшие маршруты от точек входа до узлов с критичными находками."""
from __future__ import annotations

from collections import deque


def _norm(v: str) -> str:
    return (v or "").split(" (")[0]


def attack_paths(assets: list[dict], edges: list[dict], findings: list[dict],
                 max_paths: int = 12, max_hops: int = 6) -> dict:
    """BFS от точек входа к узлам, где есть находки P0/P1.

    Возвращает подсветку: узлы и связи, входящие хотя бы в один найденный маршрут,
    и список маршрутов с человеческим описанием.
    """
    adj: dict[str, set[str]] = {}
    for e in edges:
        s, d = e.get("src"), e.get("dst")
        if not s or not d or s == d:
            continue
        adj.setdefault(s, set()).add(d)
        adj.setdefault(d, set()).add(s)          # граф считаем неориентированным для поиска маршрутов

    # узлы риска: где есть находки P0/P1
    risky: dict[str, dict] = {}
    for f in findings:
        if f.get("priority") not in ("P0", "P1"):
            continue
        for key in (_norm(f.get("asset")), f.get("ip") or ""):
            if key:
                risky.setdefault(key, {"priority": f.get("priority"), "title": f.get("title")})

    # сопоставляем с узлами графа (по вхождению значения)
    risky_nodes: dict[str, dict] = {}
    for a in assets:
        val = a.get("value") or ""
        for key, info in risky.items():
            if key and (key == val or key.startswith(val + ":") or val.startswith(key)):
                risky_nodes[val] = info
    if not risky_nodes:
        return {"paths": [], "nodes": [], "links": [], "risk_nodes": []}

    entries = [a.get("value") for a in assets
               if a.get("kind") in ("domain", "root", "subdomain")]
    if not entries:
        entries = [a.get("value") for a in assets if a.get("kind") == "ip"]
    entries = [e for e in entries if e]

    paths: list[dict] = []
    seen_targets: set[str] = set()
    highlight_nodes: set[str] = set()
    highlight_links: set[tuple] = set()
    for src in entries[:12]:
        if len(paths) >= max_paths:
            break
        prev: dict[str, str] = {src: ""}
        q = deque([(src, 0)])
        while q:
            cur, depth = q.popleft()
            if depth >= max_hops:
                continue
            for nxt in sorted(adj.get(cur, ())):
                if nxt in prev:
                    continue
                prev[nxt] = cur
                if nxt in risky_nodes and nxt not in seen_targets:
                    chain = [nxt]
                    while chain[-1] != src and prev.get(chain[-1]):
                        chain.append(prev[chain[-1]])
                    chain.reverse()
                    for i in range(len(chain) - 1):
                        highlight_links.add((chain[i], chain[i + 1]))
                    highlight_nodes.update(chain)
                    info = risky_nodes[nxt]
                    seen_targets.add(nxt)
                    paths.append({"от": src, "до": nxt, "шагов": len(chain) - 1,
                                  "узлы": chain, "приоритет": info.get("priority"),
                                  "находка": info.get("title")})
                    if len(paths) >= max_paths:
                        break
                q.append((nxt, depth + 1))
    return {"paths": paths, "nodes": sorted(highlight_nodes),
            "links": [list(x) for x in sorted(highlight_links)],
            "risk_nodes": sorted(risky_nodes.keys())}
