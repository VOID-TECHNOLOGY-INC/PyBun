# PyBun Benchmark Plan

PyBunの性能を他のPythonツールチェーンと比較するためのベンチマーク実装計画。

## 目的

1. PyBunの各機能の性能を定量的に測定
2. 競合ツール（uv, pip, poetry, pipx等）との比較
3. PyBunの優位性・改善点を明確化
4. 継続的なパフォーマンス監視の基盤構築

---

## 比較対象ツール

| ツール | カテゴリ | 備考 |
|--------|----------|------|
| **uv** | パッケージ管理 | Rust製、高速が売り。最も重要な比較対象 |
| **pip** | パッケージ管理 | 標準ツール、ベースライン |
| **poetry** | パッケージ管理 | プロジェクト管理統合型 |
| **pipx** | アドホック実行 | `pybun x` の比較対象 |
| **Python標準** | インポート | `import` のベースライン |
| **pytest** | テスト | `pybun test` の比較対象 |

---

## ベンチマークカテゴリ

### B1: 依存解決 (Dependency Resolution)

**測定対象**: `pybun install` vs `uv pip compile` vs `pip-compile` vs `poetry lock`

| シナリオ | 説明 |
|----------|------|
| B1.1 | 単一パッケージ（requests） |
| B1.2 | 中規模プロジェクト（10パッケージ） |
| B1.3 | 大規模プロジェクト（50+パッケージ、深い依存） |
| B1.4 | 競合解決（バージョン制約あり） |
| B1.5 | キャッシュあり再解決 |

**測定項目**:
- 解決時間 (ms)
- メモリ使用量 (MB)
- 解決結果のパッケージ数

---

### B2: パッケージインストール (Package Installation)

**測定対象**: `pybun install` vs `uv pip install` vs `pip install` vs `poetry install`

| シナリオ | 説明 |
|----------|------|
| B2.1 | Cold install（キャッシュなし） |
| B2.2 | Warm install（キャッシュあり） |
| B2.3 | 大規模プロジェクト install |
| B2.4 | 並列インストール効率 |

**測定項目**:
- インストール時間 (ms)
- ディスクI/O
- ネットワーク転送量

---

### B3: スクリプト実行 (Script Execution)

**測定対象**: `pybun run` vs `python` vs `uv run`

| シナリオ | 説明 |
|----------|------|
| B3.1 | 単純スクリプト起動時間 |
| B3.2 | PEP 723スクリプト（依存あり） |
| B3.3 | 大量import時の起動時間 |
| B3.4 | プロファイル別起動時間（dev/prod） |

**測定項目**:
- 起動時間 (ms)
- Time to first output
- メモリフットプリント

---

### B4: アドホック実行 (Ad-hoc Execution)

**測定対象**: `pybun x` vs `pipx run` vs `uvx`

| シナリオ | 説明 |
|----------|------|
| B4.1 | 初回実行（env作成含む） |
| B4.2 | 2回目実行（キャッシュあり） |
| B4.3 | バージョン指定実行 |

**測定項目**:
- 実行完了時間 (ms)
- 一時ディレクトリサイズ

---

### B5: モジュール検索 (Module Finding)

**測定対象**: `pybun module-find` vs Python標準 `import`

| シナリオ | 説明 |
|----------|------|
| B5.1 | 標準ライブラリモジュール検索 |
| B5.2 | サードパーティパッケージ検索 |
| B5.3 | 大規模ディレクトリスキャン |
| B5.4 | キャッシュヒット率 |

**測定項目**:
- 検索時間 (µs)
- キャッシュ効率
- 並列スキャン性能

---

### B6: 遅延インポート (Lazy Import)

**測定対象**: `pybun lazy-import` 有効/無効時の起動時間

| シナリオ | 説明 |
|----------|------|
| B6.1 | NumPy/Pandas等の重量級インポート |
| B6.2 | 多数の小規模モジュールインポート |
| B6.3 | 実際にアクセスするまでの遅延効果 |

**測定項目**:
- 起動時間差分 (ms)
- 実際のロード時間
- メモリ使用量差分

---

### B7: テスト実行 (Test Execution)

**測定対象**: `pybun test` vs `pytest` vs `unittest`

| シナリオ | 説明 |
|----------|------|
| B7.1 | テスト発見時間 |
| B7.2 | 小規模テストスイート実行 |
| B7.3 | 並列実行（shard） |
| B7.4 | AST発見 vs pytest発見 |

**測定項目**:
- 発見時間 (ms)
- 実行時間 (ms)
- 並列効率

---

### B8: MCP/JSON出力 (AI Agent Integration)

**測定対象**: MCP tools/call のレイテンシ

| シナリオ | 説明 |
|----------|------|
| B8.1 | pybun_doctor 応答時間 |
| B8.2 | pybun_run 応答時間 |
| B8.3 | pybun_resolve 応答時間 |
| B8.4 | JSON出力オーバーヘッド |

**測定項目**:
- 応答時間 (ms)
- JSON生成オーバーヘッド

---

## 実装計画

### Phase 1: 基盤構築 (Week 1)

```
scripts/
└── benchmark/
    ├── bench.py              # メインベンチマークランナー
    ├── config.toml           # ベンチマーク設定
    ├── scenarios/
    │   ├── resolution.py     # B1シナリオ
    │   ├── install.py        # B2シナリオ
    │   ├── run.py            # B3シナリオ
    │   ├── adhoc.py          # B4シナリオ
    │   ├── module_find.py    # B5シナリオ
    │   ├── lazy_import.py    # B6シナリオ
    │   ├── test.py           # B7シナリオ
    │   └── mcp.py            # B8シナリオ
    ├── fixtures/
    │   ├── small_project/    # 10パッケージ
    │   ├── medium_project/   # 30パッケージ
    │   └── large_project/    # 100+パッケージ
    ├── results/              # 結果JSON出力先
    └── report/
        └── generate.py       # レポート生成
```

### Phase 2: コアシナリオ実装 (Week 2)

**PR-B1: 依存解決ベンチマーク**
- [ ] uv, pip, poetryのインストール確認スクリプト
- [ ] 各シナリオのフィクスチャ作成
- [ ] 測定ロジック実装
- [ ] 結果JSON出力

**PR-B2: スクリプト実行ベンチマーク**
- [ ] 起動時間測定（複数回平均）
- [ ] PEP 723シナリオ
- [ ] プロファイル比較

**PR-B3: アドホック実行ベンチマーク**
- [ ] pipx/uvxとの比較
- [ ] キャッシュ効果測定

### Phase 3: 高度なシナリオ (Week 3)

**PR-B4: モジュール検索・遅延インポート**
- [ ] Rust module-finder vs Pythonインポート
- [ ] lazy-import効果測定

**PR-B5: テスト・MCP**
- [ ] テスト発見速度
- [ ] MCP応答時間

### Phase 4: レポート・CI統合 (Week 4)

**PR-B6: レポート生成**
- [ ] Markdown/HTMLレポート生成
- [ ] グラフ出力（matplotlib or ASCII）
- [ ] 回帰検出ロジック

**PR-B7: CI統合**
- [ ] GitHub Actions nightly benchmark
- [ ] 結果をartifactとして保存
- [ ] 10%以上の回帰でアラート

---

## ベンチマークスクリプト設計

### メインランナー (`bench.py`)

```python
#!/usr/bin/env python3
"""PyBun Benchmark Runner"""

import argparse
import json
import subprocess
import time
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class BenchResult:
    scenario: str
    tool: str
    duration_ms: float
    memory_mb: float
    success: bool
    metadata: Dict[str, Any]

def measure(cmd: List[str], warmup: int = 1, iterations: int = 5) -> BenchResult:
    """コマンドを複数回実行し、平均時間を測定"""
    # Warmup
    for _ in range(warmup):
        subprocess.run(cmd, capture_output=True)
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = subprocess.run(cmd, capture_output=True)
        end = time.perf_counter()
        times.append((end - start) * 1000)  # ms
    
    return BenchResult(
        duration_ms=sum(times) / len(times),
        # ... 他のフィールド
    )

def run_scenario(name: str, config: dict) -> List[BenchResult]:
    """シナリオを実行"""
    results = []
    
    # PyBun
    results.append(measure(["pybun", ...]))
    
    # 比較対象
    if config.get("compare_uv"):
        results.append(measure(["uv", ...]))
    if config.get("compare_pip"):
        results.append(measure(["pip", ...]))
    
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", "-s", help="Run specific scenario")
    parser.add_argument("--output", "-o", default="results/", help="Output directory")
    parser.add_argument("--format", choices=["json", "markdown", "csv"], default="json")
    args = parser.parse_args()
    
    # Run benchmarks
    results = run_all_scenarios(args.scenario)
    
    # Output results
    save_results(results, args.output, args.format)

if __name__ == "__main__":
    main()
```

### 設定ファイル (`config.toml`)

```toml
[general]
iterations = 5
warmup = 1
timeout_seconds = 300

[tools]
pybun = true
uv = true
pip = true
poetry = true
pipx = true

[scenarios.resolution]
enabled = true
fixtures = ["small", "medium", "large"]

[scenarios.install]
enabled = true
cold_cache = true
warm_cache = true

[scenarios.run]
enabled = true
pep723 = true
profiles = ["dev", "prod"]

[scenarios.adhoc]
enabled = true
packages = ["cowsay", "black", "ruff"]

[scenarios.module_find]
enabled = true
benchmark_parallel = true

[scenarios.test]
enabled = true
parallel_workers = [1, 2, 4, 8]

[scenarios.mcp]
enabled = true
tools = ["doctor", "run", "resolve", "gc"]

[output]
format = "json"
include_system_info = true
```

---

## 出力形式

### JSON結果

```json
{
  "meta": {
    "timestamp": "2025-12-14T12:00:00Z",
    "pybun_version": "0.1.0",
    "system": {
      "os": "macOS 14.0",
      "cpu": "Apple M1",
      "memory_gb": 16
    }
  },
  "results": [
    {
      "scenario": "B1.1_single_package",
      "tool": "pybun",
      "duration_ms": 45.2,
      "memory_mb": 12.5,
      "success": true
    },
    {
      "scenario": "B1.1_single_package",
      "tool": "uv",
      "duration_ms": 38.7,
      "memory_mb": 15.2,
      "success": true
    }
  ],
  "summary": {
    "pybun_wins": 12,
    "pybun_losses": 3,
    "average_speedup": 1.15
  }
}
```

### Markdownレポート

```markdown
# PyBun Benchmark Report

Generated: 2025-12-14

## Summary

| Metric | PyBun | uv | pip | Winner |
|--------|-------|-----|-----|--------|
| Avg Resolution Time | 45ms | 38ms | 120ms | uv |
| Avg Install Time | 230ms | 180ms | 850ms | uv |
| Script Startup | 12ms | 15ms | 18ms | **pybun** |
| Module Find | 0.5µs | N/A | 15µs | **pybun** |

## Detailed Results

### B1: Dependency Resolution

[グラフ/表]

### B2: Package Installation

[グラフ/表]

...
```

---

## 期待される優位性

PyBunが優位と予想される領域：

| 機能 | 予想優位性 | 理由 |
|------|-----------|------|
| モジュール検索 | ◎ 大幅に高速 | Rust製並列スキャン、LRUキャッシュ |
| 遅延インポート | ◎ 起動時間短縮 | 必要時までロード遅延 |
| JSON出力 | ◎ AI連携容易 | 全コマンド統一形式 |
| MCP統合 | ◎ 唯一の対応 | 他ツールは対応なし |
| PEP 723 | ○ 統合的 | 検出→install→実行が一発 |
| プロファイル | ○ 便利 | dev/prod切替が容易 |

uvが優位と予想される領域：

| 機能 | 予想 | 理由 |
|------|------|------|
| 依存解決 | uv優位 | 成熟したSAT solver |
| パッケージDL | uv優位 | 並列DL最適化 |
| venv作成 | 同等 | どちらもRust製 |

---

## 成功基準

1. **測定可能性**: 全シナリオで安定した測定結果が得られる
2. **再現性**: 同一環境で±5%以内の再現性
3. **CI統合**: nightlyで自動実行、結果保存
4. **可視化**: 分かりやすいレポート出力
5. **回帰検出**: 10%以上の性能低下でアラート

---

## 次のステップ

1. `scripts/benchmark/` ディレクトリ作成
2. 基本的な測定インフラ実装
3. B3（スクリプト実行）から開始（最も差別化しやすい）
4. 順次シナリオ追加
5. CI統合

---

## 参考リンク

- [uv benchmarks](https://github.com/astral-sh/uv/tree/main/crates/bench)
- [hyperfine](https://github.com/sharkdp/hyperfine) - コマンドラインベンチマークツール
- [pytest-benchmark](https://pytest-benchmark.readthedocs.io/)

