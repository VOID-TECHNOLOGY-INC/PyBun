# PyBun Benchmark Suite

PyBunの性能を他のPythonツールチェーン（uv, pip, pipx等）と比較するためのベンチマークスイート。

## クイックスタート

```bash
# 全シナリオを実行
python bench.py

# 特定のシナリオのみ実行
python bench.py -s run,adhoc

# ドライラン（コマンドを表示するのみ）
python bench.py --dry-run

# 利用可能なシナリオを一覧表示
python bench.py --list
```

## シナリオ

| ID | 名前 | 説明 |
|----|------|------|
| B1 | resolution | 依存関係解決のベンチマーク |
| B2 | install | パッケージインストールのベンチマーク |
| B3 | run | スクリプト実行のベンチマーク |
| B4 | adhoc | アドホック実行 (pybun x) のベンチマーク |
| B5 | module_find | モジュール検索のベンチマーク |
| B6 | lazy_import | 遅延インポートのベンチマーク |
| B7 | test | テスト実行のベンチマーク |
| B8 | mcp | MCP/JSON出力のベンチマーク |

## ディレクトリ構造

```
scripts/benchmark/
├── bench.py              # メインベンチマークランナー
├── config.toml           # 設定ファイル
├── README.md             # このファイル
├── scenarios/            # シナリオ実装
│   ├── __init__.py
│   ├── resolution.py     # B1: 依存解決
│   ├── install.py        # B2: インストール
│   ├── run.py            # B3: スクリプト実行
│   ├── adhoc.py          # B4: アドホック実行
│   ├── module_find.py    # B5: モジュール検索
│   ├── lazy_import.py    # B6: 遅延インポート
│   ├── test.py           # B7: テスト実行
│   └── mcp.py            # B8: MCP/JSON
├── fixtures/             # テスト用フィクスチャ
│   ├── small_project/    # 10パッケージ
│   ├── medium_project/   # 30パッケージ
│   └── large_project/    # 100+パッケージ
├── results/              # 結果JSON出力先
└── report/
    └── generate.py       # レポート生成
```

## 設定

`config.toml` でベンチマークの設定を行います：

```toml
[general]
iterations = 10          # 反復回数
warmup = 1               # ウォームアップ回数
trim_ratio = 0.1         # 外れ値除外の割合（左右）
timeout_seconds = 300    # タイムアウト

[tools]
pybun = true
uv = true
pip = true
poetry = false           # 遅いのでデフォルト無効
pipx = true

[scenarios.run]
enabled = true
pep723 = true
profiles = ["dev", "prod"]
pep723_fixture = "fixtures/pep723.py"
pep723_clear_envs = true
pep723_clear_fs_cache = true
```

## 出力形式

### JSON

```bash
python bench.py --format json -o results/
```

```json
{
  "meta": {
    "timestamp": "2025-12-14T12:00:00Z",
    "pybun_version": "0.1.0",
    "system": { ... }
  },
  "results": [
    {
      "scenario": "B3.1_simple_startup",
      "tool": "pybun",
      "duration_ms": 45.2,
      "success": true
    }
  ],
  "summary": {
    "pybun_wins": 12,
    "average_speedup": 1.15
  }
}
```

### Markdown

```bash
python bench.py --format markdown -o results/
```

### CSV

```bash
python bench.py --format csv -o results/
```

## レポート生成

```bash
# 結果からMarkdownレポートを生成
python report/generate.py results/ -o report.md

# HTMLレポートを生成
python report/generate.py results/ --format html -o report.html

# ベースラインとの比較
python report/generate.py results/new.json --compare results/baseline.json
```

## CI統合

GitHub Actionsでnightlyベンチマークを実行する例：

```yaml
name: Nightly Benchmark

on:
  schedule:
    - cron: '0 0 * * *'  # 毎日0時

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install uv
        run: curl -LsSf https://astral.sh/uv/install.sh | sh
      
      - name: Build pybun
        run: cargo build --release
      
      - name: Run benchmarks
        run: |
          cd scripts/benchmark
          python bench.py --format json -o results/
      
      - name: Generate report
        run: |
          cd scripts/benchmark
          python report/generate.py results/ --format markdown -o report.md
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: scripts/benchmark/results/
```

## 前提条件

- Python 3.9+
- `pybun` がPATHに存在すること（または `config.toml` でパスを指定）
- 比較対象ツール（uv, pip, pipx等）がインストールされていること（任意）

## トラブルシューティング

### tomlモジュールがない

Python 3.11未満では `toml` パッケージが必要です：

```bash
pip install toml
```

### ツールが見つからない

`config.toml` の `[paths]` セクションでパスを明示的に指定できます：

```toml
[paths]
pybun = "/path/to/pybun"
uv = "/path/to/uv"
```

### タイムアウト

大規模プロジェクトのインストールには時間がかかる場合があります。タイムアウトを延長してください：

```toml
[general]
timeout_seconds = 600
```
