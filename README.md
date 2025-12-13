# PyBun (Python Bundle)

Rust製のシングルバイナリPythonツールチェーン。高速な依存関係インストール、ランタイム/インポート最適化、テスト、ビルド機能と、AIエージェント向けJSON出力を統合。

## ステータス
- 現在: M1（高速インストーラ）、M2（ランタイム最適化）、M4（MCP/JSON）を中心に実装が進行中（**stable/preview/stub が混在**）
- プラットフォーム: macOS/Linux (arm64/amd64)

※ 機能の成熟度（stub/preview/stable）と段階導入の方針は `docs/SPECS.md` を参照。

## インストール

```bash
# ソースからビルド
cargo build --release
```

## クイックスタート

```bash
# ヘルプ表示
pybun --help

# Pythonスクリプトを実行
pybun run script.py

# インラインコードを実行
pybun run -c -- "print('Hello, PyBun!')"

# パッケージを一時的に実行（npxライク）
pybun x cowsay -- "Hello from PyBun"

# JSON形式で出力（AIエージェント向け）
pybun --format=json run script.py
```

## コマンド一覧

### パッケージ管理

```bash
# 依存関係をインストール（ロックファイル生成）
pybun install --require requests==2.31.0 --index fixtures/index.json

# パッケージを追加（pyproject.tomlを更新）
pybun add requests

# パッケージを削除
pybun remove requests
```

### スクリプト実行

```bash
# Pythonスクリプトを実行
pybun run script.py

# 引数付きで実行
pybun run script.py -- arg1 arg2

# インラインコードを実行
pybun run -c -- "import sys; print(sys.version)"

# プロファイル指定で実行
pybun run --profile=prod script.py
```

PEP 723のインラインメタデータにも対応:
```python
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.28"]
# ///
import requests
```
※ 現状は **メタデータの解析・表示が中心（preview）** で、依存の自動インストール→隔離環境実行は段階導入予定です（詳細は `docs/PLAN.md`）。

### アドホック実行 (`pybun x`)

パッケージを一時環境にインストールして実行（`npx`のPython版）:

```bash
# cowsayを一時インストールして実行
pybun x cowsay

# バージョン指定
pybun x cowsay==6.1

# 引数付き
pybun x black -- --check .
```

### Python バージョン管理

```bash
# インストール済みバージョンを表示
pybun python list

# 利用可能な全バージョンを表示
pybun python list --all

# Pythonをインストール
pybun python install 3.12

# Pythonを削除
pybun python remove 3.12

# Pythonパスを表示
pybun python which
pybun python which 3.11
```

### ランタイム最適化

#### モジュールファインダー

Rustベースの高速モジュール検索:

```bash
# モジュールを検索
pybun module-find os.path

# ディレクトリをスキャンして全モジュールを列挙
pybun module-find --scan -p ./src

# ベンチマーク付き
pybun module-find --benchmark os.path
```

#### 遅延インポート

```bash
# 設定を表示
pybun lazy-import --show-config

# モジュールの判定を確認
pybun lazy-import --check numpy

# Pythonコードを生成
pybun lazy-import --generate -o lazy_setup.py

# 許可/拒否リストを指定
pybun lazy-import --allow mymodule --deny debug_tools --generate
```

#### ファイルウォッチ（開発モード）

```bash
# ファイル変更検知→再実行（現状はプレビュー）
# ネイティブ監視は段階導入予定。今は --shell-command（外部ウォッチャー）利用を推奨。
pybun watch main.py

# 特定ディレクトリを監視
pybun watch main.py -p src

# 設定を表示
pybun watch --show-config

# 外部ウォッチャー用のシェルコマンドを生成
pybun watch --shell-command main.py
```

### プロファイル管理

```bash
# 利用可能なプロファイルを表示
pybun profile --list

# プロファイル設定を表示
pybun profile dev --show

# プロファイルを比較
pybun profile dev --compare prod

# プロファイルをエクスポート
pybun profile prod -o prod-config.toml
```

プロファイル:
- `dev`: ホットリロード有効、詳細ログ
- `prod`: 遅延インポート有効、最適化
- `benchmark`: トレース・タイミング計測

### MCP サーバー

AIエージェント向けのMCPサーバー:

```bash
# stdioモードで起動
pybun mcp serve --stdio
```

ツール: `pybun_resolve`, `pybun_install`, `pybun_run`, `pybun_gc`, `pybun_doctor`  
リソース: `pybun://cache/info`, `pybun://env/info`

※ 現状は **`pybun_gc` と resources は実動**、`pybun_resolve/install/run/doctor` は “Would …” を返す段階（stub/preview）です。

### 診断・メンテナンス

```bash
# 環境診断
pybun doctor
pybun doctor --verbose

# キャッシュのガベージコレクション
pybun gc
pybun gc --max-size 1G
pybun gc --dry-run

# セルフアップデート確認
pybun self update --dry-run
pybun self update --channel nightly
```

## JSON出力

全コマンドで`--format=json`オプションが使用可能:

```bash
pybun --format=json run script.py
pybun --format=json doctor
pybun --format=json python list
```

出力形式:
```json
{
  "version": "1",
  "command": "pybun run",
  "status": "ok",
  "duration_ms": 123,
  "detail": { ... },
  "events": [ ... ],
  "diagnostics": [ ... ],
  "trace_id": "uuid-optional"
}
```

トレースID有効化:
```bash
PYBUN_TRACE=1 pybun --format=json run script.py
```

## 環境変数

| 変数 | 説明 |
|------|------|
| `PYBUN_ENV` | 使用するvenvのパス |
| `PYBUN_PYTHON` | Pythonバイナリのパス |
| `PYBUN_PROFILE` | デフォルトプロファイル (dev/prod/benchmark) |
| `PYBUN_TRACE` | `1`でトレースIDを有効化 |
| `PYBUN_LOG` | ログレベル (debug/info/warn/error) |

## 開発

### 必要環境

- Rust stable (`rustup`, `cargo`)

### 基本コマンド

```bash
# フォーマット
cargo fmt

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# テスト
cargo test

# 開発用スクリプト
./scripts/dev fmt
./scripts/dev lint
./scripts/dev test
```

### テスト

```bash
# 全テスト
cargo test

# 特定のテスト
cargo test cli_smoke
cargo test json_schema
cargo test mcp
```

## ロードマップ

- [x] M0: リポジトリ・CIスキャフォールド
- [x] M1: 高速インストーラ（ロックファイル、リゾルバ、PEP 723）
- [x] M2: ランタイム最適化（モジュールファインダー、遅延インポート、ホットリロード）
- [ ] M3: テストランナー（ディスカバリ、並列実行、スナップショット）
- [x] M4: JSON/MCP・診断
- [ ] M5: ビルダー・セキュリティ
- [ ] M6: リモートキャッシュ、ワークスペース

詳細は `docs/PLAN.md` を参照。

## ライセンス

MIT
