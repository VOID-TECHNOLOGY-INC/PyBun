# PyBun (Python Bundle) Product Specification
**Version:** 1.0 (Draft)
**Status:** Planning
**Codename:** Python-Speed-Demon

---

## 0. 前提・適用範囲 (Scope & Target)

- **対応OS/Arch:** macOS 13+/Linux (glibc/musl) / Windows 11+, amd64/arm64。最初のGAは macOS/Linux 優先。
- **Python互換:** CPython 3.9–3.12 を同梱または動的取得（Minor互換を担保）。3.13 はベータ期にプレビュー対応。
- **ターゲットユースケース:** Web/ML サービス開発、スクリプト自動化、CI/CD、AIエージェントによる自律開発。
- **成果物:** 単一バイナリ配布 + 最小限のランタイムデータディレクトリ（グローバルキャッシュ）。

---

## 0.1 実装成熟度と段階導入 (Maturity & Staging)

本ドキュメント（SPECS）は最終的な到達点（製品仕様）を定義する。一方で実装は段階的に投入されるため、機能には成熟度を設ける。
実装計画と現状は `docs/PLAN.md` を正とし、本仕様と矛盾しない範囲で段階導入を許容する。

### 成熟度レベル

- **stub**: CLI/スキーマ/外形のみ。内部処理は未実装（例: “Would …” のダミー応答）。
- **preview**: 実用の入口として動くが、互換性/性能/OS対応が限定的。feature flag や制約を伴う。
- **stable**: 既定で利用可能。互換性/再現性/エラー診断が揃い、CI で回帰を防げる。

### 段階導入の方針（大規模修正を避ける）

- **Tester/Builder は bootstrap → ネイティブ実装へ**: まず薄いラッパーで CLI/JSON/exit-code 等の外形を固め、後から内部エンジンを差し替える。
- **MCP は stdio を先行**: `--stdio` は実装済みで安定動作する。HTTP mode（`--port`）は運用・セキュリティ要件を詰めてから追加する。
- **Hot Reload は外部ウォッチャーとネイティブ監視を併用**: macOS/Linux は `notify` クレートによるネイティブ監視を実装済み（プレビュー）。Windows はまだスタブ。

---

## 1. プロダクト概要 (Executive Summary)

**PyBun** は、Rustで記述された Python のための「オールインワン・ツールチェーン」である。
Node.js エコシステムにおける **Bun** の哲学を踏襲し、Python 開発における**パッケージ管理、スクリプト実行、テスト、ビルド、環境構築**の全工程を、単一の高速なバイナリで提供する。

既存のツール（pip, poetry, uv, conda, pytest）が抱える断片化とパフォーマンスの問題を解消し、特に **AIコーディングエージェント（Claude Code / Cursor）** が自律的にコードを生成・実行・修正しやすい環境を提供することを至上命題とする。

---

## 2. 解決する課題 (Problem Statement)

現在の Python エコシステムには以下の「痛み」が存在する：

1.  **遅い実行開始 (Slow Startup):** `import` システムのボトルネックにより、大規模な ML/Web プロジェクトの起動に数秒〜数十秒かかる。
2.  **環境管理の地獄 (Environment Hell):** venv, conda, poetry, pyenv などツールが乱立し、初学者や AI エージェントが環境構築で躓く。
3.  **依存解決の遅さ:** pip の依存解決は遅く、C拡張のビルドは複雑で失敗しやすい。
4.  **AI 親和性の欠如:** 既存ツールの出力は人間向け（テキスト）であり、AI がエラー原因（競合、ビルド失敗）を構造的に理解しにくい。

---

## 3. アーキテクチャ (Architecture)

PyBun は CPython インタプリタを内包（またはラップ）し、その周囲のツールチェーンとローディングプロセスを Rust で完全に置き換える。

```mermaid
graph TD
    User[Developer / AI Agent] --> CLI[PyBun CLI]
    
    subgraph "Rust Core (The Speed Layer)"
        CLI --> Resolver[Fast Dependency Resolver (SAT)]
        CLI --> Builder[Parallel Builder (Ninja/CMake wrapper)]
        CLI --> Runner[Runtime Loader & Watcher]
    end
    
    subgraph "Optimization Engine"
        Runner --> ImportOpt[Import Graph Optimizer]
        Runner --> HotReload[Hot Reload Manager]
        ImportOpt --> Cache[Global Bytecode/Wheel Cache]
    end
    
    subgraph "Integration Interface"
        Runner --> CPython[CPython API / ABI]
        Runner --> AgentInterface[JSON-RPC / MCP Server]
    end
````

-----

## 3.1 非機能要件 (Non-Functional)

- **起動/実行速度:** `pybun run script.py` のコールドスタートを CPython 素の起動比で **10x 改善 (p50)**、重量ライブラリの Lazy Import 時に **1–2s → ≤300ms** を目標。
- **インストール速度:** `pybun install` は `uv` 同等（p95 で 5%以内）を下回ること。
- **決定性:** 同一 lock + 同一プラットフォームで **完全再現性**（ハッシュ一致する wheel セット）を保証。
- **ディスク効率:** グローバルキャッシュ + ハードリンクで、典型的 ML プロジェクト（3GB wheel）を **70% 以上節約**。
- **並列度:** デフォルトで論理CPU数を検出し、I/O/CPU別スレッドプールを分離。環境変数で上書き可能。
- **信頼性:** すべての CLI コマンドに `--format=json` 出力と `--verbose` を用意し、AI/人間どちらにも故障解析しやすい形を提供。

-----

## 4\. コア機能要件 (Core Features)

### 4.0 配布・ランタイム構成

  * **単一バイナリ:** macOS/Linux では静的リンク優先（openssl, libz は同梱）、Windows は MSVC 再頒布依存のみ。
  * **内蔵CPython:** バイナリ内にバンドル。欠損バージョンは初回起動時に署名付きアーカイブをダウンロードしてキャッシュ。
  * **データディレクトリ:** `~/.cache/pybun`（環境変数 `PYBUN_HOME` で上書き）。環境、wheel、ログを階層管理。
  * **自己更新:** `pybun self update` でバージョン取得・署名検証・アトミック置換。

### 4.1 高速パッケージマネージャ (The Installer)

`pip` および `uv` を代替する機能。

  * **Global Caching:** プロジェクトごとにファイルをコピーせず、ディスク容量を節約するグローバルキャッシュ（Hardlink活用）。
  * **Performance:** `uv` と同等以上の依存解決速度（Rust製 SATソルバー）。
  * **Offline Mode:** キャッシュがあればオフラインで完全に動作。
  * **Universal Lock:** `bun.lockb` 相当のバイナリロックファイルにより、全OS間での再現性を保証。

### 4.2 高速実行ランタイム (The Runtime & Import Optimizer)

`python` コマンドを代替する `pybun run`。ここが最大の差別化要因。

  * **Lazy Import Injection:** ユーザーコードを変更することなく、設定ベースで重量級ライブラリ（Pandas, Torch, Terraform-cdkなど）を遅延読み込み（Lazy Loading）し、CLI起動速度を10〜100倍高速化する。
  * **Rust-based Module Finder:** `sys.meta_path` を Rust 実装に置き換え、ファイルシステム探索を並列化・最適化。
  * **Runtime Hot Reloading:** ファイル変更を検知し、プロセスを落とさずにモジュールをリロード（FastAPI/Django等の開発効率向上）。段階導入として、外部ウォッチャー生成 → ネイティブ監視（notify 等）を許容。
  * **PEP 723 (Script Support):** 依存関係が記述された単一の `.py` ファイルを、事前の install なしで即座に仮想環境構築・実行する（段階導入として、まず依存解析/診断 → 自動インストール→実行へ）。
  * **Launch Profiles:** `pybun run --profile=dev|prod|benchmark` で import 最適化/ホットリロード/ログ閾値を切替。

### 4.3 C拡張ビルド最適化 (The Builder)

  * **Isolation Build:** `setuptools`, `maturin`, `scikit-build` をラップし、ビルド環境をサンドボックス化（段階導入として `python -m build` ラッパー→本格隔離へ）。
  * **Build Cache:** コンパイル成果物（`.o`, `.so`）をハッシュ管理し、再ビルド時間を短縮。
  * **Pre-build Wheel Discovery:** OS/Arch に合致する最適な wheel を優先的に探索し、ローカルビルドを回避。

### 4.4 高速テストランナー (The Tester)

`pytest` 互換かつ、高速なテスト実行エンジン。段階導入として、まず `pytest/unittest` の薄いラッパーで CLI/JSON/exit-code/`--shard`/`--fail-fast` の外形を固め、後からネイティブ実装へ移行する。

  * **Native Discovery:** Python コードをパースせず、AST 解析レベルでテストケースを高速探索。
  * **Parallel Execution:** Rust の非同期ランタイムを用いたプロセス/スレッド並列実行。
  * **Snapshot Testing:** Jest/Bun ライクなスナップショットテストをネイティブサポート。
  * **互換モード:** `--pytest-compat` でマーカー/fixture/プラグインの互換を確保、非互換点は警告を JSON でも出力。
  * **Fail-Fast/Shard:** `--fail-fast`、`--shard N/M` を標準搭載し CI での分散実行を容易化。

### 4.5 自動環境管理 (Zero-Config Environment)

  * **No More venv:** ユーザーは `venv` を作成・有効化する必要がない。`pybun run` が現在のディレクトリコンテキストに基づき、最適な隔離環境を自動利用する。
  * **Python Version Management:** `.python-version` ファイルに基づき、必要な Python バージョンを自動でダウンロード・切り替え（pyenv統合）。
  * **環境解決優先度:** 1) `PYBUN_ENV` 指定、2) プロジェクトローカル `.pybun/venv`、3) グローバル共有環境。明示的に `--no-isolation` でホスト利用も可。
  * **ロック整合:** lock に記録された Python ABI と一致しない場合は警告を出し、自動で対応バージョンを取得。

### 4.6 設定ファイル/レイアウト

- **ロックファイル:** `pybun.lockb`（バイナリ形式）。Pythonバージョン、プラットフォームタグ、wheelハッシュ、解決グラフを格納。`pybun lock --json` でデコード可。
- **プロジェクト設定:** `pyproject.toml` の `[tool.pybun]` + `.pybun/config.toml`（後者が優先）。実行時オプションは CLI > 環境変数 > 設定ファイル。
- **キャッシュ構造:** `packages/`（wheel）、`envs/`（仮想環境）、`build/`（オブジェクトキャッシュ）、`logs/`（実行ログ/構造化イベント）。
- **クリーンアップ:** `pybun gc` で LRU ベースのキャッシュ削除、`--max-size` 指定で上限管理。

### 4.7 開発者体験 (Developer Experience)

- **Interactive Init:** `pybun init` で対話的に `pyproject.toml` を生成。`-y` で推奨デフォルト設定（`src` layout 等）を即時適用。
- **Dependency Insights:**
  - `pybun outdated`: ロックファイルとインデックスを照合し、SemVer 互換範囲内および範囲外の更新を表示。`--format=json` 対応。
  - `pybun upgrade`: `pyproject.toml` の制約内でパッケージを安全に更新。`--interactive` で TUI 選択更新（段階導入）。

### 4.8 データ連携・バックテスト拡張 (Market Data & Backtest Extension)

PyBun 本体の Python ツールチェーンを補完する任意拡張として、データ駆動開発（定量分析/バックテスト）のワークフローを定義する。

- **Exchange Connector 抽象化:** 取引所ごとの差分を `connector` 層で吸収し、`spot/futures` と `klines/trades/funding/open-interest` を共通スキーマで扱う。初期 stable 実装は Binance を第一対象とする。
- **データカタログ:** `exchange/symbol/interval/date` パーティションでローカル保存（Parquet + メタデータ）し、`source`, `fetched_at`, `checksum` を保持して再現性を担保。
- **インクリメンタル同期:** `--since/--until` で差分取得、途中失敗時の再開、欠損区間検知と修復（gap fill）をサポート。
- **再現可能バックテスト:** 実行時に戦略設定・データスナップショット・実行環境を `manifest` 化し、同一入力で結果を再現可能にする。
- **AIフレンドリー出力:** データ取得件数、欠損補完、コスト/手数料モデル、結果指標（PnL, Sharpe, MaxDD）を JSON で返し、エージェントからの自動評価を容易化。

-----

## 5\. AI エージェント最適化 (AI Integration)

Anthropic Claude Code や Cursor などの AI エージェントが、PyBun を通じて開発を行うための専用インターフェース。

### 5.1 JSON-RPC & MCP (Model Context Protocol) Support

CLI の出力を構造化データとして提供するモード。

  * **Command:** `pybun --format=json run app.py`
  * **Response:**
    ```json
    {
      "status": "error",
      "error_type": "ImportError",
      "module": "numpy",
      "context": "Dependency 'numpy' is missing in pyproject.toml but imported in app.py:3",
      "fix_suggestion": "pybun add numpy"
    }
    ```
  * **Schema:** 成功/失敗を問わず `version`, `command`, `duration_ms`, `events[]`, `diagnostics[]` を含む。`events` はビルド/ダウンロード/テスト結果などを時系列で提供。
  * **MCP サーバー:** 段階導入として `pybun mcp serve --stdio` を先行し、依存解決・インストール・実行・診断などを RPC 経由で実行できるようにする。HTTP mode（`pybun mcp serve --port 9999`）は運用/セキュリティ要件を満たした後に追加する。

### 5.2 Self-Healing Context

エラー発生時、単なるスタックトレースではなく「解決策」を含むコンテキストを提供する。

  * **Dependency Conflict:** 競合しているパッケージのバージョンツリーを JSON で提示。
  * **Build Error:** 足りないシステムライブラリ（例: `libomp`）のインストールコマンド（`brew install libomp` 等）を提案。
  * **再試行ヒント:** `pybun install --prefer-binary` 等の代替コマンドを提示し、AI が自動修復しやすいテキスト/JSON を両立。

-----

## 6\. CLI インターフェース仕様 (CLI Reference)

Bun の UX を踏襲し、短く直感的なコマンド体系とする。
テキスト出力では、解決/ダウンロード/ビルド/配置の **途中経過** を逐次表示し、TTY ではスピナーやプログレスバーで視認性を高める。`--progress=auto|always|never`（または `--no-progress`）で制御し、`--format=json` の場合は UI を無効化してイベントのみ出力する。

| コマンド | 説明 | 既存ツール対応 |
| :--- | :--- | :--- |
| `pybun run <file.py>` | スクリプト実行（Import最適化・HotReload付） | `python` |
| `pybun install` | 依存関係のインストール | `pip install -r ...` |
| `pybun add <pkg>` | パッケージ追加 & ロックファイル更新 | `poetry add` |
| `pybun remove <pkg>` | パッケージ削除 | `poetry remove` |
| `pybun test` | 高速テスト実行 | `pytest` |
| `pybun build` | 配布用パッケージ/バイナリのビルド | `python -m build` |
| `pybun x <pkg>` | ツールの一時実行（PEP 723対応） | `pipx run` / `uvx` |
| `pybun doctor` | 環境・依存関係の診断（AI向け出力対応） | - |
| `pybun self update` | バイナリアップデート（署名検証付） | - |
| `pybun mcp serve` | MCP サーバーとして待受（stdio先行、HTTPは段階導入） | - |
| `pybun data sync` | 取引所データを差分同期してカタログ化 | custom |
| `pybun backtest run` | 戦略バックテスト実行（再現用 manifest 付き） | custom |
| `pybun init` | プロジェクト初期化（pyproject.toml生成） | `npm init` / `bun init` |
| `pybun outdated` | 更新可能な依存パッケージの一覧表示 | `npm outdated` / `pip list -o` |
| `pybun upgrade` | 依存パッケージの更新 | `npm update` / `bun update` |

**共通フラグ例:** `--format=json|text`, `--profile`, `--python 3.11`, `--cache-dir`, `--offline`, `--no-lock`, `--verbose`, `--quiet`, `--progress=auto|always|never`.

-----

## 7\. 競合比較 (Competitive Landscape)

| 機能 | **PyBun** | uv (Astral) | Poetry | Conda | Standard (pip/venv) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **言語** | Rust | Rust | Python | Python | Python |
| **速度** | **最速** | 最速級 | 遅い | 普通 | 普通 |
| **Import最適化** | **あり (Runtime)** | なし | なし | なし | なし |
| **テストランナー** | **内蔵 (高速)** | なし | なし | なし | なし (pytest別途) |
| **環境管理** | **完全自動** | 手動/自動 | 自動(venv) | 独自(conda) | 手動(venv) |
| **AI API (JSON)** | **あり** | なし | なし | なし | なし |

-----

## 8\. ロードマップ (Roadmap)

### Phase 1: The Foundation (Month 1-3)

  * **Goal:** `uv` 互換の高速インストーラと、PEP 723 対応ランナーの実装。
  * Core Features:
      * 高速依存解決 (SAT Solver)
      * `pybun install` / `pybun add`
      * `pybun run script.py` (PEP 723 support)
      * Basic venv automatic handling

### Phase 2: The Runtime Revolution (Month 4-6)

  * **Goal:** Python の起動速度問題を解決し、Import Optimizer を実用化。
  * Core Features:
      * Rust-based Module Loader
      * Lazy Import Injection (MVP)
      * Runtime Hot Reloading
      * `pybun test` (Basic pytest compatibility)

### Phase 3: AI & Ecosystem (Month 7-12)

  * **Goal:** AI エージェントとの完全統合と、複雑なビルドのサポート。
  * Core Features:
      * JSON-RPC Error Reporting
      * MCP Server implementation
      * C/C++ Build Caching (Ninja integration)
      * Exchange connector + data catalog (Binance first)
      * Plugins for VSCode / Cursor

### Phase 4: Reliability & Enterprise (Month 12+)

  * **Goal:** エンタープライズ利用と大規模リポジトリ対応を完成。
  * Core Features:
      * 署名付きバイナリ/インデックスミラー + SBOM/SLSA provenance 出力
      * Remote Cache サーバー（CI とローカル共有）
      * 大規模モノレポ向けワークスペース（複数 `pyproject` の統合解決）
      * Backtest reproducibility（manifest/snapshot/report の固定化）
      * プラグインAPI（フック/サブコマンド拡張）

-----

## 9\. ライセンス

  * **License:** MIT License
  * **Business Model:**
      * Core: Open Source
      * Monetization: Enterprise Managed Cache / CI/CD Pipeline Optimization / AI Agent Cloud Integration

-----

## 10\. セキュリティ・安全性 (Security & Safety)

- **署名検証:** バイナリ・CPython アーカイブ・インデックスメタデータに署名を付与し、更新時に検証。
- **サンドボックス実行:** `pybun run --sandbox` で subprocess を seccomp/JobObject 制限下に実行（Linux/macOS/Windows で同等機能）。
- **サプライチェーン:** `pybun build` は SBOM (CycloneDX) を生成し、lock と一緒に保存。`pybun install --verify` でハッシュ検証を強制。
- **資格情報管理:** プライベートリポジトリは OS キーチェーンまたは `.netrc` を使用。環境変数は `--redact` でログからマスク。
- **取引所APIキー管理:** API キーは OS キーチェーン/環境変数から読み込み、JSON/text ログでは必ずマスク。読み取り専用キーを推奨し、取引権限付きキーは既定拒否。

## 11\. ログ・オブザーバビリティ (Logging & Observability)

- **構造化ログ:** すべてのコマンドは JSON イベントストリームを出力可能（ダウンロード開始/完了、ビルドタスク、テスト結果）。
- **トレース:** `PYBUN_TRACE=1` でトレースIDを付与し、ネットワーク/ファイルアクセスを収集。`pybun doctor` で提出用バンドルを生成。
- **メトリクス:** オプトインで匿名統計を送信（ダウンロードサイズ、成功/失敗率）。完全オフもサポート。

## 12\. 互換性ポリシー (Compatibility)

- **PEP 対応:** PEP 517/518/621/660/723 をサポート。`pyproject` 非対応のレガシー `setup.py` もラップで実行。
- **Wheel ABI:** manylinux/musllinux/macOS universal2/arm64 を優先。ABI 不一致時は明示警告と自動フォールバック（ソースビルド）を提供。
- **フォールバック:** 最適化が失敗した場合でも CPython 互換動作に自動切替し、速度低下を許容して correctness を維持。

## 13\. オープン質問 (Open Questions)

- `pybun test` のプラグイン互換度をどこまで担保するか（pytest 全プラグイン/fixture の 100% 互換を目指すか、非推奨 API の扱い）。
- Windows でのファイル監視/ホットリロードを何で実装するか（`ReadDirectoryChangesW` vs クロスプラットフォームライブラリ）。
- 内蔵 CPython の更新頻度と CVE 対応 SLA（例: 72h 以内リリース）をどう定義するか。
