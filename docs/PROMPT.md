# タスク実行プロンプト

@docs/PLAN.md を参照して、指定されたPR（例: PR2.1）の実装を進めてください。

## 実装フロー

### 1. ブランチ作成
- `feature/<pr番号>-<簡潔な説明>` の形式でブランチを作成
  - 例: `feature/pr2.1-rust-module-finder`
- `main` ブランチから分岐すること

### 2. TDD（テスト駆動開発）で実装
- **Red**: まず失敗するテストを書く
- **Green**: テストが通る最小限のコードを実装
- **Refactor**: コードを整理・改善
- ユニットテストと統合テストの両方を作成

### 3. E2Eテストの実行
```bash
just test-e2e  # または cargo test --test '*'
```
- 既存のE2Eテストが壊れていないことを確認
- 新機能のE2Eテストを追加
- ベンチマークスクリプトで性能を確認
  - **Note**: 正確な計測のため、`cargo build --release` を完了させてから実行すること。
  - **Cold Start計測**: キャッシュ (`~/.cache/pybun/pep723-envs`) をクリアして実行すること。
  - **コマンド**: `PATH=$(pwd)/target/release:$PATH python3 scripts/benchmark/bench.py -s run --format markdown`

### 4. コード品質の確認
```bash
just lint      # clippy + fmt check
just fmt       # フォーマット適用
cargo test     # 全テスト実行
```

### 5. PLAN.md の更新
- 実装したPRのステータスを `[DONE]` に更新
- 実装内容の要約を `Current:` セクションに追記
- テストの詳細を `Tests:` セクションに追記

### 6. コミット & プッシュ
- コミットメッセージ形式: `<type>(<scope>): <description>`
  - type: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`
  - 例: `feat(resolver): add SAT solver for dependency resolution`
- 適切な粒度でコミットを分割

### 7. Pull Request 作成
```bash
gh pr create --title "<PR番号>: <タイトル>" --body "<説明>"
```
- PRテンプレートに従って記述
- 関連するIssueやPRをリンク

### 8. CI結果の確認と対応
```bash
gh pr checks   # CIの状態確認
gh run list    # ワークフロー一覧
gh run view    # 詳細確認
```
- CIが失敗した場合は原因を特定して修正
- 全てのチェックがパスするまで繰り返す

## チェックリスト

- [ ] ブランチを `main` から作成した
- [ ] テストを先に書いた（TDD）
- [ ] 全てのテストがパスする
- [ ] `just lint` がエラーなし
- [ ] E2Eテストを実行した
- [ ] PLAN.md を更新した
- [ ] コミットメッセージが適切
- [ ] PRを作成した
- [ ] CIが全てパス

## 注意事項

- 既存のテストを壊さないこと
- 依存関係のあるPRがマージされていることを確認
- `--format=json` オプションは全コマンドで対応すること（AI-friendly）
- macOS/Linux を優先、Windows はスタブで対応

---

# Issue 実装プロンプト

@docs/PROMPT.md に従って Issue #<番号> を実装する。

## 実装フロー（Issue番号指定）

### 1. Issue 内容の確認
```bash
gh issue view <番号>
```
- Issue の要件・背景・受け入れ条件を把握する
- 関連する既存コード・テスト・ドキュメントを調査する

### 2. ブランチ作成
- `feature/issue-<番号>-<簡潔な説明>` の形式でブランチを作成
  - 例: `feature/issue-157-benchmark-hermetic`
- `main` ブランチから分岐すること

### 3. 適切な Skills の選択と TDD 実装
- タスクに応じて以下の Skills を選択して使うこと:
  - `/tdd-workflow` — 新機能・バグ修正・リファクタ全般（テストファースト）
  - `/rust-test` — Rust テスト TDD（cargo-llvm-cov でカバレッジ確認）
  - `/rust-review` — Rust コードレビュー
  - `/security-review` — セキュリティリスクがある変更
  - `/plan` — 複雑な実装の前に設計を整理
- **Red → Green → Refactor** のサイクルを守る
- ユニットテスト・統合テスト・E2Eテストをすべて作成する

### 4. E2E テストの実施
```bash
cargo test --test '*'          # 全統合テスト
cargo test e2e_general         # E2E 試験
just lint                      # clippy + fmt check
```

### 5. コミット & プッシュ & PR 作成
```bash
git push -u origin <ブランチ名>
gh pr create --title "fix/feat(<scope>): <説明> (Issue #<番号>)" \
  --body "Closes #<番号>\n\n## Summary\n...\n\n## Test plan\n- [ ] ..."
```

### 6. サブエージェントによるコードレビュー & PR へのコメント投稿
- `/code-review` または `code-review` サブエージェントでコードレビューを実施
- 指摘内容を `gh pr comment` または `gh api` でインラインコメントとして PR に投稿
  ```bash
  gh pr comment <PR番号> --body "<レビュー内容>"
  ```

### 7. 指摘事項への対処
- CRITICAL / HIGH の指摘は必ず修正する
- MEDIUM の指摘は可能な限り対処する
- 修正後に再コミット & プッシュ

### 8. CI がオールグリーンになるまで対処
```bash
gh pr checks <PR番号>          # CI 状態確認（全グリーンまでポーリング）
gh run view                    # 失敗時の詳細確認
```
- 失敗した場合は原因を特定して修正し、再プッシュ
- 全チェックがパスするまで繰り返す

### 9. 実装内容の最終検証 & マージ
- Issue の受け入れ条件を一つずつ確認し、検証内容をまとめる
- 検証結果を `/review` または `code-review` サブエージェントでレビュー
- 問題がなければマージ:
  ```bash
  gh pr merge <PR番号> --squash --delete-branch
  ```
- 問題があれば修正し、実装 → 検証 → レビューを正しい実装になるまで繰り返す

## Issue 実装チェックリスト

- [ ] Issue の要件・受け入れ条件を把握した
- [ ] `main` からブランチを作成した
- [ ] 適切な Skills を選択して使った
- [ ] テストを先に書いた（TDD: Red → Green → Refactor）
- [ ] ユニット・統合・E2E テストが全てパスする
- [ ] `just lint` がエラーなし
- [ ] コミット & プッシュ & PR を作成した
- [ ] サブエージェントでコードレビューを実施し PR にコメントを投稿した
- [ ] 指摘事項に対処した
- [ ] CI が全てグリーン
- [ ] Issue の受け入れ条件を検証し問題なし
- [ ] PR をマージした

## サブエージェントへの委任時の注意（完了報告の自己申告を鵜呑みにしない）

複数の Issue を並行して worktree + バックグラウンドサブエージェントに委任する際、サブエージェントが `status: completed` を返しても、それは自己申告に過ぎない。実際には `cargo test` の実行途中で応答を打ち切っており、変更はコミットされていなかった、というケースが発生した（Issue #294 対応時）。

**必須の検証手順**（サブエージェントの完了報告を受け取ったら）:

1. 該当 worktree で `git log --oneline -3` と `git status --short` を自分の Bash ツールで直接実行し、コミットが実在するか確認する。
2. 未コミットの変更が残っている場合は、`cargo test` / `cargo clippy --all-targets --all-features -- -D warnings` / `cargo fmt -- --check` を自分で実行して結果を確認する（サブエージェントの報告文だけで判断しない）。
3. 作業が中断されていた場合は、同じサブエージェント（同一 agentId）に `SendMessage` で再開を依頼するか、フルコンテキストを与えて再開させる。新しい `Agent` を素で立ち上げると worktree パスなどの前提知識を失い、二重作業や迷子になるリスクがある。
4. 全チェックがグリーンであることを自分の目で確認してから、初めて push / PR 作成に進む。

**理由**: バックグラウンドエージェントの「完了」通知は、ターン数上限や応答の打ち切りでも発火することがあり、実際のタスク完了を保証しない。特に `cargo test` のようなビルドに数分かかる処理を跨ぐ場合、サブエージェントが結果を待たずに応答してしまう可能性がある。
