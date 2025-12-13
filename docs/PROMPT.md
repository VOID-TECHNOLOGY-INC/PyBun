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
