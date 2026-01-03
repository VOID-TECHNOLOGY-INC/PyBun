# Demo GIF Creation Guide

PyBunのデモGIFを作成するためのガイドです。

## 推奨ツール

### 1. ターミナル録画

**macOS (推奨):**
- **[asciinema](https://asciinema.org/)** - ターミナル録画→SVGアニメーション変換
  ```bash
  brew install asciinema
  asciinema rec demo.cast
  ```

- **[VHS](https://github.com/charmbracelet/vhs)** - スクリプトでターミナル録画を自動化
  ```bash
  brew install vhs
  vhs demo.tape  # -> demo.gif を自動生成
  ```

- **[Terminalizer](https://terminalizer.com/)** - ターミナル→GIF
  ```bash
  npm install -g terminalizer
  terminalizer record demo
  terminalizer render demo
  ```

### 2. 画面録画 (MCP連携デモ用)

- **macOS:** Command + Shift + 5 → 画面収録
- **[LICEcap](https://www.cockos.com/licecap/)** - 直接GIF録画
- **[Kap](https://getkap.co/)** - macOS用の高品質GIF作成

## デモシナリオ

### A. 左側：PyBun高速インストール＆実行

```tape
# VHS tape file example
Output demo_left.gif

Set FontSize 14
Set Width 800
Set Height 400

Type "# PyBun Fast Install Demo"
Enter
Sleep 500ms

Type "pybun add requests httpx"
Enter
Sleep 2s

Type "pybun run -c -- \"import requests; print('Hello from PyBun!')\""
Enter
Sleep 1s

Type "pybun --format=json run -c -- \"print('JSON output!')\""
Enter
Sleep 2s
```

### B. 右側：MCP連携デモ (Claude Desktop)

**録画手順:**

1. Claude Desktopを起動
2. MCPサーバー設定を表示:
   ```json
   {
     "mcpServers": {
       "pybun": {
         "command": "pybun",
         "args": ["mcp", "serve", "--stdio"]
       }
     }
   }
   ```
3. Claudeに以下のプロンプトを入力:
   > "PyBunを使ってrequestsをインストールし、Pythonコードを実行してください"

4. AIがMCP経由でPyBunを操作し、JSON結果を受け取る様子を録画

### C. 統合GIF作成

```bash
# ffmpegで左右を結合
ffmpeg -i demo_left.gif -i demo_right.gif \
  -filter_complex "[0][1]hstack=inputs=2" \
  demo_combined.gif

# または ImageMagick
convert +append demo_left.gif demo_right.gif demo_combined.gif
```

## JSONアウトプット例

デモ内で表示するPyBun JSON出力例:

```bash
pybun --format=json run -c -- "print('Hello')"
```

```json
{
  "version": "1",
  "command": "pybun run",
  "status": "ok",
  "detail": {
    "summary": "executed inline code"
  },
  "events": [],
  "diagnostics": []
}
```

## サイズ・品質の推奨設定

- **解像度:** 1200x600 (左右分割) または 800x400 (単一)
- **フレームレート:** 10-15 FPS (GIFのファイルサイズ削減)
- **再生時間:** 10-15秒 (ループ)
- **最終GIFサイズ:** 2MB以下 (GitHub表示最適化)

## 配置場所

完成したGIFは以下に配置:

```
assets/
  └── demo.gif         # メインデモ
  └── demo_mcp.gif     # MCP連携デモ
  └── demo_speed.gif   # スピード比較デモ
```

README.mdでの埋め込み:
```markdown
<p align="center">
  <img src="assets/demo.gif" alt="PyBun Demo" width="800">
</p>
```
