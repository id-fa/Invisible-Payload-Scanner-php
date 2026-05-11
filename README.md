# Invisible Payload Scanner (PHP)

GlassWorm 系マルウェアで使われる「不可視 Unicode 文字」を検出するローカル Web ツールです。
PHP の組み込みサーバだけで動作し、外部に通信しません。

## 検出対象

| Rule ID | 文字範囲 | Severity | 用途 / 解説 |
|---|---|---|---|
| `vs_run` | U+FE00–FE0F, U+E0100–E01EF が連続 | **critical** | GlassWorm 主シグネチャ（異体字セレクタの大量埋め込み） |
| `vs_single` | 上記の単発出現 | low | 絵文字直後の U+FE0F は正規用途。誤検知に注意 |
| `tag_chars` | U+E0000–E007F | high | Unicode タグ文字（プロンプトインジェクション等） |
| `zero_width` | U+200B–200F, 2060–2064, FEFF | medium | ゼロ幅スペース・ZWJ・BOM |
| `bidi_control` | U+202A–202E, 2066–2069 | high | Trojan Source (CVE-2021-42574) |
| `hangul_filler` | U+115F, 1160, 3164, FFA0 | medium | JavaScript 識別子の不可視化に悪用 |
| `soft_hyphen` | U+00AD, 2028, 2029 | low | ソフトハイフン・行/段落セパレータ |

`vs_run` のしきい値（連続文字数）は UI から調整できます。デフォルト 8 / PC 全体スキャンは 16 推奨。

## 必要環境

- PHP 8.1 以上（`php` が PATH にあること）
- Windows / macOS / Linux

## 起動方法

### Windows
```
start.bat
```
ブラウザが自動で `http://127.0.0.1:8765/` を開きます。

### 任意のシェル
```
php -S 127.0.0.1:8765 -t .
```

## 使い方

1. ブラウザで開く
2. 上部の「検出設定」で `しきい値` / `拡張子` / `除外パス` を調整（空ならデフォルト）
3. 3 つのスキャン方式から選ぶ:
   - **テキスト貼付**: 任意の文字列をその場でスキャン
   - **ファイルアップロード**: 複数ファイル可
   - **ディレクトリ (ローカル)**: サーバ側のパスを指定して再帰スキャン
4. 結果テーブルで件数 / 行:列 / コードポイント / 周辺コンテキストを確認
5. `JSON エクスポート` で結果を保存

## セキュリティ

- アクセスは `127.0.0.1` / `::1` のみ許可（コード内で強制）
- ファイルは読み取り専用。実行・改変は行わない
- 1 ファイルあたりの上限を設定（デフォルト 5MB）
- バイナリらしいファイルは自動スキップ
- シンボリックリンクは追跡しない
- `node_modules` / `.git` / `vendor` などはデフォルト除外

## 参考

- GlassWorm 解説: https://note.com/konapieces/n/nedc01ec60271
- 参考実装 (PowerShell): https://github.com/ryojihido/Invisible-Payload-Scanner
- Trojan Source: CVE-2021-42574
