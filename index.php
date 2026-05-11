<?php
declare(strict_types=1);

require __DIR__ . '/lib/Scanner.php';

mb_internal_encoding('UTF-8');

// 安全装置: localhost 以外からのアクセスは拒否
$remote = $_SERVER['REMOTE_ADDR'] ?? '';
if (!in_array($remote, ['127.0.0.1', '::1', 'localhost'], true)) {
    http_response_code(403);
    exit('Forbidden: localhost only.');
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';

if ($action === 'scan_text' || $action === 'scan_dir' || $action === 'scan_upload') {
    header('Content-Type: application/json; charset=utf-8');
    try {
        $threshold = (int)($_POST['threshold'] ?? 8);
        $maxSize   = (int)($_POST['max_size'] ?? (5 * 1024 * 1024));

        $rawExt = trim((string)($_POST['ext'] ?? ''));
        $includeExt = $rawExt === ''
            ? Scanner::defaultIncludeExt()
            : array_values(array_filter(array_map(
                static fn($s) => ltrim(strtolower(trim($s)), '.'),
                preg_split('/[,;\s]+/', $rawExt) ?: []
            )));

        $rawExclude = trim((string)($_POST['exclude'] ?? ''));
        $excludePaths = $rawExclude === ''
            ? Scanner::defaultExcludePaths()
            : array_values(array_filter(array_map('trim', preg_split('/[,;]+/', $rawExclude) ?: [])));

        $scanner = new Scanner($threshold, $maxSize, $includeExt, $excludePaths);

        if ($action === 'scan_text') {
            $text = (string)($_POST['text'] ?? '');
            $result = $scanner->scanText($text, '(pasted text)');
            echo json_encode(['ok' => true, 'mode' => 'text', 'result' => $result], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }

        if ($action === 'scan_dir') {
            $dir = (string)($_POST['dir'] ?? '');
            if ($dir === '') throw new RuntimeException('ディレクトリパスを指定してください。');
            $result = $scanner->scanDirectory($dir);
            echo json_encode(['ok' => true, 'mode' => 'dir', 'dir' => $dir, 'result' => $result], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }

        if ($action === 'scan_upload') {
            if (empty($_FILES['files'])) {
                throw new RuntimeException('ファイルが添付されていません。');
            }
            $files = $_FILES['files'];
            $names = (array)$files['name'];
            $tmps  = (array)$files['tmp_name'];
            $errs  = (array)$files['error'];
            $sizes = (array)$files['size'];

            $allFindings = [];
            $scanned = 0;
            $skipped = [];

            foreach ($tmps as $i => $tmp) {
                $name = (string)$names[$i];
                $err  = (int)$errs[$i];
                $size = (int)$sizes[$i];
                if ($err !== UPLOAD_ERR_OK) {
                    $skipped[] = ['path' => $name, 'reason' => 'upload_error_' . $err];
                    continue;
                }
                if ($size > $maxSize) {
                    $skipped[] = ['path' => $name, 'reason' => 'size_over_limit'];
                    continue;
                }
                $bytes = @file_get_contents($tmp);
                if ($bytes === false) {
                    $skipped[] = ['path' => $name, 'reason' => 'read_error'];
                    continue;
                }
                $r = $scanner->scanText($bytes, $name);
                $allFindings = array_merge($allFindings, $r['findings']);
                $scanned++;
            }

            echo json_encode([
                'ok' => true,
                'mode' => 'upload',
                'result' => [
                    'findings' => $allFindings,
                    'stats' => [
                        'total' => count($allFindings),
                        'by_rule' => array_count_values(array_column($allFindings, 'rule_id')),
                        'by_severity' => array_count_values(array_column($allFindings, 'severity')),
                    ],
                    'scanned_files' => $scanned,
                    'skipped_files' => $skipped,
                ],
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }

    } catch (Throwable $e) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
        exit;
    }
}
?><!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<title>Invisible Payload Scanner (PHP)</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="assets/style.css?v=1">
</head>
<body>
<header>
  <h1>Invisible Payload Scanner <small>PHP</small></h1>
  <p class="lead">GlassWorm 系の不可視 Unicode 文字 (異体字セレクタ・ゼロ幅・双方向制御 など) を検出します。</p>
</header>

<main>
  <section class="config">
    <h2>検出設定</h2>
    <div class="grid">
      <label>VS 連続しきい値
        <input type="number" id="threshold" value="8" min="1" max="1000">
        <span class="hint">8 以上推奨 / PC 全体スキャンは 16</span>
      </label>
      <label>1 ファイル上限 (MB)
        <input type="number" id="max_size_mb" value="5" min="1" max="200">
      </label>
      <label>対象拡張子 (空でデフォルト)
        <input type="text" id="ext" placeholder="js;ts;ps1;cmd;json;html;...">
      </label>
      <label>除外パス断片 (; 区切り)
        <input type="text" id="exclude" placeholder="\node_modules\;\.git\;\vendor\">
      </label>
    </div>
  </section>

  <section class="tabs">
    <nav>
      <button class="tab active" data-tab="text">テキスト貼付</button>
      <button class="tab" data-tab="upload">ファイルアップロード</button>
      <button class="tab" data-tab="dir">ディレクトリ (ローカル)</button>
    </nav>

    <div class="tab-pane active" data-pane="text">
      <h2>テキストを貼り付けてスキャン</h2>
      <textarea id="text" rows="10" placeholder="ここにコードや文字列を貼り付け..."></textarea>
      <button id="btn-scan-text" class="primary">スキャン</button>
    </div>

    <div class="tab-pane" data-pane="upload">
      <h2>ファイルをアップロードしてスキャン</h2>
      <input type="file" id="files" multiple>
      <button id="btn-scan-upload" class="primary">スキャン</button>
      <p class="hint">複数ファイル可。サイズ上限を超えるものはスキップされます。</p>
    </div>

    <div class="tab-pane" data-pane="dir">
      <h2>ローカルディレクトリを再帰スキャン</h2>
      <input type="text" id="dir" placeholder="例: D:\_CODE\target_project">
      <button id="btn-scan-dir" class="primary">スキャン</button>
      <p class="hint warn">PHP プロセスが読めるパスのみ。ローカル実行専用。</p>
    </div>
  </section>

  <section id="status" class="status hidden"></section>

  <section id="result" class="result hidden">
    <h2>検出結果 <span id="summary"></span></h2>
    <div class="result-actions">
      <button id="btn-export">JSON エクスポート</button>
      <label class="filter">
        Severity フィルタ:
        <select id="filter-severity">
          <option value="">すべて</option>
          <option value="critical">critical</option>
          <option value="high+">high+ (high 以上)</option>
          <option value="high">high</option>
          <option value="medium+">medium+ (medium 以上)</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
      </label>
    </div>
    <table id="findings">
      <thead>
        <tr>
          <th>Severity</th><th>Rule</th><th>Source</th><th>Line:Col</th>
          <th>Len</th><th>Codepoints</th><th>Context</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </section>

  <section class="reference">
    <h2>検出ルール</h2>
    <table class="rules">
      <thead><tr><th>ID</th><th>対象</th><th>Severity</th><th>説明</th></tr></thead>
      <tbody>
        <tr><td>vs_run</td><td>U+FE00-FE0F / U+E0100-E01EF 連続</td><td class="sev-critical">critical</td><td>GlassWorm 主シグネチャ</td></tr>
        <tr><td>vs_single</td><td>異体字セレクタ単発</td><td class="sev-low">low</td><td>絵文字直後の U+FE0F は正規</td></tr>
        <tr><td>tag_chars</td><td>U+E0000-E007F</td><td class="sev-high">high</td><td>Unicode タグ文字</td></tr>
        <tr><td>zero_width</td><td>U+200B-200F / 2060-2064 / FEFF</td><td class="sev-medium">medium</td><td>ゼロ幅・BOM</td></tr>
        <tr><td>bidi_control</td><td>U+202A-202E / 2066-2069</td><td class="sev-high">high</td><td>Trojan Source</td></tr>
        <tr><td>hangul_filler</td><td>U+115F / 1160 / 3164 / FFA0</td><td class="sev-medium">medium</td><td>JS 識別子悪用</td></tr>
        <tr><td>soft_hyphen</td><td>U+00AD / 2028 / 2029</td><td class="sev-low">low</td><td>ソフトハイフン等</td></tr>
      </tbody>
    </table>
  </section>
</main>

<footer>
  <p>ローカル実行専用。サーバへのアクセスは 127.0.0.1 / ::1 のみ許可されます。</p>
</footer>

<script src="assets/app.js?v=1"></script>
</body>
</html>
