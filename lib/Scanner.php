<?php
declare(strict_types=1);

/**
 * Invisible Payload Scanner
 *
 * GlassWorm 系マルウェアで使われる「不可視 Unicode 文字」を検出する。
 *  - 異体字セレクタ U+FE00-U+FE0F / U+E0100-U+E01EF
 *  - ゼロ幅文字   U+200B-U+200F / U+2060-U+2064 / U+FEFF
 *  - 双方向制御   U+202A-U+202E / U+2066-U+2069 (Trojan Source)
 *  - Hangul filler U+3164 / U+FFA0 (JS 識別子悪用)
 *  - タグ文字     U+E0000-U+E007F
 */
final class Scanner
{
    /** @var array<string,array{label:string,severity:string,pattern:string,threshold:int,description:string}> */
    private array $rules;

    /** @var int 1 ファイルあたりの最大サイズ (byte) */
    private int $maxFileSize;

    /** @var string[] スキャン対象拡張子 (小文字 / 先頭ドット無し) */
    private array $includeExt;

    /** @var string[] 除外パスフラグメント */
    private array $excludePaths;

    /** @var int VS 連続しきい値 (低いほど厳しい) */
    private int $vsThreshold;

    public function __construct(
        int $vsThreshold = 8,
        int $maxFileSize = 5 * 1024 * 1024,
        array $includeExt = [],
        array $excludePaths = []
    ) {
        $this->vsThreshold  = max(1, $vsThreshold);
        $this->maxFileSize  = $maxFileSize;
        $this->includeExt   = $includeExt ?: self::defaultIncludeExt();
        $this->excludePaths = $excludePaths ?: self::defaultExcludePaths();
        $this->rules        = $this->buildRules($this->vsThreshold);
    }

    /** @return string[] */
    public static function defaultIncludeExt(): array
    {
        return [
            'js','mjs','cjs','jsx','ts','tsx',
            'ps1','psm1','psd1','cmd','bat','sh',
            'json','yml','yaml','toml','ini',
            'html','htm','vue','svelte',
            'php','py','rb','go','rs','c','cpp','h','hpp','cs','java','kt','swift',
            'lua','pl','sql',
        ];
    }

    /** @return string[] */
    public static function defaultExcludePaths(): array
    {
        return [
            '\\node_modules\\','/node_modules/',
            '\\.git\\','/.git/',
            '\\vendor\\','/vendor/',
            '\\dist\\','/dist/',
            '\\build\\','/build/',
            '\\.next\\','/.next/',
            '\\.cache\\','/.cache/',
        ];
    }

    /**
     * テキストを 1 つ受け取り検出結果を返す。
     *
     * @return array{
     *   findings: list<array<string,mixed>>,
     *   stats: array{total:int,by_rule:array<string,int>,by_severity:array<string,int>}
     * }
     */
    public function scanText(string $text, string $sourceLabel = '(text)'): array
    {
        $findings = [];

        foreach ($this->rules as $ruleId => $rule) {
            if (!preg_match_all($rule['pattern'], $text, $m, PREG_OFFSET_CAPTURE)) {
                continue;
            }
            foreach ($m[0] as $hit) {
                [$matched, $byteOffset] = $hit;
                $count = mb_strlen($matched, 'UTF-8');

                [$line, $col] = $this->byteOffsetToLineCol($text, (int)$byteOffset);
                $context     = $this->extractContext($text, (int)$byteOffset, strlen($matched));
                $codepoints  = $this->codepointsOf($matched);

                $findings[] = [
                    'source'      => $sourceLabel,
                    'rule_id'     => $ruleId,
                    'rule_label'  => $rule['label'],
                    'severity'    => $rule['severity'],
                    'description' => $rule['description'],
                    'line'        => $line,
                    'column'      => $col,
                    'byte_offset' => (int)$byteOffset,
                    'match_len'   => $count,
                    'codepoints'  => $codepoints,
                    'visible'     => $this->visualize($matched),
                    'context'     => $context,
                ];
            }
        }

        return [
            'findings' => $findings,
            'stats'    => $this->summarize($findings),
        ];
    }

    /**
     * ディレクトリを再帰スキャンする。
     *
     * @return array{
     *   findings: list<array<string,mixed>>,
     *   stats: array<string,mixed>,
     *   scanned_files: int,
     *   skipped_files: list<array{path:string,reason:string}>
     * }
     */
    public function scanDirectory(string $rootDir): array
    {
        $real = realpath($rootDir);
        if ($real === false || !is_dir($real)) {
            throw new RuntimeException("ディレクトリが存在しません: {$rootDir}");
        }

        $findings = [];
        $scanned  = 0;
        $skipped  = [];

        $iter = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($real, FilesystemIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS === 0 ? FilesystemIterator::SKIP_DOTS : FilesystemIterator::SKIP_DOTS),
                function ($current): bool {
                    /** @var SplFileInfo $current */
                    $path = $current->getPathname();
                    foreach ($this->excludePaths as $frag) {
                        if (stripos($path, $frag) !== false) {
                            return false;
                        }
                    }
                    if ($current->isLink()) {
                        return false;
                    }
                    return true;
                }
            )
        );

        foreach ($iter as $fileInfo) {
            /** @var SplFileInfo $fileInfo */
            if (!$fileInfo->isFile()) {
                continue;
            }
            $path = $fileInfo->getPathname();
            $ext  = strtolower($fileInfo->getExtension());

            if ($this->includeExt && !in_array($ext, $this->includeExt, true)) {
                continue;
            }
            $size = $fileInfo->getSize();
            if ($size === false || $size > $this->maxFileSize) {
                $skipped[] = ['path' => $path, 'reason' => 'size_over_limit'];
                continue;
            }

            $bytes = @file_get_contents($path);
            if ($bytes === false) {
                $skipped[] = ['path' => $path, 'reason' => 'read_error'];
                continue;
            }
            if ($this->looksBinary($bytes)) {
                $skipped[] = ['path' => $path, 'reason' => 'binary'];
                continue;
            }

            $result = $this->scanText($bytes, $path);
            if ($result['findings']) {
                $findings = array_merge($findings, $result['findings']);
            }
            $scanned++;
        }

        return [
            'findings'      => $findings,
            'stats'         => $this->summarize($findings),
            'scanned_files' => $scanned,
            'skipped_files' => $skipped,
        ];
    }

    // ---------- internal ----------

    /**
     * @return array<string,array{label:string,severity:string,pattern:string,threshold:int,description:string}>
     */
    private function buildRules(int $vsThreshold): array
    {
        // VS Base + VS Supplement (GlassWorm の主シグネチャ)
        $vsClass = '[\\x{FE00}-\\x{FE0F}\\x{E0100}-\\x{E01EF}]';

        return [
            'vs_run' => [
                'label'       => 'Variation Selector run',
                'severity'    => 'critical',
                'pattern'     => "/(?:{$vsClass}){{$vsThreshold},}/u",
                'threshold'   => $vsThreshold,
                'description' => 'GlassWorm が使う異体字セレクタの連続。閾値以上連続したらほぼ確実に隠匿ペイロード。',
            ],
            'vs_single' => [
                'label'       => 'Variation Selector (single / short)',
                'severity'    => 'low',
                'pattern'     => "/(?:{$vsClass})+/u",
                'threshold'   => 1,
                'description' => '単発の異体字セレクタ。絵文字直後の U+FE0F は正規用途なので要文脈確認。',
            ],
            'tag_chars' => [
                'label'       => 'Tag characters (U+E0000-U+E007F)',
                'severity'    => 'high',
                'pattern'     => '/[\\x{E0001}\\x{E0020}-\\x{E007F}]+/u',
                'threshold'   => 1,
                'description' => 'Unicode タグ文字。AI プロンプトインジェクションや隠匿命令で悪用される。',
            ],
            'zero_width' => [
                'label'       => 'Zero-width / invisible separators',
                'severity'    => 'medium',
                'pattern'     => '/[\\x{200B}-\\x{200F}\\x{2060}-\\x{2064}\\x{FEFF}]+/u',
                'threshold'   => 1,
                'description' => 'ゼロ幅スペース / ゼロ幅ジョイナー / BOM など。トークン分割を狂わせる用途。',
            ],
            'bidi_control' => [
                'label'       => 'Bidi control (Trojan Source)',
                'severity'    => 'high',
                'pattern'     => '/[\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}]+/u',
                'threshold'   => 1,
                'description' => '双方向制御文字。CVE-2021-42574 (Trojan Source) で利用される視覚的偽装。',
            ],
            'hangul_filler' => [
                'label'       => 'Hangul filler (identifier abuse)',
                'severity'    => 'medium',
                'pattern'     => '/[\\x{115F}\\x{1160}\\x{3164}\\x{FFA0}]+/u',
                'threshold'   => 1,
                'description' => 'ハングルフィラー類。JavaScript で見えない識別子を作るために悪用される。',
            ],
            'soft_hyphen' => [
                'label'       => 'Soft hyphen / line separators',
                'severity'    => 'low',
                'pattern'     => '/[\\x{00AD}\\x{2028}\\x{2029}]+/u',
                'threshold'   => 1,
                'description' => 'ソフトハイフン / ライン・パラグラフセパレータ。視覚的に欠落するため隠匿に使われる。',
            ],
        ];
    }

    /** @return array{0:int,1:int} 1-based line / column */
    private function byteOffsetToLineCol(string $text, int $byteOffset): array
    {
        $head = substr($text, 0, $byteOffset);
        $line = substr_count($head, "\n") + 1;

        $lastNl = strrpos($head, "\n");
        $lineHead = $lastNl === false ? $head : substr($head, $lastNl + 1);
        $col = mb_strlen($lineHead, 'UTF-8') + 1;

        return [$line, $col];
    }

    private function extractContext(string $text, int $byteOffset, int $byteLen): string
    {
        $start = max(0, $byteOffset - 40);
        $end   = min(strlen($text), $byteOffset + $byteLen + 40);
        $slice = substr($text, $start, $end - $start);
        $slice = $this->trimToValidUtf8($slice);
        return $this->visualize($slice);
    }

    /** バイト切断で壊れた UTF-8 シーケンスを両端からトリム */
    private function trimToValidUtf8(string $s): string
    {
        // 先頭: continuation byte (10xxxxxx) を捨てる
        while ($s !== '' && (ord($s[0]) & 0xC0) === 0x80) {
            $s = substr($s, 1);
        }
        // 末尾: 不完全シーケンスを最大 3 バイト分まで削る
        for ($i = 0; $i < 3 && $s !== '' && !mb_check_encoding($s, 'UTF-8'); $i++) {
            $s = substr($s, 0, -1);
        }
        return $s;
    }

    /** 不可視文字を [U+XXXX] 表記に置換 */
    private function visualize(string $s): string
    {
        $out  = '';
        $len  = mb_strlen($s, 'UTF-8');
        for ($i = 0; $i < $len; $i++) {
            $ch = mb_substr($s, $i, 1, 'UTF-8');
            $cp = $this->ord($ch);
            if ($this->isInvisible($cp)) {
                $out .= sprintf('[U+%04X]', $cp);
            } elseif ($cp === 0x09) {
                $out .= '\\t';
            } elseif ($cp === 0x0A) {
                $out .= '\\n';
            } elseif ($cp === 0x0D) {
                $out .= '\\r';
            } else {
                $out .= $ch;
            }
        }
        return $out;
    }

    /** @return list<string> "U+XXXX" 配列 */
    private function codepointsOf(string $s): array
    {
        $out = [];
        $len = mb_strlen($s, 'UTF-8');
        for ($i = 0; $i < $len; $i++) {
            $cp = $this->ord(mb_substr($s, $i, 1, 'UTF-8'));
            $out[] = sprintf('U+%04X', $cp);
        }
        return $out;
    }

    private function ord(string $ch): int
    {
        $cp = mb_ord($ch, 'UTF-8');
        return $cp === false ? 0 : $cp;
    }

    private function isInvisible(int $cp): bool
    {
        if ($cp >= 0xFE00 && $cp <= 0xFE0F) return true;
        if ($cp >= 0xE0100 && $cp <= 0xE01EF) return true;
        if ($cp >= 0xE0000 && $cp <= 0xE007F) return true;
        if ($cp >= 0x200B && $cp <= 0x200F) return true;
        if ($cp >= 0x2060 && $cp <= 0x2064) return true;
        if ($cp === 0xFEFF) return true;
        if ($cp >= 0x202A && $cp <= 0x202E) return true;
        if ($cp >= 0x2066 && $cp <= 0x2069) return true;
        if ($cp === 0x115F || $cp === 0x1160 || $cp === 0x3164 || $cp === 0xFFA0) return true;
        if ($cp === 0x00AD) return true;
        if ($cp === 0x2028 || $cp === 0x2029) return true;
        return false;
    }

    private function looksBinary(string $bytes): bool
    {
        $sample = substr($bytes, 0, 8000);
        if ($sample === '') return false;
        if (strpos($sample, "\x00") !== false) return true;
        // 8bit 制御文字の比率
        $nonText = 0;
        $len = strlen($sample);
        for ($i = 0; $i < $len; $i++) {
            $c = ord($sample[$i]);
            if ($c < 7 || ($c > 13 && $c < 32 && $c !== 27)) {
                $nonText++;
            }
        }
        return ($nonText / max(1, $len)) > 0.30;
    }

    /**
     * @param list<array<string,mixed>> $findings
     * @return array{total:int,by_rule:array<string,int>,by_severity:array<string,int>}
     */
    private function summarize(array $findings): array
    {
        $byRule = [];
        $bySev  = [];
        foreach ($findings as $f) {
            $byRule[$f['rule_id']]  = ($byRule[$f['rule_id']]  ?? 0) + 1;
            $bySev[$f['severity']]  = ($bySev[$f['severity']]  ?? 0) + 1;
        }
        return [
            'total'       => count($findings),
            'by_rule'     => $byRule,
            'by_severity' => $bySev,
        ];
    }
}
