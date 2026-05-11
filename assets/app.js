(() => {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let lastResult = null;

  // --- tabs ---
  $$('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('.tab').forEach((b) => b.classList.toggle('active', b === btn));
      const target = btn.dataset.tab;
      $$('.tab-pane').forEach((p) => p.classList.toggle('active', p.dataset.pane === target));
    });
  });

  function commonFields(form) {
    form.append('threshold', $('#threshold').value || '8');
    form.append('max_size', String((parseInt($('#max_size_mb').value || '5', 10)) * 1024 * 1024));
    form.append('ext', $('#ext').value || '');
    form.append('exclude', $('#exclude').value || '');
  }

  async function postForm(action, build) {
    setStatus('スキャン中...', 'pending');
    const form = new FormData();
    form.append('action', action);
    commonFields(form);
    build(form);

    try {
      const res = await fetch('index.php?action=' + action, { method: 'POST', body: form });
      const json = await res.json();
      if (!json.ok) throw new Error(json.error || 'unknown error');
      lastResult = json;
      render(json);
      setStatus(buildStatusLine(json), 'ok');
    } catch (e) {
      setStatus('エラー: ' + e.message, 'error');
      $('#result').classList.add('hidden');
    }
  }

  function buildStatusLine(json) {
    const r = json.result;
    const sev = r.stats.by_severity || {};
    const sevStr = Object.entries(sev).map(([k,v]) => `${k}:${v}`).join(' ');
    const fileLine = json.mode === 'text'
      ? ''
      : ` / scanned: ${r.scanned_files || 0} skipped: ${(r.skipped_files||[]).length}`;
    return `検出: ${r.stats.total} 件 ${sevStr}${fileLine}`;
  }

  $('#btn-scan-text').addEventListener('click', () => {
    postForm('scan_text', (f) => f.append('text', $('#text').value || ''));
  });

  $('#btn-scan-dir').addEventListener('click', () => {
    const dir = $('#dir').value.trim();
    if (!dir) { setStatus('ディレクトリパスを入力してください。', 'error'); return; }
    postForm('scan_dir', (f) => f.append('dir', dir));
  });

  $('#btn-scan-upload').addEventListener('click', () => {
    const files = $('#files').files;
    if (!files || files.length === 0) { setStatus('ファイルを選択してください。', 'error'); return; }
    postForm('scan_upload', (f) => {
      for (const file of files) f.append('files[]', file);
    });
  });

  $('#btn-export').addEventListener('click', () => {
    if (!lastResult) return;
    const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    a.href = url; a.download = `invisible-scan-${ts}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  });

  $('#filter-severity').addEventListener('change', () => render(lastResult));

  function setStatus(msg, kind) {
    const el = $('#status');
    el.classList.remove('hidden', 'error', 'ok', 'pending');
    if (kind) el.classList.add(kind);
    el.textContent = msg;
  }

  const SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

  function matchSeverity(filter, sev) {
    if (!filter) return true;
    if (filter.endsWith('+')) {
      const min = SEV_RANK[filter.slice(0, -1)] || 0;
      return (SEV_RANK[sev] || 0) >= min;
    }
    return sev === filter;
  }

  function render(json) {
    if (!json) return;
    const r = json.result;
    const filter = $('#filter-severity').value;
    const findings = r.findings.filter((f) => matchSeverity(filter, f.severity));

    const tbody = $('#findings tbody');
    tbody.innerHTML = '';
    for (const f of findings) {
      const tr = document.createElement('tr');
      tr.append(
        td(`<span class="sev sev-${f.severity}">${f.severity}</span>`, true),
        td(escapeHtml(f.rule_label)),
        td(escapeHtml(f.source)),
        td(`${f.line}:${f.column}`),
        td(String(f.match_len)),
        td(escapeHtml(f.codepoints.slice(0, 8).join(' ') + (f.codepoints.length > 8 ? ' …' : ''))),
        td(`<span class="ctx">${highlightVS(f.context)}</span>`, true),
      );
      tbody.append(tr);
    }
    $('#summary').textContent = `(${findings.length} / ${r.findings.length} 表示)`;
    $('#result').classList.remove('hidden');
  }

  function td(content, asHtml=false) {
    const el = document.createElement('td');
    if (asHtml) el.innerHTML = content; else el.textContent = content;
    return el;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }

  function highlightVS(s) {
    return escapeHtml(s).replace(/\[U\+[0-9A-F]{4,6}\]/g, (m) => `<span class="vs">${m}</span>`);
  }
})();
