import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Layers, Terminal, Code2, FolderOpen, FileJson, AlertTriangle,
  CheckCircle, RefreshCw, Play, BookOpen, Cpu, Zap, File
} from 'lucide-react';

const riskColor = { Düşük: '#22c55e', Orta: '#f59e0b', Yüksek: '#ef4444', Kritik: '#dc2626' };

const DEFAULT_SCRIPT = `# Hızlı Risk Taraması\nformat:\nsize:\nentropy:\nrisk:\nstrings: 6`;

export default function PlatformPage({ filePath }) {
  const [tab, setTab] = useState('format');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  // E1 — Format
  const [formatFile, setFormatFile] = useState(filePath || '');
  const [elfArch, setElfArch] = useState('x64');

  // E2 — Batch / Export
  const [batchFolder, setBatchFolder] = useState('');
  const [maxFiles, setMaxFiles] = useState(50);
  const [exportPath, setExportPath] = useState('');

  // E3 — Script
  const [script, setScript] = useState(DEFAULT_SCRIPT);
  const [templates, setTemplates] = useState(null);

  const run = async (fn) => {
    setLoading(true); setError(null); setResult(null);
    try { setResult(await fn()); }
    catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const tabs = [
    { key: 'format',  label: 'Format Analizi',   icon: Layers   },
    { key: 'batch',   label: 'Toplu Tarama',      icon: FolderOpen },
    { key: 'script',  label: 'Script Engine',     icon: Code2    },
    { key: 'export',  label: 'JSON Dışa Aktar',   icon: FileJson },
  ];

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 24, gap: 16, overflowY: 'auto' }}>
      {/* Başlık */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Zap size={20} color="#f59e0b" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>Platform & Otomasyon</span>
        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(245,158,11,0.12)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.25)', fontWeight: 600 }}>FAZ E</span>
        <span style={{ fontSize: 10, color: '#4b5563' }}>ELF · APK · .NET · Batch · Script</span>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        {tabs.map(t => {
          const Icon = t.icon;
          return (
            <button key={t.key} onClick={() => { setTab(t.key); setResult(null); setError(null); }}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', background: 'none', border: 'none', cursor: 'pointer', fontSize: 11, fontWeight: tab === t.key ? 700 : 400, color: tab === t.key ? '#e2e8f0' : '#6b7280', borderBottom: tab === t.key ? '2px solid #f59e0b' : '2px solid transparent', marginBottom: -1 }}>
              <Icon size={12} /> {t.label}
            </button>
          );
        })}
      </div>

      {/* Hata */}
      {error && (
        <div style={{ display: 'flex', gap: 8, padding: '8px 12px', borderRadius: 5, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#fca5a5', fontSize: 11 }}>
          <AlertTriangle size={13} style={{ flexShrink: 0 }} /> {error}
          <button onClick={() => setError(null)} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer' }}>✕</button>
        </div>
      )}

      {/* Format Analizi (E1) */}
      {tab === 'format' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 11, color: '#6b7280' }}>
            PE, ELF, APK/DEX, .NET ve Raw binary formatlarını otomatik tespit eder ve analiz eder.
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input value={formatFile} onChange={e => setFormatFile(e.target.value)}
              placeholder="Dosya yolu (örn: C:\test.exe)"
              style={{ flex: 1, minWidth: 260, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.25)', borderRadius: 5, padding: '7px 12px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <select value={elfArch} onChange={e => setElfArch(e.target.value)}
              style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.25)', borderRadius: 5, padding: '7px 10px', fontSize: 11, color: '#e2e8f0', outline: 'none' }}>
              <option value="x64">x64</option>
              <option value="x86">x86</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {[
              { label: 'Format Tespit', fn: () => invoke('detect_format', { filePath: formatFile }) },
              { label: 'ELF Analizi', fn: () => invoke('analyze_elf', { filePath: formatFile }) },
              { label: '.NET Analizi', fn: () => invoke('analyze_dotnet', { filePath: formatFile }) },
              { label: 'APK/DEX', fn: () => invoke('analyze_apk', { filePath: formatFile }) },
              { label: 'Raw Shellcode', fn: () => invoke('analyze_shellcode_file', { filePath: formatFile, arch: elfArch }) },
            ].map(({ label, fn }) => (
              <button key={label} disabled={loading || !formatFile.trim()} onClick={() => run(fn)}
                style={{ padding: '6px 14px', borderRadius: 5, background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)', color: '#f59e0b', cursor: loading ? 'not-allowed' : 'pointer', fontSize: 11, fontWeight: 600 }}>
                {label}
              </button>
            ))}
          </div>
          {result && <ResultPanel data={result} />}
        </div>
      )}

      {/* Toplu Tarama (E2) */}
      {tab === 'batch' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 11, color: '#6b7280' }}>
            Klasördeki tüm binary dosyaları toplu analiz eder. Maks 100 dosya.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input value={batchFolder} onChange={e => setBatchFolder(e.target.value)}
              placeholder="Klasör yolu (örn: C:\Samples)"
              style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.25)', borderRadius: 5, padding: '7px 12px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <input type="number" value={maxFiles} onChange={e => setMaxFiles(Number(e.target.value))}
              min={1} max={100}
              style={{ width: 70, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.25)', borderRadius: 5, padding: '7px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none', textAlign: 'center' }} />
            <button disabled={loading || !batchFolder.trim()} onClick={() => run(() => invoke('batch_scan_folder', { folderPath: batchFolder, maxFiles }))}
              style={{ padding: '7px 16px', borderRadius: 5, background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.35)', color: '#f59e0b', cursor: loading ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 600 }}>
              {loading ? <RefreshCw size={13} style={{ animation: 'spin 1s linear infinite' }} /> : 'Tara'}
            </button>
          </div>
          {result && <BatchResultPanel data={result} />}
        </div>
      )}

      {/* Script Engine (E3) */}
      {tab === 'script' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 11, color: '#6b7280' }}>
            Komut satırı tarzı analiz scriptleri yazın ve çalıştırın. Desteklenen: format, size, entropy, strings, risk, echo
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
            <textarea value={script} onChange={e => setScript(e.target.value)} rows={10}
              style={{ flex: 1, background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 6, padding: '10px 12px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace', lineHeight: 1.6, resize: 'vertical' }} />
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input value={formatFile} onChange={e => setFormatFile(e.target.value)}
              placeholder="Hedef dosya yolu"
              style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 5, padding: '6px 12px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <button disabled={loading || !formatFile.trim()} onClick={() => run(() => invoke('run_analysis_script', { filePath: formatFile, script }))}
              style={{ display: 'flex', gap: 6, alignItems: 'center', padding: '7px 16px', borderRadius: 5, background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.35)', color: '#f59e0b', cursor: loading ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 600 }}>
              <Play size={12} /> Çalıştır
            </button>
            <button onClick={() => invoke('list_script_templates').then(t => setTemplates(t)).catch(() => {})}
              style={{ display: 'flex', gap: 6, alignItems: 'center', padding: '7px 12px', borderRadius: 5, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#9ca3af', cursor: 'pointer', fontSize: 11 }}>
              <BookOpen size={12} /> Şablonlar
            </button>
          </div>
          {templates && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {templates.map(t => (
                <button key={t.id} onClick={() => { setScript(t.script); setTemplates(null); }}
                  style={{ padding: '5px 12px', borderRadius: 5, background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)', color: '#818cf8', cursor: 'pointer', fontSize: 10, textAlign: 'left' }}
                  title={t.description}>
                  {t.name}
                </button>
              ))}
            </div>
          )}
          {result && <ScriptResultPanel data={result} />}
        </div>
      )}

      {/* JSON Export (E2) */}
      {tab === 'export' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 11, color: '#6b7280' }}>
            Tek dosya taraması yapıp sonucu JSON olarak dışa aktarın.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input value={formatFile} onChange={e => setFormatFile(e.target.value)}
              placeholder="Hedef dosya yolu"
              style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.25)', borderRadius: 5, padding: '7px 12px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <button disabled={loading || !formatFile.trim()} onClick={() => run(() => invoke('cli_scan_file', { filePath: formatFile }))}
              style={{ padding: '7px 14px', borderRadius: 5, background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)', color: '#f59e0b', cursor: 'pointer', fontSize: 11, fontWeight: 600 }}>
              Tara
            </button>
          </div>
          {result && (
            <>
              <ResultPanel data={result} />
              <div style={{ display: 'flex', gap: 8 }}>
                <input value={exportPath} onChange={e => setExportPath(e.target.value)}
                  placeholder="Çıktı yolu (örn: C:\output.json)"
                  style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: 5, padding: '6px 12px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                <button disabled={!exportPath.trim()} onClick={() => invoke('export_analysis_json', { data: result, outputPath: exportPath }).then(msg => setResult({ ...result, _saved: msg })).catch(e => setError(String(e)))}
                  style={{ padding: '6px 14px', borderRadius: 5, background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', color: '#22c55e', cursor: 'pointer', fontSize: 11 }}>
                  JSON Kaydet
                </button>
              </div>
              {result._saved && <div style={{ fontSize: 11, color: '#22c55e', display: 'flex', gap: 6 }}><CheckCircle size={12} /> {result._saved}</div>}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function ResultPanel({ data }) {
  if (!data) return null;
  return (
    <div style={{ borderRadius: 7, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.15)', overflow: 'hidden' }}>
      {/* Özet şerit */}
      <div style={{ display: 'flex', gap: 12, padding: '8px 14px', background: 'rgba(245,158,11,0.04)', borderBottom: '1px solid rgba(245,158,11,0.1)', flexWrap: 'wrap' }}>
        {Object.entries(data).filter(([k]) => !['sections','strings_sample','suspicious_strings','disassembly_preview','permissions','suspicious_apis','findings','needed_libs','possible_namespaces','pinvoke_dlls','_saved'].includes(k)).map(([k, v]) => (
          <div key={k} style={{ display: 'flex', gap: 5 }}>
            <span style={{ fontSize: 9, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 1 }}>{k}:</span>
            <span style={{ fontSize: 10, color: k === 'risk_level' ? (riskColor[String(v)] || '#e2e8f0') : '#e2e8f0', fontFamily: 'monospace' }}>{String(v)}</span>
          </div>
        ))}
      </div>
      {/* Bölümler */}
      {data.sections?.length > 0 && (
        <div style={{ padding: '8px 14px' }}>
          <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 4 }}>Bölümler ({data.sections.length})</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {data.sections.slice(0, 16).map(s => (
              <span key={s.name} style={{ padding: '2px 8px', borderRadius: 3, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)', fontSize: 10, color: '#9ca3af', fontFamily: 'monospace' }}>{s.name}</span>
            ))}
          </div>
        </div>
      )}
      {/* Şüpheli string'ler */}
      {data.suspicious_strings?.length > 0 && (
        <div style={{ padding: '8px 14px', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
          <div style={{ fontSize: 10, color: '#ef4444', marginBottom: 4 }}>Şüpheli String'ler</div>
          {data.suspicious_strings.slice(0, 10).map((s, i) => (
            <div key={i} style={{ fontSize: 10, color: '#fca5a5', fontFamily: 'monospace' }}>{s}</div>
          ))}
        </div>
      )}
      {/* Disassembly önizleme */}
      {data.disassembly_preview?.length > 0 && (
        <div style={{ padding: '8px 14px', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
          <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 4 }}>Disassembly Önizleme</div>
          <pre style={{ fontSize: 10, color: '#a78bfa', margin: 0, fontFamily: 'monospace', lineHeight: 1.5 }}>
            {data.disassembly_preview.join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
}

function BatchResultPanel({ data }) {
  if (!data) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', gap: 10 }}>
        {[
          { label: 'Taranan', value: data.total_scanned, color: '#e2e8f0' },
          { label: 'Yüksek Risk', value: data.high_risk_count, color: '#ef4444' },
          { label: 'Hata', value: data.errors?.length || 0, color: '#f59e0b' },
        ].map(s => (
          <div key={s.label} style={{ padding: '8px 16px', borderRadius: 7, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: s.color }}>{s.value}</div>
            <div style={{ fontSize: 9, color: '#6b7280' }}>{s.label}</div>
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 320, overflowY: 'auto' }}>
        {data.results?.map((r, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 10px', borderRadius: 5, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
            <File size={11} color="#6b7280" />
            <span style={{ fontSize: 11, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#e2e8f0' }}>{r.file}</span>
            <span style={{ fontSize: 9, color: '#6b7280' }}>{r.format}</span>
            <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: `${riskColor[r.risk_level] || '#6b7280'}22`, color: riskColor[r.risk_level] || '#9ca3af', border: `1px solid ${riskColor[r.risk_level] || '#6b7280'}44` }}>{r.risk_level}</span>
            <span style={{ fontSize: 9, color: '#4b5563' }}>e:{r.entropy}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ScriptResultPanel({ data }) {
  if (!data) return null;
  const statusColor = { ok: '#22c55e', error: '#ef4444' };
  return (
    <div style={{ borderRadius: 7, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(99,102,241,0.2)', padding: '10px 14px' }}>
      <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 8 }}>
        {data.total_steps} adım · {data.file_path}
      </div>
      {data.steps?.map((s, i) => (
        <div key={i} style={{ display: 'flex', gap: 8, padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.03)', alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: '#4b5563', width: 16, textAlign: 'right' }}>{s.step}.</span>
          <span style={{ fontSize: 10, color: '#818cf8', width: 60, fontFamily: 'monospace' }}>{s.command}</span>
          <span style={{ fontSize: 10, color: statusColor[s.status] || '#9ca3af', flex: 1, fontFamily: 'monospace' }}>
            {s.result ?? s.count ?? s.message ?? s.status}
          </span>
          {s.sample && <span style={{ fontSize: 9, color: '#4b5563' }}>({s.count} adet)</span>}
        </div>
      ))}
    </div>
  );
}
