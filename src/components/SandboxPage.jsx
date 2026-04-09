import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Play, Shield, AlertTriangle, CheckCircle, Clock, File, Database, Terminal, Info } from 'lucide-react';

const riskColor = {
  Düşük: '#22c55e',
  Orta: '#f59e0b',
  Yüksek: '#ef4444',
  Kritik: '#dc2626',
};

export default function SandboxPage({ filePath: propFilePath }) {
  const [filePath, setFilePath] = useState(propFilePath || '');
  const [args, setArgs] = useState('');
  const [timeout, setTimeout_] = useState(5000);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState('ozet'); // ozet | dosyalar | registry | cikti

  const handleDrop = (e) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) setFilePath(f.path || f.name);
  };

  const run = async () => {
    if (!filePath.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const argList = args.trim() ? args.split(/\s+/) : null;
      const res = await invoke('sandbox_run', {
        filePath,
        timeoutMs: timeout,
        args: argList,
      });
      setResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { key: 'ozet', label: 'Özet', icon: Shield },
    { key: 'dosyalar', label: 'Dosya Sistemi', icon: File },
    { key: 'registry', label: 'Registry', icon: Database },
    { key: 'cikti', label: 'Çıktı', icon: Terminal },
  ];

  return (
    <div onDragOver={e => e.preventDefault()} onDrop={handleDrop}
      style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 24, gap: 16, overflowY: 'auto' }}>

      {/* Başlık */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Shield size={20} color="#f59e0b" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>Sandbox Çalıştırma</span>
        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(245,158,11,0.15)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)', fontWeight: 600 }}>C2</span>
      </div>

      {/* Uyarı */}
      <div style={{ display: 'flex', gap: 8, padding: '8px 12px', borderRadius: 6, background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)' }}>
        <AlertTriangle size={14} color="#f59e0b" style={{ flexShrink: 0, marginTop: 1 }} />
        <span style={{ fontSize: 11, color: '#fbbf24', lineHeight: 1.5 }}>
          Bu özellik kısıtlı izinlerle binary çalıştırır ve temel davranış analizi yapar.
          Gerçek izolasyon için sanal makine önerilir. Timeout: maksimum 30 saniye.
        </span>
      </div>

      {/* Form */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 16, borderRadius: 8, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label style={{ fontSize: 11, color: '#9ca3af' }}>Dosya Yolu (sürükle/bırak desteklenir)</label>
          <input
            value={filePath}
            onChange={e => setFilePath(e.target.value)}
            placeholder="C:\yol\dosya.exe"
            style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 5, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }}
          />
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, color: '#9ca3af' }}>Argümanlar (opsiyonel)</label>
            <input
              value={args}
              onChange={e => setArgs(e.target.value)}
              placeholder="--arg1 değer"
              style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 5, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none' }}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, color: '#9ca3af' }}>Timeout (ms)</label>
            <input
              type="number"
              min={1000}
              max={30000}
              step={1000}
              value={timeout}
              onChange={e => setTimeout_(Number(e.target.value))}
              style={{ width: 90, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 5, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none' }}
            />
          </div>
        </div>
        <button
          onClick={run}
          disabled={loading || !filePath.trim()}
          style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8, padding: '8px 20px', borderRadius: 6, background: loading ? 'rgba(245,158,11,0.1)' : 'rgba(245,158,11,0.2)', border: '1px solid rgba(245,158,11,0.4)', color: '#f59e0b', cursor: loading ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 600, transition: 'all 0.2s' }}>
          {loading ? <><Clock size={14} style={{ animation: 'spin 1s linear infinite' }} /> Çalıştırılıyor...</> : <><Play size={14} /> Sandbox'ta Çalıştır</>}
        </button>
      </div>

      {/* Hata */}
      {error && (
        <div style={{ display: 'flex', gap: 8, padding: '10px 14px', borderRadius: 6, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#fca5a5', fontSize: 12 }}>
          <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
          {error}
        </div>
      )}

      {/* Sonuçlar */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Üst özet kartları */}
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {[
              { label: 'Risk Seviyesi', value: result.risk_level, color: riskColor[result.risk_level] || '#9ca3af', suffix: `(${result.risk_score}/100)` },
              { label: 'Çıkış Kodu', value: result.exit_code, color: result.exit_code === 0 ? '#22c55e' : '#ef4444' },
              { label: 'Süre', value: `${result.elapsed_ms}ms`, color: '#94a3b8' },
              { label: 'Timeout', value: result.timed_out ? 'Evet' : 'Hayır', color: result.timed_out ? '#ef4444' : '#22c55e' },
              { label: 'Yeni Dosya', value: result.new_files?.length || 0, color: result.new_files?.length ? '#f59e0b' : '#4b5563' },
              { label: 'Yeni Registry', value: result.new_registry_keys?.length || 0, color: result.new_registry_keys?.length ? '#f59e0b' : '#4b5563' },
            ].map(card => (
              <div key={card.label} style={{ padding: '8px 14px', borderRadius: 6, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', minWidth: 90 }}>
                <div style={{ fontSize: 9, color: '#6b7280', marginBottom: 2 }}>{card.label}</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: card.color }}>{card.value}</div>
                {card.suffix && <div style={{ fontSize: 9, color: '#6b7280' }}>{card.suffix}</div>}
              </div>
            ))}
          </div>

          {/* Uyarılar */}
          {result.warnings?.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {result.warnings.map((w, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, padding: '5px 10px', borderRadius: 5, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.15)', fontSize: 10, color: '#9ca3af' }}>
                  <Info size={11} color="#818cf8" style={{ flexShrink: 0, marginTop: 1 }} />
                  {w}
                </div>
              ))}
            </div>
          )}

          {/* Tab bar */}
          <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: 0 }}>
            {tabs.map(t => {
              const Icon = t.icon;
              return (
                <button key={t.key} onClick={() => setTab(t.key)}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', background: 'none', border: 'none', cursor: 'pointer', fontSize: 11, fontWeight: tab === t.key ? 700 : 400, color: tab === t.key ? '#e2e8f0' : '#9ca3af', borderBottom: tab === t.key ? '2px solid #f59e0b' : '2px solid transparent', marginBottom: -1 }}>
                  <Icon size={12} /> {t.label}
                </button>
              );
            })}
          </div>

          {/* Tab içeriği */}
          <div style={{ padding: 12, borderRadius: 6, background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.06)', minHeight: 150 }}>
            {/* Özet */}
            {tab === 'ozet' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11, color: '#9ca3af' }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: riskColor[result.risk_level] || '#e2e8f0', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  {result.risk_score > 50 ? <AlertTriangle size={14} /> : <CheckCircle size={14} />}
                  Risk Skoru: {result.risk_score}/100 — {result.risk_level}
                </div>
                <div>Dosya karması (ön): <span style={{ fontFamily: 'monospace', color: '#e2e8f0' }}>{result.file_hash}</span></div>
                <div>Yeni dosya: <span style={{ color: result.new_files?.length ? '#f59e0b' : '#4b5563' }}>{result.new_files?.length || 0}</span></div>
                <div>Silinen dosya: <span style={{ color: result.deleted_files?.length ? '#ef4444' : '#4b5563' }}>{result.deleted_files?.length || 0}</span></div>
                <div>Yeni registry anahtarı: <span style={{ color: result.new_registry_keys?.length ? '#f59e0b' : '#4b5563' }}>{result.new_registry_keys?.length || 0}</span></div>
                <div>Çalışma süresi: <span style={{ color: '#e2e8f0' }}>{result.elapsed_ms}ms</span> {result.timed_out && <span style={{ color: '#ef4444', fontWeight: 700 }}>(Zaman aşımı!)</span>}</div>
              </div>
            )}

            {/* Dosya sistemi */}
            {tab === 'dosyalar' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {result.new_files?.length > 0 ? (
                  <div>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 6 }}>Yeni oluşturulan dosyalar:</div>
                    {result.new_files.map((f, i) => (
                      <div key={i} style={{ padding: '3px 8px', fontSize: 11, color: '#fde68a', fontFamily: 'monospace', background: 'rgba(253,230,138,0.05)', borderRadius: 3, marginBottom: 2 }}>+ {f}</div>
                    ))}
                  </div>
                ) : <div style={{ fontSize: 11, color: '#4b5563' }}>Yeni dosya oluşturulmadı.</div>}
                {result.deleted_files?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 6 }}>Silinen dosyalar:</div>
                    {result.deleted_files.map((f, i) => (
                      <div key={i} style={{ padding: '3px 8px', fontSize: 11, color: '#fca5a5', fontFamily: 'monospace', background: 'rgba(252,165,165,0.05)', borderRadius: 3, marginBottom: 2 }}>- {f}</div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Registry */}
            {tab === 'registry' && (
              <div>
                {result.new_registry_keys?.length > 0 ? (
                  <>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 6 }}>Yeni/değişen registry anahtarları:</div>
                    {result.new_registry_keys.map((k, i) => (
                      <div key={i} style={{ padding: '3px 8px', fontSize: 11, color: '#fde68a', fontFamily: 'monospace', background: 'rgba(253,230,138,0.05)', borderRadius: 3, marginBottom: 2 }}>{k}</div>
                    ))}
                  </>
                ) : <div style={{ fontSize: 11, color: '#4b5563' }}>Registry değişikliği tespit edilmedi.</div>}
              </div>
            )}

            {/* Çıktı */}
            {tab === 'cikti' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {result.stdout?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 4 }}>Standart çıktı:</div>
                    <pre style={{ margin: 0, fontFamily: 'monospace', fontSize: 10, color: '#22c55e', background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: 5, overflowX: 'auto', maxHeight: 200, overflowY: 'auto' }}>
                      {result.stdout.join('\n')}
                    </pre>
                  </div>
                )}
                {result.stderr?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 4 }}>Standart hata:</div>
                    <pre style={{ margin: 0, fontFamily: 'monospace', fontSize: 10, color: '#fca5a5', background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: 5, overflowX: 'auto', maxHeight: 150, overflowY: 'auto' }}>
                      {result.stderr.join('\n')}
                    </pre>
                  </div>
                )}
                {!result.stdout?.length && !result.stderr?.length && (
                  <div style={{ fontSize: 11, color: '#4b5563' }}>Çıktı yok.</div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
