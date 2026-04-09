import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { GitCompare, Plus, Minus } from 'lucide-react';
import { Card } from './shared';

function BinDiffPage() {
  const [fileA, setFileA] = useState('');
  const [fileB, setFileB] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('genel'); // genel | importlar | exportlar | bölümler

  const doCompare = async () => {
    if (!fileA.trim() || !fileB.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await invoke('compare_pe_functions', { fileA: fileA.trim(), fileB: fileB.trim() });
      setResult(r);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const pct = result?.similarity_pct ?? 0;
  const pctColor = pct >= 90 ? '#22c55e' : pct >= 60 ? '#f59e0b' : '#ef4444';

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <GitCompare size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>PE Fark Analizi (BinDiff)</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— İmport / Export / Bölüm Karşılaştırma (B4)</span>
      </div>

      {/* Dosya yolları */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 250 }}>
          <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>Dosya A (Orijinal)</div>
          <input value={fileA} onChange={e => setFileA(e.target.value)}
            placeholder="C:\original.exe"
            style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', fontFamily: 'monospace', boxSizing: 'border-box' }} />
        </div>
        <div style={{ flex: 1, minWidth: 250 }}>
          <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>Dosya B (Değiştirilmiş)</div>
          <input value={fileB} onChange={e => setFileB(e.target.value)}
            placeholder="C:\patched.exe"
            style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', fontFamily: 'monospace', boxSizing: 'border-box' }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end' }}>
          <button onClick={doCompare} disabled={loading || !fileA.trim() || !fileB.trim()}
            style={{ fontSize: 10, padding: '7px 22px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>
            {loading ? '⏳ Karşılaştırılıyor...' : '⚖ Karşılaştır'}
          </button>
        </div>
      </div>

      {error && <div style={{ color: '#f87171', fontSize: 11, marginBottom: 10, padding: '6px 10px', background: 'rgba(248,113,113,0.08)', borderRadius: 6 }}>❌ {error}</div>}

      {result && (
        <>
          {/* Özet kartları */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
            {/* Benzerlik */}
            <Card style={{ textAlign: 'center', minWidth: 110 }}>
              <div style={{ fontSize: 26, fontWeight: 800, color: pctColor, fontFamily: 'monospace' }}>{pct.toFixed(1)}%</div>
              <div style={{ fontSize: 9, color: '#6e7681', marginTop: 2 }}>Benzerlik</div>
              {result.identical && <div style={{ fontSize: 9, color: '#22c55e', marginTop: 4, fontWeight: 700 }}>✓ Özdeş Dosya</div>}
            </Card>
            {/* Boyut */}
            <Card style={{ minWidth: 140 }}>
              <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>Dosya Boyutu</div>
              <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#818cf8', marginBottom: 2 }}>A: {(result.size_a / 1024).toFixed(1)} KB</div>
              <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#f87171' }}>B: {(result.size_b / 1024).toFixed(1)} KB</div>
              <div style={{ fontSize: 9, color: result.size_b > result.size_a ? '#ef4444' : '#22c55e', marginTop: 4 }}>
                {result.size_b > result.size_a ? '+' : ''}{((result.size_b - result.size_a) / 1024).toFixed(1)} KB fark
              </div>
            </Card>
            {/* Hash */}
            <Card style={{ minWidth: 200, flex: 1 }}>
              <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>Dosya Hash (Basit)</div>
              <div style={{ fontSize: 9, fontFamily: 'monospace', color: '#8b949e', marginBottom: 2 }}>A: <span style={{ color: '#818cf8' }}>{result.hash_a}</span></div>
              <div style={{ fontSize: 9, fontFamily: 'monospace', color: '#8b949e' }}>B: <span style={{ color: result.hash_a === result.hash_b ? '#22c55e' : '#f87171' }}>{result.hash_b}</span></div>
            </Card>
            {/* Import/Export özet */}
            <Card style={{ minWidth: 140 }}>
              <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>Import Değişim</div>
              <div style={{ fontSize: 10, color: '#22c55e' }}>+{result.added_imports?.length || 0} eklendi</div>
              <div style={{ fontSize: 10, color: '#ef4444' }}>-{result.removed_imports?.length || 0} kaldırıldı</div>
              <div style={{ fontSize: 10, color: '#8b949e' }}>{result.common_imports?.length || 0} ortak</div>
            </Card>
          </div>

          {/* Sekmeler */}
          <div style={{ display: 'flex', gap: 2, marginBottom: 12 }}>
            {[['genel', 'Genel Özet'], ['importlar', `İmportlar`], ['exportlar', `Exportlar`], ['bölümler', `Bölümler`]].map(([key, lbl]) => (
              <button key={key} onClick={() => setActiveTab(key)}
                style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: `1px solid ${activeTab === key ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`, background: activeTab === key ? 'rgba(99,102,241,0.12)' : 'transparent', color: activeTab === key ? '#818cf8' : '#8b949e', cursor: 'pointer', fontWeight: activeTab === key ? 700 : 400 }}>{lbl}</button>
            ))}
          </div>

          {/* Genel Özet */}
          {activeTab === 'genel' && (
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Card style={{ flex: 1, minWidth: 200 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#818cf8', marginBottom: 8 }}>Dosya A</div>
                <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#e6edf3', marginBottom: 2 }}>{result.file_a}</div>
                <div style={{ fontSize: 9, color: '#8b949e' }}>Import: {result.imports_a?.length || 0} &nbsp;·&nbsp; Export: {result.exports_a?.length || 0}</div>
                <div style={{ fontSize: 9, color: '#8b949e' }}>Bölüm: {result.sections_a?.length || 0}</div>
              </Card>
              <Card style={{ flex: 1, minWidth: 200 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#f87171', marginBottom: 8 }}>Dosya B</div>
                <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#e6edf3', marginBottom: 2 }}>{result.file_b}</div>
                <div style={{ fontSize: 9, color: '#8b949e' }}>Import: {result.imports_b?.length || 0} &nbsp;·&nbsp; Export: {result.exports_b?.length || 0}</div>
                <div style={{ fontSize: 9, color: '#8b949e' }}>Bölüm: {result.sections_b?.length || 0}</div>
              </Card>
            </div>
          )}

          {/* İmportlar */}
          {activeTab === 'importlar' && (
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <DiffList title="Eklenen İmportlar (Sadece B'de)" items={result.added_imports || []} color="#22c55e" icon={<Plus size={10} />} />
              <DiffList title="Kaldırılan İmportlar (Sadece A'da)" items={result.removed_imports || []} color="#ef4444" icon={<Minus size={10} />} />
              <DiffList title="Ortak İmportlar (Her İkisinde)" items={result.common_imports || []} color="#8b949e" />
            </div>
          )}

          {/* Exportlar */}
          {activeTab === 'exportlar' && (
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <DiffList title="Eklenen Exportlar (Sadece B'de)" items={result.added_exports || []} color="#22c55e" icon={<Plus size={10} />} />
              <DiffList title="Kaldırılan Exportlar (Sadece A'da)" items={result.removed_exports || []} color="#ef4444" icon={<Minus size={10} />} />
            </div>
          )}

          {/* Bölümler */}
          {activeTab === 'bölümler' && (
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Card style={{ flex: 1, minWidth: 250 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>Boyutu Değişen Bölümler ({result.changed_sections?.length || 0})</div>
                {result.changed_sections?.length === 0 ? (
                  <div style={{ fontSize: 10, color: '#22c55e' }}>✓ Tüm bölüm boyutları aynı</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10, fontFamily: 'monospace' }}>
                    <thead><tr style={{ background: 'rgba(255,255,255,0.02)' }}>
                      <th style={{ padding: '3px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Bölüm</th>
                      <th style={{ padding: '3px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>A Boyutu</th>
                      <th style={{ padding: '3px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>B Boyutu</th>
                      <th style={{ padding: '3px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Fark</th>
                    </tr></thead>
                    <tbody>
                      {result.changed_sections?.map((s, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                          <td style={{ padding: '3px 8px', color: '#818cf8' }}>{s.name}</td>
                          <td style={{ padding: '3px 8px', color: '#8b949e' }}>{s.size_a}</td>
                          <td style={{ padding: '3px 8px', color: '#8b949e' }}>{s.size_b}</td>
                          <td style={{ padding: '3px 8px', color: s.size_b > s.size_a ? '#ef4444' : '#22c55e' }}>
                            {s.size_b > s.size_a ? '+' : ''}{s.size_b - s.size_a}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Card>
              <Card style={{ flex: 1, minWidth: 250 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>Bölüm Karşılaştırması</div>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10, fontFamily: 'monospace' }}>
                  <thead><tr style={{ background: 'rgba(255,255,255,0.02)' }}>
                    <th style={{ padding: '3px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Bölüm</th>
                    <th style={{ padding: '3px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>A</th>
                    <th style={{ padding: '3px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>B</th>
                  </tr></thead>
                  <tbody>
                    {[...(result.sections_a || [])].map((sec, i) => {
                      const inB = (result.sections_b || []).includes(sec);
                      return (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                          <td style={{ padding: '3px 8px', color: '#818cf8' }}>{sec}</td>
                          <td style={{ padding: '3px 8px', color: '#22c55e' }}>✓</td>
                          <td style={{ padding: '3px 8px', color: inB ? '#22c55e' : '#ef4444' }}>{inB ? '✓' : '✗'}</td>
                        </tr>
                      );
                    })}
                    {(result.sections_b || []).filter(s => !(result.sections_a || []).includes(s)).map((sec, i) => (
                      <tr key={'b'+i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ padding: '3px 8px', color: '#818cf8' }}>{sec}</td>
                        <td style={{ padding: '3px 8px', color: '#ef4444' }}>✗</td>
                        <td style={{ padding: '3px 8px', color: '#22c55e' }}>✓</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>
            </div>
          )}
        </>
      )}

      {!result && !loading && (
        <Card>
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#6b7280' }}>
            <GitCompare size={32} color="#4b5563" style={{ margin: '0 auto 10px' }} />
            <div style={{ fontSize: 12, marginBottom: 4, color: '#8b949e' }}>İki PE dosyasını karşılaştır</div>
            <div style={{ fontSize: 10 }}>Import/export farkları, bölüm boyut değişimleri ve benzerlik yüzdesi hesaplanır.</div>
          </div>
        </Card>
      )}
    </div>
  );
}

function DiffList({ title, items, color, icon }) {
  return (
    <Card style={{ flex: 1, minWidth: 200 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 8 }}>
        {icon && <span style={{ color }}>{icon}</span>}
        <span style={{ fontSize: 10, fontWeight: 700, color }}>{title}</span>
        <span style={{ fontSize: 9, color: '#6e7681' }}>({items.length})</span>
      </div>
      {items.length === 0 ? (
        <div style={{ fontSize: 10, color: '#4b5563' }}>—</div>
      ) : (
        <div style={{ maxHeight: 250, overflowY: 'auto' }}>
          {items.map((item, i) => (
            <div key={i} style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 0', color: color === '#8b949e' ? '#8b949e' : color, borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
              {icon ? <span style={{ marginRight: 4 }}>{icon}</span> : null}
              {item}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

export default BinDiffPage;
