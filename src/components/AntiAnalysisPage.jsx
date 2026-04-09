import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Shield, Bug, Eye, Package, Clock, Lightbulb } from 'lucide-react';
import { Card } from './shared';

const SEVERITY_COLOR = {
  Kritik: '#dc2626',
  Yüksek: '#ef4444',
  Orta:   '#f59e0b',
  Düşük:  '#a3e635',
};

const CATEGORY_ICON = {
  'Anti-Debug':       <Bug size={11} />,
  'Anti-VM':          <Eye size={11} />,
  'Anti-Sandbox':     <Shield size={11} />,
  'Packer':           <Package size={11} />,
  'Timing Evasion':   <Clock size={11} />,
  'Exception Evasion':<Clock size={11} />,
};

function AntiAnalysisPage() {
  const [filePath, setFilePath] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('bulgular'); // bulgular | bypass

  const doScan = async () => {
    if (!filePath.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await invoke('detect_anti_analysis', { filePath: filePath.trim() });
      setResult(r);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const scoreColor = !result ? '#8b949e' : result.total_score >= 75 ? '#dc2626' : result.total_score >= 40 ? '#ef4444' : result.total_score >= 15 ? '#f59e0b' : '#22c55e';

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Shield size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Anti-Analiz Tespiti</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Anti-Debug · Anti-VM · Packer · Bypass Önerileri (C4)</span>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
        <input value={filePath} onChange={e => setFilePath(e.target.value)}
          placeholder="PE dosya yolu (ör: C:\malware.exe)"
          style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', fontFamily: 'monospace' }} />
        <button onClick={doScan} disabled={loading || !filePath.trim()}
          style={{ fontSize: 10, padding: '7px 18px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 600 }}>
          {loading ? '⏳ Taranıyor...' : '🛡 Tara'}
        </button>
      </div>

      {error && <div style={{ color: '#f87171', fontSize: 11, marginBottom: 10, padding: '6px 10px', background: 'rgba(248,113,113,0.08)', borderRadius: 6 }}>❌ {error}</div>}

      {result && (
        <>
          {/* Özet */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
            <Card style={{ textAlign: 'center', minWidth: 100 }}>
              <div style={{ fontSize: 28, fontWeight: 800, color: scoreColor, fontFamily: 'monospace' }}>{result.total_score}</div>
              <div style={{ fontSize: 9, color: '#6e7681' }}>Evasion Skoru</div>
            </Card>
            {[['Anti-Debug', result.categories?.anti_debug, '#ef4444', <Bug size={14} />],
              ['Anti-VM / Sandbox', result.categories?.anti_vm, '#f59e0b', <Eye size={14} />],
              ['Packer', result.categories?.packer, '#c084fc', <Package size={14} />],
              ['Timing / Exception', result.categories?.timing, '#38bdf8', <Clock size={14} />]
            ].map(([lbl, val, col, icon]) => (
              <Card key={lbl} style={{ textAlign: 'center', minWidth: 100 }}>
                <div style={{ color: col, marginBottom: 4 }}>{icon}</div>
                <div style={{ fontSize: 20, fontWeight: 700, color: col, fontFamily: 'monospace' }}>{val || 0}</div>
                <div style={{ fontSize: 9, color: '#6e7681' }}>{lbl}</div>
              </Card>
            ))}
            <Card style={{ flex: 1 }}>
              <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 4 }}>Bypass önerisi sayısı</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: '#22c55e' }}>{result.bypasses?.length || 0}</div>
            </Card>
          </div>

          {/* Sekmeler */}
          <div style={{ display: 'flex', gap: 2, marginBottom: 12 }}>
            {[['bulgular', `Bulgular (${result.count})`], ['bypass', `Bypass Tavsiyeleri (${result.bypasses?.length || 0})`]].map(([key, lbl]) => (
              <button key={key} onClick={() => setActiveTab(key)}
                style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: `1px solid ${activeTab === key ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`, background: activeTab === key ? 'rgba(99,102,241,0.12)' : 'transparent', color: activeTab === key ? '#818cf8' : '#8b949e', cursor: 'pointer', fontWeight: activeTab === key ? 700 : 400 }}>{lbl}</button>
            ))}
          </div>

          {/* Bulgular */}
          {activeTab === 'bulgular' && (
            <Card>
              {result.findings?.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 24, color: '#22c55e', fontSize: 12 }}>✓ Anti-analiz tekniği tespit edilmedi.</div>
              ) : (
                <>
                  <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>Tespit Edilen Teknikler ({result.findings.length})</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {result.findings.map((f, i) => (
                      <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '8px 10px', borderRadius: 6, background: 'rgba(255,255,255,0.02)', borderLeft: `3px solid ${SEVERITY_COLOR[f.severity] || '#6e7681'}` }}>
                        <span style={{ color: SEVERITY_COLOR[f.severity] || '#6e7681', marginTop: 1 }}>{CATEGORY_ICON[f.category] || <Shield size={11} />}</span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 2 }}>
                            <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#e6edf3', fontWeight: 600 }}>{f.api}</span>
                            <span style={{ fontSize: 8, padding: '1px 5px', borderRadius: 8, background: (SEVERITY_COLOR[f.severity] || '#6e7681') + '22', color: SEVERITY_COLOR[f.severity] || '#6e7681' }}>{f.severity}</span>
                            <span style={{ fontSize: 8, padding: '1px 5px', borderRadius: 8, background: 'rgba(255,255,255,0.04)', color: '#8b949e' }}>{f.category}</span>
                          </div>
                          <div style={{ fontSize: 10, color: '#8b949e' }}>{f.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </Card>
          )}

          {/* Bypass Tavsiyeleri */}
          {activeTab === 'bypass' && (
            <Card>
              {result.bypasses?.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 24, color: '#6e7681', fontSize: 11 }}>Otomatik bypass tavsiyesi oluşturulamadı.</div>
              ) : (
                <>
                  <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>
                    <Lightbulb size={11} color="#fde68a" style={{ marginRight: 5, verticalAlign: 'middle' }} />
                    Bypass Tavsiyeleri
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {result.bypasses.map((b, i) => (
                      <div key={i} style={{ padding: '10px 12px', borderRadius: 6, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(253,230,138,0.1)' }}>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 5 }}>
                          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#fde68a', fontWeight: 600 }}>{b.technique}</span>
                          <span style={{ fontSize: 8, padding: '1px 6px', borderRadius: 8, background: 'rgba(99,102,241,0.15)', color: '#818cf8' }}>{b.type}</span>
                        </div>
                        <div style={{ fontSize: 10, color: '#a8b3c4', lineHeight: 1.5 }}>💡 {b.bypass_tip}</div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </Card>
          )}
        </>
      )}

      {!result && !loading && (
        <Card>
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#6b7280' }}>
            <Shield size={32} color="#4b5563" style={{ margin: '0 auto 10px' }} />
            <div style={{ fontSize: 12, marginBottom: 4, color: '#8b949e' }}>Anti-analiz tekniklerini tespit et</div>
            <div style={{ fontSize: 10 }}>Anti-debug (IsDebuggerPresent, NtQueryInformationProcess), Anti-VM (VMware, VirtualBox, Sandboxie), Packer imzaları (UPX, Themida, Enigma) ve timing evasion teknikleri tespit edilir. Bypass tavsiyeleri üretilir.</div>
          </div>
        </Card>
      )}
    </div>
  );
}

export default AntiAnalysisPage;
