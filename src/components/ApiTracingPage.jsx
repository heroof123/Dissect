import React, { useState, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Activity, AlertTriangle, Search, ShieldAlert } from 'lucide-react';
import { Card } from './shared';

const CATEGORY_COLORS = {
  Network:  '#38bdf8',
  File:     '#a3e635',
  Registry: '#fb923c',
  Process:  '#f87171',
  Memory:   '#c084fc',
  Crypto:   '#fde68a',
  System:   '#94a3b8',
  Other:    '#4b5563',
};

function ApiTracingPage() {
  const [filePath, setFilePath] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [riskResult, setRiskResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('tümü'); // tümü | şüpheli | kategori
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('Tümü');

  const doScan = async () => {
    if (!filePath.trim()) return;
    setLoading(true); setError(null); setResult(null); setRiskResult(null);
    try {
      const [r, risk] = await Promise.all([
        invoke('trace_api_calls', { filePath: filePath.trim() }),
        invoke('get_suspicious_apis', { filePath: filePath.trim() }),
      ]);
      setResult(r);
      setRiskResult(risk);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const allCalls = result?.calls || [];

  const displayedCalls = useMemo(() => {
    let list = allCalls;
    if (activeTab === 'şüpheli') list = list.filter(c => c.suspicious);
    if (activeCategory !== 'Tümü') list = list.filter(c => c.category === activeCategory);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(c => c.function.toLowerCase().includes(q) || c.dll.toLowerCase().includes(q));
    }
    return list;
  }, [allCalls, activeTab, activeCategory, search]);

  // Kategoriler
  const categories = useMemo(() => {
    const cats = ['Tümü'];
    const seen = new Set();
    allCalls.forEach(c => { if (!seen.has(c.category)) { seen.add(c.category); cats.push(c.category); } });
    return cats;
  }, [allCalls]);

  const riskColor = {
    Temiz: '#22c55e', Düşük: '#a3e635', Orta: '#f59e0b', Yüksek: '#ef4444', Kritik: '#dc2626'
  }[riskResult?.risk_level] || '#8b949e';

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Activity size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>API Çağrı İzleme</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— IAT analizi · Şüpheli API tespiti (C1)</span>
      </div>

      {/* Dosya yolu + tara */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
        <input value={filePath} onChange={e => setFilePath(e.target.value)}
          placeholder="PE dosya yolu (ör: C:\malware.exe)"
          style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', fontFamily: 'monospace' }} />
        <button onClick={doScan} disabled={loading || !filePath.trim()}
          style={{ fontSize: 10, padding: '7px 18px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 600 }}>
          {loading ? '⏳ Analiz ediliyor...' : '🔬 Analiz Et'}
        </button>
      </div>

      {error && <div style={{ color: '#f87171', fontSize: 11, marginBottom: 10, padding: '6px 10px', background: 'rgba(248,113,113,0.08)', borderRadius: 6 }}>❌ {error}</div>}

      {result && riskResult && (
        <>
          {/* Üst özet */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
            {/* Risk skoru */}
            <Card style={{ textAlign: 'center', minWidth: 100 }}>
              <div style={{ fontSize: 28, fontWeight: 800, color: riskColor, fontFamily: 'monospace' }}>{riskResult.risk_score}</div>
              <div style={{ fontSize: 9, color: '#6e7681' }}>Risk Skoru</div>
              <div style={{ fontSize: 10, color: riskColor, fontWeight: 700, marginTop: 2 }}>{riskResult.risk_level}</div>
            </Card>
            {/* Toplam import */}
            <Card style={{ textAlign: 'center', minWidth: 100 }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#818cf8', fontFamily: 'monospace' }}>{result.total_imports}</div>
              <div style={{ fontSize: 9, color: '#6e7681' }}>Toplam Import</div>
            </Card>
            {/* Şüpheli */}
            <Card style={{ textAlign: 'center', minWidth: 100 }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#ef4444', fontFamily: 'monospace' }}>{result.suspicious_count}</div>
              <div style={{ fontSize: 9, color: '#6e7681' }}>Şüpheli API</div>
            </Card>
            {/* Kategori dağılımı */}
            <Card style={{ flex: 1, minWidth: 200 }}>
              <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>Kategori Dağılımı</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {(result.category_summary || []).sort((a, b) => b.count - a.count).map((item, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 12, background: 'rgba(255,255,255,0.04)', border: `1px solid ${CATEGORY_COLORS[item.category] || '#4b5563'}33` }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: CATEGORY_COLORS[item.category] || '#4b5563', display: 'inline-block' }} />
                    <span style={{ fontSize: 9, color: '#8b949e' }}>{item.category}</span>
                    <span style={{ fontSize: 9, color: CATEGORY_COLORS[item.category] || '#4b5563', fontWeight: 700 }}>{item.count}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Şüpheli API uyarı kutusu */}
          {riskResult.suspicious_apis?.length > 0 && (
            <Card style={{ marginBottom: 14, borderColor: 'rgba(239,68,68,0.2)', background: 'rgba(239,68,68,0.04)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                <ShieldAlert size={14} color="#ef4444" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#ef4444' }}>Şüpheli API Uyarıları ({riskResult.suspicious_apis.length})</span>
              </div>
              {riskResult.suspicious_apis.map((api, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, padding: '5px 8px', borderRadius: 4, marginBottom: 4, background: 'rgba(255,255,255,0.02)', borderLeft: '2px solid #ef4444' }}>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#f87171', minWidth: 180 }}>{api.function}</span>
                  <span style={{ fontSize: 9, color: '#8b949e', minWidth: 100 }}>{api.dll}</span>
                  <span style={{ fontSize: 9, color: '#fde68a' }}>{api.reason}</span>
                  <span style={{ fontSize: 9, color: '#ef4444', marginLeft: 'auto', fontWeight: 700 }}>+{api.risk_weight}</span>
                </div>
              ))}
            </Card>
          )}

          {/* Filtreler */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Sekme */}
            {[['tümü', 'Tüm APIler'], ['şüpheli', `Şüpheli (${result.suspicious_count})`]].map(([key, lbl]) => (
              <button key={key} onClick={() => setActiveTab(key)}
                style={{ fontSize: 10, padding: '4px 12px', borderRadius: 5, border: `1px solid ${activeTab === key ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`, background: activeTab === key ? 'rgba(99,102,241,0.12)' : 'transparent', color: activeTab === key ? '#818cf8' : '#8b949e', cursor: 'pointer', fontWeight: activeTab === key ? 700 : 400 }}>{lbl}</button>
            ))}

            {/* Kategori filtre */}
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {categories.map(cat => (
                <button key={cat} onClick={() => setActiveCategory(cat)}
                  style={{ fontSize: 9, padding: '3px 8px', borderRadius: 10, border: `1px solid ${activeCategory === cat ? (CATEGORY_COLORS[cat] || '#818cf8') + '66' : 'rgba(255,255,255,0.04)'}`, background: activeCategory === cat ? (CATEGORY_COLORS[cat] || '#818cf8') + '18' : 'transparent', color: activeCategory === cat ? (CATEGORY_COLORS[cat] || '#818cf8') : '#6e7681', cursor: 'pointer' }}>{cat}</button>
              ))}
            </div>

            {/* Arama */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginLeft: 'auto' }}>
              <Search size={12} color="#8b949e" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="API / DLL ara..."
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '4px 8px', fontSize: 10, color: '#e6edf3', outline: 'none', width: 180 }} />
            </div>
          </div>

          {/* API Tablosu */}
          <Card>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>
              Import Tablosu ({displayedCalls.length} sonuç)
            </div>
            <div style={{ maxHeight: 420, overflowY: 'auto' }}>
              {displayedCalls.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 24, color: '#6e7681', fontSize: 11 }}>Sonuç bulunamadı.</div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10, fontFamily: 'monospace' }}>
                  <thead><tr style={{ background: 'rgba(255,255,255,0.03)', position: 'sticky', top: 0 }}>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>DLL</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Fonksiyon</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Kategori</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>RVA</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Uyarı</th>
                  </tr></thead>
                  <tbody>
                    {displayedCalls.map((c, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', background: c.suspicious ? 'rgba(239,68,68,0.04)' : 'transparent' }}>
                        <td style={{ padding: '3px 8px', color: '#818cf8' }}>{c.dll}</td>
                        <td style={{ padding: '3px 8px', color: c.suspicious ? '#fca5a5' : '#e6edf3' }}>
                          {c.suspicious && <AlertTriangle size={9} color="#ef4444" style={{ marginRight: 4, verticalAlign: 'middle' }} />}
                          {c.function}
                        </td>
                        <td style={{ padding: '3px 8px' }}>
                          <span style={{ padding: '1px 6px', borderRadius: 8, background: (CATEGORY_COLORS[c.category] || '#4b5563') + '22', color: CATEGORY_COLORS[c.category] || '#8b949e', fontSize: 9 }}>{c.category}</span>
                        </td>
                        <td style={{ padding: '3px 8px', color: '#6e7681' }}>0x{c.rva?.toString(16).toUpperCase()}</td>
                        <td style={{ padding: '3px 8px', color: '#fde68a', fontSize: 9 }}>{c.reason || ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Card>
        </>
      )}

      {!result && !loading && (
        <Card>
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#6b7280' }}>
            <Activity size={32} color="#4b5563" style={{ margin: '0 auto 10px' }} />
            <div style={{ fontSize: 12, marginBottom: 4, color: '#8b949e' }}>PE dosyasının import tablosunu analiz et</div>
            <div style={{ fontSize: 10 }}>API kategorileri (Network, File, Registry, Process, Memory, Crypto) ve şüpheli API'ler (injection, keylogger, anti-debug) tespit edilir.</div>
          </div>
        </Card>
      )}
    </div>
  );
}

export default ApiTracingPage;
