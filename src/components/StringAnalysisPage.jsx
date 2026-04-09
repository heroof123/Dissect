import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Search, Key } from 'lucide-react';
import { Card } from './shared';

function StringAnalysisPage() {
  const [filePath, setFilePath] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('xor'); // xor | b64
  const [search, setSearch] = useState('');
  const [selectedKey, setSelectedKey] = useState(null);

  const doScan = async () => {
    if (!filePath.trim()) return;
    setLoading(true); setError(null); setResult(null); setSelectedKey(null);
    try {
      const r = await invoke('detect_encoded_strings', { filePath: filePath.trim() });
      setResult(r);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  // XOR sonuçlarını key'e göre grupla
  const xorByKey = result?.xor ? result.xor.reduce((acc, item) => {
    if (!acc[item.key]) acc[item.key] = [];
    acc[item.key].push(item);
    return acc;
  }, {}) : {};

  const xorKeys = Object.keys(xorByKey).sort();
  const displayedXor = selectedKey ? (xorByKey[selectedKey] || []) : (result?.xor || []);
  const filteredXor = displayedXor.filter(r => !search || r.decoded.toLowerCase().includes(search.toLowerCase()));
  const filteredB64 = (result?.b64 || []).filter(r => !search || r.decoded.toLowerCase().includes(search.toLowerCase()) || r.encoded.toLowerCase().includes(search.toLowerCase()));

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Key size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Gizlenmiş String Analizi</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— XOR / Base64 Tespiti (B3)</span>
      </div>

      {/* Dosya path + tara */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
        <input value={filePath} onChange={e => setFilePath(e.target.value)}
          placeholder="PE dosya yolu (ör: C:\malware.exe)"
          style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', fontFamily: 'monospace' }} />
        <button onClick={doScan} disabled={loading || !filePath.trim()}
          style={{ fontSize: 10, padding: '7px 18px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 600 }}>
          {loading ? '⏳ Taranıyor...' : '🔍 Tara'}
        </button>
      </div>

      {error && <div style={{ color: '#f87171', fontSize: 11, marginBottom: 10, padding: '6px 10px', background: 'rgba(248,113,113,0.08)', borderRadius: 6 }}>❌ {error}</div>}

      {result && (
        <>
          {/* İstatistikler */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
            {[['XOR Eşleşme', result.xor?.length || 0, '#818cf8'], ['Base64 Eşleşme', result.b64?.length || 0, '#22c55e'], ['XOR Anahtar Sayısı', xorKeys.length, '#f59e0b']].map(([lbl, val, col]) => (
              <div key={lbl} style={{ padding: '8px 20px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', textAlign: 'center' }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: col, fontFamily: 'monospace' }}>{val}</div>
                <div style={{ fontSize: 9, color: '#6e7681' }}>{lbl}</div>
              </div>
            ))}
          </div>

          {/* Sekmeler */}
          <div style={{ display: 'flex', gap: 2, marginBottom: 12 }}>
            {[['xor', `XOR (${result.xor?.length || 0})`], ['b64', `Base64 (${result.b64?.length || 0})`]].map(([key, lbl]) => (
              <button key={key} onClick={() => { setActiveTab(key); setSearch(''); setSelectedKey(null); }}
                style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: `1px solid ${activeTab === key ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`, background: activeTab === key ? 'rgba(99,102,241,0.12)' : 'transparent', color: activeTab === key ? '#818cf8' : '#8b949e', cursor: 'pointer', fontWeight: activeTab === key ? 700 : 400 }}>{lbl}</button>
            ))}
          </div>

          {/* Arama */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 10, alignItems: 'center' }}>
            <Search size={13} color="#8b949e" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Decoded içerik ara..."
              style={{ flex: 1, maxWidth: 300, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
          </div>

          {/* XOR Sekmesi */}
          {activeTab === 'xor' && (
            <div style={{ display: 'flex', gap: 12 }}>
              {/* XOR Key listesi (sol panel) */}
              <Card style={{ width: 120, flexShrink: 0 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>XOR Anahtarlar</div>
                <div style={{ maxHeight: 400, overflowY: 'auto' }}>
                  <div onClick={() => setSelectedKey(null)} style={{ padding: '4px 8px', borderRadius: 4, cursor: 'pointer', fontSize: 10, background: !selectedKey ? 'rgba(99,102,241,0.15)' : 'transparent', color: !selectedKey ? '#818cf8' : '#8b949e', marginBottom: 2 }}>
                    Tümü ({result.xor?.length || 0})
                  </div>
                  {xorKeys.map(k => (
                    <div key={k} onClick={() => setSelectedKey(k)} style={{ padding: '4px 8px', borderRadius: 4, cursor: 'pointer', fontSize: 10, fontFamily: 'monospace', background: selectedKey === k ? 'rgba(99,102,241,0.15)' : 'transparent', color: selectedKey === k ? '#818cf8' : '#8b949e', marginBottom: 2 }}>
                      {k} ({xorByKey[k].length})
                    </div>
                  ))}
                </div>
              </Card>

              {/* XOR sonuçlar (sağ) */}
              <Card style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>
                  XOR ile Gizlenmiş Stringler {selectedKey ? `— Anahtar: ${selectedKey}` : ''} ({filteredXor.length})
                </div>
                <div style={{ maxHeight: 400, overflowY: 'auto' }}>
                  {filteredXor.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: 24, color: '#6e7681', fontSize: 11 }}>Sonuç bulunamadı.</div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10, fontFamily: 'monospace' }}>
                      <thead><tr style={{ background: 'rgba(255,255,255,0.02)' }}>
                        <th style={{ padding: '4px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Offset</th>
                        <th style={{ padding: '4px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Anahtar</th>
                        <th style={{ padding: '4px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Uzunluk</th>
                        <th style={{ padding: '4px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Çözülmüş String</th>
                      </tr></thead>
                      <tbody>
                        {filteredXor.slice(0, 500).map((r, i) => (
                          <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                            <td style={{ padding: '3px 8px', color: '#818cf8' }}>{r.offset}</td>
                            <td style={{ padding: '3px 8px', color: '#f59e0b' }}>{r.key}</td>
                            <td style={{ padding: '3px 8px', color: '#6e7681' }}>{r.len}</td>
                            <td style={{ padding: '3px 8px', color: '#e6edf3' }}>{r.decoded}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </Card>
            </div>
          )}

          {/* Base64 Sekmesi */}
          {activeTab === 'b64' && (
            <Card>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>Base64 ile Kodlanmış Stringler ({filteredB64.length})</div>
              {filteredB64.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 24, color: '#6e7681', fontSize: 11 }}>Sonuç bulunamadı.</div>
              ) : (
                <div style={{ maxHeight: 450, overflowY: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10, fontFamily: 'monospace' }}>
                    <thead><tr style={{ background: 'rgba(255,255,255,0.02)' }}>
                      <th style={{ padding: '4px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Offset</th>
                      <th style={{ padding: '4px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Kodlanmış</th>
                      <th style={{ padding: '4px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Çözülmüş</th>
                      <th style={{ padding: '4px 8px', textAlign: 'left', color: '#8b949e', fontSize: 9 }}>Uzunluk</th>
                    </tr></thead>
                    <tbody>
                      {filteredB64.map((r, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                          <td style={{ padding: '3px 8px', color: '#818cf8' }}>{r.offset}</td>
                          <td style={{ padding: '3px 8px', color: '#f59e0b', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.encoded}</td>
                          <td style={{ padding: '3px 8px', color: '#22c55e', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.decoded}</td>
                          <td style={{ padding: '3px 8px', color: '#6e7681' }}>{r.len}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          )}
        </>
      )}

      {!result && !loading && (
        <Card>
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#6b7280' }}>
            <Key size={32} color="#4b5563" style={{ margin: '0 auto 10px' }} />
            <div style={{ fontSize: 12, marginBottom: 4, color: '#8b949e' }}>XOR ve Base64 ile gizlenmiş stringleri bul</div>
            <div style={{ fontSize: 10 }}>1-255 arası tüm XOR anahtarları denenir. Okunabilir string (&gt;5 karakter) bulunanlar listelenir.</div>
          </div>
        </Card>
      )}
    </div>
  );
}

export default StringAnalysisPage;
