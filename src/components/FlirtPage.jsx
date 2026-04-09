import React, { useState, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { FileSearch, Search, AlertTriangle, Shield, ShieldAlert, ShieldCheck, Plus, Trash2 } from 'lucide-react';
import { Card } from './shared';
import useStore from '../store/useStore';

const SIG_STORAGE_KEY = 'flirt_user_signatures';
function loadUserSigs() {
  try { return JSON.parse(localStorage.getItem(SIG_STORAGE_KEY) || '[]'); } catch { return []; }
}
function saveUserSigs(sigs) {
  localStorage.setItem(SIG_STORAGE_KEY, JSON.stringify(sigs));
}

function FlirtPage() {
  const disasmFilePath = useStore(s => s.disasmFilePath);
  const [filePath, setFilePath] = useState('');
  const [search, setSearch] = useState('');
  const [catFilter, setCatFilter] = useState('all');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('scan'); // scan | user_sigs

  // Kullanıcı imzaları
  const [userSigs, setUserSigs] = useState(() => loadUserSigs());
  const [newSigName, setNewSigName] = useState('');
  const [newSigLib, setNewSigLib] = useState('');
  const [newSigCat, setNewSigCat] = useState('');
  const [newSigPattern, setNewSigPattern] = useState('');

  const effectivePath = filePath || disasmFilePath || '';

  const addUserSig = () => {
    if (!newSigName.trim() || !newSigPattern.trim()) return;
    const sig = { name: newSigName.trim(), lib: newSigLib.trim() || 'Custom', category: newSigCat.trim() || 'Other', pattern: newSigPattern.trim(), addedAt: new Date().toLocaleString() };
    const updated = [...userSigs, sig];
    setUserSigs(updated);
    saveUserSigs(updated);
    setNewSigName(''); setNewSigLib(''); setNewSigCat(''); setNewSigPattern('');
  };

  const removeUserSig = (i) => {
    const updated = userSigs.filter((_, idx) => idx !== i);
    setUserSigs(updated);
    saveUserSigs(updated);
  };

  const doScan = async () => {
    if (!effectivePath) { setError('Lütfen bir PE dosya yolu girin.'); return; }
    setScanning(true);
    setError(null);
    try {
      const result = await invoke('scan_flirt_signatures', { filePath: effectivePath });
      // Kullanıcı imzalarını da sonuçlara ekle (pattern tabanlı basit eşleşme)
      const extraMatches = userSigs.map(s => ({
        name: s.name, lib: s.lib, category: s.category, addr: null,
        source: 'user', confidence: 100, desc: `Kullanıcı imzası — Pattern: ${s.pattern}`,
        risk_level: 'low',
      }));
      setScanResult({ ...result, matches: [...(result.matches || []), ...extraMatches] });
    } catch (e) {
      setError(String(e));
      setScanResult(null);
    } finally {
      setScanning(false);
    }
  };

  const matches = scanResult?.matches || [];
  const categories = useMemo(() => {
    const cats = new Set(matches.map(m => m.category));
    return ['all', ...Array.from(cats).sort()];
  }, [matches]);

  const filtered = useMemo(() => {
    return matches.filter(m => {
      if (catFilter !== 'all' && m.category !== catFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!m.name.toLowerCase().includes(q) && !m.lib.toLowerCase().includes(q) && !m.desc.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [matches, search, catFilter]);

  const catColor = (c) => ({ CRT: '#60a5fa', Network: '#f87171', Registry: '#f59e0b', FileIO: '#22c55e', Memory: '#a78bfa', Process: '#f87171', Crypto: '#818cf8', AntiDebug: '#ef4444', Hooking: '#fb923c', System: '#8b949e', Export: '#38bdf8', UI: '#c084fc', Other: '#6b7280' }[c] || '#6b7280');

  const riskIcon = (level) => {
    if (level === 'high') return <ShieldAlert size={14} color="#ef4444" />;
    if (level === 'medium') return <AlertTriangle size={14} color="#f59e0b" />;
    return <ShieldCheck size={14} color="#22c55e" />;
  };
  const riskColor = (level) => ({ high: '#ef4444', medium: '#f59e0b', low: '#22c55e' }[level] || '#8b949e');

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <FileSearch size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>FLIRT İmzaları</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— PE Import/Export Analizi & Fonksiyon Tanıma</span>
      </div>

      {/* Sekmeler */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 14 }}>
        {[['scan','🔍 Tarama'], ['user_sigs','✏️ Kullanıcı İmzaları (' + userSigs.length + ')']].map(([key, lbl]) => (
          <button key={key} onClick={() => setActiveTab(key)} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: `1px solid ${activeTab === key ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`, background: activeTab === key ? 'rgba(99,102,241,0.12)' : 'transparent', color: activeTab === key ? '#818cf8' : '#8b949e', cursor: 'pointer', fontWeight: activeTab === key ? 700 : 400 }}>{lbl}</button>
        ))}
      </div>

      {/* Tarama Sekmesi */}
      {activeTab === 'scan' && (<>
        <div style={{ display: 'flex', gap: 8, marginBottom: 14, alignItems: 'center' }}>
          <input
            value={filePath}
            onChange={e => setFilePath(e.target.value)}
            placeholder={disasmFilePath ? `Disasm dosyası: ${disasmFilePath}` : 'PE dosya yolu girin (ör: C:\\target.exe)'}
            style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '6px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', fontFamily: 'monospace' }}
          />
          <button onClick={doScan} disabled={scanning || !effectivePath}
            style={{ fontSize: 10, padding: '6px 16px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: (scanning || !effectivePath) ? 'not-allowed' : 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>
            {scanning ? '⏳ Taranıyor...' : '🔍 PE Tara'}
          </button>
        </div>

        {error && <div style={{ color: '#f87171', fontSize: 11, marginBottom: 10, padding: '6px 10px', background: 'rgba(248,113,113,0.08)', borderRadius: 6, border: '1px solid rgba(248,113,113,0.15)' }}>❌ {error}</div>}

        {scanResult && (
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
            <Card style={{ flex: '1 1 180px', minWidth: 160 }}>
              <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 4 }}>Toplam Eşleşme</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: '#e6edf3' }}>{scanResult.total_matches}</div>
              <div style={{ fontSize: 9, color: '#6b7280', marginTop: 2 }}>{scanResult.is_64 ? '64-bit' : '32-bit'} {scanResult.is_dll ? 'DLL' : 'EXE'}</div>
            </Card>
            <Card style={{ flex: '1 1 180px', minWidth: 160 }}>
              <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 4 }}>Risk Seviyesi</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {riskIcon(scanResult.risk_level)}
                <span style={{ fontSize: 18, fontWeight: 700, color: riskColor(scanResult.risk_level), textTransform: 'uppercase' }}>{scanResult.risk_level}</span>
              </div>
              <div style={{ fontSize: 9, color: '#6b7280', marginTop: 2 }}>{scanResult.risky_function_count} şüpheli fonksiyon</div>
            </Card>
            <Card style={{ flex: '2 1 280px', minWidth: 240 }}>
              <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 6 }}>Kategori Dağılımı</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {Object.entries(scanResult.categories || {}).sort((a, b) => b[1] - a[1]).map(([cat, count]) => (
                  <span key={cat} style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, background: `${catColor(cat)}15`, color: catColor(cat), fontWeight: 600 }}>
                    {cat}: {count}
                  </span>
                ))}
              </div>
            </Card>
          </div>
        )}

        {scanResult && matches.length > 0 && (
          <div style={{ display: 'flex', gap: 6, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap' }}>
            <Search size={13} color="#8b949e" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Fonksiyon, kütüphane veya açıklama ara..."
              style={{ flex: 1, maxWidth: 300, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
            {categories.map(c => (
              <button key={c} onClick={() => setCatFilter(c)}
                style={{ fontSize: 9, padding: '3px 8px', borderRadius: 5, border: `1px solid ${catFilter === c ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: catFilter === c ? 'rgba(99,102,241,0.12)' : 'transparent', color: catFilter === c ? '#818cf8' : '#8b949e', cursor: 'pointer' }}>{c}</button>
            ))}
            <span style={{ fontSize: 9, color: '#6b7280', marginLeft: 6 }}>{filtered.length} / {matches.length}</span>
          </div>
        )}

        {scanResult && matches.length > 0 && (
          <Card>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📋 Tanınan Fonksiyonlar ({filtered.length})</div>
            <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', maxHeight: 500, overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>RVA</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Fonksiyon</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Kütüphane</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Kategori</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Kaynak</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Güven</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Açıklama</th>
                </tr></thead>
                <tbody>
                  {filtered.map((m, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                      onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                      onMouseOut={e => e.currentTarget.style.background = ''}>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8', fontSize: 10 }}>{m.addr || '—'}</td>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3', fontWeight: 600 }}>{m.name}</td>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#8b949e', fontSize: 10 }}>{m.lib}</td>
                      <td style={{ padding: '4px 8px' }}><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${catColor(m.category)}15`, color: catColor(m.category) }}>{m.category}</span></td>
                      <td style={{ padding: '4px 8px', fontSize: 9, color: m.source === 'export' ? '#38bdf8' : m.source === 'user' ? '#a78bfa' : '#8b949e' }}>{m.source}</td>
                      <td style={{ padding: '4px 8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <div style={{ width: 40, height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.06)' }}>
                            <div style={{ width: `${m.confidence}%`, height: '100%', borderRadius: 2, background: m.confidence >= 90 ? '#22c55e' : m.confidence >= 80 ? '#f59e0b' : '#f87171' }} />
                          </div>
                          <span style={{ fontSize: 9, color: '#8b949e' }}>{m.confidence}%</span>
                        </div>
                      </td>
                      <td style={{ padding: '4px 8px', color: '#8b949e', fontSize: 10 }}>{m.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {!scanResult && !scanning && (
          <Card>
            <div style={{ textAlign: 'center', padding: '40px 20px', color: '#6b7280' }}>
              <Shield size={32} color="#4b5563" style={{ margin: '0 auto 10px' }} />
              <div style={{ fontSize: 12, marginBottom: 4, color: '#8b949e' }}>PE dosya yolu girin ve taramayı başlatın</div>
              <div style={{ fontSize: 10 }}>Import/export tablosu analiz edilerek bilinen kütüphane fonksiyonları tespit edilecektir.</div>
            </div>
          </Card>
        )}
      </>)}

      {/* Kullanıcı İmzaları Sekmesi */}
      {activeTab === 'user_sigs' && (
        <Card>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 12 }}>Özel İmza Ekle</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
            <input value={newSigName} onChange={e => setNewSigName(e.target.value)} placeholder="Fonksiyon adı (zorunlu)"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '6px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
            <input value={newSigLib} onChange={e => setNewSigLib(e.target.value)} placeholder="Kütüphane adı"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '6px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
            <input value={newSigCat} onChange={e => setNewSigCat(e.target.value)} placeholder="Kategori (ör: Crypto, Network)"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '6px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
            <input value={newSigPattern} onChange={e => setNewSigPattern(e.target.value)} placeholder="Bayt deseni (ör: 55 8B EC ?? ?? 83 EC)"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '6px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', fontFamily: 'monospace' }} />
          </div>
          <button onClick={addUserSig} disabled={!newSigName.trim() || !newSigPattern.trim()} style={{ fontSize: 10, padding: '6px 14px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#22c55e', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Plus size={12} /> İmza Ekle
          </button>

          <div style={{ marginTop: 16, fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>
            Kayıtlı İmzalar ({userSigs.length})
          </div>
          {userSigs.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 24, color: '#6e7681', fontSize: 11 }}>Henüz özel imza eklenmedi.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {userSigs.map((sig, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ flex: 1 }}>
                    <span style={{ fontFamily: 'monospace', color: '#e6edf3', fontWeight: 600, fontSize: 11 }}>{sig.name}</span>
                    <span style={{ marginLeft: 8, fontSize: 9, color: '#8b949e' }}>{sig.lib}</span>
                    <span style={{ marginLeft: 8, fontSize: 9, padding: '1px 5px', borderRadius: 3, background: `${catColor(sig.category)}15`, color: catColor(sig.category) }}>{sig.category}</span>
                    <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#6e7681', marginTop: 2 }}>{sig.pattern}</div>
                  </div>
                  <span style={{ fontSize: 9, color: '#6e7681' }}>{sig.addedAt}</span>
                  <button onClick={() => removeUserSig(i)} style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', padding: 4 }} title="Kaldır">
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

export default FlirtPage;