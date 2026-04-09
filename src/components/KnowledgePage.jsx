import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Database, Search, Plus, List, BookOpen, File, AlertTriangle, CheckCircle, RefreshCw } from 'lucide-react';

const riskColor = { Düşük: '#22c55e', Orta: '#f59e0b', Yüksek: '#ef4444', Kritik: '#dc2626', Bilinmiyor: '#6b7280' };
const archColor = { x64: '#818cf8', x86: '#fb923c', '?': '#4b5563' };

export default function KnowledgePage({ filePath }) {
  const [tab, setTab] = useState('gecmis'); // gecmis | ara | mitre | index
  const [scans, setScans] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState(null);
  const [mitreQuery, setMitreQuery] = useState('');
  const [mitreResults, setMitreResults] = useState(null);
  const [indexFile, setIndexFile] = useState(filePath || '');
  const [indexResult, setIndexResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (tab === 'gecmis') loadScans();
  }, [tab]);

  const loadScans = async () => {
    setLoading(true);
    try {
      const res = await invoke('rag_list_scans', { limit: 100 });
      setScans(res.scans || []);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    setLoading(true);
    setSearchResults(null);
    try {
      const res = await invoke('rag_search_similar', { query: searchQuery, limit: 20 });
      setSearchResults(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleMitre = async () => {
    if (!mitreQuery.trim()) return;
    setLoading(true);
    setMitreResults(null);
    try {
      const res = await invoke('rag_search_knowledge', { query: mitreQuery });
      setMitreResults(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleIndex = async () => {
    if (!indexFile.trim()) return;
    setLoading(true);
    setIndexResult(null);
    setError(null);
    try {
      const res = await invoke('rag_index_scan', { filePath: indexFile });
      setIndexResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { key: 'gecmis', label: 'Tarama Geçmişi', icon: List },
    { key: 'ara', label: 'Benzer Binary Ara', icon: Search },
    { key: 'mitre', label: 'ATT&CK / Tehdit Bilgisi', icon: BookOpen },
    { key: 'index', label: 'Binary İndeksle', icon: Plus },
  ];

  const formatBytes = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes/1024).toFixed(1)} KB`;
    return `${(bytes/1048576).toFixed(1)} MB`;
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 24, gap: 16, overflowY: 'auto' }}>
      {/* Başlık */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Database size={20} color="#a78bfa" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>Bilgi Tabanı & RAG</span>
        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(167,139,250,0.15)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.3)', fontWeight: 600 }}>D2</span>
        <span style={{ fontSize: 10, color: '#4b5563' }}>SQLite · TF-IDF · MITRE ATT&CK</span>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        {tabs.map(t => {
          const Icon = t.icon;
          return (
            <button key={t.key} onClick={() => setTab(t.key)}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', background: 'none', border: 'none', cursor: 'pointer', fontSize: 11, fontWeight: tab === t.key ? 700 : 400, color: tab === t.key ? '#e2e8f0' : '#6b7280', borderBottom: tab === t.key ? '2px solid #a78bfa' : '2px solid transparent', marginBottom: -1 }}>
              <Icon size={12} /> {t.label}
            </button>
          );
        })}
      </div>

      {/* Hata */}
      {error && (
        <div style={{ display: 'flex', gap: 8, padding: '8px 12px', borderRadius: 5, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#fca5a5', fontSize: 11 }}>
          <AlertTriangle size={13} style={{ flexShrink: 0 }} /> {error}
          <button onClick={() => setError(null)} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer', fontSize: 10 }}>✕</button>
        </div>
      )}

      {/* Tarama Geçmişi */}
      {tab === 'gecmis' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 11, color: '#6b7280' }}>{scans.length} kayıt</span>
            <button onClick={loadScans} disabled={loading} style={{ display: 'flex', gap: 5, alignItems: 'center', padding: '4px 10px', borderRadius: 5, background: 'rgba(167,139,250,0.1)', border: '1px solid rgba(167,139,250,0.2)', color: '#a78bfa', cursor: 'pointer', fontSize: 10 }}>
              <RefreshCw size={11} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} /> Yenile
            </button>
          </div>
          {scans.length === 0 && !loading && (
            <div style={{ textAlign: 'center', padding: 40, color: '#4b5563', fontSize: 12 }}>
              Henüz indekslenmiş binary yok.<br />
              <span style={{ fontSize: 10, color: '#374151' }}>Binary İndeksle sekmesinde PE dosyası ekleyebilirsin.</span>
            </div>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 8 }}>
            {scans.map(s => (
              <div key={s.id} style={{ padding: '10px 14px', borderRadius: 7, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <File size={12} color="#6b7280" />
                  <span style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.file_name}</span>
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', fontSize: 9 }}>
                  <span style={{ padding: '1px 6px', borderRadius: 3, background: `${archColor[s.arch] || '#6b7280'}22`, color: archColor[s.arch] || '#6b7280', border: `1px solid ${archColor[s.arch] || '#6b7280'}44` }}>{s.arch}</span>
                  {s.is_dll && <span style={{ padding: '1px 6px', borderRadius: 3, background: 'rgba(234,179,8,0.1)', color: '#eab308', border: '1px solid rgba(234,179,8,0.2)' }}>DLL</span>}
                  <span style={{ padding: '1px 6px', borderRadius: 3, background: `${riskColor[s.risk_level] || '#6b7280'}22`, color: riskColor[s.risk_level] || '#9ca3af', border: `1px solid ${riskColor[s.risk_level] || '#6b7280'}44` }}>{s.risk_level}</span>
                  <span style={{ color: '#4b5563' }}>{formatBytes(s.size_bytes)}</span>
                </div>
                <div style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace' }}>{s.file_hash?.slice(0, 16)}...</div>
                <div style={{ fontSize: 9, color: '#4b5563' }}>{s.scanned_at}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Benzer Binary Ara */}
      {tab === 'ara' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 11, color: '#6b7280' }}>
            İmport adı, section adı, risk seviyesi veya SHA256 ile geçmiş taramalarda arama yapın.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSearch()}
              placeholder="Örn: CreateRemoteThread, UPX, Yüksek, kernel32.dll..."
              style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(167,139,250,0.3)', borderRadius: 5, padding: '7px 12px', fontSize: 12, color: '#e2e8f0', outline: 'none' }}
            />
            <button onClick={handleSearch} disabled={loading} style={{ padding: '7px 16px', borderRadius: 5, background: 'rgba(167,139,250,0.2)', border: '1px solid rgba(167,139,250,0.4)', color: '#a78bfa', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
              {loading ? '...' : 'Ara'}
            </button>
          </div>
          {searchResults && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 10, color: '#6b7280' }}>{searchResults.results?.length || 0} sonuç bulundu</div>
              {searchResults.results?.map(r => (
                <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 6, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <File size={13} color="#6b7280" />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, color: '#e2e8f0', fontWeight: 600 }}>{r.file_name}</div>
                    <div style={{ fontSize: 10, color: '#6b7280', fontFamily: 'monospace' }}>{r.file_hash?.slice(0,20)}...</div>
                  </div>
                  <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: `${riskColor[r.risk_level] || '#6b7280'}22`, color: riskColor[r.risk_level] || '#9ca3af', border: `1px solid ${riskColor[r.risk_level] || '#6b7280'}44` }}>{r.risk_level}</span>
                  <span style={{ fontSize: 9, color: '#818cf8' }}>Puan: {r.score}</span>
                </div>
              ))}
              {searchResults.results?.length === 0 && (
                <div style={{ font: '11px sans-serif', color: '#4b5563', padding: '12px 0' }}>Eşleşen sonuç bulunamadı.</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* MITRE ATT&CK */}
      {tab === 'mitre' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 11, color: '#6b7280' }}>
            MITRE ATT&CK tekniklerini ve zararlı yazılım ailelerini sorgulayın.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={mitreQuery}
              onChange={e => setMitreQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleMitre()}
              placeholder="Örn: injection, ransomware, persistence, WannaCry..."
              style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(167,139,250,0.3)', borderRadius: 5, padding: '7px 12px', fontSize: 12, color: '#e2e8f0', outline: 'none' }}
            />
            <button onClick={handleMitre} disabled={loading} style={{ padding: '7px 16px', borderRadius: 5, background: 'rgba(167,139,250,0.2)', border: '1px solid rgba(167,139,250,0.4)', color: '#a78bfa', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
              {loading ? '...' : 'Sorgula'}
            </button>
          </div>
          {mitreResults && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ fontSize: 10, color: '#6b7280' }}>Kaynak: {mitreResults.source} · {mitreResults.count} sonuç</div>
              {mitreResults.results?.map((r, i) => (
                <div key={i} style={{ padding: '10px 14px', borderRadius: 6, background: 'rgba(167,139,250,0.05)', border: '1px solid rgba(167,139,250,0.15)' }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: 'rgba(167,139,250,0.2)', color: '#a78bfa', fontWeight: 700, fontFamily: 'monospace' }}>{r.id}</span>
                    <span style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{r.name}</span>
                  </div>
                  <div style={{ fontSize: 11, color: '#9ca3af', lineHeight: 1.5 }}>{r.description}</div>
                </div>
              ))}
              {mitreResults.results?.length === 0 && (
                <div style={{ font: '11px sans-serif', color: '#4b5563', padding: '12px 0' }}>Eşleşen teknik bulunamadı.</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Binary İndeksle */}
      {tab === 'index' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 11, color: '#6b7280' }}>
            Bir PE dosyasını analiz edip bilgi tabanına ekleyin. Gelecekte "benzer binary" aramalarında kullanılabilir.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={indexFile}
              onChange={e => setIndexFile(e.target.value)}
              placeholder="C:\yol\dosya.exe"
              style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(167,139,250,0.3)', borderRadius: 5, padding: '7px 12px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }}
            />
            <button onClick={handleIndex} disabled={loading || !indexFile.trim()} style={{ padding: '7px 16px', borderRadius: 5, background: 'rgba(167,139,250,0.2)', border: '1px solid rgba(167,139,250,0.4)', color: '#a78bfa', cursor: loading ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 600 }}>
              {loading ? 'İşleniyor...' : 'İndeksle'}
            </button>
          </div>
          {indexResult && (
            <div style={{ display: 'flex', gap: 10, padding: '10px 14px', borderRadius: 6, background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)' }}>
              <CheckCircle size={14} color="#22c55e" style={{ flexShrink: 0, marginTop: 2 }} />
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <div style={{ fontSize: 12, color: '#22c55e', fontWeight: 600 }}>{indexResult.status} — {indexResult.file_name}</div>
                <div style={{ fontSize: 10, color: '#6b7280' }}>Hash: <span style={{ fontFamily: 'monospace', color: '#9ca3af' }}>{indexResult.file_hash?.slice(0,20)}...</span></div>
                <div style={{ fontSize: 10, color: '#6b7280' }}>
                  Risk: <span style={{ color: riskColor[indexResult.risk_level] || '#9ca3af' }}>{indexResult.risk_level}</span>
                  {' · '}Anti-analiz skoru: <span style={{ color: '#e2e8f0' }}>{indexResult.anti_score}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
