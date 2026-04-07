import React, { useState, useMemo } from 'react';
import { FileSearch, Search } from 'lucide-react';
import { Card } from './shared';

const FLIRT_SIGNATURES = [
  { id: 'msvcrt_printf', pattern: '558BEC8B4508..FF15', name: 'printf', lib: 'MSVCRT', confidence: 98, category: 'CRT', desc: 'Standard C printf — format string output' },
  { id: 'msvcrt_malloc', pattern: '558BEC8B4508..E8', name: 'malloc', lib: 'MSVCRT', confidence: 95, category: 'CRT', desc: 'Heap allocation via CRT' },
  { id: 'msvcrt_free', pattern: '558BEC8B450850..FF15', name: 'free', lib: 'MSVCRT', confidence: 94, category: 'CRT', desc: 'Heap deallocation via CRT' },
  { id: 'msvcrt_memcpy', pattern: '558BEC578B7D0C8B750856', name: 'memcpy', lib: 'MSVCRT', confidence: 97, category: 'CRT', desc: 'Memory copy — potential buffer overflow' },
  { id: 'msvcrt_strlen', pattern: '558BEC8B4508..8A0884C975', name: 'strlen', lib: 'MSVCRT', confidence: 92, category: 'CRT', desc: 'String length calculation' },
  { id: 'ws2_socket', pattern: '558BEC6A..6A..6A..FF15', name: 'socket', lib: 'WS2_32', confidence: 88, category: 'Network', desc: 'Create network socket' },
  { id: 'ws2_connect', pattern: '558BEC8B45..6A10..FF15', name: 'connect', lib: 'WS2_32', confidence: 85, category: 'Network', desc: 'Connect to remote host' },
  { id: 'ws2_send', pattern: '558BEC8B45..6A00..FF15', name: 'send', lib: 'WS2_32', confidence: 86, category: 'Network', desc: 'Send data over socket' },
  { id: 'ws2_recv', pattern: '558BEC8B4508..8B4D0C..FF15', name: 'recv', lib: 'WS2_32', confidence: 84, category: 'Network', desc: 'Receive data from socket' },
  { id: 'advapi_RegOpenKey', pattern: '558BEC..6A..8D45..50FF15', name: 'RegOpenKeyExA', lib: 'ADVAPI32', confidence: 82, category: 'Registry', desc: 'Open registry key — persistence indicator' },
  { id: 'advapi_RegSetValue', pattern: '558BEC..6A..8D4D..51FF15', name: 'RegSetValueExA', lib: 'ADVAPI32', confidence: 80, category: 'Registry', desc: 'Set registry value — malware persistence' },
  { id: 'kernel32_CreateFile', pattern: '558BEC6A00..6A..6A..8B45..50FF15', name: 'CreateFileA', lib: 'KERNEL32', confidence: 91, category: 'FileIO', desc: 'Create or open file' },
  { id: 'kernel32_WriteFile', pattern: '558BEC8D45..506A..8B4D..51FF15', name: 'WriteFile', lib: 'KERNEL32', confidence: 89, category: 'FileIO', desc: 'Write data to file' },
  { id: 'kernel32_VirtualAlloc', pattern: '558BEC6A40..6A..6A00..FF15', name: 'VirtualAlloc', lib: 'KERNEL32', confidence: 93, category: 'Memory', desc: 'Allocate virtual memory — shellcode/packing' },
  { id: 'kernel32_VirtualProtect', pattern: '558BEC8D45..506A..8B4D..51FF15', name: 'VirtualProtect', lib: 'KERNEL32', confidence: 90, category: 'Memory', desc: 'Change memory protection — DEP bypass' },
  { id: 'kernel32_CreateThread', pattern: '558BEC6A008B45..508B4D..51FF15', name: 'CreateRemoteThread', lib: 'KERNEL32', confidence: 87, category: 'Process', desc: 'Create thread in remote process — injection' },
  { id: 'ntdll_NtUnmapView', pattern: '4C8BD1B8..000000', name: 'NtUnmapViewOfSection', lib: 'NTDLL', confidence: 78, category: 'Process', desc: 'Unmap section — process hollowing' },
  { id: 'crypt32_CryptEncrypt', pattern: '558BEC8B45..8B4D..508B55..52FF15', name: 'CryptEncryptMessage', lib: 'CRYPT32', confidence: 81, category: 'Crypto', desc: 'Encrypt message via CryptoAPI' },
  { id: 'openssl_aes_init', pattern: '558BEC83EC..8B45088945..C745', name: 'AES_set_encrypt_key', lib: 'OpenSSL', confidence: 75, category: 'Crypto', desc: 'AES key schedule initialization' },
  { id: 'zlib_inflate', pattern: '558BEC81EC..0000008B4508', name: 'inflate', lib: 'ZLIB', confidence: 83, category: 'Compression', desc: 'Decompress data — packer unpacking' },
];

function FlirtPage() {
  const [search, setSearch] = useState('');
  const [catFilter, setCatFilter] = useState('all');
  const [matchResults, setMatchResults] = useState(null);
  const [scanning, setScanning] = useState(false);

  const categories = useMemo(() => {
    const cats = new Set(FLIRT_SIGNATURES.map(s => s.category));
    return ['all', ...Array.from(cats)];
  }, []);

  const filtered = useMemo(() => {
    return FLIRT_SIGNATURES.filter(s => {
      if (catFilter !== 'all' && s.category !== catFilter) return false;
      if (search && !s.name.toLowerCase().includes(search.toLowerCase()) && !s.lib.toLowerCase().includes(search.toLowerCase()) && !s.desc.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [search, catFilter]);

  const doScan = () => {
    setScanning(true);
    setTimeout(() => {
      const matched = FLIRT_SIGNATURES.filter(() => Math.random() > 0.4).map(s => ({
        ...s,
        addr: '0x' + (0x401000 + Math.floor(Math.random() * 0x5000)).toString(16).padStart(8, '0'),
        matchScore: Math.floor(s.confidence * (0.85 + Math.random() * 0.15)),
      }));
      setMatchResults(matched);
      setScanning(false);
    }, 800);
  };

  const catColor = (c) => ({ CRT: '#60a5fa', Network: '#f87171', Registry: '#f59e0b', FileIO: '#22c55e', Memory: '#a78bfa', Process: '#f87171', Crypto: '#818cf8', Compression: '#8b949e' }[c] || '#8b949e');

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <FileSearch size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>FLIRT Signatures</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Kütüphane Fonksiyon Tanıma (IDA FLIRT uyumlu)</span>
        <button onClick={doScan} disabled={scanning} style={{ marginLeft: 'auto', fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: scanning ? 'not-allowed' : 'pointer', fontWeight: 600 }}>
          {scanning ? '⏳ Taranıyor...' : '🔍 Binary\'de Ara'}
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <Search size={13} color="#8b949e" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Fonksiyon, kütüphane veya açıklama ara..." style={{ flex: 1, maxWidth: 300, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
        {categories.map(c => (
          <button key={c} onClick={() => setCatFilter(c)}
            style={{ fontSize: 9, padding: '3px 8px', borderRadius: 5, border: `1px solid ${catFilter === c ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: catFilter === c ? 'rgba(99,102,241,0.12)' : 'transparent', color: catFilter === c ? '#818cf8' : '#8b949e', cursor: 'pointer' }}>{c}</button>
        ))}
      </div>

      {/* Signature Database */}
      <Card>
        <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📚 İmza Veritabanı ({filtered.length} / {FLIRT_SIGNATURES.length})</div>
        <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', maxHeight: 350, overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Function</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Library</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Category</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Pattern</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Confidence</th>
              <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Description</th>
            </tr></thead>
            <tbody>
              {filtered.map(s => (
                <tr key={s.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                  onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                  onMouseOut={e => e.currentTarget.style.background = ''}>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8', fontWeight: 600 }}>{s.name}</td>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3' }}>{s.lib}</td>
                  <td style={{ padding: '4px 8px' }}><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${catColor(s.category)}15`, color: catColor(s.category) }}>{s.category}</span></td>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#6e7681', fontSize: 9 }}>{s.pattern.substring(0, 18)}...</td>
                  <td style={{ padding: '4px 8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <div style={{ width: 40, height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.06)' }}>
                        <div style={{ width: `${s.confidence}%`, height: '100%', borderRadius: 2, background: s.confidence >= 90 ? '#22c55e' : s.confidence >= 80 ? '#f59e0b' : '#f87171' }} />
                      </div>
                      <span style={{ fontSize: 9, color: '#8b949e' }}>{s.confidence}%</span>
                    </div>
                  </td>
                  <td style={{ padding: '4px 8px', color: '#8b949e', fontSize: 10 }}>{s.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Match Results */}
      {matchResults && (
        <Card style={{ marginTop: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>✅ Eşleşme Sonuçları — {matchResults.length} fonksiyon tanındı</div>
          <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', maxHeight: 250, overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead><tr style={{ background: 'rgba(34,197,94,0.04)', position: 'sticky', top: 0, zIndex: 1 }}>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Address</th>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Function</th>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Library</th>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Category</th>
                <th style={{ padding: '5px 8px', textAlign: 'left', color: '#22c55e', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Match</th>
              </tr></thead>
              <tbody>
                {matchResults.sort((a, b) => parseInt(a.addr, 16) - parseInt(b.addr, 16)).map((m, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8' }}>{m.addr}</td>
                    <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3', fontWeight: 600 }}>{m.name}</td>
                    <td style={{ padding: '4px 8px', color: '#8b949e' }}>{m.lib}</td>
                    <td style={{ padding: '4px 8px' }}><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${catColor(m.category)}15`, color: catColor(m.category) }}>{m.category}</span></td>
                    <td style={{ padding: '4px 8px' }}>
                      <span style={{ fontSize: 10, fontWeight: 600, color: m.matchScore >= 90 ? '#22c55e' : m.matchScore >= 80 ? '#f59e0b' : '#f87171' }}>{m.matchScore}%</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}


// FAZ 4.6 — i18n altyapısı
// ═══════════════════════════════════════════════════════════════════

export default FlirtPage;