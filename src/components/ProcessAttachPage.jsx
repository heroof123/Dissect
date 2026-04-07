import React, { useState, useMemo, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Monitor, Search, RefreshCw } from 'lucide-react';
import { Card } from './shared';


function ProcessAttachPage() {
  const [procs, setProcs] = useState([]);
  const [search, setSearch] = useState('');
  const [attached, setAttached] = useState(null);
  const [regions, setRegions] = useState([]);
  const [memDump, setMemDump] = useState(null);
  const [readAddr, setReadAddr] = useState('0x00401000');
  const [readSize, setReadSize] = useState('64');
  const [loading, setLoading] = useState(false);
  const [sortKey, setSortKey] = useState('pid');
  const [sortAsc, setSortAsc] = useState(true);
  const [errMsg, setErrMsg] = useState(null);

  const refreshProcs = useCallback(async () => {
    setLoading(true); setErrMsg(null);
    try {
      const list = await invoke('list_processes');
      setProcs(list.map(p => ({
        pid: p.pid, name: p.name, threads: p.threads,
        parent: p.parent_pid, exe_path: p.exe_path,
        mem: p.memory_kb > 1024 ? `${(p.memory_kb/1024).toFixed(1)} MB` : `${p.memory_kb} KB`,
        memory_kb: p.memory_kb,
      })));
    } catch (e) { setErrMsg(String(e)); }
    setLoading(false);
  }, []);

  useEffect(() => { refreshProcs(); }, [refreshProcs]);

  const filtered = useMemo(() => {
    let list = procs.filter(p => p.name.toLowerCase().includes(search.toLowerCase()) || String(p.pid).includes(search));
    list.sort((a, b) => {
      const av = a[sortKey], bv = b[sortKey];
      const cmp = typeof av === 'string' ? (av || '').localeCompare(bv || '') : (av || 0) - (bv || 0);
      return sortAsc ? cmp : -cmp;
    });
    return list;
  }, [procs, search, sortKey, sortAsc]);

  const doAttach = async (proc) => {
    setLoading(true); setErrMsg(null);
    try {
      const regs = await invoke('query_memory_regions', { pid: proc.pid });
      setAttached(proc);
      setRegions(regs.map(r => ({
        base: r.base_address, size: `0x${r.size.toString(16).toUpperCase()}`,
        type: r.type, protect: r.protect, state: r.state, info: `${r.type} — ${r.protect}`,
      })));
      setMemDump(null);
    } catch (e) { setErrMsg(String(e)); }
    setLoading(false);
  };

  const doDetach = () => { setAttached(null); setRegions([]); setMemDump(null); };

  const doReadMem = async () => {
    if (!attached) return;
    setLoading(true); setErrMsg(null);
    try {
      const hexStr = await invoke('read_process_memory', { pid: attached.pid, address: readAddr, size: parseInt(readSize) || 64 });
      const bytes = [];
      for (let i = 0; i < hexStr.length; i += 2) bytes.push(parseInt(hexStr.substr(i, 2), 16));
      setMemDump({ addr: readAddr, bytes });
    } catch (e) { setErrMsg(String(e)); }
    setLoading(false);
  };

  const hexRow = (bytes, startAddr) => {
    const rows = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const addr = (parseInt(startAddr, 16) + i).toString(16).padStart(8, '0').toUpperCase();
      const hex = chunk.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
      const ascii = chunk.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
      rows.push({ addr, hex: hex.padEnd(48, ' '), ascii });
    }
    return rows;
  };

  const SortHeader = ({ label, k }) => (
    <th onClick={() => { if (sortKey === k) setSortAsc(!sortAsc); else { setSortKey(k); setSortAsc(true); } }}
      style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, color: sortKey === k ? '#818cf8' : '#8b949e', cursor: 'pointer', whiteSpace: 'nowrap', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
      {label} {sortKey === k ? (sortAsc ? '▲' : '▼') : ''}
    </th>
  );

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
        <Monitor size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Process Attach</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Canlı Süreç Bağlanma & Bellek Okuma</span>
        {attached && (
          <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e66', display: 'inline-block' }} />
            <span style={{ fontSize: 11, color: '#22c55e', fontWeight: 600 }}>Attached: {attached.name} (PID {attached.pid})</span>
            <button onClick={doDetach} style={{ marginLeft: 8, fontSize: 10, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>Detach</button>
          </span>
        )}
      </div>

      {loading && <div style={{ textAlign: 'center', padding: 30, color: '#818cf8' }}><div style={{ width: 20, height: 20, border: '2px solid #818cf8', borderTopColor: 'transparent', borderRadius: '50%', animation: '_sp 0.6s linear infinite', display: 'inline-block' }} /></div>}

      {!attached && !loading && (
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <Search size={13} color="#8b949e" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="PID veya isim ara..." style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
            <button onClick={refreshProcs} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.06)', color: '#818cf8', cursor: 'pointer' }}><RefreshCw size={11} style={{ marginRight: 4 }} />Yenile</button>
          </div>
          <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead><tr style={{ background: 'rgba(255,255,255,0.02)' }}>
                <SortHeader label="PID" k="pid" />
                <SortHeader label="Process Name" k="name" />
                <SortHeader label="Memory" k="memory_kb" />
                <SortHeader label="Threads" k="threads" />
                <SortHeader label="Path" k="exe_path" />
                <th style={{ padding: '6px 10px', fontSize: 10, color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}></th>
              </tr></thead>
              <tbody>
                {filtered.map(p => (
                  <tr key={p.pid} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', cursor: 'pointer' }}
                    onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                    onMouseOut={e => e.currentTarget.style.background = ''}>
                    <td style={{ padding: '5px 10px', color: '#818cf8', fontFamily: 'monospace' }}>{p.pid}</td>
                    <td style={{ padding: '5px 10px', fontWeight: 600, color: '#e6edf3' }}>{p.name}</td>
                    <td style={{ padding: '5px 10px', fontFamily: 'monospace', color: '#8b949e' }}>{p.mem}</td>
                    <td style={{ padding: '5px 10px', fontFamily: 'monospace', color: '#8b949e' }}>{p.threads}</td>
                    <td style={{ padding: '5px 10px', color: '#8b949e', fontSize: 10, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.exe_path}</td>
                    <td style={{ padding: '5px 10px' }}>
                      <button onClick={() => doAttach(p)} style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#22c55e', cursor: 'pointer' }}>Attach</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: 8, fontSize: 10, color: '#8b949e' }}>Toplam: {filtered.length} süreç{errMsg && <span style={{ color: '#f87171', marginLeft: 8 }}>{errMsg}</span>}</div>
        </Card>
      )}

      {attached && !loading && (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <Card style={{ flex: 2, minWidth: 400 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📦 Bellek Bölgeleri — {attached.name}</div>
            <div style={{ overflowX: 'auto', maxHeight: 340, overflowY: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Base Address</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Size</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Type</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Protect</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>State</th>
                  <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Info</th>
                </tr></thead>
                <tbody>
                  {regions.map((r, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                      onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                      onMouseOut={e => e.currentTarget.style.background = ''}>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8' }}>{r.base}</td>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#e6edf3' }}>{r.size}</td>
                      <td style={{ padding: '4px 8px' }}>
                        <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4,
                          background: r.type === '.text' ? 'rgba(239,68,68,0.12)' : r.type === 'Heap' ? 'rgba(245,158,11,0.12)' : r.type === 'DLL' ? 'rgba(59,130,246,0.12)' : 'rgba(255,255,255,0.06)',
                          color: r.type === '.text' ? '#f87171' : r.type === 'Heap' ? '#f59e0b' : r.type === 'DLL' ? '#60a5fa' : '#8b949e'
                        }}>{r.type}</span>
                      </td>
                      <td style={{ padding: '4px 8px', fontFamily: 'monospace', fontWeight: 600,
                        color: r.protect.includes('X') ? '#f87171' : r.protect.includes('W') ? '#f59e0b' : '#22c55e'
                      }}>{r.protect}</td>
                      <td style={{ padding: '4px 8px', color: '#8b949e' }}>{r.state}</td>
                      <td style={{ padding: '4px 8px', color: '#8b949e', fontSize: 9 }}>{r.info}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card style={{ flex: 1, minWidth: 300 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>🔍 Bellek Oku</div>
            <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: 120 }}>
                <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 3 }}>Adres</div>
                <input value={readAddr} onChange={e => setReadAddr(e.target.value)} style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '4px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
              </div>
              <div style={{ width: 60 }}>
                <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 3 }}>Boyut</div>
                <input value={readSize} onChange={e => setReadSize(e.target.value)} style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '4px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <button onClick={doReadMem} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>Oku</button>
              </div>
            </div>
            {memDump && (
              <div style={{ background: '#0d1117', borderRadius: 6, padding: 8, fontFamily: 'monospace', fontSize: 10, overflowX: 'auto', border: '1px solid rgba(255,255,255,0.06)', maxHeight: 260, overflowY: 'auto' }}>
                {hexRow(memDump.bytes, memDump.addr).map((r, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, lineHeight: '18px' }}>
                    <span style={{ color: '#818cf8', minWidth: 70 }}>{r.addr}</span>
                    <span style={{ color: '#e6edf3', minWidth: 340 }}>{r.hex}</span>
                    <span style={{ color: '#6e7681' }}>{r.ascii}</span>
                  </div>
                ))}
              </div>
            )}
            <div style={{ marginTop: 8, fontSize: 10, color: '#6e7681' }}>Hızlı bölge seçimi:</div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
              {regions.filter(r => r.type === '.text' || r.type === '.data' || r.type === 'Heap').map((r, i) => (
                <button key={i} onClick={() => { setReadAddr(r.base); setReadSize(String(parseInt(r.size, 16))); }}
                  style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#8b949e', cursor: 'pointer' }}>
                  {r.type} @ {r.base}
                </button>
              ))}
            </div>
          </Card>

          <Card style={{ width: '100%' }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📊 Süreç Detayları</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(175px, 1fr))', gap: 10 }}>
              {[
                { label: 'PID', value: attached.pid, color: '#818cf8' },
                { label: 'İsim', value: attached.name, color: '#e6edf3' },
                { label: 'Bellek', value: attached.mem, color: '#22c55e' },
                { label: 'Thread', value: attached.threads, color: '#60a5fa' },
                { label: 'Parent PID', value: attached.parent, color: '#8b949e' },
                { label: 'Bölge Sayısı', value: regions.length, color: '#a78bfa' },
                { label: 'Path', value: attached.exe_path || '-', color: '#8b949e' },
              ].map((d, i) => (
                <div key={i} style={{ padding: '8px 12px', borderRadius: 6, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 2 }}>{d.label}</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: d.color, fontFamily: typeof d.value === 'number' ? 'monospace' : 'inherit' }}>{d.value}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

// ── 6.2 Debugger Entegrasyonu ─────────────────────────────────────


export default ProcessAttachPage;