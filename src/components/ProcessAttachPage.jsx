import React, { useState, useMemo, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Monitor, Search, RefreshCw, ArrowLeft, Layers, Cpu, PenTool, Database } from 'lucide-react';
import { Card } from './shared';


function ProcessAttachPage() {
  const [procs, setProcs] = useState([]);
  const [search, setSearch] = useState('');
  const [attached, setAttached] = useState(null);
  const [regions, setRegions] = useState([]);
  const [modules, setModules] = useState([]);
  const [threads, setThreads] = useState([]);
  const [memDump, setMemDump] = useState(null);
  const [readAddr, setReadAddr] = useState('0x00401000');
  const [readSize, setReadSize] = useState('64');
  const [loading, setLoading] = useState(false);
  const [sortKey, setSortKey] = useState('pid');
  const [sortAsc, setSortAsc] = useState(true);
  const [errMsg, setErrMsg] = useState(null);
  const [activeTab, setActiveTab] = useState('regions');

  // Memory write state
  const [writeAddr, setWriteAddr] = useState('');
  const [writeHex, setWriteHex] = useState('');
  const [writeStatus, setWriteStatus] = useState(null);

  // Memory search state
  const [searchPattern, setSearchPattern] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [searching, setSearching] = useState(false);

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
      setModules([]); setThreads([]);
      // Load modules & threads in parallel
      try {
        const [mods, thr] = await Promise.all([
          invoke('list_process_modules', { pid: proc.pid }).catch(() => []),
          invoke('list_process_threads', { pid: proc.pid }).catch(() => []),
        ]);
        setModules(mods || []);
        setThreads(thr || []);
      } catch (_) {}
    } catch (e) { setErrMsg(String(e)); }
    setLoading(false);
  };

  const doDetach = () => { setAttached(null); setRegions([]); setMemDump(null); setModules([]); setThreads([]); setSearchResults([]); setWriteStatus(null); };

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

  const doWriteMem = async () => {
    if (!attached || !writeAddr || !writeHex) return;
    setWriteStatus(null);
    try {
      const clean = writeHex.replace(/\s/g, '');
      if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
        setWriteStatus({ ok: false, msg: 'Geçersiz hex formatı (çift sayıda hex karakter gerekir)' });
        return;
      }
      const bytes = [];
      for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.substr(i, 2), 16));
      const written = await invoke('write_process_memory', { pid: attached.pid, address: writeAddr, data: bytes });
      setWriteStatus({ ok: true, msg: `${written} byte yazıldı @ ${writeAddr}` });
    } catch (e) { setWriteStatus({ ok: false, msg: String(e) }); }
  };

  const doSearchMem = async () => {
    if (!attached || !searchPattern) return;
    setSearching(true); setSearchResults([]);
    try {
      const clean = searchPattern.replace(/\s/g, '');
      if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length < 2 || clean.length % 2 !== 0) {
        setSearchResults([{ error: 'Geçersiz hex pattern (min 1 byte, çift sayıda hex)' }]);
        setSearching(false);
        return;
      }
      const bytes = [];
      for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.substr(i, 2), 16));
      const results = await invoke('search_process_memory', { pid: attached.pid, pattern: bytes });
      setSearchResults(results || []);
    } catch (e) { setSearchResults([{ error: String(e) }]); }
    setSearching(false);
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

  const tabBtn = (id, label, icon) => (
    <button key={id} onClick={() => setActiveTab(id)}
      style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, padding: '5px 12px', borderRadius: 5, border: `1px solid ${activeTab === id ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: activeTab === id ? 'rgba(99,102,241,0.12)' : 'transparent', color: activeTab === id ? '#818cf8' : '#8b949e', cursor: 'pointer', fontWeight: activeTab === id ? 600 : 400 }}>
      {icon}{label}
    </button>
  );

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
        <Monitor size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Process Attach</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Canlı Süreç Bağlanma & Bellek Okuma</span>
        {attached && (
          <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
            <button onClick={doDetach} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, padding: '4px 12px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}><ArrowLeft size={12} /> Geri</button>
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
        <div>
          {/* Tabs */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' }}>
            {tabBtn('regions', `Bölgeler (${regions.length})`, <Layers size={11} />)}
            {tabBtn('modules', `Modüller (${modules.length})`, <Database size={11} />)}
            {tabBtn('threads', `Thread'ler (${threads.length})`, <Cpu size={11} />)}
            {tabBtn('readwrite', 'Oku / Yaz', <PenTool size={11} />)}
            {tabBtn('search', 'Bellek Ara', <Search size={11} />)}
          </div>

          {/* Regions Tab */}
          {activeTab === 'regions' && (
            <Card>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📦 Bellek Bölgeleri — {attached.name}</div>
              <div style={{ overflowX: 'auto', maxHeight: 400, overflowY: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                  <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Base Address</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Size</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Type</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Protect</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>State</th>
                    <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}></th>
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
                        <td style={{ padding: '4px 8px' }}>
                          <button onClick={() => { setReadAddr(r.base); setReadSize('256'); setActiveTab('readwrite'); }}
                            style={{ fontSize: 8, padding: '1px 6px', borderRadius: 3, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer' }}>Oku</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {/* Modules Tab */}
          {activeTab === 'modules' && (
            <Card>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3' }}>📦 Yüklü Modüller — {attached.name}</span>
                <button onClick={async () => { try { const m = await invoke('list_process_modules', { pid: attached.pid }); setModules(m || []); } catch(_){} }}
                  style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer' }}>
                  <RefreshCw size={9} /> Yenile
                </button>
              </div>
              {modules.length === 0 ? (
                <div style={{ color: '#6b7280', fontSize: 11, padding: 20, textAlign: 'center' }}>Modül bilgisi alınamadı. Yönetici olarak çalıştırmayı deneyin.</div>
              ) : (
                <div style={{ overflowX: 'auto', maxHeight: 400, overflowY: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                    <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Module Name</th>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Base Address</th>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Size</th>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Path</th>
                    </tr></thead>
                    <tbody>
                      {modules.map((m, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                          onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                          onMouseOut={e => e.currentTarget.style.background = ''}>
                          <td style={{ padding: '4px 8px', fontWeight: 600, color: '#e6edf3' }}>{m.name}</td>
                          <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8' }}>{m.base_address}</td>
                          <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#8b949e' }}>{m.size ? `0x${m.size.toString(16).toUpperCase()}` : '-'}</td>
                          <td style={{ padding: '4px 8px', color: '#6b7280', fontSize: 9, maxWidth: 350, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.path || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          )}

          {/* Threads Tab */}
          {activeTab === 'threads' && (
            <Card>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3' }}>🧵 Thread'ler — {attached.name}</span>
                <button onClick={async () => { try { const t = await invoke('list_process_threads', { pid: attached.pid }); setThreads(t || []); } catch(_){} }}
                  style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer' }}>
                  <RefreshCw size={9} /> Yenile
                </button>
              </div>
              {threads.length === 0 ? (
                <div style={{ color: '#6b7280', fontSize: 11, padding: 20, textAlign: 'center' }}>Thread bilgisi alınamadı.</div>
              ) : (
                <div style={{ overflowX: 'auto', maxHeight: 400, overflowY: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                    <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Thread ID</th>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Owner PID</th>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Base Priority</th>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>İşlem</th>
                    </tr></thead>
                    <tbody>
                      {threads.map((t, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                          onMouseOver={e => e.currentTarget.style.background = 'rgba(99,102,241,0.04)'}
                          onMouseOut={e => e.currentTarget.style.background = ''}>
                          <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#818cf8', fontWeight: 600 }}>{t.tid || t.thread_id}</td>
                          <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#8b949e' }}>{t.owner_pid}</td>
                          <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: '#8b949e' }}>{t.base_priority}</td>
                          <td style={{ padding: '4px 8px' }}>
                            <div style={{ display: 'flex', gap: 4 }}>
                              <button onClick={async () => { try { const msg = await invoke('suspend_thread', { tid: t.tid || t.thread_id }); alert(msg); } catch(e) { alert(String(e)); } }}
                                style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#f59e0b', cursor: 'pointer' }}>Durdur</button>
                              <button onClick={async () => { try { const msg = await invoke('resume_thread', { tid: t.tid || t.thread_id }); alert(msg); } catch(e) { alert(String(e)); } }}
                                style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#22c55e', cursor: 'pointer' }}>Devam</button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          )}

          {/* Read / Write Tab */}
          {activeTab === 'readwrite' && (
            <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
              <Card style={{ flex: 1, minWidth: 320 }}>
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
                  <div style={{ background: '#0d1117', borderRadius: 6, padding: 8, fontFamily: 'monospace', fontSize: 10, overflowX: 'auto', border: '1px solid rgba(255,255,255,0.06)', maxHeight: 300, overflowY: 'auto' }}>
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
                  {regions.filter(r => r.type === '.text' || r.type === '.data' || r.type === 'Heap').slice(0, 8).map((r, i) => (
                    <button key={i} onClick={() => { setReadAddr(r.base); setReadSize('256'); }}
                      style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#8b949e', cursor: 'pointer' }}>
                      {r.type} @ {r.base}
                    </button>
                  ))}
                </div>
              </Card>

              <Card style={{ flex: 1, minWidth: 320 }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>✏️ Bellek Yaz</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div>
                    <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 3 }}>Hedef Adres</div>
                    <input value={writeAddr} onChange={e => setWriteAddr(e.target.value)} placeholder="0x00401000"
                      style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '4px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 3 }}>Hex Veri (ör: 90 90 CC EB 05)</div>
                    <input value={writeHex} onChange={e => setWriteHex(e.target.value)} placeholder="90 90 90 90"
                      style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '4px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
                  </div>
                  <button onClick={doWriteMem} disabled={!writeAddr || !writeHex}
                    style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.12)', color: '#f59e0b', cursor: (!writeAddr || !writeHex) ? 'not-allowed' : 'pointer', fontWeight: 600, alignSelf: 'flex-start' }}>
                    ⚡ Yaz
                  </button>
                  {writeStatus && (
                    <div style={{ fontSize: 10, padding: '4px 8px', borderRadius: 4, background: writeStatus.ok ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', color: writeStatus.ok ? '#22c55e' : '#f87171', border: `1px solid ${writeStatus.ok ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)'}` }}>
                      {writeStatus.ok ? '✓' : '✗'} {writeStatus.msg}
                    </div>
                  )}
                </div>
              </Card>
            </div>
          )}

          {/* Search Tab */}
          {activeTab === 'search' && (
            <Card>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>🔎 Bellek Arama — Tüm bölgelerde pattern ara</div>
              <div style={{ display: 'flex', gap: 6, marginBottom: 10, alignItems: 'flex-end' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 3 }}>Hex Pattern (ör: 4D 5A 90 00)</div>
                  <input value={searchPattern} onChange={e => setSearchPattern(e.target.value)} placeholder="4D 5A 90 00"
                    style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '5px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
                </div>
                <button onClick={doSearchMem} disabled={searching || !searchPattern}
                  style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: (searching || !searchPattern) ? 'not-allowed' : 'pointer', fontWeight: 600 }}>
                  {searching ? '⏳ Aranıyor...' : '🔍 Ara'}
                </button>
              </div>
              {searchResults.length > 0 && !searchResults[0]?.error && (
                <div style={{ overflowX: 'auto', maxHeight: 350, overflowY: 'auto', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: 10, color: '#8b949e', marginBottom: 4 }}>{searchResults.length} sonuç bulundu</div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                    <thead><tr style={{ background: 'rgba(255,255,255,0.02)', position: 'sticky', top: 0, zIndex: 1 }}>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>#</th>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>Address</th>
                      <th style={{ padding: '5px 8px', textAlign: 'left', color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}></th>
                    </tr></thead>
                    <tbody>
                      {searchResults.map((addr, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                          <td style={{ padding: '3px 8px', color: '#6b7280' }}>{i + 1}</td>
                          <td style={{ padding: '3px 8px', fontFamily: 'monospace', color: '#818cf8' }}>{typeof addr === 'string' ? addr : `0x${addr.toString(16).toUpperCase()}`}</td>
                          <td style={{ padding: '3px 8px' }}>
                            <button onClick={() => { setReadAddr(typeof addr === 'string' ? addr : `0x${addr.toString(16)}`); setReadSize('64'); setActiveTab('readwrite'); }}
                              style={{ fontSize: 8, padding: '1px 6px', borderRadius: 3, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer' }}>Göster</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {searchResults.length > 0 && searchResults[0]?.error && (
                <div style={{ color: '#f87171', fontSize: 11, padding: '6px 10px', background: 'rgba(248,113,113,0.08)', borderRadius: 6 }}>❌ {searchResults[0].error}</div>
              )}
              {searchResults.length === 0 && !searching && searchPattern && (
                <div style={{ color: '#6b7280', fontSize: 11, padding: 10 }}>Henüz arama yapılmadı.</div>
              )}
            </Card>
          )}

          {/* Process Details */}
          <Card style={{ marginTop: 14 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', marginBottom: 8 }}>📊 Süreç Detayları</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(175px, 1fr))', gap: 10 }}>
              {[
                { label: 'PID', value: attached.pid, color: '#818cf8' },
                { label: 'İsim', value: attached.name, color: '#e6edf3' },
                { label: 'Bellek', value: attached.mem, color: '#22c55e' },
                { label: 'Thread', value: threads.length || attached.threads, color: '#60a5fa' },
                { label: 'Modül', value: modules.length, color: '#a78bfa' },
                { label: 'Parent PID', value: attached.parent, color: '#8b949e' },
                { label: 'Bölge Sayısı', value: regions.length, color: '#f59e0b' },
                { label: 'Path', value: attached.exe_path || '-', color: '#8b949e' },
              ].map((d, i) => (
                <div key={i} style={{ padding: '8px 12px', borderRadius: 6, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 2 }}>{d.label}</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: d.color, fontFamily: typeof d.value === 'number' ? 'monospace' : 'inherit', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.value}</div>
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