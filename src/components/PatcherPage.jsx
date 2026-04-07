import React, { useState, useRef, useCallback, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Plus, Trash2, Play, Download, Copy, ChevronDown,
  Binary, RefreshCw, FolderOpen, Search, CheckCircle2, XCircle,
  Zap, AlertTriangle, Bot
} from 'lucide-react';
import { Card, CardHeader, Spinner } from './shared';

function PatcherPage({ onSendToChat }) {
  const [patchFile,    setPatchFile]    = useState(null);
  const [patchBytes,   setPatchBytes]   = useState(null);  // 45 — raw bytes for pattern search
  const [patches, setPatches] = useState([
    { id: 1, name: 'NOP License Check',   offset: '0x004A1B2C', original: 'FF D0 84 C0 74 0E', patched: '90 90 90 90 90 90', enabled: true,  applied: false },
    { id: 2, name: 'Skip Steam Init',     offset: '0x00521FF0', original: 'E8 3B 00 00 00',    patched: '90 90 90 90 90',    enabled: false, applied: false },
    { id: 3, name: 'Disable Intro Video', offset: '0x00389A10', original: 'E8 C4 2A 00 00 85', patched: '33 C0 40 90 90 90', enabled: true,  applied: false },
  ]);
  const [showForm,     setShowForm]     = useState(false);
  const [form,         setForm]         = useState({ name: '', offset: '', original: '', patched: '' });
  const [dragOver,     setDragOver]     = useState(false);
  const [applyStatus,  setApplyStatus]  = useState(null);
  const [hexData,      setHexData]      = useState(null);
  const [hexLoading,   setHexLoading]   = useState(false);
  const [patHex,       setPatHex]       = useState('');   // 45
  const [patResults,   setPatResults]   = useState(null); // 45
  const ref           = useRef(null);
  const jsonImportRef = useRef(null);                     // 46
  // D3/D5 — Patch validation + before/after state
  const [patchValidation, setPatchValidation] = useState(null); // D3
  const [preApplyHex, setPreApplyHex]         = useState({});   // D5 — {patchId: hexBefore}
  // D4 — Conditional patch script
  const [scriptText, setScriptText] = useState('# Örnek:\n# if byte@0x00400000 == 0xE8 then patch 0x00400000 = 90 90 90 90 90\n');
  const [scriptResults, setScriptResults] = useState(null);
  const [showScript, setShowScript] = useState(false);
  // D6 — Bulk patch
  const [bulkFiles, setBulkFiles]     = useState([]); // {name, path, status}
  const [bulkRunning, setBulkRunning] = useState(false);
  const bulkRef = useRef(null);

  const enabledCount = patches.filter(p => p.enabled).length;
  const appliedCount = patches.filter(p => p.applied).length;

  // Load file + store raw bytes for pattern search (45)
  const loadPatchFile = (f) => {
    if (!f) return;
    setPatchFile(f); setPatchBytes(null); setPatResults(null);
    const reader = new FileReader();
    reader.onload = e => setPatchBytes(new Uint8Array(e.target.result));
    reader.readAsArrayBuffer(f);
  };

  // 45 — Byte pattern search (0xFF = wildcard)
  const searchPattern = () => {
    if (!patchBytes || !patHex.trim()) return;
    const bytes = patHex.trim().split(/[\s,]+/).map(h => parseInt(h, 16)).filter(n => !isNaN(n));
    if (!bytes.length) return;
    const offsets = [];
    outer: for (let i = 0; i <= patchBytes.length - bytes.length; i++) {
      for (let j = 0; j < bytes.length; j++)
        if (bytes[j] !== 0xFF && patchBytes[i + j] !== bytes[j]) continue outer;
      offsets.push(`0x${i.toString(16).toUpperCase().padStart(8,'0')}`);
      if (offsets.length >= 200) { offsets.push('⬦(limit 200)'); break; }
    }
    setPatResults(offsets);
  };

  // 46 — Export patches to JSON
  const exportPatches = () => {
    const blob = new Blob([JSON.stringify({ version: 1, patches }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `patches_${(patchFile?.name || 'export').replace(/\.[^.]+$/, '')}_${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(a.href);
  };

  // 46 — Import patches from JSON
  const importPatches = (f) => {
    if (!f) return;
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const data = JSON.parse(e.target.result);
        if (Array.isArray(data.patches))
          setPatches(data.patches.map((p, i) => ({ ...p, id: Date.now() + i, applied: false })));
      } catch { alert('Geçersiz patch JSON dosyası.'); }
    };
    reader.readAsText(f);
  };

  // 42+43 — Real apply via Rust
  const applyPatches = async () => {
    if (!patchFile?.path) { setApplyStatus({ ok: false, msg: 'Tauri dosya yolu alınamadı. Dosyayı önce sürükle-bırak ile yükleyin.' }); return; }
    setApplyStatus(null); setPatchValidation(null);

    // D5 — capture before-apply hex for enabled patches
    const beforeHex = {};
    for (const p of patches.filter(x => x.enabled)) {
      try {
        const offset = parseInt(p.offset, 16) || parseInt(p.offset, 10) || 0;
        const hex = await invoke('read_hex_region', { filePath: patchFile.path, offset, length: p.patched.trim().split(/\s+/).length });
        beforeHex[p.id] = hex;
      } catch {}
    }
    setPreApplyHex(beforeHex);

    try {
      const msg = await invoke('apply_patches', {
        filePath: patchFile.path,
        patches: patches.map(p => ({ name: p.name, offset: p.offset, patched: p.patched, enabled: p.enabled })),
      });
      setPatches(ps => ps.map(p => p.enabled ? { ...p, applied: true } : p));
      setApplyStatus({ ok: true, msg });

      // D3 — Validate: re-read bytes after apply and compare with expected
      const validation = [];
      for (const p of patches.filter(x => x.enabled)) {
        try {
          const offset = parseInt(p.offset, 16) || parseInt(p.offset, 10) || 0;
          const expected = p.patched.trim().split(/\s+/).map(h => parseInt(h, 16));
          const hex = await invoke('read_hex_region', { filePath: patchFile.path, offset, length: expected.length });
          const actual = hex.split(/\s+/).map(h => parseInt(h, 16));
          const match = expected.every((b, i) => b === actual[i]);
          validation.push({ name: p.name, offset: p.offset, expected: p.patched, actual: hex.trim(), ok: match });
        } catch (e) {
          validation.push({ name: p.name, offset: p.offset, ok: false, error: String(e) });
        }
      }
      setPatchValidation(validation);
    } catch (e) {
      setApplyStatus({ ok: false, msg: String(e) });
    }
  };

  // 44 — Hex viewer
  const loadHex = async (patch) => {
    if (!patchFile?.path) return;
    if (hexData?.patchId === patch.id) { setHexData(null); return; } // toggle
    setHexLoading(true);
    try {
      const offset = parseInt(patch.offset, 16) || parseInt(patch.offset, 10) || 0;
      const hex = await invoke('read_hex_region', { filePath: patchFile.path, offset, length: 128 });
      setHexData({ patchId: patch.id, hex, offset: patch.offset });
    } catch (e) { setHexData({ patchId: patch.id, hex: `Hata: ${e}`, offset: patch.offset }); }
    finally { setHexLoading(false); }
  };

  // D4 — Conditional patch script interpreter
  const runScript = async () => {
    if (!patchFile?.path) { setScriptResults([{ ok: false, msg: 'Dosya yüklü değilil' }]); return; }
    const lines = scriptText.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
    const results = [];
    for (const line of lines) {
      const m = line.trim().match(/^if\s+byte@(0x[\da-f]+|\d+)\s*==\s*(0x[\da-f]+|\d+)\s+then\s+patch\s+(0x[\da-f]+|\d+)\s*=\s*([\da-f\s]+)$/i);
      if (!m) { results.push({ line, ok: false, msg: 'Sözdizimi hatası' }); continue; }
      const [, readOff, expected, patchOff, patchBytes] = m;
      try {
        const readN = parseInt(readOff); const expN = parseInt(expected);
        const hex = await invoke('read_hex_region', { filePath: patchFile.path, offset: readN, length: 1 });
        const actual = parseInt(hex.trim().split(/\s+/)[0], 16);
        if (actual !== expN) { results.push({ line, ok: false, msg: `byte@${readOff} = 0x${actual.toString(16)} ≠ 0x${expected} ? skip` }); continue; }
        await invoke('apply_patches', { filePath: patchFile.path, patches: [{ name: `Script@${patchOff}`, offset: patchOff, patched: patchBytes.trim(), enabled: true }] });
        results.push({ line, ok: true, msg: `? patch 0x${parseInt(patchOff).toString(16)} applied` });
      } catch (e) { results.push({ line, ok: false, msg: String(e) }); }
    }
    setScriptResults(results);
  };

  // D6 — Bulk patch: apply current enabled patches to multiple files
  const runBulkPatch = async () => {
    const enabled = patches.filter(p => p.enabled);
    if (!enabled.length || !bulkFiles.length) return;
    setBulkRunning(true);
    setBulkFiles(prev => prev.map(f => ({ ...f, status: 'pending' })));
    for (let i = 0; i < bulkFiles.length; i++) {
      setBulkFiles(prev => prev.map((x, j) => j === i ? { ...x, status: 'running' } : x));
      try {
        await invoke('apply_patches', {
          filePath: bulkFiles[i].path,
          patches: enabled.map(p => ({ name: p.name, offset: p.offset, patched: p.patched, enabled: true })),
        });
        setBulkFiles(prev => prev.map((x, j) => j === i ? { ...x, status: 'done' } : x));
      } catch (e) {
        setBulkFiles(prev => prev.map((x, j) => j === i ? { ...x, status: 'error', error: String(e) } : x));
      }
    }
    setBulkRunning(false);
  };

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 22 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(245,158,11,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Binary size={17} color="#f59e0b" /></div>
            <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0, color: '#f1f5f9' }}>Hex Patcher</h1>
          </div>
          <p style={{ fontSize: 12, color: '#374151', margin: 0 }}>Offset-based byte patching · NOP injection · Enable/disable patches before committing</p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button onClick={() => setShowForm(true)} style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.25)', background: 'rgba(245,158,11,0.07)', color: '#f59e0b', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}><Plus size={13} /> New Patch</button>
          {patchFile && enabledCount > 0 && (
            <button onClick={applyPatches}
              style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Play size={13} /> Apply ({enabledCount}) & Save
            </button>
          )}
          {/* 46 — Export / Import JSON */}
          <button onClick={exportPatches} style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(96,165,250,0.25)', background: 'rgba(96,165,250,0.07)', color: '#60a5fa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}><Download size={13} /> Export JSON</button>
          <button onClick={() => jsonImportRef.current.click()} style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(96,165,250,0.15)', background: 'transparent', color: '#60a5fa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}><FolderOpen size={13} /> Import JSON</button>
          <input ref={jsonImportRef} type="file" accept=".json" onChange={e => importPatches(e.target.files[0])} style={{ display: 'none' }} />
          {patches.length > 0 && <button onClick={() => onSendToChat({ type: 'patcher', fileName: patchFile?.name, data: patches })} style={{ fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.07)', color: '#a78bfa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}><MessageSquare size={13} /> Chat'e Gönder</button>}
        </div>
      </div>

      {/* Target file */}
      <div onClick={() => !patchFile && ref.current.click()} onDrop={(e) => { e.preventDefault(); setDragOver(false); loadPatchFile(e.dataTransfer.files[0]); }} onDragOver={(e) => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)}
        style={{ borderRadius: 12, marginBottom: 20, padding: patchFile ? '12px 16px' : '22px 16px', border: `1px ${patchFile ? 'solid' : 'dashed'} ${patchFile ? 'rgba(245,158,11,0.28)' : dragOver ? 'rgba(245,158,11,0.5)' : 'rgba(245,158,11,0.14)'}`, background: patchFile ? 'rgba(245,158,11,0.04)' : 'rgba(245,158,11,0.01)', cursor: patchFile ? 'default' : 'pointer', display: 'flex', alignItems: 'center', gap: 12, transition: 'all 0.18s' }}>
        <div style={{ width: 36, height: 36, borderRadius: 9, background: 'rgba(245,158,11,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Binary size={17} color="#f59e0b" /></div>
        {patchFile
          ? <><div style={{ flex: 1 }}><div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>{patchFile.name}</div><div style={{ fontSize: 11, color: '#4b5563', marginTop: 2 }}>{(patchFile.size / 1048576).toFixed(2)} MB · {appliedCount}/{patches.length} patches applied{patchBytes ? ' · bytes loaded' : ''}</div></div><button onClick={e => { e.stopPropagation(); setPatchFile(null); setPatchBytes(null); setPatResults(null); }} style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(239,68,68,0.22)', background: 'rgba(239,68,68,0.07)', color: '#f87171', cursor: 'pointer' }}>Remove</button></>
          : <div><div style={{ fontSize: 13, fontWeight: 500, color: '#6b7280' }}>Select target binary</div><div style={{ fontSize: 11, color: '#2d3748', marginTop: 2 }}>Drop an .exe or .dll, or click to browse</div></div>
        }
        <input ref={ref} type="file" accept=".exe,.dll,.sys,*" onChange={e => loadPatchFile(e.target.files[0])} style={{ display: 'none' }} />
      </div>

      {/* New patch form */}
      {showForm && (
        <div style={{ borderRadius: 12, marginBottom: 16, padding: 16, background: 'rgba(245,158,11,0.04)', border: '1px solid rgba(245,158,11,0.22)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', marginBottom: 13, textTransform: 'uppercase', letterSpacing: '0.07em' }}>New Patch</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 12 }}>
            {[{ key: 'name', label: 'Patch Name', ph: 'e.g. Skip Intro', mono: false }, { key: 'offset', label: 'File Offset', ph: '0x00400000', mono: true }, { key: 'original', label: 'Original Bytes', ph: 'FF D0 84 C0', mono: true }, { key: 'patched', label: 'Patched Bytes', ph: '90 90 90 90', mono: true }].map(({ key, label, ph, mono }) => (
              <div key={key}>
                <div style={{ fontSize: 10, color: '#374151', marginBottom: 5, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
                <input value={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} placeholder={ph} style={{ width: '100%', background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 10px', fontSize: 12, color: '#e2e8f0', fontFamily: mono ? 'monospace' : 'inherit', outline: 'none', boxSizing: 'border-box' }} />
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => { if (!form.name || !form.offset) return; setPatches(p => [...p, { id: Date.now(), ...form, enabled: true, applied: false }]); setForm({ name: '', offset: '', original: '', patched: '' }); setShowForm(false); }} style={{ fontSize: 11, padding: '6px 15px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontWeight: 500 }}>Add</button>
            <button onClick={() => setShowForm(false)} style={{ fontSize: 11, padding: '6px 13px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.07)', background: 'transparent', color: '#4b5563', cursor: 'pointer' }}>Cancel</button>
          </div>
        </div>
      )}

      {/* 45 — Byte pattern search */}
      {patchBytes && (
        <div style={{ marginBottom: 16, borderRadius: 10, padding: '12px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 9 }}>Pattern Search (45) — 0xFF = wildcard</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input value={patHex} onChange={e => setPatHex(e.target.value)} onKeyDown={e => e.key === 'Enter' && searchPattern()}
              placeholder="FF D0 || 74  ← boşlukla ay&#305;r, 0xFF wildcard"
              style={{ flex: 1, background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 10px', fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace', outline: 'none' }} />
            <button onClick={searchPattern}
              style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#f59e0b', cursor: 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>
              Ara
            </button>
          </div>
          {patResults !== null && (
            <div style={{ marginTop: 9 }}>
              {patResults.length === 0
                ? <span style={{ fontSize: 11, color: '#374151' }}>Eşleşme bulunamadıı.</span>
                : <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                    {patResults.map((off, i) => (
                      <span key={i} onClick={() => off.startsWith('0x') && setForm(f => ({ ...f, offset: off }))}
                        style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 4, background: 'rgba(245,158,11,0.1)', color: '#fbbf24', cursor: off.startsWith('0x') ? 'pointer' : 'default', border: '1px solid rgba(245,158,11,0.2)' }}
                        title={off.startsWith('0x') ? 'Offset\'i forma aktar' : ''}>
                        {off}
                      </span>
                    ))}
                  </div>
              }
              <div style={{ fontSize: 10, color: '#2d3748', marginTop: 5 }}>{patResults.filter(o => o.startsWith('0x')).length} offset bulundu — ofset'e tıklayarak New Patch formuna aktar</div>
            </div>
          )}
        </div>
      )}

      {/* D1 — NOP Sled generator + D2 — JMP/CALL injection */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
        {/* D1 — NOP sled */}
        <div style={{ borderRadius: 10, padding: '12px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(99,102,241,0.15)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#6366f1', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 9 }}>NOP Sled Üreticisireticisi (D1)</div>
          {(() => {
            const [nopOff, setNopOff] = React.useState('0x00000000');
            const [nopLen, setNopLen] = React.useState('16');
            const genNop = () => {
              const len = Math.min(256, Math.max(1, parseInt(nopLen) || 16));
              const bytes = Array(len).fill('90').join(' ');
              const orig  = Array(len).fill('??').join(' ');
              setPatches(ps => [...ps, { id: Date.now(), name: `NOP Sled x${len}`, offset: nopOff, original: orig, patched: bytes, enabled: true, applied: false }]);
            };
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                <input value={nopOff} onChange={e => setNopOff(e.target.value)} placeholder="Offset (0x...)"
                  style={{ fontSize: 12, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.05)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                <div style={{ display: 'flex', gap: 7, alignItems: 'center' }}>
                  <input value={nopLen} onChange={e => setNopLen(e.target.value)} placeholder="Uzunluk (byte)"
                    style={{ width: 100, fontSize: 12, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.05)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                  <button onClick={genNop} style={{ flex: 1, fontSize: 11, padding: '5px 10px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>
                    Oluştur + Ekle
                  </button>
                </div>
              </div>
            );
          })()}
        </div>

        {/* D2 — JMP/CALL relative offset injection */}
        <div style={{ borderRadius: 10, padding: '12px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(245,158,11,0.15)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 9 }}>JMP / CALL Enjeksiyonu (D2)</div>
          {(() => {
            const [src, setSrc] = React.useState('0x00000000');
            const [tgt, setTgt] = React.useState('0x00000000');
            const [type, setType] = React.useState('JMP');
            const genJmp = () => {
              const srcN = parseInt(src, 16) || 0;
              const tgtN = parseInt(tgt, 16) || 0;
              const op   = type === 'JMP' ? 'E9' : 'E8';
              const rel  = ((tgtN - (srcN + 5)) >>> 0) & 0xFFFFFFFF;
              const b    = [(rel & 0xFF), ((rel >> 8) & 0xFF), ((rel >> 16) & 0xFF), ((rel >> 24) & 0xFF)];
              const bytes = `${op} ${b.map(x => x.toString(16).padStart(2,'0').toUpperCase()).join(' ')}`;
              setPatches(ps => [...ps, { id: Date.now(), name: `${type} @${src}?${tgt}`, offset: src, original: '?? ?? ?? ?? ??', patched: bytes, enabled: true, applied: false }]);
            };
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  {['JMP', 'CALL'].map(t => (
                    <button key={t} onClick={() => setType(t)}
                      style={{ flex: 1, fontSize: 11, padding: '4px 0', borderRadius: 5, border: `1px solid ${type===t ? 'rgba(245,158,11,0.5)' : 'rgba(255,255,255,0.08)'}`, background: type===t ? 'rgba(245,158,11,0.12)' : 'transparent', color: type===t ? '#f59e0b' : '#4b5563', cursor: 'pointer', fontWeight: 700 }}>{t}</button>
                  ))}
                </div>
                <input value={src} onChange={e => setSrc(e.target.value)} placeholder="Kaynak offset (0x...)"
                  style={{ fontSize: 12, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(245,158,11,0.04)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                <div style={{ display: 'flex', gap: 7, alignItems: 'center' }}>
                  <input value={tgt} onChange={e => setTgt(e.target.value)} placeholder="Hedef offset (0x...)"
                    style={{ flex: 1, fontSize: 12, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(245,158,11,0.04)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                  <button onClick={genJmp} style={{ fontSize: 11, padding: '5px 10px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.1)', color: '#f59e0b', cursor: 'pointer', fontWeight: 600, whiteSpace: 'nowrap' }}>
                    + Ekle
                  </button>
                </div>
              </div>
            );
          })()}
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <span style={{ fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Patches ({patches.length})</span>
        <span style={{ fontSize: 10, color: '#2d3748' }}>{enabledCount} enabled · {appliedCount} applied</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
        {patches.map(p => (
          <div key={p.id}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ flex: 1 }}>
                <PatchCard patch={p} onToggle={() => setPatches(ps => ps.map(x => x.id === p.id ? { ...x, enabled: !x.enabled } : x))} onDelete={() => { setPatches(ps => ps.filter(x => x.id !== p.id)); if (hexData?.patchId === p.id) setHexData(null); }} />
              </div>
              {patchFile?.path && (
                <button onClick={() => loadHex(p)} disabled={hexLoading}
                  title="Hex görüntüle"
                  style={{ padding: '5px 9px', borderRadius: 6, border: `1px solid ${hexData?.patchId === p.id ? 'rgba(245,158,11,0.4)' : 'rgba(255,255,255,0.06)'}`, background: hexData?.patchId === p.id ? 'rgba(245,158,11,0.08)' : 'transparent', color: hexData?.patchId === p.id ? '#fbbf24' : '#374151', cursor: 'pointer', fontSize: 10, fontFamily: 'monospace', fontWeight: 600 }}>
                  HEX
                </button>
              )}
            </div>
            {/* 44 — Hex viewer panel + G2 minimap */}
            {hexData?.patchId === p.id && (
              <div style={{ margin: '4px 0 8px 0', borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(0,0,0,0.3)' }}>
                <div style={{ padding: '4px 12px', background: 'rgba(245,158,11,0.07)', fontSize: 10, color: '#f59e0b', fontWeight: 600, fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span>offset {hexData.offset} · 128 bytes</span>
                  {/* 2.3 — Hex range AI explanation */}
                  <button onClick={() => onSendToChat({ type: 'hex_region', fileName: patchFile?.name || '?', offset: hexData.offset, hex: hexData.hex })}
                    style={{ marginLeft: 'auto', padding: '2px 8px', borderRadius: 5, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.08)', color: '#a78bfa', cursor: 'pointer', fontSize: 9, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Bot size={10} /> AI'a Sor
                  </button>
                </div>
                <div style={{ display: 'flex', gap: 0 }}>
                  <pre style={{ margin: 0, padding: '10px 14px', fontSize: 11, color: '#94a3b8', fontFamily: 'monospace', lineHeight: 1.7, overflowX: 'auto', flex: 1 }}>{hexData.hex}</pre>
                  {/* G2 — Hex minimap: visual byte density bar */}
                  {(() => {
                    const bytes = hexData.hex.trim().split(/\s+/).map(h => parseInt(h, 16)).filter(n => !isNaN(n));
                    if (!bytes.length) return null;
                    const rows = Math.ceil(bytes.length / 16);
                    return (
                      <div style={{ width: 36, flexShrink: 0, background: 'rgba(0,0,0,0.2)', borderLeft: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', padding: '4px 3px', gap: 1, overflowY: 'auto' }} title="G2 — Hex Minimap">
                        {Array.from({ length: rows }, (_, r) => {
                          const row = bytes.slice(r * 16, (r + 1) * 16);
                          const nonNull = row.filter(b => b !== 0).length;
                          const allSame = row.every(b => b === row[0]);
                          const pct = nonNull / row.length;
                          const col = allSame && row[0] === 0x90 ? '#6366f1' : allSame ? '#fbbf24' : pct > 0.9 ? '#f87171' : pct > 0.5 ? '#60a5fa' : '#1f2937';
                          return <div key={r} style={{ height: 3, borderRadius: 1, background: col, opacity: 0.3 + pct * 0.7 }} />;
                        })}
                        <div style={{ fontSize: 7, color: '#1f2937', textAlign: 'center', marginTop: 2 }}>map</div>
                      </div>
                    );
                  })()}
                </div>
              </div>
            )}
          </div>
        ))}
        {patches.length === 0 && <div style={{ textAlign: 'center', padding: '40px 20px', color: '#2d3748', fontSize: 13 }}>No patches yet. Click "New Patch" to add one.</div>}
      </div>

      {/* Apply status (42+43) */}
      {applyStatus && (
        <div style={{ marginTop: 14, borderRadius: 9, padding: '10px 14px', background: applyStatus.ok ? 'rgba(34,197,94,0.06)' : 'rgba(239,68,68,0.06)', border: `1px solid ${applyStatus.ok ? 'rgba(34,197,94,0.22)' : 'rgba(239,68,68,0.22)'}`, display: 'flex', alignItems: 'center', gap: 8 }}>
          {applyStatus.ok
            ? <CheckCircle2 size={14} color="#4ade80" />
            : <XCircle size={14} color="#f87171" />
          }
          <span style={{ fontSize: 11, color: applyStatus.ok ? '#4ade80' : '#f87171', fontFamily: 'monospace' }}>{applyStatus.msg}</span>
        </div>
      )}

      {/* D3 — Patch Validation Results */}
      {patchValidation && patchValidation.length > 0 && (
        <div style={{ marginTop: 12, borderRadius: 9, padding: '10px 14px', background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.15)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#6366f1', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8 }}>Patch Validation (D3)</div>
          {patchValidation.map((v, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 5, fontSize: 11, fontFamily: 'monospace' }}>
              {v.ok ? <CheckCircle2 size={12} color="#4ade80" style={{ flexShrink: 0, marginTop: 1 }} /> : <XCircle size={12} color="#f87171" style={{ flexShrink: 0, marginTop: 1 }} />}
              <div>
                <span style={{ color: '#6366f1' }}>{v.name}</span>
                <span style={{ color: '#374151' }}> @{v.offset} — </span>
                {v.ok
                  ? <span style={{ color: '#4ade80' }}>OK ({v.actual})</span>
                  : <span style={{ color: '#f87171' }}>{v.error || `Expected: ${v.expected} / Got: ${v.actual}`}</span>
                }
                {/* D5 — Before/After */}
                {preApplyHex[patches.find(p => p.name === v.name)?.id] && (
                  <div style={{ marginTop: 3, color: '#1f2937' }}>
                    <span>Before: <span style={{ color: '#fbbf24' }}>{preApplyHex[patches.find(p => p.name === v.name)?.id]}</span></span>
                    <span style={{ marginLeft: 12 }}>After: <span style={{ color: '#4ade80' }}>{v.actual}</span></span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* D4 — Conditional Patch Script */}
      <div style={{ marginTop: 14 }}>
        <button onClick={() => setShowScript(s => !s)} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.25)', background: showScript ? 'rgba(139,92,246,0.1)' : 'transparent', color: '#a78bfa', cursor: 'pointer', fontWeight: 500 }}>
          ✎ Conditional Script (D4) {showScript ? '?' : '?'}
        </button>
        {showScript && (
          <div style={{ marginTop: 8, borderRadius: 9, padding: '12px 14px', background: 'rgba(139,92,246,0.04)', border: '1px solid rgba(139,92,246,0.18)' }}>
            <div style={{ fontSize: 9, color: '#4b5563', marginBottom: 6 }}>Sözdizimi: <code style={{ color: '#a78bfa' }}>if byte@OFFSET == VALUE then patch TARGET = BYTES</code></div>
            <textarea value={scriptText} onChange={e => setScriptText(e.target.value)} rows={5}
              style={{ width: '100%', fontFamily: 'monospace', fontSize: 11, padding: '8px 10px', borderRadius: 7, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(139,92,246,0.2)', color: '#c4b5fd', outline: 'none', resize: 'vertical', boxSizing: 'border-box' }} />
            <button onClick={runScript} style={{ marginTop: 6, fontSize: 11, padding: '5px 14px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.35)', background: 'rgba(139,92,246,0.1)', color: '#a78bfa', cursor: 'pointer', fontWeight: 600 }}>▶ Script'i Çalıştır</button>
            {scriptResults && (
              <div style={{ marginTop: 8 }}>
                {scriptResults.map((r, i) => (
                  <div key={i} style={{ fontSize: 10, fontFamily: 'monospace', padding: '3px 0', color: r.ok ? '#4ade80' : '#f87171' }}>
                    {r.ok ? '?' : '✗'} {r.msg} — <span style={{ color: '#374151' }}>{r.line}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* D6 — Bulk Patch */}
      {patches.filter(p => p.enabled).length > 0 && (
        <div style={{ marginTop: 14, borderRadius: 9, padding: '12px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Bulk Patch (D6) — Apply to multiple files</div>
            <button onClick={() => bulkRef.current.click()} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.07)', color: '#f59e0b', cursor: 'pointer' }}>+ Dosya Ekle</button>
            <input ref={bulkRef} type="file" multiple accept=".exe,.dll,.sys" onChange={e => {
              const files = Array.from(e.target.files).filter(f => f.path);
              setBulkFiles(prev => [...prev, ...files.map(f => ({ name: f.name, path: f.path, status: 'ready' }))]);
            }} style={{ display: 'none' }} />
            {bulkFiles.length > 0 && !bulkRunning && <button onClick={runBulkPatch} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 6, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer', fontWeight: 600 }}>▶ Hepsine Uygula</button>}
            {bulkFiles.length > 0 && <button onClick={() => setBulkFiles([])} style={{ fontSize: 10, padding: '3px 8px', borderRadius: 6, border: 'none', background: 'transparent', color: '#374151', cursor: 'pointer', marginLeft: 'auto' }}>Temizle</button>}
          </div>
          {bulkFiles.length === 0 && <div style={{ fontSize: 11, color: '#374151' }}>Dosya yolu gerektiriyor — Tauri drag-drop ile yüklenen dosyalar.</div>}
          {bulkFiles.map((f, i) => {
            const col = f.status === 'done' ? '#4ade80' : f.status === 'error' ? '#f87171' : f.status === 'running' ? '#fbbf24' : '#374151';
            return (
              <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 11, padding: '3px 0' }}>
                <span style={{ color: col }}>{f.status === 'running' ? '⏳' : f.status === 'done' ? '?' : f.status === 'error' ? '✗' : '?'}</span>
                <span style={{ fontFamily: 'monospace', color: '#94a3b8' }}>{f.name}</span>
                {f.error && <span style={{ color: '#f87171', fontSize: 10 }}>{f.error}</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// —�—�—� System Page (GPU + Model Manager) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

export default PatcherPage;