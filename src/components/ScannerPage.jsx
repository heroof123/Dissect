import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Zap, ShieldAlert, FileSearch, Binary, AlertTriangle, ShieldCheck,
  ChevronRight, Plus, Trash2, FolderOpen, Download, RefreshCw,
  Cpu, Bot, Microscope, CheckCircle2, XCircle, Search, Copy,
  ChevronDown, Layers
} from 'lucide-react';
import {
  analyzePE, STR_PATTERNS, YARA_RULES, YARA_SEV_COLOR,
  extractStrings, addToHistory, getHistory, getStarred, toggleStarred,
  STARRED_KEY, HISTORY_KEY, calcEntropy, calcCRC32, calcMD5, _pluginHooks,
} from '../utils/peHelpers';
import { Card, CardHeader, Spinner, MdText } from './shared';

function ScannerPage({ onSendToAI, onSendToChat, onOpenDisasm }) {
  const [file, setFile]         = useState(null);
  const [result, setResult]     = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError]       = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [tab, setTab]           = useState('overview');
  const [strFilter, setStrFilter] = useState('');
  const [strCat, setStrCat]     = useState('all');
  const [showHistory, setShowHistory]     = useState(false);         // 22
  const [history, setHistory]             = useState(() => getHistory()); // 22
  const [histSearch, setHistSearch]       = useState('');            // 24 — history search
  const [editNoteId, setEditNoteId]       = useState(null);          // 25 — active note edit
  const [noteText, setNoteText]           = useState('');            // 25
  const [notes, setNotes]                 = useState(() => getNotes()); // 25
  const [multiResults, setMultiResults]   = useState([]);            // 01 — multi-file
  const [compareFile, setCompareFile]     = useState(null);          // 23
  const [compareResult, setCompareResult] = useState(null);          // 23
  const [comparingFile, setComparingFile] = useState(false);         // 23
  const [compareDragOver, setCompareDragOver] = useState(false);     // 23
  const [starred, setStarred]             = useState(() => getStarred()); // G4
  const [vtApiKey, setVtApiKey]           = useState(() => localStorage.getItem('dissect_vt_key') || ''); // E3
  const [vtResult, setVtResult]           = useState(null);          // E3
  const [vtLoading, setVtLoading]         = useState(false);         // E3
  const [scanFilePath, setScanFilePath]   = useState(null);          // A1 — native file path
  const [disasmResult, setDisasmResult]   = useState(null);          // A1
  const [disasmLoading, setDisasmLoading] = useState(false);         // A1
  const [scanRawBytes, setScanRawBytes]   = useState(null);          // B6 — first 8K bytes for hex diff
  const [compareRawBytes, setCompareRawBytes] = useState(null);      // B6
  const [upxResult, setUpxResult]         = useState(null);          // F2
  const [upxRunning, setUpxRunning]       = useState(false);         // F2
  const [dumpResult, setDumpResult]       = useState(null);          // F3
  const [dumpRunning, setDumpRunning]     = useState(false);         // F3
  const compareRef = useRef(null);
  const ref = useRef(null);
  const folderRef = useRef(null);  // 02 — folder scan

  // 01 — multi-file scan
  const processFiles = (files) => {
    if (!files || files.length === 0) return;
    if (files.length === 1) { processFile(files[0]); return; }
    setResult(null); setError(null); setCompareFile(null); setCompareResult(null);
    setMultiResults(Array.from(files).map(f => ({ name: f.name, size: f.size, status: 'pending', result: null })));
    setScanning(true);

    // FAZ 3.5 — use Rust parallel batch scanner if all files have native paths
    const fileArr = Array.from(files);
    const allPaths = fileArr.every(f => f.path);
    if (allPaths && window.__TAURI__) {
      (async () => {
        try {
          const paths = fileArr.map(f => f.path);
          const results = await invoke('batch_scan', { filePaths: paths });
          const mapped = fileArr.map((f, i) => {
            const r = results[i];
            if (r && r._status === 'ok') {
              addToHistory(f.name, r);
              return { name: f.name, size: f.size, status: 'done', result: r };
            } else {
              return { name: f.name, size: f.size, status: 'error', error: r?._error || 'Bilinmeyen hata' };
            }
          });
          setMultiResults(mapped);
          setHistory(getHistory());
        } catch (err) {
          console.warn('Batch scan failed, falling back to JS:', err);
          processFilesJS(fileArr);
          return;
        } finally { setScanning(false); }
      })();
      return;
    }
    processFilesJS(fileArr);
  };

  // JS fallback for multi-file scan
  const processFilesJS = (files) => {
    Array.from(files).forEach((f, idx) => {
      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const r = await analyzePE(new Uint8Array(e.target.result));
          addToHistory(f.name, r);
          setMultiResults(prev => { const next = [...prev]; next[idx] = { ...next[idx], status: 'done', result: r }; return next; });
        } catch (err) {
          setMultiResults(prev => { const next = [...prev]; next[idx] = { ...next[idx], status: 'error', error: err.message }; return next; });
        } finally {
          setMultiResults(prev => {
            const allDone = prev.every(x => x.status !== 'pending');
            if (allDone) { setScanning(false); setHistory(getHistory()); }
            return prev;
          });
        }
      };
      reader.readAsArrayBuffer(f);
    });
  };

  const processFile = (f) => {
    if (!f) return;
    setFile(f); setResult(null); setError(null); setScanning(true); setTab('overview');
    setStrFilter(''); setStrCat('all');
    setCompareFile(null); setCompareResult(null); setMultiResults([]);
    setDisasmResult(null);
    // A1 — store native path if available (drag-drop in Tauri provides f.path)
    if (f.path) setScanFilePath(f.path); else setScanFilePath(null);

    // FAZ 3.1 — prefer Rust scanner when native path available
    if (f.path && window.__TAURI__) {
      (async () => {
        try {
          await new Promise(r => setTimeout(r, 200));
          const r = await invoke('scan_pe_full', { filePath: f.path });
          // Normalize string objects for frontend compat
          if (r.strings) r.strings = r.strings.map(s => typeof s === 'string' ? { text: s, cat: null } : { text: s.text, cat: s.cat });
          setResult(r);
          addToHistory(f.name, r);
          setHistory(getHistory());
          if (Notification.permission === 'granted') {
            new Notification('Dissect — Scan Complete', { body: `${f.name} · Risk ${r.riskScore} · ${r.riskScore >= 60 ? '⚡ HIGH RISK' : r.riskScore >= 30 ? 'MODERATE' : 'CLEAN'} (Rust ⚡)`, silent: true });
          }
          // Also read first 8K for hex view
          const reader2 = new FileReader();
          reader2.onload = (e2) => setScanRawBytes(new Uint8Array(e2.target.result).slice(0, 8192));
          reader2.readAsArrayBuffer(f);
        } catch (err) {
          // Fallback to JS scanner
          console.warn('Rust scanner failed, falling back to JS:', err);
          processFileJS(f);
        } finally { setScanning(false); }
      })();
      return;
    }
    processFileJS(f);
  };

  // JS fallback scanner
  const processFileJS = (f) => {
    setScanning(true);
    const reader = new FileReader();
    reader.onload = async (e) => {
      const arr = new Uint8Array(e.target.result);
      setScanRawBytes(arr.slice(0, 8192)); // B6 store first 8K
      try {
        await new Promise(r => setTimeout(r, 700));
        const r = await analyzePE(arr);
        setResult(r);
        addToHistory(f.name, r);                                   // 22 — auto-save
        setHistory(getHistory());
        // 50 — OS notification
        if (Notification.permission === 'granted') {
          new Notification('Dissect — Scan Complete', { body: `${f.name} · Risk ${r.riskScore} · ${r.riskScore >= 60 ? '⚡ HIGH RISK' : r.riskScore >= 30 ? 'MODERATE' : 'CLEAN'}`, silent: true });
        } else if (Notification.permission !== 'denied') {
          Notification.requestPermission();
        }

      } catch (err) { setError(err.message); }
      finally { setScanning(false); }
    };
    reader.readAsArrayBuffer(f);
  };

  // 23 — Process second (compare) file
  const processCompareFile = (f) => {
    if (!f) return;
    setCompareFile(f); setComparingFile(true); setCompareResult(null); setCompareRawBytes(null);
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const arr = new Uint8Array(e.target.result);
        setCompareRawBytes(arr.slice(0, 8192)); // B6
        const r = await analyzePE(arr);
        setCompareResult(r);
        setTab('compare');
      } catch (err) { setCompareResult({ error: err.message }); }
      finally { setComparingFile(false); }
    };
    reader.readAsArrayBuffer(f);
  };

  // 22 — JSON export of full history
  const exportHistory = () => {
    const blob = new Blob([JSON.stringify(getHistory(), null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `dissect_history_${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(a.href);
  };

  // FAZ 10.1 — Import scan from JSON file
  const importScanRef = useRef(null);
  const importScan = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result);
        if (Array.isArray(data)) {
          data.forEach(item => { if (item.sha256) addToHistory(item); });
          setHistory(getHistory());
        } else if (data.sha256) {
          addToHistory(data);
          setHistory(getHistory());
          setResult(data);
        }
      } catch { /* invalid JSON */ }
    };
    reader.readAsText(f);
    e.target.value = '';
  };

  // FAZ 10.1 — Share scan via encoded URL
  const shareScan = useCallback(() => {
    if (!result) return;
    const shareData = { fileName: result.fileName, sha256: result.sha256, riskScore: result.riskScore, arch: result.arch, ep: result.ep, denuvo: result.denuvo, vmp: result.vmp, antiDebug: result.antiDebug, sections: result.sections?.length, imports: result.imports?.length };
    const encoded = btoa(JSON.stringify(shareData));
    const shareId = result.sha256?.slice(0, 12) || Date.now().toString(36);
    navigator.clipboard.writeText(`dissect://share/${shareId}?d=${encoded}`);
  }, [result]);

  // FAZ 10.2 — Annotations (team notes per scan)
  const [annotations, setAnnotations] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_annotations') || '{}'); } catch { return {}; }
  });
  const addAnnotation = useCallback((text) => {
    if (!result?.sha256 || !text.trim()) return;
    const key = result.sha256;
    setAnnotations(prev => {
      const arr = prev[key] || [];
      const updated = { ...prev, [key]: [...arr, { text, user: 'Analyst', ts: Date.now() }] };
      localStorage.setItem('dissect_annotations', JSON.stringify(updated));
      return updated;
    });
  }, [result]);

  const risk   = result?.riskScore || 0;
  const rColor = risk >= 60 ? '#ef4444' : risk >= 30 ? '#f59e0b' : '#22c55e';
  const rLabel = risk >= 60 ? 'HIGH RISK' : risk >= 30 ? 'MODERATE' : 'CLEAN';

  const totalStrings  = result?.strings?.length || 0;
  const flaggedStrings = result?.strings?.filter(s => s.cat).length || 0;
  const yaraHits = result ? YARA_RULES.filter(r => { try { return r.match(result); } catch { return false; } }) : [];

  const TABS = [
    { id: 'overview',   label: 'Overview'  },
    { id: 'sections',   label: 'Sections'  },
    { id: 'strings',    label: `Strings (${totalStrings})`, badge: flaggedStrings > 0 ? flaggedStrings : null },
    { id: 'imports',    label: `Imports (${result?.imports?.length || 0})` },
    { id: 'exports',    label: `Exports (${result?.exports?.length || 0})` },
    { id: 'resources',  label: `Resources (B1)`, badge: result?.resources?.length > 0 ? result.resources.length : null },
    { id: 'yara',       label: `YARA`, badge: yaraHits.length > 0 ? yaraHits.length : null },
    { id: 'analyze',    label: 'Analyze' },
    { id: 'disasm',     label: 'Disasm (A1)' },
    ...(compareResult && !compareResult.error ? [{ id: 'compare', label: 'Diff ↓' }] : []),
  ];

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 22 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(99,102,241,0.13)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><ShieldAlert size={17} color="#818cf8" /></div>
            <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0, color: '#f1f5f9' }}>Binary Scanner</h1>
          </div>
          <p style={{ fontSize: 12, color: '#374151', margin: 0 }}>PE header · Entropy · Import table · Anti-debug · Denuvo / VMProtect / Themida · String classification</p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {/* 22 — History button */}
          <button onClick={() => setShowHistory(h => !h)}
            style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: `1px solid ${showHistory ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: showHistory ? 'rgba(99,102,241,0.12)' : 'transparent', color: showHistory ? '#818cf8' : '#374151', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
            <Layers size={13} /> Geçmiş {history.length > 0 && `(${history.length})`}
          </button>
          {result && (
            <button onClick={() => onSendToAI(result, file?.name)}
              style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Bot size={13} /> Send to AI
            </button>
          )}
          {result && (
            <button onClick={() => onSendToChat({ type: 'scanner', fileName: file?.name, data: result })}
              style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.07)', color: '#a78bfa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <MessageSquare size={13} /> Chat'e Gönder
            </button>
          )}
          {/* 38 — JSON report export */}
          {result && (
            <button onClick={() => {
              const blob = new Blob([JSON.stringify({ file: file?.name, size: file?.size, ...result }, null, 2)], { type: 'application/json' });
              const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
              a.download = `dissect_${(file?.name || 'scan').replace(/\.[^.]+$/, '')}_${Date.now()}.json`;
              a.click(); URL.revokeObjectURL(a.href);
            }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Download size={13} /> JSON
            </button>
          )}
          {/* E2 — STIX 2.1 export */}
          {result && (
            <button onClick={() => {
              const now = new Date().toISOString();
              const iocs = [];
              (result.strings || []).filter(s => s.cat === 'ip').forEach(s => iocs.push({ type: 'ipv4-addr', id: `ipv4-addr--${crypto.randomUUID?.() || Date.now()}`, value: s.text }));
              (result.strings || []).filter(s => s.cat === 'domain').forEach(s => iocs.push({ type: 'domain-name', id: `domain-name--${crypto.randomUUID?.() || Date.now()}`, value: s.text }));
              if (result.sha256) iocs.push({ type: 'file', id: `file--${crypto.randomUUID?.() || Date.now()}`, hashes: { 'SHA-256': result.sha256, 'SHA-1': result.sha1, 'MD5': result.md5 }, name: file?.name, size: file?.size });
              const bundle = {
                type: 'bundle', id: `bundle--${crypto.randomUUID?.() || Date.now()}`,
                spec_version: '2.1', created: now, modified: now,
                objects: [
                  { type: 'malware', spec_version: '2.1', id: `malware--${crypto.randomUUID?.() || Date.now()}`, created: now, modified: now, name: file?.name || 'unknown', malware_types: result.denuvo ? ['ransomware'] : ['unknown'], is_family: false,
                    custom_properties: { x_risk_score: result.riskScore, x_packers: result.packers, x_entropy: result.overallEntropy, x_arch: result.arch } },
                  ...iocs,
                ],
              };
              const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
              const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
              a.download = `dissect_stix_${Date.now()}.json`; a.click(); URL.revokeObjectURL(a.href);
            }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.06)', color: '#fbbf24', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Download size={13} /> STIX
            </button>
          )}
          {/* E5 — IOC CSV */}
          {result && (
            <button onClick={() => {
              const rows = [['type','value','category']];
              (result.strings || []).filter(s => s.cat).forEach(s => rows.push([s.cat, s.text, s.cat]));
              if (result.sha256) rows.push(['sha256', result.sha256, 'hash']);
              if (result.sha1)   rows.push(['sha1',   result.sha1,   'hash']);
              if (result.md5)    rows.push(['md5',    result.md5,    'hash']);
              const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
              const blob = new Blob([csv], { type: 'text/csv' });
              const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
              a.download = `dissect_ioc_${Date.now()}.csv`; a.click(); URL.revokeObjectURL(a.href);
            }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(96,165,250,0.3)', background: 'rgba(96,165,250,0.06)', color: '#60a5fa', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Download size={13} /> IOC CSV
            </button>
          )}
          {/* E4 — Bulk report (all multi-scan results) */}
          {multiResults.length > 1 && (
            <button onClick={() => {
              const done = multiResults.filter(r => r.status === 'done');
              if (!done.length) return;
              const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Dissect Bulk Report</title><style>body{font-family:system-ui;background:#0d1117;color:#e2e8f0;padding:32px}h1{color:#818cf8}table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #1f2937}th{background:#161b22;font-weight:600}tr:nth-child(even){background:#0d1117}tr:nth-child(odd){background:#090c12}.risk-hi{color:#f87171}.risk-md{color:#fbbf24}.risk-lo{color:#4ade80}</style></head><body><h1>Dissect Bulk Scan Report (E4)</h1><p style="color:#4b5563">${new Date().toLocaleString('tr-TR')} · ${done.length} files</p><table><thead><tr><th>File</th><th>Arch</th><th>Risk</th><th>Protections</th><th>SHA-256</th><th>Entropy</th><th>Sections</th></tr></thead><tbody>${done.map(({ name, result: r }) => `<tr><td>${name}</td><td>${r.arch}</td><td class="${r.riskScore >= 60 ? 'risk-hi' : r.riskScore >= 30 ? 'risk-md' : 'risk-lo'}">${r.riskScore}</td><td>${[r.denuvo&&'Denuvo',r.vmp&&'VMProtect',r.themida&&'Themida',r.antiDebug&&'Anti-Debug',r.antiVM&&'Anti-VM',...(r.packers||[])].filter(Boolean).join(', ')||'—'}</td><td style="font-family:monospace;font-size:10px">${r.sha256?.slice(0,16)+'⬦'||'—'}</td><td style="font-family:monospace">${r.overallEntropy?.toFixed(3)||'—'}</td><td>${r.numSec}</td></tr>`).join('')}</tbody></table></body></html>`;
              const blob = new Blob([html], { type: 'text/html' });
              const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
              a.download = `dissect_bulk_${Date.now()}.html`; a.click(); URL.revokeObjectURL(a.href);
            }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(168,85,247,0.3)', background: 'rgba(168,85,247,0.06)', color: '#c084fc', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Download size={13} /> Bulk Report
            </button>
          )}
          {file && !scanning && (
            <button onClick={() => { setFile(null); setResult(null); setError(null); setCompareFile(null); setCompareResult(null); }}
              style={{ fontSize: 11, padding: '5px 13px', borderRadius: 7, border: '1px solid rgba(239,68,68,0.25)', background: 'rgba(239,68,68,0.07)', color: '#f87171', cursor: 'pointer', fontWeight: 500 }}>
              Clear
            </button>
          )}
        </div>
      </div>

      {/* 22 — History panel (24 = search, 25 = notes) */}
      {showHistory && (
        <div style={{ borderRadius: 12, marginBottom: 16, background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(99,102,241,0.15)', overflow: 'hidden' }}>
          <div style={{ padding: '9px 14px', background: 'rgba(99,102,241,0.06)', borderBottom: '1px solid rgba(99,102,241,0.1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: '#818cf8', textTransform: 'uppercase', letterSpacing: '0.07em', flexShrink: 0 }}>Tarama Geçmişi</span>
            {/* 24 — search */}
            <input value={histSearch} onChange={e => setHistSearch(e.target.value)} placeholder="Ara&"
              style={{ flex: 1, maxWidth: 180, fontSize: 10, padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.07)', color: '#94a3b8', outline: 'none' }} />
            <div style={{ display: 'flex', gap: 8 }}>
              {history.length > 0 && <button onClick={exportHistory} style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer' }}>JSON Export</button>}
              <button onClick={() => importScanRef.current?.click()} style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(6,182,212,0.25)', background: 'rgba(6,182,212,0.07)', color: '#06b6d4', cursor: 'pointer' }}>Import</button>
              <input ref={importScanRef} type="file" accept=".json" onChange={importScan} style={{ display: 'none' }} />
              {result && <button onClick={shareScan} style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(168,85,247,0.25)', background: 'rgba(168,85,247,0.07)', color: '#a855f7', cursor: 'pointer' }}>📎 Share Link</button>}
              {history.length > 0 && <button onClick={() => { localStorage.removeItem(HISTORY_KEY); setHistory([]); }} style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.2)', background: 'transparent', color: '#f87171', cursor: 'pointer' }}>Temizle</button>}
            </div>
          </div>
          {history.length === 0
            ? <div style={{ padding: '24px', textAlign: 'center', fontSize: 12, color: '#374151' }}>Henüz kayıtlı tarama yok</div>
            : <div style={{ maxHeight: 260, overflowY: 'auto' }}>
                {(() => {
                  const q = histSearch.toLowerCase();
                  const filtered = history.filter(h => !q
                    || h.fileName.toLowerCase().includes(q)
                    || String(h.riskScore).includes(q)
                    || h.arch?.toLowerCase().includes(q)
                    || (h.packers || []).some(p => p.toLowerCase().includes(q))
                    || (h.result?.sha256 || '').toLowerCase().includes(q)
                  );
                  // G4: starred first
                  const sorted = [...filtered.filter(h => starred.has(h.id)), ...filtered.filter(h => !starred.has(h.id))];
                  return sorted.map(h => {
                  const note = notes[h.id];
                  const isEditing = editNoteId === h.id;
                  const isStar = starred.has(h.id);
                  return (
                    <div key={h.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <div onClick={() => { if (!isEditing) { setResult(h.result); setFile({ name: h.fileName, size: 0 }); setTab('overview'); setShowHistory(false); } }}
                        style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 14px', cursor: 'pointer', transition: 'background 0.12s' }}
                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                        {/* G4 — star button */}
                        <button onClick={e => { e.stopPropagation(); setStarred(toggleStarred(h.id)); }}
                          title={isStar ? 'Y1ld1z1 kald1r' : 'Y1ld1zla'}
                          style={{ fontSize: 12, lineHeight: 1, background: 'transparent', border: 'none', cursor: 'pointer', color: isStar ? '#fbbf24' : '#2d3748', padding: 0, flexShrink: 0 }}>
                          {isStar ? '⭐' : '☆'}
                        </button>
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: h.riskScore >= 60 ? '#ef4444' : h.riskScore >= 30 ? '#f59e0b' : '#22c55e', flexShrink: 0 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 12, color: isStar ? '#fef3c7' : '#94a3b8', fontWeight: isStar ? 600 : 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.fileName}</div>
                          <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>{h.arch} · Risk {h.riskScore} · {new Date(h.ts).toLocaleString('tr-TR')}</div>
                          {note && !isEditing && <div style={{ fontSize: 10, color: '#a78bfa', marginTop: 2, fontStyle: 'italic' }}>✎ {note}</div>}
                        </div>
                        {/* 25 — note button */}
                        <button onClick={e => { e.stopPropagation(); setEditNoteId(isEditing ? null : h.id); setNoteText(note || ''); }}
                          style={{ fontSize: 10, padding: '2px 7px', borderRadius: 5, border: '1px solid rgba(139,92,246,0.2)', background: isEditing ? 'rgba(139,92,246,0.1)' : 'transparent', color: '#a78bfa', cursor: 'pointer', flexShrink: 0 }}>
                          {isEditing ? '💾' : (note ? '✏️' : '+ Not')}
                        </button>
                        <span style={{ fontSize: 9, color: '#6b7280', fontFamily: 'monospace', flexShrink: 0 }}>Yükle →</span>
                      </div>
                      {/* 25 — inline note editor */}
                      {isEditing && (
                        <div style={{ padding: '0 14px 10px 32px', display: 'flex', gap: 6 }}>
                          <input autoFocus value={noteText} onChange={e => setNoteText(e.target.value)}
                            onKeyDown={e => { if (e.key === 'Enter') { saveNote(h.id, noteText); setNotes(getNotes()); setEditNoteId(null); } if (e.key === 'Escape') setEditNoteId(null); }}
                            placeholder="Not ekle⬦ (Enter = kaydet)"
                            style={{ flex: 1, fontSize: 11, padding: '4px 8px', borderRadius: 5, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(0,0,0,0.3)', color: '#c4b5fd', outline: 'none' }} />
                          <button onClick={() => { saveNote(h.id, noteText); setNotes(getNotes()); setEditNoteId(null); }}
                            style={{ fontSize: 10, padding: '4px 9px', borderRadius: 5, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.1)', color: '#a78bfa', cursor: 'pointer' }}>
                            Kaydet
                          </button>
                        </div>
                      )}
                    </div>
                  );
                  });})()} 
              </div>
          }
        </div>
      )}

      {/* Drop Zone — 01 multi-file */}
      {!result && !scanning && !error && multiResults.length === 0 && (
        <>
          {/* F4 — Scan Profiles */}
          {(() => {
            const PROFILES = [
              { id: 'quick',    label: '⚡ Quick',    desc: 'EP + protections + hash',     color: '#4ade80' },
              { id: 'deep',     label: '🔬 Deep',     desc: 'All sections + strings + IOC', color: '#60a5fa' },
              { id: 'forensic', label: '🧪 Forensic', desc: 'Full analysis + PDB + diff',   color: '#c084fc' },
            ];
            const [profile, setProfile] = React.useState(() => localStorage.getItem('dissect_profile') || 'deep');
            return (
              <div style={{ display: 'flex', gap: 6, marginBottom: 10, justifyContent: 'center' }}>
                {PROFILES.map(p => (
                  <button key={p.id} onClick={() => { setProfile(p.id); localStorage.setItem('dissect_profile', p.id); }}
                    title={p.desc}
                    style={{ fontSize: 11, padding: '5px 14px', borderRadius: 8, border: `1px solid ${profile === p.id ? p.color + '44' : 'rgba(255,255,255,0.06)'}`, background: profile === p.id ? p.color + '12' : 'transparent', color: profile === p.id ? p.color : '#374151', cursor: 'pointer', fontWeight: profile === p.id ? 600 : 400, transition: 'all 0.15s' }}>
                    {p.label}
                  </button>
                ))}
                <span style={{ fontSize: 10, color: '#2d3748', alignSelf: 'center', marginLeft: 6 }}>{PROFILES.find(p => p.id === profile)?.desc}</span>
              </div>
            );
          })()}
        <div onClick={() => ref.current.click()} onDrop={(e) => { e.preventDefault(); setDragOver(false); processFiles(e.dataTransfer.files); }} onDragOver={(e) => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)}
          style={{ borderRadius: 16, border: `2px dashed ${dragOver ? '#6366f1' : 'rgba(99,102,241,0.22)'}`, background: dragOver ? 'rgba(99,102,241,0.07)' : 'rgba(99,102,241,0.02)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 280, cursor: 'pointer', transition: 'all 0.18s' }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(99,102,241,0.45)'; e.currentTarget.style.background = 'rgba(99,102,241,0.04)'; }}
          onMouseLeave={e => { if (!dragOver) { e.currentTarget.style.borderColor = 'rgba(99,102,241,0.22)'; e.currentTarget.style.background = 'rgba(99,102,241,0.02)'; }}}>
          <div style={{ width: 58, height: 58, borderRadius: 16, background: 'rgba(99,102,241,0.11)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 18 }}><FileSearch size={28} color="#6366f1" /></div>
          <div style={{ fontSize: 15, fontWeight: 600, color: '#94a3b8', marginBottom: 7 }}>Drop a binary or click to browse</div>
          <div style={{ fontSize: 12, color: '#2d3748' }}>.exe · .dll · .sys — Multiple files · Drag a folder to scan all binaries</div>
          {/* 02 — folder scan button */}
          <div style={{ display: 'flex', gap: 10, marginTop: 14 }} onClick={e => e.stopPropagation()}>
            <button onClick={() => ref.current.click()}
              style={{ fontSize: 11, padding: '5px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer' }}>
              Files
            </button>
            <button onClick={() => folderRef.current.click()}
              style={{ fontSize: 11, padding: '5px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#6366f1', cursor: 'pointer' }}>
              📁 Folder Scan
            </button>
          </div>
          <input ref={ref} type="file" multiple onChange={e => processFiles(e.target.files)} style={{ display: 'none' }} />
          <input ref={folderRef} type="file" multiple webkitdirectory="" onChange={e => {
            const files = Array.from(e.target.files).filter(f => /\.(exe|dll|sys|ocx|scr|cpl)$/i.test(f.name));
            if (files.length > 0) processFiles(files);
          }} style={{ display: 'none' }} />
        </div>
        </>
      )}

      {/* 01 — Multi-file results grid */}
      {multiResults.length > 0 && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#94a3b8' }}>Toplu Tarama — {multiResults.length} dosya</span>
            <button onClick={() => { setMultiResults([]); setScanning(false); }}
              style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(239,68,68,0.2)', background: 'transparent', color: '#f87171', cursor: 'pointer' }}>Temizle</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 10 }}>
            {multiResults.map((item, i) => {
              const rc = item.result?.riskScore >= 60 ? '#ef4444' : item.result?.riskScore >= 30 ? '#f59e0b' : '#22c55e';
              return (
                <div key={i} onClick={() => item.status === 'done' && (setFile({ name: item.name, size: item.size }), setResult(item.result), setTab('overview'), setMultiResults([]))}
                  style={{ borderRadius: 10, padding: '12px 14px', background: 'rgba(0,0,0,0.25)', border: `1px solid ${item.status === 'done' ? 'rgba(99,102,241,0.18)' : item.status === 'error' ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.05)'}`, cursor: item.status === 'done' ? 'pointer' : 'default', transition: 'border-color 0.15s' }}
                  onMouseEnter={e => item.status === 'done' && (e.currentTarget.style.borderColor = 'rgba(99,102,241,0.4)')}
                  onMouseLeave={e => item.status === 'done' && (e.currentTarget.style.borderColor = 'rgba(99,102,241,0.18)')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    {item.status === 'pending' && <Spinner />}
                    {item.status === 'done'    && <div style={{ width: 8, height: 8, borderRadius: '50%', background: rc, boxShadow: `0 0 6px ${rc}66` }} />}
                    {item.status === 'error'   && <AlertTriangle size={12} color="#f87171" />}
                    <div style={{ fontSize: 11, fontWeight: 600, color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.name}</div>
                  </div>
                  {item.status === 'done' && (
                    <div style={{ fontSize: 10, color: '#374151' }}>
                      Risk <span style={{ color: rc, fontWeight: 700 }}>{item.result.riskScore}</span> · {item.result.arch} · {(item.size / 1024).toFixed(0)} KB
                      {item.result.packers?.length > 0 && <span style={{ color: '#fbbf24', marginLeft: 6 }}>{item.result.packers[0]}</span>}
                    </div>
                  )}
                  {item.status === 'error'   && <div style={{ fontSize: 10, color: '#f87171' }}>{item.error}</div>}
                  {item.status === 'done'    && <div style={{ fontSize: 9, color: '#374151', marginTop: 4 }}>Detay için tıkla →</div>}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Scanning */}
      {scanning && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 280, gap: 18 }}>
          <Spinner />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Analyzing {file?.name}</div>
            <div style={{ fontSize: 11, color: '#2d3748', marginTop: 5 }}>Parsing PE headers · Computing entropy · Scanning signatures · Extracting strings</div>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{ borderRadius: 12, padding: '14px 16px', background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}><AlertTriangle size={15} color="#f87171" /><span style={{ fontSize: 13, color: '#f87171', fontWeight: 600 }}>Analysis Failed</span></div>
          <div style={{ fontSize: 12, color: '#6b7280' }}>{error}</div>
          <button onClick={() => { setFile(null); setError(null); }} style={{ marginTop: 10, fontSize: 11, padding: '5px 12px', borderRadius: 6, border: '1px solid rgba(239,68,68,0.25)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>Try Again</button>
        </div>
      )}

      {/* Results */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

          {/* Risk Banner */}
          <div style={{ borderRadius: 12, padding: '14px 18px', background: `${rColor}0d`, border: `1px solid ${rColor}2e`, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 13 }}>
              <div style={{ width: 42, height: 42, borderRadius: 11, background: `${rColor}1a`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                {risk >= 30 ? <AlertTriangle size={20} color={rColor} /> : <ShieldCheck size={20} color={rColor} />}
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: rColor }}>{rLabel}</div>
                <div style={{ fontSize: 11, color: '#4b5563', marginTop: 3, fontFamily: 'monospace' }}>
                  {[result.denuvo && 'Denuvo', result.vmp && 'VMProtect', result.themida && 'Themida', result.antiDebug && 'Anti-Debug', result.antiVM && 'Anti-VM'].filter(Boolean).join(' · ') || 'No major protection'}
                  {result.suspiciousCount > 0 && ` · ${result.suspiciousCount} suspicious section${result.suspiciousCount > 1 ? 's' : ''}`}
                </div>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 30, fontWeight: 800, color: rColor, lineHeight: 1 }}>{result.riskScore}</div>
              <div style={{ fontSize: 9, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 2 }}>Risk Score</div>
            </div>
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 2, borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: 0 }}>
            {TABS.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                style={{ padding: '7px 14px', fontSize: 12, fontWeight: 500, border: 'none', cursor: 'pointer', background: 'transparent', borderBottom: `2px solid ${tab === t.id ? '#6366f1' : 'transparent'}`, color: tab === t.id ? '#818cf8' : '#374151', transition: 'all 0.13s', marginBottom: -1, display: 'flex', alignItems: 'center', gap: 5 }}>
                {t.label}
                {t.badge && <span style={{ fontSize: 9, background: 'rgba(239,68,68,0.2)', color: '#f87171', padding: '1px 5px', borderRadius: 4, fontWeight: 700 }}>{t.badge}</span>}
              </button>
            ))}
          </div>

          {/* Overview tab */}
          {tab === 'overview' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 260px', gap: 14 }}>
              {/* File info */}
              <Card>
                <CardHeader>File Info</CardHeader>
                <div style={{ padding: '4px 16px 12px' }}>
                  {[
                    { label: 'File Name',     value: file?.name,                                       trunc: true },
                    { label: 'Size',          value: `${(file?.size / 1048576).toFixed(2)} MB`         },
                    { label: 'Architecture',  value: result.arch + (result.isDll ? ' · DLL' : ' · EXE'), accent: true },
                    { label: 'Entry Point',   value: `0x${result.ep.toString(16).toUpperCase()}`,       mono: true, accent: true },
                    { label: 'Compiled',      value: result.compiledAt ? new Date(result.compiledAt).toLocaleDateString('tr-TR') + (result.fakeTimestamp ? ' ⚠ Sahte' : '') : '—', warn: result.fakeTimestamp },
                    { label: '.NET / CLR',    value: result.isDotNet ? 'YES — managed code' : 'No',    accent: result.isDotNet, warn: false },
                    { label: 'Overlay',       value: result.overlaySize > 0 ? `${(result.overlaySize / 1024).toFixed(1)} KB ⚡` : 'None', danger: result.overlaySize > 0 },
                    { label: 'Sections',      value: result.numSec                                      },
                    { label: 'Overall Entropy', value: `${result.overallEntropy.toFixed(4)} H`,         mono: true, warn: result.overallEntropy > 7 },
                    { label: 'Suspicious',    value: result.suspiciousCount,                            danger: result.suspiciousCount > 0 },
                    { label: 'Strings Found', value: result.strings.length                              },
                    { label: 'Flagged Strings', value: flaggedStrings,                                   danger: flaggedStrings > 0 },
                    { label: 'Imports (DLLs)',  value: result.imports?.length || 0,                     accent: true },
                    { label: 'Exports',         value: result.exports?.length || 0,                     accent: result.exports?.length > 0 },
                    { label: 'SHA-256',         value: result.sha256 ? result.sha256.slice(0,16)+'⬦' : '—', mono: true, title: result.sha256 || undefined },
                    { label: 'SHA-1',           value: result.sha1   ? result.sha1.slice(0,16)+'⬦'   : '—', mono: true, title: result.sha1   || undefined },
                    { label: 'MD5 (F5)',        value: result.md5    ? result.md5.slice(0,16)+'⬦'    : '—', mono: true, title: result.md5    || undefined },
                    { label: 'CRC32 (F5)',      value: result.crc32 || '—', mono: true },
                    { label: 'Imphash',         value: result.imphash ? result.imphash.slice(0,16)+'⬦' : '—', mono: true, title: result.imphash || undefined },
                    { label: 'Rich Header',     value: result.richHash ? result.richHash.slice(0,36)+'⬦' : 'Not found', mono: !!result.richHash, title: result.richHash || undefined, accent: !!result.richHash },
                    { label: 'PDB Path (B8)',   value: result.debugPdb || '—', mono: true, accent: !!result.debugPdb, title: result.debugPdb || undefined },
                  ].map(({ label, value, mono, trunc, accent, danger, warn, title }) => (
                    <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <span style={{ fontSize: 11, color: '#374151' }}>{label}</span>
                      <span title={title} style={{ fontSize: 11, fontFamily: mono ? 'monospace' : 'inherit', fontWeight: 500, color: danger ? '#f87171' : warn ? '#f59e0b' : accent ? '#818cf8' : '#94a3b8', maxWidth: trunc ? 160 : undefined, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              </Card>

              {/* E3 — VirusTotal hash sorgulama */}
              {result.sha256 && (
                <Card>
                  <CardHeader>VirusTotal Sorgula (E3)</CardHeader>
                  <div style={{ padding: '10px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <div style={{ display: 'flex', gap: 7 }}>
                      <input value={vtApiKey} onChange={e => { setVtApiKey(e.target.value); localStorage.setItem('dissect_vt_key', e.target.value); }}
                        placeholder="VirusTotal API Key (ücretsiz key: virustotal.com/gui/my-apikey)"
                        type="password"
                        style={{ flex: 1, fontSize: 11, padding: '5px 9px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(0,0,0,0.3)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                      <button disabled={!vtApiKey.trim() || vtLoading} onClick={async () => {
                        setVtLoading(true); setVtResult(null);
                        try {
                          const res = await fetch(`https://www.virustotal.com/api/v3/files/${result.sha256}`, { headers: { 'x-apikey': vtApiKey } });
                          const json = await res.json();
                          if (json.error) { setVtResult({ error: json.error.message }); }
                          else {
                            const a = json.data?.attributes;
                            setVtResult({ malicious: a?.last_analysis_stats?.malicious || 0, undetected: a?.last_analysis_stats?.undetected || 0, total: Object.values(a?.last_analysis_stats || {}).reduce((s, v) => s + v, 0), names: a?.names?.slice(0, 5) || [], firstSeen: a?.first_submission_date ? new Date(a.first_submission_date * 1000).toLocaleDateString('tr-TR') : null, permalink: `https://www.virustotal.com/gui/file/${result.sha256}` });
                          }
                        } catch (e) { setVtResult({ error: String(e) }); }
                        finally { setVtLoading(false); }
                      }} style={{ fontSize: 11, padding: '5px 14px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: vtApiKey.trim() && !vtLoading ? 'pointer' : 'not-allowed', fontWeight: 600, whiteSpace: 'nowrap', opacity: vtApiKey.trim() && !vtLoading ? 1 : 0.5 }}>
                        {vtLoading ? '⬦' : '🔍 Sorgula'}
                      </button>
                    </div>
                    {vtResult && (vtResult.error
                      ? <div style={{ fontSize: 11, color: '#f87171', fontFamily: 'monospace' }}>Hata: {vtResult.error}</div>
                      : <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 13, fontWeight: 700, color: vtResult.malicious > 0 ? '#f87171' : '#4ade80' }}>{vtResult.malicious}/{vtResult.total} tespit</span>
                          {vtResult.malicious > 0 && <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)', fontWeight: 700 }}>MALICIOUS</span>}
                          {vtResult.firstSeen && <span style={{ fontSize: 10, color: '#374151' }}>İlk: {vtResult.firstSeen}</span>}
                          {vtResult.names?.length > 0 && <span style={{ fontSize: 10, color: '#374151' }}>{vtResult.names.join(', ')}</span>}
                          <a href={vtResult.permalink} target="_blank" rel="noreferrer" style={{ fontSize: 10, color: '#818cf8', marginLeft: 'auto' }}>VT'de aç  ?</a>
                        </div>
                    )}
                  </div>
                </Card>
              )}

              {/* Protection layers + 41 — Ordered analysis suggestions */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <Card>
                  <CardHeader>Protection Layers</CardHeader>
                  <div style={{ padding: '4px 16px 12px' }}>
                    {[
                      { name: 'Denuvo',     detected: result.denuvo,    desc: 'Anti-tamper · Online DRM' },
                      { name: 'VMProtect',  detected: result.vmp,       desc: 'Code virtualization' },
                      { name: 'Themida',    detected: result.themida,   desc: 'Anti-dump · Obfuscation' },
                      { name: 'Anti-Debug', detected: result.antiDebug, desc: 'IsDebuggerPresent / NtQuery⬦' },
                      { name: 'Anti-VM',    detected: result.antiVM,    desc: 'VMware / VBox / sandbox checks' },
                    ].map(({ name, detected, desc }) => (
                      <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        {detected ? <XCircle size={15} color="#ef4444" /> : <CheckCircle2 size={15} color="#22c55e" />}
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: detected ? '#f87171' : '#374151' }}>{name}</div>
                          <div style={{ fontSize: 10, color: '#2d3748' }}>{desc}</div>
                        </div>
                        <span style={{ fontSize: 10, fontWeight: 700, color: detected ? '#f87171' : '#22c55e' }}>{detected ? 'FOUND' : 'CLEAN'}</span>
                      </div>
                    ))}
                    {/* 16 — Detected packers */}
                    {result.packers?.length > 0 && (
                      <div style={{ paddingTop: 10, marginTop: 4 }}>
                        <div style={{ fontSize: 10, color: '#374151', marginBottom: 7, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Detected Packers</div>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {result.packers.map(p => (
                            <span key={p} style={{ padding: '2px 9px', borderRadius: 5, background: 'rgba(251,191,36,0.12)', color: '#fbbf24', fontSize: 11, fontWeight: 700, border: '1px solid rgba(251,191,36,0.25)' }}>{p}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </Card>

                {/* 41 — Ordered analysis recommendations */}
                {(() => {
                  const steps = [];
                  if (result.packers?.length > 0 || result.overallEntropy > 7.2)
                    steps.push({ n: 1, label: 'Unpack first', detail: 'High entropy / packer detected — unpack before analysis', col: '#f87171' });
                  if (result.antiDebug)
                    steps.push({ n: steps.length + 1, label: 'Bypass anti-debug', detail: 'Patch IsDebuggerPresent / NtQueryInformationProcess checks', col: '#fb923c' });
                  if (result.antiVM)
                    steps.push({ n: steps.length + 1, label: 'Remove VM checks', detail: 'VMware/VBox registry and process name queries detected', col: '#fb923c' });
                  if (result.denuvo || result.themida || result.vmp)
                    steps.push({ n: steps.length + 1, label: 'Handle DRM layer', detail: [result.denuvo && 'Denuvo', result.vmp && 'VMProtect', result.themida && 'Themida'].filter(Boolean).join(' + '), col: '#fbbf24' });
                  if (result.overlaySize > 0)
                    steps.push({ n: steps.length + 1, label: 'Inspect overlay', detail: `${(result.overlaySize / 1024).toFixed(1)} KB after last section — may contain payload`, col: '#fbbf24' });
                  const injStrings = result.strings?.filter(s => s.cat?.cat === 'injection') || [];
                  if (injStrings.length > 0)
                    steps.push({ n: steps.length + 1, label: 'Trace injection', detail: `${injStrings.length} injection API pattern(s) in strings`, col: '#f59e0b' });
                  if (result.imports?.length > 0)
                    steps.push({ n: steps.length + 1, label: 'Audit import table', detail: `${result.imports.length} DLL(s) — check for suspicious functions`, col: '#6366f1' });
                  if (result.strings?.some(s => s.cat?.cat === 'url' || s.cat?.cat === 'ip'))
                    steps.push({ n: steps.length + 1, label: 'Investigate network IOCs', detail: 'URLs and/or IPs found in strings — trace callbacks', col: '#818cf8' });
                  if (steps.length === 0)
                    steps.push({ n: 1, label: 'No major threats detected', detail: 'File appears clean — proceed with standard review', col: '#22c55e' });
                  return (
                    <Card>
                      <CardHeader>İnceleme Sırası (41)</CardHeader>
                      <div style={{ padding: '4px 16px 12px' }}>
                        {steps.map(({ n, label, detail, col }) => (
                          <div key={n} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                            <div style={{ width: 18, height: 18, borderRadius: '50%', background: `${col}22`, border: `1px solid ${col}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                              <span style={{ fontSize: 9, fontWeight: 700, color: col }}>{n}</span>
                            </div>
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 600, color: col }}>{label}</div>
                              <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>{detail}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </Card>
                  );
                })()}
              </div>
            </div>
          )}

          {/* Sections tab — 47: entropy bar chart */}
          {tab === 'sections' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* Bar chart */}
              <Card>
                <CardHeader>Entropy Chart — sections</CardHeader>
                <div style={{ padding: '14px 16px 4px', position: 'relative', display: 'flex', alignItems: 'flex-end', gap: 8, minHeight: 90 }}>
                  {/* 11 — 7.2 H danger threshold line */}
                  <div style={{ position: 'absolute', left: 16, right: 16, bottom: `calc(4px + ${(7.2/8)*60}px)`, height: 1, background: 'rgba(239,68,68,0.35)', zIndex: 1, pointerEvents: 'none' }}>
                    <span style={{ position: 'absolute', right: 0, top: -10, fontSize: 8, color: '#ef4444', opacity: 0.7 }}>7.2H</span>
                  </div>
                  {result.sections.map((sec, i) => {
                    const pct  = (sec.entropy / 8) * 100;
                    const col  = sec.entropy > 7.2 ? '#ef4444' : sec.entropy > 6.5 ? '#f59e0b' : '#6366f1';
                    return (
                      <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1, gap: 5 }}>
                        <span style={{ fontSize: 9, color: col, fontFamily: 'monospace', fontWeight: 700 }}>{sec.entropy.toFixed(2)}</span>
                        <div style={{ width: '100%', height: 60, background: 'rgba(255,255,255,0.04)', borderRadius: 4, display: 'flex', alignItems: 'flex-end', overflow: 'hidden' }}>
                          <div style={{ width: '100%', height: `${pct}%`, background: col, transition: 'height 0.8s ease', opacity: 0.85 }} />
                        </div>
                        <span style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace', maxWidth: 40, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'center' }}>{sec.name}</span>
                      </div>
                    );
                  })}
                </div>
                {/* 11 — stats row */}
                <div style={{ padding: '4px 16px 8px', display: 'flex', gap: 16 }}>
                  {(() => {
                    const ents = result.sections.map(s => s.entropy);
                    const avg = ents.reduce((a,b) => a+b, 0) / (ents.length || 1);
                    const max = Math.max(...ents);
                    const hi  = ents.filter(e => e > 7.2).length;
                    return [
                      ['Avg', avg.toFixed(2)+'H', avg > 6.5 ? '#f59e0b' : '#374151'],
                      ['Max', max.toFixed(2)+'H', max > 7.2 ? '#ef4444' : '#374151'],
                      ['High-entropy sections', hi, hi > 0 ? '#ef4444' : '#374151'],
                    ].map(([l, v, c]) => (
                      <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span style={{ fontSize: 9, color: '#2d3748' }}>{l}</span>
                        <span style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: c }}>{v}</span>
                      </div>
                    ));
                  })()}
                </div>
                <div style={{ padding: '0 16px 10px', display: 'flex', gap: 14 }}>
                  {[['#4ade80','< 6.5 H Normal'], ['#6366f1','6.5–7.2 H Elevated'], ['#f59e0b','7.2–7.5 H High'], ['#ef4444','> 7.5 H Packed/Encrypted']].map(([c,l]) => (
                    <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ width: 8, height: 8, borderRadius: 2, background: c }} />
                      <span style={{ fontSize: 10, color: '#374151' }}>{l}</span>
                    </div>
                  ))}
                </div>
              </Card>

              {/* Section list */}
              <Card>
                <CardHeader>
                  PE Sections ({result.sections.length}) &nbsp;·&nbsp;
                  <span style={{ color: '#4b5563', textTransform: 'none', fontWeight: 400 }}>Overall entropy: </span>
                  <span style={{ color: result.overallEntropy > 7.0 ? '#f59e0b' : '#4b5563', fontFamily: 'monospace' }}>{result.overallEntropy.toFixed(3)} H</span>
                </CardHeader>
                {result.sections.map((sec, i) => (
                  <div key={i} style={{ padding: '10px 16px', borderBottom: i < result.sections.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none', background: sec.suspicious ? 'rgba(239,68,68,0.03)' : 'transparent' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 7 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 11, fontFamily: 'monospace', fontWeight: 700, padding: '2px 7px', borderRadius: 4, background: sec.suspicious ? 'rgba(239,68,68,0.13)' : 'rgba(99,102,241,0.1)', color: sec.suspicious ? '#f87171' : '#818cf8' }}>{sec.name}</span>
                        <span style={{ fontSize: 10, color: '#2d3748', fontFamily: 'monospace' }}>0x{sec.vaddr.toString(16).toUpperCase().padStart(8, '0')}</span>
                        {sec.isExec && <span style={{ fontSize: 9, color: '#4b5563', background: 'rgba(255,255,255,0.05)', padding: '1px 5px', borderRadius: 3 }}>EXEC</span>}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        {sec.suspicious && <AlertTriangle size={11} color="#f59e0b" />}
                        <span style={{ fontSize: 10, fontFamily: 'monospace', fontWeight: 700, color: sec.entropy > 7.2 ? '#f87171' : sec.entropy > 6.5 ? '#f59e0b' : '#4ade80' }}>{sec.entropy.toFixed(3)} H</span>
                        <span style={{ fontSize: 10, color: '#2d3748', fontFamily: 'monospace' }}>{(sec.rsize / 1024).toFixed(0)} KB</span>
                      </div>
                    </div>
                    <div style={{ height: 3, borderRadius: 2, background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', borderRadius: 2, width: `${(sec.entropy / 8) * 100}%`, background: sec.entropy > 7.2 ? 'linear-gradient(90deg,#f59e0b,#ef4444)' : sec.entropy > 6.0 ? '#6366f1' : '#22c55e', transition: 'width 0.7s ease' }} />
                    </div>
                  </div>
                ))}
              </Card>
            </div>
          )}

          {/* Strings tab — 48: filter + category */}
          {tab === 'strings' && (() => {
            const cats = ['all', ...STR_PATTERNS.map(p => p.cat)];
            const filtered = result.strings.filter(s => {
              const matchCat = strCat === 'all' || s.cat?.cat === strCat;
              const matchTxt = !strFilter || s.text.toLowerCase().includes(strFilter.toLowerCase());
              return matchCat && matchTxt;
            });
            return (
              <Card>
                <CardHeader>
                  Strings — {filtered.length} / {totalStrings} &nbsp;·&nbsp;
                  <span style={{ color: '#f87171', textTransform: 'none', fontWeight: 400 }}>{flaggedStrings} flagged</span>
                </CardHeader>
                {/* Controls */}
                <div style={{ padding: '10px 12px 6px', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <input value={strFilter} onChange={e => setStrFilter(e.target.value)} placeholder="Filter strings⬦"
                    style={{ flex: 1, minWidth: 140, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6, padding: '5px 9px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
                  {cats.map(c => {
                    const pat = STR_PATTERNS.find(p => p.cat === c);
                    const cnt = c === 'all' ? totalStrings : result.strings.filter(s => s.cat?.cat === c).length;
                    if (c !== 'all' && cnt === 0) return null;
                    return (
                      <button key={c} onClick={() => setStrCat(c)}
                        style={{ padding: '3px 9px', borderRadius: 5, border: `1px solid ${strCat === c ? (pat?.color || '#818cf8') : 'rgba(255,255,255,0.07)'}`, background: strCat === c ? `${pat?.color || '#818cf8'}18` : 'transparent', color: strCat === c ? (pat?.color || '#818cf8') : '#374151', cursor: 'pointer', fontSize: 10, fontWeight: strCat === c ? 700 : 400 }}>
                        {pat?.label || 'All'} {cnt > 0 && <span style={{ opacity: 0.7 }}>({cnt})</span>}
                      </button>
                    );
                  })}
                </div>
                <div style={{ padding: 12, maxHeight: 400, overflowY: 'auto', display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {filtered.slice(0, 400).map((s, i) => (
                    <span key={i} onClick={() => setStrFilter(s.text === strFilter ? '' : s.text)} style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4, background: s.cat ? `${s.cat.color}18` : 'rgba(255,255,255,0.04)', color: s.cat ? s.cat.color : '#6b7280', border: s.cat ? `1px solid ${s.cat.color}33` : '1px solid transparent', maxWidth: 340, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }} title={s.text}>{s.text}</span>
                  ))}
                  {filtered.length === 0 && <span style={{ fontSize: 12, color: '#374151' }}>No strings match the filter.</span>}
                </div>
                {/* A6 — String Cross-Reference: find import functions matching current filter */}
                {strFilter && (() => {
                  const q = strFilter.toLowerCase();
                  const refs = [];
                  (result.imports || []).forEach(imp => {
                    imp.funcs.filter(fn => fn.toLowerCase().includes(q)).forEach(fn => refs.push({ dll: imp.dll, fn }));
                  });
                  if (!refs.length) return null;
                  return (
                    <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', padding: '8px 12px' }}>
                      <div style={{ fontSize: 9, fontWeight: 700, color: '#818cf8', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 5 }}>String Cross-Reference (A6) — Import hits for "{strFilter}"</div>
                      {refs.map((r, i) => (
                        <div key={i} style={{ fontSize: 11, fontFamily: 'monospace', color: '#94a3b8', padding: '2px 0' }}>
                          <span style={{ color: '#6366f1' }}>{r.dll}</span> → <span style={{ color: '#60a5fa' }}>{r.fn}</span>
                        </div>
                      ))}
                    </div>
                  );
                })()}
              </Card>
            );
          })()}

          {/* Imports tab — 03: Import Table */}
          {tab === 'imports' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* 26 — Dependency map */}
              {result.imports && result.imports.length > 0 && (
                <Card>
                  <CardHeader>Dependency Map — {result.imports.length} DLL{result.imports.length !== 1 ? 's' : ''}</CardHeader>
                  <div style={{ padding: '10px 16px 14px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                      {/* root node */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingBottom: 6 }}>
                        <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(99,102,241,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Binary size={14} color="#818cf8" /></div>
                        <span style={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 700, color: '#818cf8' }}>{file?.name || 'target.exe'}</span>
                      </div>
                      {result.imports.map((imp, i) => {
                        const isLast = i === result.imports.length - 1;
                        const isSystemDll = /^(kernel32|ntdll|user32|gdi32|advapi32|msvcrt|ole32|shell32|ws2_32|wininet|urlmon)/i.test(imp.dll);
                        const isDanger   = imp.funcs.some(fn => /VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThread|LoadLibrary/i.test(fn));
                        const col = isDanger ? '#f87171' : isSystemDll ? '#374151' : '#94a3b8';
                        return (
                          <div key={i} style={{ display: 'flex', gap: 0 }}>
                            <div style={{ width: 14, flexShrink: 0, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                              <div style={{ width: 1, flex: 1, background: 'rgba(99,102,241,0.2)' }} />
                              {!isLast && <div style={{ width: 1, flex: 1, background: 'rgba(99,102,241,0.2)' }} />}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingBottom: isLast ? 0 : 4, paddingLeft: 8 }}>
                              <div style={{ width: 8, height: 1, background: 'rgba(99,102,241,0.3)', flexShrink: 0 }} />
                              <div style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '2px 8px', borderRadius: 5, background: isDanger ? 'rgba(239,68,68,0.07)' : 'rgba(255,255,255,0.03)', border: `1px solid ${isDanger ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.05)'}` }}>
                                <span style={{ fontSize: 11, fontFamily: 'monospace', color: col }}>{imp.dll}</span>
                                <span style={{ fontSize: 9, color: '#374151' }}>{imp.funcs.length}f</span>
                                {isDanger && <AlertTriangle size={9} color="#f87171" />}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </Card>
              )}
              <Card>
              <CardHeader>Import Table — {result.imports?.length || 0} DLLs</CardHeader>
              {(!result.imports || result.imports.length === 0) && (
                <div style={{ padding: 20, fontSize: 12, color: '#374151', textAlign: 'center' }}>No imports found or import directory not parseable.</div>
              )}
              <div style={{ maxHeight: 520, overflowY: 'auto' }}>
                {result.imports?.map((imp, i) => (
                  <div key={i} style={{ borderBottom: i < result.imports.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                    <div style={{ padding: '9px 16px 5px', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Layers size={12} color="#6366f1" style={{ flexShrink: 0 }} />
                      <span style={{ fontSize: 12, fontFamily: 'monospace', fontWeight: 700, color: '#818cf8' }}>{imp.dll}</span>
                      <span style={{ fontSize: 10, color: '#374151', marginLeft: 'auto' }}>{imp.funcs.length} func{imp.funcs.length !== 1 ? 's' : ''}</span>
                    </div>
                    <div style={{ padding: '2px 16px 10px', display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {imp.funcs.slice(0, 60).map((fn, j) => {
                        const isAntiDebug = STR_PATTERNS.find(p => p.cat === 'antidebug')?.re.test(fn);
                        const isNetwork   = STR_PATTERNS.find(p => p.cat === 'network')?.re.test(fn);
                        const isCrypto    = STR_PATTERNS.find(p => p.cat === 'crypto')?.re.test(fn);
                        const col = isAntiDebug ? '#f87171' : isNetwork ? '#34d399' : isCrypto ? '#fbbf24' : '#4b5563';
                        return (
                          <span key={j} style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3, background: 'rgba(255,255,255,0.03)', color: col, border: '1px solid rgba(255,255,255,0.04)' }}>{fn}</span>
                        );
                      })}
                      {imp.funcs.length > 60 && <span style={{ fontSize: 10, color: '#374151' }}>+{imp.funcs.length - 60} more⬦</span>}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
            </div>
          )}

          {/* Exports tab — 04 */}
          {tab === 'exports' && (
            <Card>
              <CardHeader>Export Table — {result.exports?.length || 0} function{result.exports?.length !== 1 ? 's' : ''}</CardHeader>
              {(!result.exports || result.exports.length === 0)
                ? <div style={{ padding: 24, textAlign: 'center', fontSize: 12, color: '#374151' }}>No exports found — this is likely an EXE rather than a DLL.</div>
                : (
                  <div style={{ maxHeight: 520, overflowY: 'auto' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.06em', padding: '7px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                      <span>Function Name</span><span style={{ marginRight: 24 }}>Ordinal</span><span>RVA</span>
                    </div>
                    {result.exports.map((ex, i) => (
                      <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', padding: '6px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)', alignItems: 'center' }}>
                        <span style={{ fontSize: 12, fontFamily: 'monospace', color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ex.name || `(unnamed)`}</span>
                        <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#4b5563', marginRight: 24 }}>#{ex.ordinal}</span>
                        <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#6366f1' }}>{ex.rva}</span>
                      </div>
                    ))}
                  </div>
                )
              }
            </Card>
          )}

          {/* B1 — Resources tab */}
          {tab === 'resources' && (
            <Card>
              <CardHeader>PE Resources (B1) — {result.resources?.length || 0} resource types</CardHeader>
              {(!result.resources || result.resources.length === 0) && (
                <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 12, color: '#374151' }}>
                  No resource directory found, or resource section could not be parsed.<br />
                  <span style={{ fontSize: 10, color: '#1f2937' }}>This is normal for many command-line executables.</span>
                </div>
              )}
              {result.resources && result.resources.length > 0 && (
                <div style={{ padding: '8px 16px 14px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8, marginBottom: 12 }}>
                    {result.resources.map((r, i) => {
                      const ICONS = { Icon: '🖼', Bitmap: '🖼', Manifest: '📋', VersionInfo: '✎', String: '✎', Menu: '☰', Dialog: '💬', Cursor: '🖼', RCData: '✎' };
                      const ic = ICONS[r.name] || '✎';
                      return (
                        <div key={i} style={{ padding: '10px 14px', borderRadius: 9, background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.14)', display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{ fontSize: 20 }}>{ic}</span>
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 600, color: '#818cf8' }}>{r.name}</div>
                            <div style={{ fontSize: 10, color: '#4b5563' }}>Type {r.type} · {r.count} item{r.count !== 1 ? 's' : ''}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {result.resources.some(r => r.name === 'VersionInfo') && (
                    <div style={{ fontSize: 11, color: '#374151', padding: '8px 0' }}>
                      📋 <strong style={{ color: '#818cf8' }}>VersionInfo</strong> resource detected — may contain product name, version, company, copyright strings.
                    </div>
                  )}
                  {result.resources.some(r => r.name === 'Manifest') && (
                    <div style={{ fontSize: 11, color: '#374151', padding: '4px 0' }}>
                      📋 <strong style={{ color: '#60a5fa' }}>Manifest</strong> resource detected — may contain requested execution level, DPI settings, dependencies.
                    </div>
                  )}
                </div>
              )}
            </Card>
          )}

          {/* B1 — Resources tab */}
          {tab === 'resources' && (
            <Card>
              <CardHeader>PE Resources (B1) — {result.resources?.length || 0} resource types</CardHeader>
              {(!result.resources || result.resources.length === 0) && (
                <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 12, color: '#374151' }}>
                  No resource directory found, or resource section could not be parsed.<br />
                  <span style={{ fontSize: 10, color: '#1f2937' }}>This is normal for many command-line executables.</span>
                </div>
              )}
              {result.resources && result.resources.length > 0 && (
                <div style={{ padding: '8px 16px 14px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8, marginBottom: 12 }}>
                    {result.resources.map((r, i) => {
                      const ICONS = { Icon: '🖼', Bitmap: '🖼', Manifest: '📋', VersionInfo: '✎', String: '✎', Menu: '☰', Dialog: '💬', Cursor: '🖼', RCData: '✎' };
                      const ic = ICONS[r.name] || '✎';
                      return (
                        <div key={i} style={{ padding: '10px 14px', borderRadius: 9, background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.14)', display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{ fontSize: 20 }}>{ic}</span>
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 600, color: '#818cf8' }}>{r.name}</div>
                            <div style={{ fontSize: 10, color: '#4b5563' }}>Type {r.type} · {r.count} item{r.count !== 1 ? 's' : ''}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {result.resources.some(r => r.name === 'VersionInfo') && (
                    <div style={{ fontSize: 11, color: '#374151', padding: '8px 0' }}>
                      📋 <strong style={{ color: '#818cf8' }}>VersionInfo</strong> resource detected — may contain product name, version, company, copyright strings.
                    </div>
                  )}
                  {result.resources.some(r => r.name === 'Manifest') && (
                    <div style={{ fontSize: 11, color: '#374151', padding: '4px 0' }}>
                      📋 <strong style={{ color: '#60a5fa' }}>Manifest</strong> resource detected — may contain requested execution level, DPI settings, dependencies.
                    </div>
                  )}
                </div>
              )}
            </Card>
          )}

          {/* YARA tab — 12 */}
          {tab === 'yara' && (
            <Card>
              <CardHeader>YARA-like Rule Engine — {yaraHits.length} kural eşleşti / {YARA_RULES.length} kural</CardHeader>
              <div style={{ padding: '8px 16px 12px' }}>
                {YARA_RULES.map(rule => {
                  let hit = false;
                  try { hit = rule.match(result); } catch {}
                  const col = YARA_SEV_COLOR[rule.sev] || '#6b7280';
                  const desc = typeof rule.desc === 'function' ? rule.desc(result) : rule.desc;
                  return (
                    <div key={rule.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', opacity: hit ? 1 : 0.35 }}>
                      <div style={{ width: 8, height: 8, borderRadius: '50%', background: hit ? col : '#1e2330', flexShrink: 0, boxShadow: hit ? `0 0 6px ${col}66` : 'none' }} />
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 12, fontWeight: hit ? 600 : 400, color: hit ? col : '#374151' }}>{rule.name}</div>
                        {hit && desc && <div style={{ fontSize: 10, color: '#6b7280', marginTop: 2 }}>{desc}</div>}
                      </div>
                      <span style={{ fontSize: 9, padding: '1px 7px', borderRadius: 4, background: hit ? `${col}18` : 'rgba(255,255,255,0.03)', color: hit ? col : '#2d3748', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        {hit ? rule.sev : 'clean'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}

          {/* —�—� Analyze tab — A3/A4/A5/B5/B7 —�—� */}
          {tab === 'analyze' && (() => {
            // A3 — minimal x86/x64 byte description helper
            const descByte = (bytes, i) => {
              const b = bytes[i] ? parseInt(bytes[i], 16) : null;
              if (b === null) return { mnem: '??', bytes: 1 };
              const ops = {
                0x90: { mnem: 'NOP', bytes: 1 },
                0xCC: { mnem: 'INT3', bytes: 1 },
                0xC3: { mnem: 'RETN', bytes: 1 },
                0xC2: { mnem: `RETN ${parseInt(bytes[i+1]||'0',16)+(parseInt(bytes[i+2]||'0',16)<<8)}`, bytes: 3 },
                0xEB: { mnem: `JMP SHORT +0x${bytes[i+1]||'00'}`, bytes: 2 },
                0xE9: { mnem: `JMP [→ ${bytes.slice(i+1,i+5).reverse().join('')}]`, bytes: 5 },
                0xE8: { mnem: `CALL [→ ${bytes.slice(i+1,i+5).reverse().join('')}]`, bytes: 5 },
                0x55: { mnem: 'PUSH EBP/RBP', bytes: 1 },
                0x53: { mnem: 'PUSH EBX', bytes: 1 },
                0x56: { mnem: 'PUSH ESI', bytes: 1 },
                0x57: { mnem: 'PUSH EDI', bytes: 1 },
                0x5D: { mnem: 'POP EBP', bytes: 1 }, 0x5B: { mnem: 'POP EBX', bytes: 1 },
                0x6A: { mnem: `PUSH ${bytes[i+1]||'??'}`, bytes: 2 },
                0x68: { mnem: `PUSH DWORD [${bytes.slice(i+1,i+5).join(' ')}]`, bytes: 5 },
                0x8B: { mnem: 'MOV r, r/m', bytes: 2 },
                0x89: { mnem: 'MOV r/m, r', bytes: 2 },
                0x8D: { mnem: 'LEA r, m', bytes: 2 },
                0x83: { mnem: 'OP r/m, imm8', bytes: 3 },
                0x81: { mnem: 'OP r/m, imm32', bytes: 6 },
                0x85: { mnem: 'TEST r/m, r', bytes: 2 },
                0x31: { mnem: 'XOR r/m, r', bytes: 2 },
                0x33: { mnem: 'XOR r, r/m', bytes: 2 },
                0x01: { mnem: 'ADD r/m, r', bytes: 2 },
                0x03: { mnem: 'ADD r, r/m', bytes: 2 },
                0x29: { mnem: 'SUB r/m, r', bytes: 2 },
                0x2B: { mnem: 'SUB r, r/m', bytes: 2 },
                0xFF: { mnem: 'CALL/JMP/INC/DEC r/m', bytes: 2 },
                0x50: { mnem: 'PUSH EAX/RAX', bytes: 1 }, 0x51: { mnem: 'PUSH ECX', bytes: 1 },
                0x52: { mnem: 'PUSH EDX', bytes: 1 }, 0x58: { mnem: 'POP EAX', bytes: 1 },
                0x74: { mnem: `JZ +${bytes[i+1]||'00'}h`, bytes: 2 }, 0x75: { mnem: `JNZ +${bytes[i+1]||'00'}h`, bytes: 2 },
                0x72: { mnem: `JB +${bytes[i+1]||'00'}h`, bytes: 2 }, 0x73: { mnem: `JAE +${bytes[i+1]||'00'}h`, bytes: 2 },
                0xF3: { mnem: 'REP prefix', bytes: 1 }, 0xF2: { mnem: 'REPNE prefix', bytes: 1 },
                0x48: { mnem: bytes[i+1] ? 'REX.W prefix' : 'DEC EAX', bytes: 1 },
                0x40: { mnem: 'INC EAX / REX', bytes: 1 },
                0x0F: { mnem: `0F ${bytes[i+1]||'?'} (ext)`, bytes: 2 },
              };
              return ops[b] || { mnem: `db ${bytes[i]}`, bytes: 1 };
            };
            const epRows = [];
            const byts = result.epBytes || [];
            let off = 0;
            while (off < Math.min(byts.length, 64)) {
              const d = descByte(byts, off);
              epRows.push({ off, hex: byts.slice(off, off + d.bytes).join(' '), mnem: d.mnem, bytes: d.bytes });
              off += d.bytes || 1;
            }
            // A5 state via local component isn't possible here inline — use controlled input in closure
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

                {/* A3 — EP disassembly */}
                <Card>
                  <CardHeader>Entry Point Disassembly — EP RVA: 0x{result.ep?.toString(16).toUpperCase().padStart(8,'0')} · File Offset: 0x{result.epFileOff?.toString(16).toUpperCase().padStart(8,'0')}</CardHeader>
                  <div style={{ padding: '8px 0 10px', fontFamily: 'monospace' }}>
                    {byts.length === 0
                      ? <div style={{ padding: '8px 16px', fontSize: 11, color: '#374151' }}>EP baytları yüklenemedi (packed/overlay EP olabilir)</div>
                      : epRows.map((r, i) => (
                        <div key={i} style={{ display: 'grid', gridTemplateColumns: '80px 140px 1fr', padding: '2px 16px', fontSize: 11, background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                          <span style={{ color: '#4b5563' }}>+0x{r.off.toString(16).padStart(4,'0')}</span>
                          <span style={{ color: '#374151' }}>{r.hex}</span>
                          <span style={{ color: r.mnem.startsWith('db') ? '#6b7280' : r.mnem.includes('CALL') || r.mnem.includes('JMP') ? '#60a5fa' : r.mnem === 'NOP' ? '#4b5563' : r.mnem.includes('PUSH') || r.mnem.includes('POP') ? '#c4b5fd' : '#94a3b8' }}>{r.mnem}</span>
                        </div>
                      ))
                    }
                    {byts.length > 0 && <div style={{ padding: '6px 16px 0', fontSize: 10, color: '#1f2937' }}>Showing first ~64 bytes at EP. JMP/CALL targets are relative offsets only.</div>}
                  </div>
                </Card>

                {/* A5 — RVA  — File Offset calculator */}
                {(() => {
                  const [rvaIn, setRvaIn] = React.useState('');
                  const [calcResult, setCalcResult] = React.useState(null);
                  const calcRva = () => {
                    const n = parseInt(rvaIn, 16) || parseInt(rvaIn, 10) || 0;
                    const secs = result.sections || [];
                    const match = secs.find(s => n >= s.vaddr && n < s.vaddr + (s.vsize || s.rsize));
                    if (match) {
                      const fileOff = (match.rawOff || 0) + (n - match.vaddr);
                      setCalcResult({ rva: `0x${n.toString(16).toUpperCase().padStart(8,'0')}`, fileOff: `0x${fileOff.toString(16).toUpperCase().padStart(8,'0')}`, section: match.name });
                    } else {
                      setCalcResult({ error: `RVA 0x${n.toString(16).toUpperCase()} herhangi bir section içinde de?il` });
                    }
                  };
                  return (
                    <Card>
                      <CardHeader>RVA / VA → File Offset Calculator (A5)</CardHeader>
                      <div style={{ padding: '12px 16px', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                        <input value={rvaIn} onChange={e => setRvaIn(e.target.value)} placeholder="RVA veya VA (hex: 0x... veya decimal)"
                          style={{ flex: 1, minWidth: 220, fontSize: 12, padding: '6px 10px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.05)', color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }}
                          onKeyDown={e => e.key === 'Enter' && calcRva()} />
                        <button onClick={calcRva} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: 'pointer' }}>Hesapla</button>
                        {calcResult && !calcResult.error && (
                          <div style={{ display: 'flex', gap: 16, fontSize: 11, fontFamily: 'monospace', flexWrap: 'wrap' }}>
                            <span style={{ color: '#374151' }}>RVA: <span style={{ color: '#6366f1' }}>{calcResult.rva}</span></span>
                            <span style={{ color: '#374151' }}>File Offset: <span style={{ color: '#4ade80' }}>{calcResult.fileOff}</span></span>
                            <span style={{ color: '#374151' }}>Section: <span style={{ color: '#94a3b8' }}>{calcResult.section}</span></span>
                          </div>
                        )}
                        {calcResult?.error && <span style={{ fontSize: 11, color: '#f87171' }}>{calcResult.error}</span>}
                      </div>
                      <div style={{ padding: '0 16px 10px', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        {(result.sections || []).map(s => (
                          <div key={s.name} onClick={() => { setRvaIn(`0x${s.vaddr.toString(16).toUpperCase()}`); }}
                            style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.02)', color: '#4b5563', cursor: 'pointer', fontFamily: 'monospace' }}>
                            {s.name} VA=0x{s.vaddr.toString(16).toUpperCase().padStart(8,'0')}
                          </div>
                        ))}
                      </div>
                    </Card>
                  );
                })()}

                {/* A4 — Code caves */}
                <Card>
                  <CardHeader>Code Cave Tespiti — {result.codeCaves?.length || 0} boş bölge (exec section'larda ≥16 byte 0x00)</CardHeader>
                  <div style={{ padding: '8px 0 10px' }}>
                    {(!result.codeCaves || result.codeCaves.length === 0)
                      ? <div style={{ padding: '6px 16px', fontSize: 11, color: '#374151' }}>Anlamlı code cave bulunamadı.</div>
                      : result.codeCaves.map((c, i) => (
                        <div key={i} style={{ display: 'grid', gridTemplateColumns: '80px 130px 1fr', padding: '5px 16px', borderBottom: '1px solid rgba(255,255,255,0.03)', alignItems: 'center' }}>
                          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#6366f1' }}>0x{c.fileOff.toString(16).toUpperCase().padStart(8,'0')}</span>
                          <span style={{ fontSize: 10, fontFamily: 'monospace', color: c.size >= 128 ? '#4ade80' : '#f59e0b' }}>{c.size} bytes</span>
                          <span style={{ fontSize: 10, color: '#374151' }}>{c.section}</span>
                        </div>
                      ))
                    }
                  </div>
                </Card>

                {/* B5 — WRX sections */}
                {result.wrxSections?.length > 0 && (
                  <Card>
                    <CardHeader style={{ color: '#f87171' }}>⚡ Writeable + Executable Sections (B5)</CardHeader>
                    <div style={{ padding: '8px 16px 12px' }}>
                      <div style={{ fontSize: 11, color: '#6b7280', marginBottom: 8 }}>W+X flag kombinasyonu — inject/shellcode barındırma riski</div>
                      {result.wrxSections.map(s => (
                        <span key={s} style={{ display: 'inline-block', marginRight: 8, marginBottom: 4, fontSize: 11, padding: '2px 10px', borderRadius: 5, background: 'rgba(239,68,68,0.12)', color: '#f87171', fontFamily: 'monospace', border: '1px solid rgba(239,68,68,0.2)' }}>{s}</span>
                      ))}
                    </div>
                  </Card>
                )}

                {/* B7 — Packing ratios */}
                <Card>
                  <CardHeader>Packing Ratios — raw/virtual size oranı</CardHeader>
                  <div style={{ padding: '6px 0 10px' }}>
                    {(result.packingRatios || []).map((s, i) => {
                      const r = parseFloat(s.ratio) || 0;
                      const col = r < 0.3 ? '#ef4444' : r < 0.7 ? '#f59e0b' : '#4ade80';
                      return (
                        <div key={i} style={{ display: 'grid', gridTemplateColumns: '90px 90px 90px 1fr', padding: '5px 16px', borderBottom: '1px solid rgba(255,255,255,0.03)', alignItems: 'center', fontSize: 11 }}>
                          <span style={{ fontFamily: 'monospace', color: '#94a3b8' }}>{s.name}</span>
                          <span style={{ fontFamily: 'monospace', color: '#4b5563' }}>{(s.raw/1024).toFixed(1)}K raw</span>
                          <span style={{ fontFamily: 'monospace', color: '#374151' }}>{(s.virt/1024).toFixed(1)}K virt</span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <div style={{ flex: 1, height: 5, borderRadius: 3, background: 'rgba(255,255,255,0.04)', overflow: 'hidden' }}>
                              <div style={{ width: `${Math.min(100, r * 100)}%`, height: '100%', background: col, transition: 'width 0.5s' }} />
                            </div>
                            <span style={{ fontSize: 10, fontFamily: 'monospace', color: col }}>{s.ratio}</span>
                            {r < 0.3 && <span style={{ fontSize: 9, color: '#ef4444' }}>PACKED?</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Card>

                {/* F2 — Multi-Packer Unpack (FAZ 3.2) */}
                {result.packers?.length > 0 || result.sections?.some(s => /^(\.upx|\.aspack|\.mpress|\.petite|\.pec|nsp|\.te!|\.exec|enigma)/i.test(s.name)) ? (
                  <Card>
                    <CardHeader>Packer Detected (FAZ 3.2) — {result.packers?.join(', ') || 'Unknown'} — Unpack</CardHeader>
                    <div style={{ padding: '12px 16px' }}>
                      <div style={{ fontSize: 12, color: '#f59e0b', marginBottom: 10 }}>
                        Packed executable detected. Click to attempt automatic decompression (UPX/ASPack/MPRESS/PECompact/Petite support).
                      </div>
                      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                        <button disabled={upxRunning || !scanFilePath} onClick={async () => {
                          if (!scanFilePath) return;
                          setUpxRunning(true); setUpxResult(null);
                          try { const r = await invoke('try_unpack', { filePath: scanFilePath }); setUpxResult(r); }
                          catch (e) { setUpxResult({ ok: false, msg: String(e) }); }
                          finally { setUpxRunning(false); }
                        }} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.35)', background: upxRunning ? 'transparent' : 'rgba(245,158,11,0.08)', color: '#fbbf24', cursor: scanFilePath ? 'pointer' : 'not-allowed', opacity: scanFilePath ? 1 : 0.5, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}>
                          {upxRunning ? <><Spinner /> Unpacking...</> : '⚡ Auto-Unpack'}
                        </button>
                        {!scanFilePath && <span style={{ fontSize: 10, color: '#4b5563' }}>Requires native file path (drag & drop file)</span>}
                      </div>
                      {upxResult && (
                        <div style={{ marginTop: 10, padding: '8px 12px', borderRadius: 7, background: upxResult.ok ? 'rgba(34,197,94,0.06)' : 'rgba(239,68,68,0.06)', border: `1px solid ${upxResult.ok ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}` }}>
                          <div style={{ fontSize: 11, color: upxResult.ok ? '#4ade80' : '#f87171', marginBottom: 4 }}>{upxResult.ok ? '✅ Unpacked successfully' : '❌ Unpack failed'}</div>
                          {upxResult.method && <div style={{ fontSize: 10, color: '#6366f1', marginBottom: 4 }}>Method: {upxResult.method}</div>}
                          {upxResult.detected_packers?.length > 0 && <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Detected: {upxResult.detected_packers.join(', ')}</div>}
                          {upxResult.suggestion && <div style={{ fontSize: 10, color: '#f59e0b', marginBottom: 4 }}>💡 {upxResult.suggestion}</div>}
                          <pre style={{ fontSize: 10, color: '#6b7280', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{upxResult.msg}</pre>
                        </div>
                      )}
                    </div>
                  </Card>
                ) : null}

                {/* F3 — Enhanced Memory Dump Analysis (FAZ 3.3) */}
                {(() => {
                  const isDump = file?.name?.match(/\.(dmp|dump|mem|bin|raw)$/i) || (result.overallEntropy > 5.0 && !result.isPe);
                  if (!isDump) return null;
                  return (
                    <Card>
                      <CardHeader>Memory Dump / Raw Binary Analysis (FAZ 3.3)</CardHeader>
                      <div style={{ padding: '12px 16px' }}>
                        <div style={{ fontSize: 12, color: '#60a5fa', marginBottom: 10 }}>
                          Detected memory dump or raw binary. Deep analysis: MDMP parsing, embedded PE search, entropy mapping, region enumeration, and PE extraction.
                        </div>
                        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: dumpResult ? 12 : 0 }}>
                          <button disabled={dumpRunning || !scanFilePath} onClick={async () => {
                            if (!scanFilePath) return;
                            setDumpRunning(true); setDumpResult(null);
                            try { const r = await invoke('analyze_dump_enhanced', { filePath: scanFilePath }); setDumpResult(r); }
                            catch (e) { setDumpResult({ error: String(e) }); }
                            finally { setDumpRunning(false); }
                          }} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(96,165,250,0.35)', background: dumpRunning ? 'transparent' : 'rgba(96,165,250,0.08)', color: '#60a5fa', cursor: scanFilePath ? 'pointer' : 'not-allowed', opacity: scanFilePath ? 1 : 0.5, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}>
                            {dumpRunning ? <><Spinner /> Analyzing...</> : '🔬 Enhanced Dump Analysis'}
                          </button>
                          {!scanFilePath && <span style={{ fontSize: 10, color: '#4b5563' }}>Requires native file path (drag & drop)</span>}
                        </div>
                        {dumpResult && !dumpResult.error && (
                          <div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 8, marginBottom: 10 }}>
                              <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.14)' }}>
                                <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>File Size</div>
                                <div style={{ fontSize: 13, fontWeight: 700, color: '#818cf8', fontFamily: 'monospace' }}>{(dumpResult.size / 1024 / 1024).toFixed(2)} MB</div>
                              </div>
                              <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.14)' }}>
                                <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>Entropy</div>
                                <div style={{ fontSize: 13, fontWeight: 700, color: dumpResult.entropy > 7.5 ? '#f87171' : dumpResult.entropy > 6.5 ? '#f59e0b' : '#4ade80', fontFamily: 'monospace' }}>{dumpResult.entropy?.toFixed(3)}</div>
                              </div>
                              <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.14)' }}>
                                <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>Embedded PEs</div>
                                <div style={{ fontSize: 13, fontWeight: 700, color: (dumpResult.pe_count || dumpResult.pe_offsets?.length) > 0 ? '#f59e0b' : '#94a3b8', fontFamily: 'monospace' }}>{dumpResult.pe_count || dumpResult.pe_offsets?.length || 0}</div>
                              </div>
                              <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.14)' }}>
                                <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 2 }}>Format</div>
                                <div style={{ fontSize: 13, fontWeight: 700, color: dumpResult.is_minidump ? '#f59e0b' : '#4ade80' }}>{dumpResult.is_minidump ? 'MDMP' : dumpResult.is_likely_dump ? 'Raw Dump' : 'Binary'}</div>
                              </div>
                            </div>

                            {/* MDMP info */}
                            {dumpResult.is_minidump && dumpResult.dump_info && (
                              <div style={{ marginBottom: 10, padding: '8px 12px', borderRadius: 7, background: 'rgba(245,158,11,0.05)', border: '1px solid rgba(245,158,11,0.15)' }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#fbbf24', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Windows Minidump Header</div>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6, fontSize: 10 }}>
                                  <div><span style={{ color: '#4b5563' }}>Version:</span> <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{dumpResult.dump_info.version}</span></div>
                                  <div><span style={{ color: '#4b5563' }}>Streams:</span> <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{dumpResult.dump_info.num_streams}</span></div>
                                  <div><span style={{ color: '#4b5563' }}>Timestamp:</span> <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{dumpResult.dump_info.timestamp}</span></div>
                                </div>
                                {dumpResult.dump_info.streams?.length > 0 && (
                                  <div style={{ marginTop: 6, maxHeight: 100, overflowY: 'auto' }}>
                                    {dumpResult.dump_info.streams.map((s, i) => (
                                      <div key={i} style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace', padding: '1px 0' }}>
                                        [{s.type}] {s.name} — {s.size} bytes @ 0x{Number(s.offset).toString(16).toUpperCase()}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}

                            {/* Embedded PE images with extraction */}
                            {dumpResult.pe_images?.length > 0 && (
                              <div style={{ marginBottom: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Embedded PE Images ({dumpResult.pe_images.length})</div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                  {dumpResult.pe_images.map((pe, i) => (
                                    <div key={i} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 6, background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)' }}>
                                      <span style={{ fontFamily: 'monospace', color: '#fbbf24' }}>{pe.offset}</span>
                                      <span style={{ color: '#4b5563', marginLeft: 6 }}>{pe.arch} · {pe.sections} sections · {(pe.estimated_size/1024).toFixed(1)}KB</span>
                                      {pe.can_extract && <span style={{ color: '#4ade80', marginLeft: 6 }}>✓ extractable</span>}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Fallback: legacy pe_offsets */}
                            {!dumpResult.pe_images && dumpResult.pe_offsets?.length > 0 && (
                              <div style={{ marginBottom: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>MZ Headers at offsets</div>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                  {dumpResult.pe_offsets.map((off, i) => (
                                    <span key={i} style={{ fontSize: 11, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 5, background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', color: '#fbbf24' }}>
                                      0x{Number(off).toString(16).toUpperCase().padStart(8, '0')}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Memory regions */}
                            {dumpResult.memory_regions?.length > 0 && (
                              <div style={{ marginBottom: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#818cf8', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Memory Regions ({dumpResult.memory_regions.length})</div>
                                <div style={{ maxHeight: 150, overflowY: 'auto', fontSize: 10, fontFamily: 'monospace' }}>
                                  {dumpResult.memory_regions.map((r, i) => (
                                    <div key={i} style={{ display: 'grid', gridTemplateColumns: '90px 90px 80px 70px 1fr', padding: '2px 0', borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                                      <span style={{ color: '#6366f1' }}>{r.start}</span>
                                      <span style={{ color: '#4b5563' }}>{r.end}</span>
                                      <span style={{ color: '#94a3b8' }}>{(r.size/1024).toFixed(1)}K</span>
                                      <span style={{ color: r.entropy > 7 ? '#f87171' : r.entropy > 5 ? '#f59e0b' : '#4ade80' }}>{r.entropy}</span>
                                      <span style={{ color: '#374151' }}>{r.type}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {dumpResult.strings_sample?.length > 0 && (
                              <div>
                                <div style={{ fontSize: 10, fontWeight: 700, color: '#818cf8', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>String Sample ({dumpResult.strings_sample.length} of up to 100)</div>
                                <div style={{ maxHeight: 160, overflowY: 'auto', fontFamily: 'monospace', fontSize: 10, color: '#374151', background: 'rgba(0,0,0,0.25)', borderRadius: 6, padding: '6px 10px', lineHeight: 1.7 }}>
                                  {dumpResult.strings_sample.map((s, i) => <div key={i}>{s}</div>)}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                        {dumpResult?.error && <div style={{ fontSize: 11, color: '#f87171', marginTop: 8 }}>{dumpResult.error}</div>}
                      </div>
                    </Card>
                  );
                })()}

                {/* FAZ 3.1 — YARA Rule Matches (from Rust scanner) */}
                {result.yaraMatches?.length > 0 && (
                  <Card>
                    <CardHeader>YARA-like Rules — {result.yaraMatches.length} match</CardHeader>
                    <div style={{ padding: '8px 0 10px' }}>
                      {result.yaraMatches.map((m, i) => {
                        const cols = { critical: '#ef4444', high: '#f59e0b', medium: '#60a5fa', warn: '#fbbf24', low: '#94a3b8' };
                        const col = cols[m.sev] || '#94a3b8';
                        return (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 16px', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                            <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${col}22`, color: col, fontWeight: 700, textTransform: 'uppercase', minWidth: 52, textAlign: 'center' }}>{m.sev}</span>
                            <span style={{ fontSize: 11, color: '#e5e7eb', fontWeight: 600 }}>{m.name}</span>
                            {m.desc && <span style={{ fontSize: 10, color: '#4b5563', marginLeft: 'auto' }}>{m.desc}</span>}
                          </div>
                        );
                      })}
                    </div>
                  </Card>
                )}

                {/* FAZ 3.4 — Fuzzy Hash (ssdeep-style) */}
                {scanFilePath && window.__TAURI__ && (
                  <Card>
                    <CardHeader>Fuzzy Hash — CTPH (FAZ 3.4)</CardHeader>
                    <div style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
                        <button onClick={async () => {
                          try {
                            const r = await invoke('fuzzy_hash', { filePath: scanFilePath });
                            setResult(prev => ({ ...prev, fuzzyHash: r.fuzzy_hash, fuzzyBlockSize: r.block_size }));
                          } catch (e) { console.error('fuzzy_hash error', e); }
                        }} style={{ fontSize: 11, padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(168,85,247,0.35)', background: 'rgba(168,85,247,0.08)', color: '#a855f7', cursor: 'pointer', fontWeight: 500 }}>
                          🔑 Generate Fuzzy Hash
                        </button>
                        {result.fuzzyHash && (
                          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#94a3b8', wordBreak: 'break-all' }}>{result.fuzzyHash}</span>
                        )}
                      </div>
                      {result.fuzzyHash && (
                        <div style={{ fontSize: 10, color: '#4b5563' }}>Block size: {result.fuzzyBlockSize} — Compare with another file's fuzzy hash for similarity detection</div>
                      )}
                    </div>
                  </Card>
                )}

                {/* FAZ 3.1 — Scanner badge */}
                {result._scanner === 'rust' && (
                  <div style={{ padding: '6px 16px', fontSize: 10, color: '#4b5563', textAlign: 'right' }}>
                    ⚡ Scanned by Rust backend{result._format ? ` · ${result._format}` : ' · PE'}{result.fileSize ? ` · ${(result.fileSize/1024).toFixed(1)} KB` : ''}
                  </div>
                )}

              </div>
            );
          })()}
          {tab === 'disasm' && (() => {
            const loadDisasm = async () => {
              if (!scanFilePath) return;
              setDisasmLoading(true);
              try {
                const r = await invoke('disassemble_ep', { filePath: scanFilePath, count: 80 });
                setDisasmResult(r);
              } catch (e) { setDisasmResult({ error: e }); }
              finally { setDisasmLoading(false); }
            };
            if (!disasmResult && !disasmLoading && scanFilePath) loadDisasm();
            const kindColor = { call: '#60a5fa', jmp: '#f59e0b', ret: '#f87171', '': '#94a3b8' };
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <Card>
                  <CardHeader>Disassembly — Entry Point (A1/A2) · {result?.arch}</CardHeader>
                  {scanFilePath && (
                    <div style={{ padding: '8px 16px 0', display: 'flex', justifyContent: 'flex-end' }}>
                      <button onClick={() => onOpenDisasm && onOpenDisasm(scanFilePath)}
                        style={{ fontSize: 11, padding: '5px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5 }}>
                        <Code size={12} /> Tam Disassembly Görünümü →
                      </button>
                    </div>
                  )}
                  {!scanFilePath && (
                    <div style={{ padding: 16, fontSize: 12, color: '#374151' }}>
                      📌 Disassembly requires the native file path. Drag & drop the file onto Dissect to enable this feature.
                      <div style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Raw EP Bytes (from JS analysis)</div>
                        <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#374151', wordBreak: 'break-all', lineHeight: 2 }}>
                          {(result.epBytes || []).slice(0, 64).join(' ')}
                        </div>
                      </div>
                    </div>
                  )}
                  {scanFilePath && disasmLoading && <div style={{ padding: 24, display: 'flex', justifyContent: 'center' }}><Spinner /></div>}
                  {scanFilePath && !disasmLoading && disasmResult && !disasmResult.error && (
                    <div style={{ fontFamily: 'monospace', overflowX: 'auto' }}>
                      {/* A2 — Mark basic block boundaries */}
                      {disasmResult.map((ins, i) => {
                        const isBlockEnd = ins.kind === 'ret' || ins.kind === 'jmp';
                        return (
                          <div key={i} style={{ display: 'grid', gridTemplateColumns: '110px 160px 80px 1fr', padding: '3px 16px', fontSize: 11, background: isBlockEnd ? 'rgba(99,102,241,0.04)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)', borderBottom: isBlockEnd ? '1px solid rgba(99,102,241,0.1)' : undefined }}>
                            <span style={{ color: '#4b5563', userSelect: 'text' }}>{ins.addr}</span>
                            <span style={{ color: '#1f2937', userSelect: 'text' }}>{ins.bytes}</span>
                            <span style={{ color: kindColor[ins.kind] || '#94a3b8', fontWeight: 600, userSelect: 'text' }}>{ins.mnemonic}</span>
                            <span style={{ color: '#4b5563', userSelect: 'text' }}>{ins.operands}</span>
                          </div>
                        );
                      })}
                      <div style={{ padding: '8px 16px', fontSize: 10, color: '#1f2937' }}>
                        {disasmResult.length} instructions · CALL=<span style={{ color: '#60a5fa' }}>blue</span> · JMP=<span style={{ color: '#f59e0b' }}>amber</span> · RET=<span style={{ color: '#f87171' }}>red</span> · Block boundaries marked
                      </div>
                    </div>
                  )}
                  {scanFilePath && !disasmLoading && disasmResult?.error && (
                    <div style={{ padding: 16, color: '#f87171', fontSize: 12 }}>Hata: {String(disasmResult.error)}</div>
                  )}
                  {scanFilePath && !disasmLoading && !disasmResult && (
                    <button onClick={loadDisasm} style={{ margin: 16, fontSize: 12, padding: '8px 18px', borderRadius: 8, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.07)', color: '#818cf8', cursor: 'pointer' }}>
                      Disassemble EP
                    </button>
                  )}
                </Card>
                {/* B2/B3/B4/B8 advanced PE info */}
                <Card>
                  <CardHeader>Advanced PE Fields (B2/B3/B4/B8)</CardHeader>
                  <div style={{ padding: '10px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {[
                      { label: 'TLS Section (B2)', value: result.hasTls ? '✅ PRESENT (.tls detected)' : '— Not found', color: result.hasTls ? '#fbbf24' : '#374151' },
                      { label: 'Exception Entries (B3)', value: result.exceptionEntries > 0 ? `${result.exceptionEntries} RUNTIME_FUNCTION entries in .pdata` : '— No .pdata section', color: result.exceptionEntries > 0 ? '#60a5fa' : '#374151' },
                      { label: 'Delayed Imports (B4)', value: result.delayedImports?.length > 0 ? result.delayedImports.join(', ') : '— None detected', color: result.delayedImports?.length > 0 ? '#c4b5fd' : '#374151' },
                      { label: 'Debug PDB Path (B8)', value: result.debugPdb || '— Not found (stripped binary)', color: result.debugPdb ? '#4ade80' : '#374151' },
                    ].map(({ label, value, color }) => (
                      <div key={label} style={{ display: 'flex', gap: 12, fontSize: 11, alignItems: 'flex-start' }}>
                        <span style={{ minWidth: 180, color: '#4b5563', fontWeight: 600, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em', paddingTop: 1 }}>{label}</span>
                        <span style={{ fontFamily: 'monospace', color, flex: 1, wordBreak: 'break-all' }}>{value}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            );
          })()}
          {tab === 'compare' && compareResult && !compareResult.error && (() => {
            const mkRow = (label, a, b, dangerFn) => {
              const diff = String(a) !== String(b);
              return (
                <div key={label} style={{ display: 'flex', gap: 0, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ width: 130, padding: '7px 12px', fontSize: 10, color: '#374151', fontWeight: 600, flexShrink: 0 }}>{label}</div>
                  <div style={{ flex: 1, padding: '7px 12px', fontSize: 11, fontFamily: 'monospace', color: diff ? '#fbbf24' : '#94a3b8', background: 'rgba(255,255,255,0.01)' }}>{String(a)}</div>
                  <div style={{ flex: 1, padding: '7px 12px', fontSize: 11, fontFamily: 'monospace', color: diff ? '#fbbf24' : '#94a3b8', background: 'rgba(255,255,255,0.01)', borderLeft: '1px solid rgba(255,255,255,0.04)' }}>{String(b)}</div>
                </div>
              );
            };
            return (
              <>
              <Card>
                <CardHeader>Binary Diff — {file?.name}  — {compareFile?.name}</CardHeader>
                <div style={{ padding: '6px 16px 4px', display: 'flex', fontSize: 10, color: '#374151', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ width: 130 }} />
                  <div style={{ flex: 1, fontWeight: 600, color: '#818cf8', padding: '0 12px' }}>{file?.name?.slice(0, 30)}</div>
                  <div style={{ flex: 1, fontWeight: 600, color: '#60a5fa', padding: '0 12px', borderLeft: '1px solid rgba(255,255,255,0.04)' }}>{compareFile?.name?.slice(0, 30)}</div>
                </div>
                {mkRow('Architecture', result.arch, compareResult.arch)}
                {mkRow('Risk Score',   result.riskScore, compareResult.riskScore)}
                {mkRow('Entropy',      result.overallEntropy?.toFixed(3), compareResult.overallEntropy?.toFixed(3))}
                {mkRow('Sections',     result.numSec, compareResult.numSec)}
                {mkRow('Imports (DLL)',result.imports?.length || 0, compareResult.imports?.length || 0)}
                {mkRow('Denuvo',       result.denuvo ? 'YES' : 'NO', compareResult.denuvo ? 'YES' : 'NO')}
                {mkRow('VMProtect',    result.vmp ? 'YES' : 'NO', compareResult.vmp ? 'YES' : 'NO')}
                {mkRow('Anti-Debug',   result.antiDebug ? 'YES' : 'NO', compareResult.antiDebug ? 'YES' : 'NO')}
                {mkRow('Anti-VM',      result.antiVM ? 'YES' : 'NO', compareResult.antiVM ? 'YES' : 'NO')}
                {mkRow('Packers',      result.packers?.join(', ') || '—', compareResult.packers?.join(', ') || '—')}
                {mkRow('Flagged Str.', result.strings?.filter(s=>s.cat).length || 0, compareResult.strings?.filter(s=>s.cat).length || 0)}

                {/* Section diff */}
                <div style={{ padding: '10px 16px 4px', fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Sections</div>
                <div style={{ maxHeight: 300, overflowY: 'auto' }}>
                  {result.sections.map((s, i) => {
                    const s2 = compareResult.sections[i];
                    const entropyDiff = s2 ? Math.abs(s.entropy - s2.entropy) > 0.15 : false;
                    return (
                      <div key={i} style={{ display: 'flex', gap: 0, borderBottom: '1px solid rgba(255,255,255,0.04)', alignItems: 'center' }}>
                        <div style={{ width: 130, padding: '6px 12px', fontSize: 10, color: '#4b5563', fontFamily: 'monospace', flexShrink: 0 }}>{s.name}</div>
                        <div style={{ flex: 1, padding: '6px 12px', fontSize: 10, fontFamily: 'monospace', color: '#94a3b8' }}>H={s.entropy.toFixed(3)}</div>
                        <div style={{ flex: 1, padding: '6px 12px', fontSize: 10, fontFamily: 'monospace', color: entropyDiff ? '#fbbf24' : '#94a3b8', borderLeft: '1px solid rgba(255,255,255,0.04)' }}>H={s2 ? s2.entropy.toFixed(3) : '—'} {entropyDiff && '?'}</div>
                      </div>
                    );
                  })}
                </div>
              </Card>

              {/* B6 — Byte-level Hex Diff (Enhanced — FAZ 4.2) */}
              {scanRawBytes && compareRawBytes && (() => {
                const LEN = Math.min(scanRawBytes.length, compareRawBytes.length, 2048);
                let diffCount = 0;
                const diffRegions = []; // contiguous diff ranges
                let inDiff = false, regionStart = 0;
                for (let i = 0; i < LEN; i++) {
                  const d = scanRawBytes[i] !== compareRawBytes[i];
                  if (d) diffCount++;
                  if (d && !inDiff) { inDiff = true; regionStart = i; }
                  if (!d && inDiff) { inDiff = false; diffRegions.push({ start: regionStart, end: i }); }
                }
                if (inDiff) diffRegions.push({ start: regionStart, end: LEN });

                // Import diff (LCS-based)
                const dlls1 = (result.imports || []).map(i => i.dll).sort();
                const dlls2 = (compareResult.imports || []).map(i => i.dll).sort();
                const addedDlls = dlls2.filter(d => !dlls1.includes(d));
                const removedDlls = dlls1.filter(d => !dlls2.includes(d));
                const commonDlls = dlls1.filter(d => dlls2.includes(d));

                // String diff
                const str1 = new Set((result.strings || []).map(s => s.text || s));
                const str2 = new Set((compareResult.strings || []).map(s => s.text || s));
                const addedStrs = [...str2].filter(s => !str1.has(s)).slice(0, 20);
                const removedStrs = [...str1].filter(s => !str2.has(s)).slice(0, 20);

                const COLS = 16;
                const rows = Math.ceil(LEN / COLS);
                return (
                  <Card style={{ marginTop: 12 }}>
                    <CardHeader>Binary Diff (FAZ 4.2 Enhanced) — {LEN} bytes · {diffCount} differences ({((diffCount/LEN)*100).toFixed(1)}% changed) · {diffRegions.length} regions</CardHeader>

                    {/* Diff summary strip */}
                    <div style={{ padding: '8px 16px', display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <span style={{ color: '#f87171' }}>Changed: {diffCount} bytes</span>
                      <span style={{ color: '#94a3b8' }}>Unchanged: {LEN - diffCount} bytes</span>
                      <span style={{ color: '#fbbf24' }}>Regions: {diffRegions.length}</span>
                      {scanRawBytes.length !== compareRawBytes.length && <span style={{ color: '#60a5fa' }}>Size diff: {Math.abs(scanRawBytes.length - compareRawBytes.length)} bytes</span>}
                    </div>

                    {/* Diff heatmap mini strip */}
                    <div style={{ padding: '4px 16px 8px', display: 'flex', height: 10, gap: 0 }}>
                      {Array.from({ length: Math.min(200, LEN) }, (_, i) => {
                        const idx = Math.floor(i * LEN / Math.min(200, LEN));
                        const d = scanRawBytes[idx] !== compareRawBytes[idx];
                        return <div key={i} style={{ flex: 1, background: d ? '#f87171' : 'rgba(255,255,255,0.03)', minWidth: 1 }} />;
                      })}
                    </div>

                    {/* Import diff */}
                    {(addedDlls.length > 0 || removedDlls.length > 0) && (
                      <div style={{ padding: '8px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', marginBottom: 4 }}>Import Diff (DLLs)</div>
                        <div style={{ display: 'flex', gap: 16, fontSize: 10, fontFamily: 'monospace' }}>
                          {removedDlls.length > 0 && <div>{removedDlls.map(d => <div key={d} style={{ color: '#f87171' }}>- {d}</div>)}</div>}
                          {addedDlls.length > 0 && <div>{addedDlls.map(d => <div key={d} style={{ color: '#4ade80' }}>+ {d}</div>)}</div>}
                          <div style={{ color: '#374151' }}>Common: {commonDlls.length}</div>
                        </div>
                      </div>
                    )}

                    {/* String diff */}
                    {(addedStrs.length > 0 || removedStrs.length > 0) && (
                      <div style={{ padding: '8px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: '#374151', textTransform: 'uppercase', marginBottom: 4 }}>String Diff (first 20)</div>
                        <div style={{ display: 'flex', gap: 16, fontSize: 10, fontFamily: 'monospace', maxHeight: 120, overflowY: 'auto' }}>
                          {removedStrs.length > 0 && <div>{removedStrs.map((s,i) => <div key={i} style={{ color: '#f87171', wordBreak: 'break-all' }}>- {s}</div>)}</div>}
                          {addedStrs.length > 0 && <div>{addedStrs.map((s,i) => <div key={i} style={{ color: '#4ade80', wordBreak: 'break-all' }}>+ {s}</div>)}</div>}
                        </div>
                      </div>
                    )}

                    {/* Hex grid */}
                    <div style={{ overflowX: 'auto', padding: '8px 0', maxHeight: 500, overflowY: 'auto' }}>
                      <div style={{ fontFamily: 'monospace', fontSize: 10, minWidth: 700 }}>
                        {Array.from({ length: rows }, (_, row) => {
                          const start = row * COLS;
                          return (
                            <div key={row} style={{ display: 'flex', gap: 0, alignItems: 'center', padding: '1px 16px', background: row % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                              <span style={{ color: '#1f2937', minWidth: 50 }}>{(start).toString(16).toUpperCase().padStart(6,'0')}</span>
                              <div style={{ display: 'flex', gap: 2, flex: 1 }}>
                                {Array.from({ length: COLS }, (_, col) => {
                                  const idx = start + col;
                                  if (idx >= LEN) return <span key={col} style={{ minWidth: 20 }} />;
                                  const a = scanRawBytes[idx], b = compareRawBytes[idx];
                                  const diff = a !== b;
                                  return (
                                    <span key={col} style={{ minWidth: 20, color: diff ? '#f87171' : '#374151', background: diff ? 'rgba(239,68,68,0.1)' : undefined, borderRadius: 2, textAlign: 'center' }}
                                      title={diff ? `File1: ${a.toString(16).padStart(2,'0')} / File2: ${b.toString(16).padStart(2,'0')}` : undefined}>
                                      {a.toString(16).padStart(2,'0')}
                                    </span>
                                  );
                                })}
                              </div>
                              <div style={{ display: 'flex', gap: 2, flex: 1, borderLeft: '1px solid rgba(255,255,255,0.04)', paddingLeft: 8 }}>
                                {Array.from({ length: COLS }, (_, col) => {
                                  const idx = start + col;
                                  if (idx >= LEN) return <span key={col} style={{ minWidth: 20 }} />;
                                  const a = scanRawBytes[idx], b = compareRawBytes[idx];
                                  const diff = a !== b;
                                  return (
                                    <span key={col} style={{ minWidth: 20, color: diff ? '#f87171' : '#374151', background: diff ? 'rgba(239,68,68,0.1)' : undefined, borderRadius: 2, textAlign: 'center' }}>
                                      {b.toString(16).padStart(2,'0')}
                                    </span>
                                  );
                                })}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </Card>
                );
              })()}
              </>
            );
          })()}

          {/* C2 — İki dosyayı AI'da karşılaştır */}
          {tab === 'compare' && compareResult && !compareResult.error && (
            <div style={{ marginTop: 8, display: 'flex', justifyContent: 'flex-end' }}>
              <button onClick={() => onSendToAI({
                  comparison: true,
                  fileA: { name: file?.name, sha256: result.sha256, arch: result.arch, riskScore: result.riskScore, sections: result.sections, imports: result.imports, denuvo: result.denuvo, vmp: result.vmp, antiDebug: result.antiDebug, packers: result.packers, overallEntropy: result.overallEntropy },
                  fileB: { name: compareFile?.name, sha256: compareResult.sha256, arch: compareResult.arch, riskScore: compareResult.riskScore, sections: compareResult.sections, imports: compareResult.imports, denuvo: compareResult.denuvo, vmp: compareResult.vmp, antiDebug: compareResult.antiDebug, packers: compareResult.packers, overallEntropy: compareResult.overallEntropy },
                }, `${file?.name}  — ${compareFile?.name}`)}
                style={{ fontSize: 11, padding: '6px 16px', borderRadius: 7, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.07)', color: '#a78bfa', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Bot size={13} /> İki Dosyayı AI'da Karşılaştır (C2)
              </button>
            </div>
          )}

          {/* 23 — second file drop zone (shown after first scan, before compare tab exists) */}
          {tab !== 'compare' && result && (
            <div style={{ marginTop: 4 }}>
              <div onClick={() => !compareFile && compareRef.current.click()}
                onDrop={e => { e.preventDefault(); setCompareDragOver(false); processCompareFile(e.dataTransfer.files[0]); }}
                onDragOver={e => { e.preventDefault(); setCompareDragOver(true); }}
                onDragLeave={() => setCompareDragOver(false)}
                style={{ borderRadius: 10, padding: '10px 14px', border: `1px dashed ${compareDragOver ? 'rgba(96,165,250,0.5)' : 'rgba(255,255,255,0.06)'}`, background: compareDragOver ? 'rgba(96,165,250,0.04)' : 'transparent', cursor: compareFile ? 'default' : 'pointer', display: 'flex', alignItems: 'center', gap: 10, transition: 'all 0.15s' }}>
                <FileSearch size={14} color="#374151" style={{ flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: '#374151' }}>
                  {comparingFile ? 'Taranıyor…' : compareFile ? ` ile Karşılaştırma` : 'Karşılaştırmak için ikinci dosya bırak → "Diff ↓" sekmesi açılır'}
                </span>
                {compareFile && !comparingFile && (
                  <button onClick={e => { e.stopPropagation(); setCompareFile(null); setCompareResult(null); }} style={{ marginLeft: 'auto', fontSize: 10, color: '#f87171', background: 'transparent', border: 'none', cursor: 'pointer' }}>✕</button>
                )}
                <input ref={compareRef} type="file" accept=".exe,.dll,.sys,*" onChange={e => processCompareFile(e.target.files[0])} style={{ display: 'none' }} />
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}

function PatchCard({ patch, onToggle, onDelete }) {
  const [h, setH] = useState(false);
  return (
    <div onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)}
      style={{ borderRadius: 10, padding: '12px 15px', transition: 'all 0.13s', background: patch.applied ? 'rgba(34,197,94,0.04)' : patch.enabled ? 'rgba(245,158,11,0.03)' : 'rgba(255,255,255,0.015)', border: `1px solid ${patch.applied ? 'rgba(34,197,94,0.22)' : patch.enabled ? 'rgba(245,158,11,0.18)' : 'rgba(255,255,255,0.05)'}` }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <button onClick={onToggle} style={{ width: 18, height: 18, borderRadius: 4, border: `2px solid ${patch.enabled ? '#f59e0b' : '#2d3748'}`, background: patch.enabled ? '#f59e0b' : 'transparent', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          {patch.enabled && <span style={{ color: '#000', fontSize: 9, fontWeight: 900 }}>✓</span>}
        </button>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: patch.applied ? '#4ade80' : '#e2e8f0' }}>{patch.name}</span>
            {patch.applied && <span style={{ fontSize: 9, color: '#4ade80', background: 'rgba(34,197,94,0.11)', padding: '1px 6px', borderRadius: 4, fontWeight: 700 }}>APPLIED</span>}
          </div>
          <div style={{ display: 'flex', gap: 14, marginTop: 5 }}>
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#4b5563' }}>@ {patch.offset}</span>
            {patch.original && <span style={{ fontSize: 10, fontFamily: 'monospace' }}><span style={{ color: '#374151' }}>orig </span><span style={{ color: '#ef4444' }}>{patch.original}</span></span>}
            {patch.patched  && <span style={{ fontSize: 10, fontFamily: 'monospace' }}><span style={{ color: '#374151' }}>? </span><span style={{ color: '#4ade80' }}>{patch.patched}</span></span>}
          </div>
        </div>
        {h && <button onClick={onDelete} style={{ width: 28, height: 28, borderRadius: 6, border: 'none', background: 'rgba(239,68,68,0.09)', color: '#f87171', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Trash2 size={13} /></button>}
      </div>
    </div>
  );
}

export default ScannerPage;