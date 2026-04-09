import React, { useState, useRef, useEffect, useCallback } from 'react';
import { List as VirtualList } from 'react-window';
import { invoke } from '@tauri-apps/api/core';
import {
  Code, ArrowUp, ArrowDown, List, GitBranch, Search,
  Bot, X, CheckCircle2, Activity, Shield, Bug, Diff, Layers, Zap
} from 'lucide-react';
import { CFGPanel } from './CfgComponents';

function DisasmRow({ index, style, instructions, kindColor, jumpToTarget, handleInsRightClick, openXref, flirtMatches }) {
  const i = index;
  const ins = instructions[i];
  const isBlockEnd = ins.kind === 'ret' || ins.kind === 'jmp';
  const isCall = ins.kind === 'call';
  const hasTarget = !!ins.target;
  const flirt = flirtMatches && flirtMatches[ins.addr];
  return (
    <div style={{
      ...style,
      display: 'grid', gridTemplateColumns: '100px 60px 150px 75px 1fr', padding: '2px 12px', fontSize: 11, lineHeight: '20px',
      background: isBlockEnd ? 'rgba(248,113,113,0.03)' : isCall ? 'rgba(96,165,250,0.03)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.008)',
      borderBottom: isBlockEnd ? '2px solid rgba(248,113,113,0.15)' : undefined,
      cursor: hasTarget ? 'pointer' : 'default',
    }} onClick={() => hasTarget && jumpToTarget(ins.target_val)}
       onContextMenu={(e) => handleInsRightClick(e, ins)}
       onDoubleClick={() => openXref(ins.addr_val)}
       title={hasTarget ? `Jump to ${ins.target} | Sağ tık: Patch | Çift tık: XRef` : 'Sağ tık: Patch | Çift tık: XRef'}>
      <span style={{ color: '#4b5563', userSelect: 'text' }}>{ins.addr}</span>
      <span style={{ color: '#1f2937', fontSize: 9, userSelect: 'text' }}>+{(ins.offset || 0).toString(16).toUpperCase()}</span>
      <span style={{ color: '#374151', userSelect: 'text', fontSize: 10 }}>{ins.bytes}</span>
      <span style={{ color: kindColor[ins.kind] || '#e2e8f0', fontWeight: 700, userSelect: 'text' }}>{ins.mnemonic}</span>
      <span style={{ color: hasTarget ? '#818cf8' : '#94a3b8', userSelect: 'text', textDecoration: hasTarget ? 'underline' : 'none' }}>
        {ins.operands}
        {hasTarget && <span style={{ fontSize: 9, color: '#4b5563', marginLeft: 8 }}>→ {ins.target}</span>}
        {flirt && (
          <span style={{ marginLeft: 10, fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'rgba(96,165,250,0.12)', color: '#60a5fa', fontWeight: 600, border: '1px solid rgba(96,165,250,0.2)' }}
            title={`FLIRT: ${flirt.lib} — ${flirt.category}`}>
            ⚑ FLIRT:{flirt.name}
          </span>
        )}
      </span>
    </div>
  );
}

function colorizePC(code) {
  if (!code) return '';
  return code
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\b(void|int|int32_t|int16_t|uint8_t|uintptr_t|return|if|else|goto|while|for)\b/g,
      '<span style="color:#22d3ee;font-weight:600">$1</span>')
    .replace(/\b(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|eax|ebx|ecx|edx|r8|r9|r10|r11|r12|r13|r14|r15)\b/g,
      '<span style="color:#a78bfa">$1</span>')
    .replace(/(\/\/[^\n]*)/g, '<span style="color:#4b5563;font-style:italic">$1</span>')
    .replace(/\b(sub_[0-9a-fA-F]+|local_[0-9a-fA-F]+)\b/g,
      '<span style="color:#fde68a">$1</span>')
    .replace(/\b(0x[0-9a-fA-F]+)\b/g, '<span style="color:#86efac">$1</span>');
}

function DisassemblyPage({ filePath, onSendToChat }) {
  const [instructions, setInstructions] = useState([]);
  const [functions, setFunctions]       = useState([]);
  const [funcsLoading, setFuncsLoading] = useState(false);
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState(null);
  const [is64, setIs64]                 = useState(true);
  const [currentAddr, setCurrentAddr]   = useState(0);
  const [gotoInput, setGotoInput]       = useState('');
  const [funcFilter, setFuncFilter]     = useState('');
  const [funcPanelOpen, setFuncPanelOpen] = useState(true);
  const [selectedFunc, setSelectedFunc] = useState(null);
  const [chunkSize]                     = useState(200);
  const [localFilePath, setLocalFilePath] = useState(filePath || null);
  const [cfgOpen, setCfgOpen]           = useState(false);
  const [cfgFuncAddr, setCfgFuncAddr]   = useState(null);
  const [cfgFuncName, setCfgFuncName]   = useState('');
  const [xrefOpen, setXrefOpen]         = useState(false);
  const [xrefAddr, setXrefAddr]         = useState(null);
  const [xrefData, setXrefData]         = useState(null);
  const [xrefLoading, setXrefLoading]   = useState(false);
  const [ctxMenu, setCtxMenu]           = useState(null); // {x,y,ins} for right-click
  const [patchLog, setPatchLog]         = useState([]);
  const [flirtMatches, setFlirtMatches] = useState({}); // addr_hex → {name, lib, category}
  const listRef = useRef(null);
  const dragRef = useRef(null);

  // ── FAZ 11 states ──
  const [analysisOpen, setAnalysisOpen]     = useState(false);
  const [analysisTab, setAnalysisTab]       = useState('symbolic'); // symbolic|taint|obfuscation|shellcode|diff|types
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisHex, setAnalysisHex]       = useState('');
  const [analysisHexB, setAnalysisHexB]     = useState('');
  const [taintSources, setTaintSources]     = useState('eax,ecx');

  const kindColor = {
    call: '#60a5fa', jmp: '#f59e0b', jcc: '#fbbf24', ret: '#f87171',
    nop: '#374151', data: '#94a3b8', cmp: '#c084fc', '': '#e2e8f0',
  };

  const loadChunk = useCallback(async (addr, isVirtual = true, count) => {
    if (!localFilePath) return;
    setLoading(true);
    setError(null);
    try {
      const r = await invoke('disassemble_at', {
        filePath: localFilePath,
        offset: addr,
        count: count || chunkSize,
        isVirtual,
      });
      setInstructions(r.instructions);
      setIs64(r.is_64);
      setCurrentAddr(r.start_addr);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [localFilePath, chunkSize]);

  const loadFunctions = useCallback(async () => {
    if (!localFilePath) return;
    setFuncsLoading(true);
    try {
      const r = await invoke('list_functions', { filePath: localFilePath });
      setFunctions(r);
      const ep = r.find(f => f.is_entry);
      if (ep) {
        loadChunk(ep.addr_val, true);
        setSelectedFunc(ep.addr_val);
      }
    } catch (e) {
      console.error('list_functions error:', e);
    } finally {
      setFuncsLoading(false);
    }
  }, [localFilePath, loadChunk]);

  useEffect(() => { if (filePath) setLocalFilePath(filePath); }, [filePath]);
  useEffect(() => { if (localFilePath) loadFunctions(); }, [localFilePath]);

  const handleDrop = async (e) => {
    e.preventDefault();
    const files = e.dataTransfer?.files;
    if (files?.length > 0 && files[0].path) setLocalFilePath(files[0].path);
  };

  const gotoAddress = () => {
    const input = gotoInput.trim();
    if (!input) return;
    const val = parseInt(input, 16) || parseInt(input, 10);
    if (!isNaN(val) && val >= 0) {
      loadChunk(val, input.toLowerCase().startsWith('0x') || val > 0x10000);
      setGotoInput('');
    }
  };

  const loadMore = () => {
    if (!instructions.length) return;
    const last = instructions[instructions.length - 1];
    loadChunk(last.addr_val + last.size, true);
  };

  const loadPrev = () => {
    if (!instructions.length || currentAddr === 0) return;
    loadChunk(Math.max(0, currentAddr - chunkSize * 4), true);
  };

  const jumpToTarget = (addr) => { loadChunk(addr, true); setSelectedFunc(null); };
  const goToFunc = (func) => {
    setSelectedFunc(func.addr_val);
    loadChunk(func.addr_val, true);
    setCfgFuncAddr(func.addr_val);
    setCfgFuncName(func.name);
  };

  const openCfgForFunc = (func) => {
    setCfgFuncAddr(func.addr_val);
    setCfgFuncName(func.name);
    setCfgOpen(true);
  };

  const onCfgBlockClick = (addr) => {
    loadChunk(addr, true);
  };

  // XRef functions
  const openXref = async (addr) => {
    if (!localFilePath || !addr) return;
    setXrefAddr(addr);
    setXrefOpen(true);
    setXrefLoading(true);
    try {
      const r = await invoke('get_xrefs', { filePath: localFilePath, targetAddr: addr });
      setXrefData(r);
    } catch (e) {
      setXrefData(null);
      console.error('XRef error:', e);
    } finally {
      setXrefLoading(false);
    }
  };

  // 2.6 — Decompile: send function assembly to AI chat
  const decompileFunc = (func) => {
    if (!instructions.length) return;
    // Get assembly text for the currently visible instructions (or a selected function's range)
    const asmLines = instructions.map(ins =>
      `${ins.addr}  ${ins.bytes?.padEnd(24) || ''}  ${ins.mnemonic} ${ins.operands}`
    ).join('\n');
    onSendToChat({
      type: 'disasm_func',
      fileName: localFilePath?.split(/[/\\]/).pop() || '?',
      funcName: func?.name || cfgFuncName || `func_${currentAddr.toString(16)}`,
      funcAddr: func?.addr || `0x${currentAddr.toString(16).toUpperCase()}`,
      arch: is64 ? 'x86-64' : 'x86',
      assembly: asmLines,
    });
  };

  // Patch functions
  const doPatch = async (addr, patchType) => {
    if (!localFilePath) return;
    setCtxMenu(null);
    try {
      const r = await invoke('patch_instruction', { filePath: localFilePath, addr, patchType });
      setPatchLog(prev => [r, ...prev].slice(0, 50));
      // Reload current view to show updated bytes
      if (currentAddr > 0) loadChunk(currentAddr, true);
    } catch (e) {
      alert('Patch hatası: ' + e);
    }
  };

  // Right-click handler
  const handleInsRightClick = (e, ins) => {
    e.preventDefault();
    setCtxMenu({ x: e.clientX, y: e.clientY, ins });
  };

  const filteredFuncs = funcFilter
    ? functions.filter(f => f.name.toLowerCase().includes(funcFilter.toLowerCase()) || f.addr.toLowerCase().includes(funcFilter.toLowerCase()))
    : functions;

  // ── FAZ 11 analysis handlers ──
  const getHexForAnalysis = useCallback(() => {
    if (analysisHex) return analysisHex;
    // Extract hex bytes from current instructions
    return instructions.map(i => i.bytes || '').join('');
  }, [analysisHex, instructions]);

  const runAnalysis = useCallback(async () => {
    setAnalysisLoading(true);
    setAnalysisResult(null);
    try {
      const hexBytes = getHexForAnalysis();
      const arch = is64 ? 'x64' : 'x86';
      const addr = currentAddr || 0;
      let result;
      switch (analysisTab) {
        case 'symbolic':
          result = await invoke('symbolic_execute', { hexBytes, arch, startAddr: addr, maxSteps: 500 });
          break;
        case 'taint':
          result = await invoke('taint_analysis', { hexBytes, arch, startAddr: addr, taintSources: taintSources.split(',').map(s => s.trim()).filter(Boolean) });
          break;
        case 'obfuscation':
          result = await invoke('detect_obfuscation', { hexBytes, arch, startAddr: addr });
          break;
        case 'shellcode':
          result = await invoke('analyze_shellcode', { hexBytes, arch });
          break;
        case 'diff':
          result = await invoke('binary_diff', { hexA: hexBytes, hexB: analysisHexB, arch });
          break;
        case 'types':
          result = await invoke('recover_types', { hexBytes, arch, startAddr: addr });
          break;
        case 'pseudo':
          result = await invoke('pseudo_decompile', { hexBytes, arch, funcName: selectedFunc?.name || null });
          break;
      }
      setAnalysisResult(result);
    } catch (e) {
      setAnalysisResult({ error: String(e) });
    } finally {
      setAnalysisLoading(false);
    }
  }, [analysisTab, getHexForAnalysis, is64, currentAddr, taintSources, analysisHexB]);

  const ANALYSIS_TABS = [
    { key: 'symbolic', label: 'Symbolic', icon: Zap, color: '#f59e0b' },
    { key: 'taint', label: 'Taint', icon: Activity, color: '#ef4444' },
    { key: 'obfuscation', label: 'Obfuscation', icon: Shield, color: '#8b5cf6' },
    { key: 'shellcode', label: 'Shellcode', icon: Bug, color: '#22c55e' },
    { key: 'diff', label: 'Diff', icon: Diff, color: '#3b82f6' },
    { key: 'types', label: 'Types', icon: Layers, color: '#ec4899' },
    { key: 'pseudo', label: 'Pseudo-C', icon: Code, color: '#22d3ee' },
  ];

  if (!localFilePath) {
    return (
      <div onDragOver={e => e.preventDefault()} onDrop={handleDrop}
        style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 40, gap: 16 }}>
        <Code size={48} color="#374151" />
        <div style={{ fontSize: 16, fontWeight: 600, color: '#e2e8f0' }}>Disassembly Görünümü</div>
        <div style={{ fontSize: 12, color: '#64748b', textAlign: 'center', maxWidth: 400 }}>
          PE dosyasını sürükleyip bırakın veya Scanner'dan "Tam Disassembly Görünümü" butonuna tıklayın.
        </div>
        <div style={{ fontSize: 11, color: '#374151', marginTop: 12, padding: '8px 16px', borderRadius: 8, border: '1px dashed rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.03)' }}>
          x86/x64 · Fonksiyon Listesi · Adres Navigasyonu · Branch Takibi
        </div>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }} onDragOver={e => e.preventDefault()} onDrop={handleDrop}>
      {/* Top bar */}
      <div style={{ padding: '8px 16px', background: 'rgba(0,0,0,0.2)', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <Code size={14} color="#818cf8" />
        <span style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>Disassembly</span>
        <span style={{ fontSize: 10, color: '#64748b' }}>{is64 ? 'x86-64' : 'x86'}</span>
        <span style={{ fontSize: 10, color: '#374151' }}>·</span>
        <span style={{ fontSize: 10, color: '#64748b', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{localFilePath.split(/[/\\]/).pop()}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          <input value={gotoInput} onChange={e => setGotoInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && gotoAddress()} placeholder="0x00401000 veya offset"
            style={{ width: 180, padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(0,0,0,0.3)', fontSize: 11, color: '#e2e8f0', fontFamily: 'monospace', outline: 'none' }} />
          <button onClick={gotoAddress} style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', fontSize: 11, cursor: 'pointer' }}>Git</button>
          <button onClick={() => setFuncPanelOpen(v => !v)}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: funcPanelOpen ? 'rgba(99,102,241,0.12)' : 'transparent', color: funcPanelOpen ? '#818cf8' : '#64748b', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
            <List size={12} /> Fonksiyonlar {functions.length > 0 && `(${functions.length})`}
          </button>
          <button onClick={() => { if (cfgFuncAddr) setCfgOpen(v => !v); }}
            disabled={!cfgFuncAddr}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: cfgOpen ? 'rgba(34,197,94,0.12)' : 'transparent', color: cfgOpen ? '#22c55e' : cfgFuncAddr ? '#64748b' : '#1f2937', fontSize: 11, cursor: cfgFuncAddr ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 4 }}>
            <GitBranch size={12} /> CFG
          </button>
          {/* 2.6 — Decompile button */}
          <button onClick={() => decompileFunc(functions.find(f => f.addr_val === selectedFunc))}
            disabled={!instructions.length}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(139,92,246,0.2)', background: 'rgba(139,92,246,0.06)', color: instructions.length ? '#a78bfa' : '#1f2937', fontSize: 11, cursor: instructions.length ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Bot size={12} /> Decompile
          </button>
          <button onClick={() => setAnalysisOpen(v => !v)}
            style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: analysisOpen ? 'rgba(245,158,11,0.12)' : 'transparent', color: analysisOpen ? '#f59e0b' : '#64748b', fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Activity size={12} /> Analysis
          </button>
          <button onClick={async () => {
            if (!localFilePath) return;
            try {
              const result = await invoke('scan_flirt_signatures', { filePath: localFilePath });
              const map = {};
              for (const m of (result?.matches || [])) {
                if (m.addr) map[m.addr] = m;
              }
              setFlirtMatches(map);
              alert(`FLIRT: ${Object.keys(map).length} fonksiyon tanındı`);
            } catch (e) { alert('FLIRT hata: ' + e); }
          }} disabled={!localFilePath} style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(96,165,250,0.2)', background: 'rgba(96,165,250,0.06)', color: localFilePath ? '#60a5fa' : '#1f2937', fontSize: 11, cursor: localFilePath ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 4 }}>
            ⚑ FLIRT
          </button>
        </div>
      </div>

      {/* Main content */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Function panel */}
        {funcPanelOpen && (
          <div style={{ width: 260, flexShrink: 0, borderRight: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.15)' }}>
            <div style={{ padding: '8px 10px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <input value={funcFilter} onChange={e => setFuncFilter(e.target.value)} placeholder="Fonksiyon ara..."
                style={{ width: '100%', padding: '5px 8px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.3)', fontSize: 11, color: '#e2e8f0', outline: 'none' }} />
            </div>
            <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden' }}>
              {funcsLoading && <div style={{ padding: 20, textAlign: 'center', fontSize: 11, color: '#64748b' }}>Fonksiyonlar taranıyor...</div>}
              {!funcsLoading && filteredFuncs.map((f, i) => (
                <button key={i} onClick={() => goToFunc(f)}
                  style={{ width: '100%', border: 'none', cursor: 'pointer', padding: '6px 10px', textAlign: 'left',
                    background: selectedFunc === f.addr_val ? 'rgba(99,102,241,0.12)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                    borderLeft: `2px solid ${f.is_entry ? '#f59e0b' : selectedFunc === f.addr_val ? '#6366f1' : 'transparent'}`,
                    display: 'flex', flexDirection: 'column', gap: 1, transition: 'background 0.1s' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: f.is_entry ? '#f59e0b' : '#e2e8f0', fontFamily: 'monospace', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', flex: 1 }}>{f.name}</span>
                    {f.call_count > 0 && <span style={{ fontSize: 9, color: '#60a5fa', background: 'rgba(96,165,250,0.1)', padding: '1px 5px', borderRadius: 4, flexShrink: 0 }}>{f.call_count}x</span>}
                    <span onClick={(e) => { e.stopPropagation(); openCfgForFunc(f); }}
                      style={{ fontSize: 9, color: '#22c55e', background: 'rgba(34,197,94,0.08)', padding: '1px 4px', borderRadius: 3, flexShrink: 0, cursor: 'pointer' }}
                      title="CFG görüntüle">
                      <GitBranch size={9} />
                    </span>
                    <span onClick={(e) => { e.stopPropagation(); openXref(f.addr_val); }}
                      style={{ fontSize: 9, color: '#818cf8', background: 'rgba(99,102,241,0.08)', padding: '1px 4px', borderRadius: 3, flexShrink: 0, cursor: 'pointer' }}
                      title="XRef göster">
                      <Search size={9} />
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: 8, fontSize: 9, color: '#4b5563' }}>
                    <span>{f.addr}</span>
                    <span>{f.size > 1024 ? `${(f.size / 1024).toFixed(1)}KB` : `${f.size}B`}</span>
                  </div>
                </button>
              ))}
              {!funcsLoading && filteredFuncs.length === 0 && (
                <div style={{ padding: 16, fontSize: 11, color: '#374151', textAlign: 'center' }}>{functions.length === 0 ? 'Henüz taranmadı' : 'Sonuç yok'}</div>
              )}
            </div>
          </div>
        )}

        {/* Disassembly listing + CFG */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Disassembly section */}
          <div style={{ flex: cfgOpen ? '0 0 45%' : 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderBottom: cfgOpen ? '2px solid rgba(99,102,241,0.2)' : undefined }}>
          <div style={{ display: 'flex', gap: 6, padding: '4px 12px', borderBottom: '1px solid rgba(255,255,255,0.04)', background: 'rgba(0,0,0,0.1)', alignItems: 'center' }}>
            <button onClick={loadPrev} disabled={loading || !instructions.length}
              style={{ padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#64748b', fontSize: 10, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }}>
              <ArrowUp size={10} /> Yukarı
            </button>
            <button onClick={loadMore} disabled={loading || !instructions.length}
              style={{ padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#64748b', fontSize: 10, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }}>
              <ArrowDown size={10} /> Aşağı
            </button>
            {currentAddr > 0 && <span style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace' }}>0x{currentAddr.toString(16).toUpperCase().padStart(8, '0')} — {instructions.length} talimat</span>}
            {loading && <span style={{ fontSize: 10, color: '#818cf8', marginLeft: 'auto' }}>Yükleniyor...</span>}
          </div>

          <div ref={listRef} style={{ flex: 1, overflow: 'hidden', fontFamily: '"JetBrains Mono", monospace', display: 'flex', flexDirection: 'column' }}>
            {error && <div style={{ padding: 16, color: '#f87171', fontSize: 12 }}>Hata: {error}</div>}
            {!error && instructions.length === 0 && !loading && (
              <div style={{ padding: 32, textAlign: 'center', color: '#374151', fontSize: 12 }}>Sol panelden fonksiyon seçin veya adres girin</div>
            )}
            {instructions.length > 0 && (
              <div style={{ display: 'grid', gridTemplateColumns: '100px 60px 150px 75px 1fr', padding: '4px 12px', fontSize: 9, color: '#374151', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(13,17,23,0.97)', zIndex: 2, flexShrink: 0 }}>
                <span>Adres</span><span>Offset</span><span>Bytes</span><span>Mnemonic</span><span>Operands</span>
              </div>
            )}
            {instructions.length > 0 && (
              <VirtualList
                defaultHeight={600}
                style={{ height: 600, width: '100%', flex: 1 }}
                rowCount={instructions.length}
                rowHeight={24}
                rowComponent={DisasmRow}
                rowProps={{ instructions, kindColor, jumpToTarget, handleInsRightClick, openXref, flirtMatches }}
              />
            )}
          </div>
        </div>

          {/* CFG Panel */}
          {cfgOpen && cfgFuncAddr && localFilePath && (
            <CFGPanel
              filePath={localFilePath}
              funcAddr={cfgFuncAddr}
              funcName={cfgFuncName}
              onBlockClick={onCfgBlockClick}
              onClose={() => setCfgOpen(false)}
            />
          )}
        </div>
      </div>

      {/* Right-click context menu */}
      {ctxMenu && (
        <div onClick={() => setCtxMenu(null)} style={{ position: 'fixed', inset: 0, zIndex: 100 }}>
          <div style={{
            position: 'fixed', left: ctxMenu.x, top: ctxMenu.y,
            background: 'rgba(15,20,30,0.97)', border: '1px solid rgba(99,102,241,0.2)',
            borderRadius: 8, padding: 4, minWidth: 180, boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ padding: '4px 10px', fontSize: 10, color: '#4b5563', fontFamily: 'monospace', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              {ctxMenu.ins.addr} — {ctxMenu.ins.mnemonic} {ctxMenu.ins.operands}
            </div>
            {[
              { label: 'NOP ile değiştir', type: 'nop', color: '#64748b', icon: '90' },
              { label: 'JMP yap (zorla)', type: 'jmp', color: '#f59e0b', icon: 'EB' },
              { label: 'Koşulu ters çevir', type: 'invert', color: '#a78bfa', icon: '⊕' },
              { label: 'RET ile değiştir', type: 'ret', color: '#f87171', icon: 'C3' },
            ].map(p => (
              <button key={p.type} onClick={() => doPatch(ctxMenu.ins.addr_val, p.type)}
                style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 10px', border: 'none', background: 'transparent', color: '#e2e8f0', fontSize: 11, cursor: 'pointer', textAlign: 'left', borderRadius: 4 }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.1)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <span style={{ fontSize: 9, fontFamily: 'monospace', color: p.color, background: 'rgba(255,255,255,0.05)', padding: '1px 4px', borderRadius: 3, minWidth: 20, textAlign: 'center' }}>{p.icon}</span>
                {p.label}
              </button>
            ))}
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.04)', marginTop: 2 }}>
              <button onClick={() => { openXref(ctxMenu.ins.addr_val); setCtxMenu(null); }}
                style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 10px', border: 'none', background: 'transparent', color: '#818cf8', fontSize: 11, cursor: 'pointer', textAlign: 'left', borderRadius: 4 }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.1)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <Search size={10} /> XRef göster
              </button>
              {/* 2.6 — Decompile from context menu */}
              <button onClick={() => { decompileFunc(null); setCtxMenu(null); }}
                style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '6px 10px', border: 'none', background: 'transparent', color: '#a78bfa', fontSize: 11, cursor: 'pointer', textAlign: 'left', borderRadius: 4 }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(139,92,246,0.1)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <Bot size={10} /> AI Decompile
              </button>
            </div>
          </div>
        </div>
      )}

      {/* XRef drawer */}
      {xrefOpen && (
        <div style={{
          position: 'absolute', right: 0, top: 0, bottom: 0, width: 340,
          background: 'rgba(10,14,22,0.98)', borderLeft: '1px solid rgba(99,102,241,0.15)',
          display: 'flex', flexDirection: 'column', zIndex: 50,
          boxShadow: '-4px 0 24px rgba(0,0,0,0.4)',
        }}>
          <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <Search size={12} color="#818cf8" />
            <span style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0' }}>Cross-References</span>
            {xrefData && <span style={{ fontSize: 10, color: '#818cf8', fontFamily: 'monospace' }}>{xrefData.target_name}</span>}
            <button onClick={() => setXrefOpen(false)} style={{ marginLeft: 'auto', padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#64748b', fontSize: 10, cursor: 'pointer' }}>
              <X size={10} />
            </button>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 8 }}>
            {xrefLoading && <div style={{ padding: 20, textAlign: 'center', fontSize: 11, color: '#64748b' }}>Taranıyor...</div>}
            {xrefData && !xrefLoading && (
              <>
                {/* Refs TO this address */}
                <div style={{ fontSize: 10, fontWeight: 700, color: '#22c55e', padding: '6px 4px 4px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  Buraya referanslar ({xrefData.refs_to.length})
                </div>
                {xrefData.refs_to.length === 0 && <div style={{ padding: 8, fontSize: 10, color: '#374151' }}>Referans bulunamadı</div>}
                {xrefData.refs_to.map((r, i) => (
                  <button key={i} onClick={() => { loadChunk(r.from_addr_val, true); }}
                    style={{ display: 'flex', gap: 6, padding: '4px 6px', width: '100%', border: 'none', background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)', cursor: 'pointer', borderRadius: 3, textAlign: 'left', alignItems: 'center' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.08)'}
                    onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)'}>
                    <span style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace', minWidth: 80 }}>{r.from_addr}</span>
                    <span style={{ fontSize: 10, fontWeight: 700, fontFamily: 'monospace', color: r.xref_type === 'call' ? '#60a5fa' : r.xref_type === 'data' ? '#94a3b8' : '#fbbf24', minWidth: 30 }}>{r.mnemonic}</span>
                    <span style={{ fontSize: 9, color: '#64748b' }}>[{r.context}]</span>
                  </button>
                ))}

                {/* Refs FROM this address */}
                <div style={{ fontSize: 10, fontWeight: 700, color: '#f59e0b', padding: '10px 4px 4px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  Buradan referanslar ({xrefData.refs_from.length})
                </div>
                {xrefData.refs_from.length === 0 && <div style={{ padding: 8, fontSize: 10, color: '#374151' }}>Referans bulunamadı</div>}
                {xrefData.refs_from.map((r, i) => (
                  <button key={i} onClick={() => { loadChunk(r.to_addr_val, true); }}
                    style={{ display: 'flex', gap: 6, padding: '4px 6px', width: '100%', border: 'none', background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)', cursor: 'pointer', borderRadius: 3, textAlign: 'left', alignItems: 'center' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.08)'}
                    onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)'}>
                    <span style={{ fontSize: 10, color: '#4b5563', fontFamily: 'monospace', minWidth: 80 }}>{r.to_addr}</span>
                    <span style={{ fontSize: 10, fontWeight: 700, fontFamily: 'monospace', color: r.xref_type === 'call' ? '#60a5fa' : '#fbbf24', minWidth: 30 }}>{r.mnemonic}</span>
                    <span style={{ fontSize: 9, color: '#818cf8' }}>{r.context}</span>
                  </button>
                ))}
              </>
            )}
          </div>
        </div>
      )}

      {/* FAZ 11 — Analysis Panel */}
      {analysisOpen && (
        <div style={{ height: 300, flexShrink: 0, borderTop: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.25)', display: 'flex', flexDirection: 'column' }}>
          {/* Tab bar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 2, padding: '4px 8px', borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
            {ANALYSIS_TABS.map(t => {
              const Icon = t.icon;
              return (
                <button key={t.key} onClick={() => { setAnalysisTab(t.key); setAnalysisResult(null); }}
                  style={{ padding: '4px 10px', borderRadius: 5, border: 'none', background: analysisTab === t.key ? `${t.color}18` : 'transparent', color: analysisTab === t.key ? t.color : '#64748b', fontSize: 10, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontWeight: analysisTab === t.key ? 700 : 400 }}>
                  <Icon size={11} /> {t.label}
                </button>
              );
            })}
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
              <input value={analysisHex} onChange={e => setAnalysisHex(e.target.value)} placeholder="Hex bytes (boşsa mevcut talimatlar)"
                style={{ width: 220, padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.3)', fontSize: 10, color: '#e2e8f0', fontFamily: 'monospace', outline: 'none' }} />
              {analysisTab === 'taint' && (
                <input value={taintSources} onChange={e => setTaintSources(e.target.value)} placeholder="Taint kaynakları (eax,ecx)"
                  style={{ width: 120, padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.2)', background: 'rgba(0,0,0,0.3)', fontSize: 10, color: '#fca5a5', fontFamily: 'monospace', outline: 'none' }} />
              )}
              {analysisTab === 'diff' && (
                <input value={analysisHexB} onChange={e => setAnalysisHexB(e.target.value)} placeholder="Hex B (karşılaştırma)"
                  style={{ width: 180, padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(59,130,246,0.2)', background: 'rgba(0,0,0,0.3)', fontSize: 10, color: '#93c5fd', fontFamily: 'monospace', outline: 'none' }} />
              )}
              <button onClick={runAnalysis} disabled={analysisLoading}
                style={{ padding: '4px 12px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.1)', color: '#f59e0b', fontSize: 10, cursor: 'pointer', fontWeight: 600 }}>
                {analysisLoading ? 'Analiz...' : 'Çalıştır'}
              </button>
              <button onClick={() => setAnalysisOpen(false)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: 2 }}><X size={12} /></button>
            </div>
          </div>
          {/* Results */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 10, fontSize: 11, fontFamily: 'monospace', color: '#e2e8f0' }}>
            {analysisResult?.error && <div style={{ color: '#f87171' }}>{analysisResult.error}</div>}
            {!analysisResult && !analysisLoading && <div style={{ color: '#4b5563', textAlign: 'center', paddingTop: 40 }}>Analiz sonuçları burada görünecek</div>}

            {/* Symbolic */}
            {analysisTab === 'symbolic' && analysisResult && !analysisResult.error && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 16, fontSize: 10, color: '#9ca3af' }}>
                  <span>Toplam talimat: <b style={{ color: '#e2e8f0' }}>{analysisResult.total_instructions}</b></span>
                  <span>Branch: <b style={{ color: '#f59e0b' }}>{analysisResult.branch_count}</b></span>
                  <span>Path adresleri: <b style={{ color: '#818cf8' }}>{analysisResult.path_addresses?.length}</b></span>
                </div>
                {analysisResult.constraints?.length > 0 && (
                  <div style={{ marginTop: 4 }}>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 4 }}>Kısıtlar:</div>
                    {analysisResult.constraints.map((c, i) => <div key={i} style={{ fontSize: 10, color: '#fbbf24', paddingLeft: 8 }}>{c}</div>)}
                  </div>
                )}
                {analysisResult.paths?.map((p, i) => (
                  <div key={i} style={{ padding: '4px 8px', borderRadius: 4, background: p.type === 'call' ? 'rgba(96,165,250,0.06)' : p.type === 'return' ? 'rgba(248,113,113,0.06)' : 'rgba(245,158,11,0.06)', display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={{ color: '#9ca3af', minWidth: 80 }}>{p.branch_addr}</span>
                    <span style={{ color: p.type === 'call' ? '#60a5fa' : p.type === 'return' ? '#f87171' : '#fbbf24', fontWeight: 600, minWidth: 70 }}>{p.type}</span>
                    {p.target && <span style={{ color: '#818cf8' }}>{p.target}</span>}
                    {p.condition && <span style={{ color: '#94a3b8', fontSize: 9 }}>({p.condition})</span>}
                  </div>
                ))}
              </div>
            )}

            {/* Taint */}
            {analysisTab === 'taint' && analysisResult && !analysisResult.error && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 16, fontSize: 10, color: '#9ca3af' }}>
                  <span>Toplam: <b style={{ color: '#e2e8f0' }}>{analysisResult.total_instructions}</b></span>
                  <span>Taint olayları: <b style={{ color: '#ef4444' }}>{analysisResult.taint_log?.length}</b></span>
                  <span>Tehlikeli noktalar: <b style={{ color: '#dc2626' }}>{analysisResult.dangerous_sinks?.length}</b></span>
                </div>
                {analysisResult.dangerous_sinks?.map((s, i) => (
                  <div key={i} style={{ padding: '4px 8px', borderRadius: 4, background: s.severity === 'critical' ? 'rgba(220,38,38,0.12)' : 'rgba(239,68,68,0.08)', border: `1px solid ${s.severity === 'critical' ? 'rgba(220,38,38,0.3)' : 'rgba(239,68,68,0.2)'}` }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={{ color: '#fca5a5', minWidth: 80 }}>{s.addr}</span>
                      <span style={{ color: s.severity === 'critical' ? '#dc2626' : '#ef4444', fontWeight: 700, fontSize: 10 }}>{s.severity.toUpperCase()}</span>
                      <span style={{ color: '#e2e8f0', fontSize: 10 }}>{s.reason}</span>
                    </div>
                    {s.tainted_args && <div style={{ fontSize: 9, color: '#f87171', paddingLeft: 88 }}>Tainted args: {s.tainted_args.join(', ')}</div>}
                  </div>
                ))}
                {analysisResult.taint_log?.slice(0, 20).map((t, i) => (
                  <div key={i} style={{ fontSize: 10, padding: '2px 8px', display: 'flex', gap: 8, color: t.action === 'propagate' ? '#fbbf24' : t.action === 'clean' ? '#22c55e' : '#f59e0b' }}>
                    <span style={{ color: '#9ca3af', minWidth: 80 }}>{t.addr}</span>
                    <span style={{ minWidth: 80, fontWeight: 600 }}>{t.action}</span>
                    <span style={{ color: '#e2e8f0' }}>{t.inst}</span>
                  </div>
                ))}
                <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 4 }}>Son tainted registerlar: <b style={{ color: '#ef4444' }}>{analysisResult.final_tainted_regs?.join(', ') || 'yok'}</b></div>
              </div>
            )}

            {/* Obfuscation */}
            {analysisTab === 'obfuscation' && analysisResult && !analysisResult.error && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 16, fontSize: 10, color: '#9ca3af', alignItems: 'center' }}>
                  <span>Obfuscation Skoru: <b style={{ color: analysisResult.obfuscation_score > 60 ? '#ef4444' : analysisResult.obfuscation_score > 30 ? '#f59e0b' : '#22c55e', fontSize: 14 }}>{analysisResult.obfuscation_score}/100</b></span>
                  <span>NOP: <b>{analysisResult.stats?.nop_count}</b></span>
                  <span>JMP: <b>{analysisResult.stats?.jmp_count}</b></span>
                  <span>Indirect JMP: <b>{analysisResult.stats?.indirect_jmp_count}</b></span>
                  <span>XOR ops: <b>{analysisResult.stats?.xor_operations}</b></span>
                </div>
                {analysisResult.findings?.map((f, i) => (
                  <div key={i} style={{ padding: '4px 8px', borderRadius: 4, background: f.severity === 'high' ? 'rgba(139,92,246,0.08)' : 'rgba(139,92,246,0.04)', border: '1px solid rgba(139,92,246,0.15)' }}>
                    <span style={{ color: f.severity === 'high' ? '#a78bfa' : '#8b5cf6', fontWeight: 600, fontSize: 10, marginRight: 8 }}>[{f.type}]</span>
                    <span style={{ color: '#e2e8f0', fontSize: 10 }}>{f.detail}</span>
                  </div>
                ))}
                {analysisResult.findings?.length === 0 && <div style={{ color: '#22c55e', textAlign: 'center', paddingTop: 20 }}>Obfuscation tespit edilmedi</div>}
              </div>
            )}

            {/* Shellcode */}
            {analysisTab === 'shellcode' && analysisResult && !analysisResult.error && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 12, fontSize: 10, color: '#9ca3af', flexWrap: 'wrap' }}>
                  <span>Boyut: <b style={{ color: '#e2e8f0' }}>{analysisResult.size_bytes} bytes</b></span>
                  <span>Talimat: <b>{analysisResult.total_instructions}</b></span>
                  <span>PIC: <b style={{ color: analysisResult.position_independent ? '#22c55e' : '#f59e0b' }}>{analysisResult.position_independent ? 'evet' : 'hayır'}</b></span>
                  <span>PEB erişimi: <b style={{ color: analysisResult.peb_access ? '#ef4444' : '#4b5563' }}>{analysisResult.peb_access ? 'EVET' : 'hayır'}</b></span>
                  <span>Syscall: <b style={{ color: analysisResult.syscall_found ? '#ef4444' : '#4b5563' }}>{analysisResult.syscall_found ? 'EVET' : 'hayır'}</b></span>
                </div>
                {analysisResult.api_patterns?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 4 }}>API kalıpları:</div>
                    {analysisResult.api_patterns.map((a, i) => (
                      <div key={i} style={{ padding: '2px 8px', fontSize: 10, display: 'flex', gap: 8 }}>
                        <span style={{ color: '#9ca3af', minWidth: 60 }}>{a.addr}</span>
                        <span style={{ color: '#22c55e', fontWeight: 600, minWidth: 80 }}>{a.type}</span>
                        <span style={{ color: '#e2e8f0' }}>{a.detail || a.api}</span>
                      </div>
                    ))}
                  </div>
                )}
                {analysisResult.stack_strings?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 4 }}>Stack string'ler:</div>
                    {analysisResult.stack_strings.map((s, i) => <div key={i} style={{ fontSize: 10, color: '#fbbf24', paddingLeft: 8 }}>"{s}"</div>)}
                  </div>
                )}
              </div>
            )}

            {/* Diff */}
            {analysisTab === 'diff' && analysisResult && !analysisResult.error && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 16, fontSize: 10, color: '#9ca3af' }}>
                  <span>Benzerlik: <b style={{ color: analysisResult.similarity_pct > 80 ? '#22c55e' : analysisResult.similarity_pct > 50 ? '#f59e0b' : '#ef4444', fontSize: 14 }}>{analysisResult.similarity_pct}%</b></span>
                  <span>A: <b>{analysisResult.total_a}</b> talimat ({analysisResult.size_a} byte)</span>
                  <span>B: <b>{analysisResult.total_b}</b> talimat ({analysisResult.size_b} byte)</span>
                  <span>Farklı talimatlar: <b style={{ color: '#3b82f6' }}>{analysisResult.instruction_diffs?.length}</b></span>
                </div>
                {analysisResult.instruction_diffs?.slice(0, 30).map((d, i) => (
                  <div key={i} style={{ display: 'flex', gap: 4, fontSize: 10, padding: '2px 0' }}>
                    <span style={{ color: '#9ca3af', minWidth: 30 }}>#{d.index}</span>
                    <span style={{ color: '#fca5a5', minWidth: 80 }}>{d.addr_a}</span>
                    <span style={{ color: '#fca5a5', flex: 1, maxWidth: '40%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.inst_a}</span>
                    <span style={{ color: '#4b5563' }}>→</span>
                    <span style={{ color: '#86efac', flex: 1, maxWidth: '40%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.inst_b}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Types */}
            {analysisTab === 'types' && analysisResult && !analysisResult.error && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 16, fontSize: 10, color: '#9ca3af' }}>
                  <span>Frame boyutu: <b style={{ color: '#e2e8f0' }}>{analysisResult.frame_size} bytes</b></span>
                  <span>Stack değişkenleri: <b style={{ color: '#ec4899' }}>{analysisResult.stack_variables?.length}</b></span>
                  <span>vtable ref: <b style={{ color: '#818cf8' }}>{analysisResult.vtable_references?.length}</b></span>
                  <span>Pointer boyutu: <b>{analysisResult.ptr_size}</b></span>
                </div>
                {analysisResult.stack_variables?.length > 0 && (
                  <div style={{ display: 'grid', gridTemplateColumns: '80px 60px 60px 120px auto', gap: '2px 8px', fontSize: 10, marginTop: 4 }}>
                    <span style={{ color: '#6b7280', fontWeight: 600 }}>Offset</span>
                    <span style={{ color: '#6b7280', fontWeight: 600 }}>Size</span>
                    <span style={{ color: '#6b7280', fontWeight: 600 }}>Name</span>
                    <span style={{ color: '#6b7280', fontWeight: 600 }}>Tür</span>
                    <span style={{ color: '#6b7280', fontWeight: 600 }}>İlk Erişim</span>
                    {analysisResult.stack_variables.map((v, i) => (
                      <React.Fragment key={i}>
                        <span style={{ color: '#f9a8d4' }}>{v.offset < 0 ? '-' : '+'}0x{Math.abs(v.offset).toString(16)}</span>
                        <span style={{ color: '#e2e8f0' }}>{v.size}</span>
                        <span style={{ color: '#c084fc' }}>{v.name}</span>
                        <span style={{ color: '#22d3ee' }}>{v.inferred_type}</span>
                        <span style={{ color: '#9ca3af' }}>{v.first_access}</span>
                      </React.Fragment>
                    ))}
                  </div>
                )}
                {analysisResult.vtable_references?.length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ fontSize: 10, color: '#6b7280', marginBottom: 4 }}>vtable referansları:</div>
                    {analysisResult.vtable_references.map((v, i) => (
                      <div key={i} style={{ fontSize: 10, padding: '2px 8px', display: 'flex', gap: 8 }}>
                        <span style={{ color: '#9ca3af' }}>{v.addr}</span>
                        <span style={{ color: '#818cf8' }}>{v.instruction}</span>
                        <span style={{ color: '#a78bfa', fontWeight: 600 }}>{v.type}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Pseudo-C Decompiler */}
            {analysisTab === 'pseudo' && analysisResult && !analysisResult.error && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ display: 'flex', gap: 16, fontSize: 10, color: '#9ca3af', flexWrap: 'wrap' }}>
                  <span>Fonksiyon: <b style={{ color: '#22d3ee' }}>{analysisResult.func_name}</b></span>
                  <span>Talimat: <b style={{ color: '#e2e8f0' }}>{analysisResult.instructions}</b></span>
                  <span>Lokal değişken: <b style={{ color: '#f472b6' }}>{analysisResult.locals}</b></span>
                  <span>Mimari: <b style={{ color: '#a78bfa' }}>{analysisResult.arch}</b></span>
                </div>
                <pre style={{
                  background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(34,211,238,0.15)',
                  borderRadius: 6, padding: '10px 14px', fontSize: 11, lineHeight: 1.6,
                  color: '#e2e8f0', overflowX: 'auto', overflowY: 'auto', maxHeight: 380,
                  fontFamily: "'Consolas', 'Courier New', monospace", whiteSpace: 'pre',
                  userSelect: 'text',
                }}>
                  <code dangerouslySetInnerHTML={{ __html: colorizePC(analysisResult.pseudo_c) }} />
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Patch log toast */}
      {patchLog.length > 0 && (
        <div style={{ position: 'absolute', bottom: 12, right: 12, zIndex: 60, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {patchLog.slice(0, 3).map((p, i) => (
            <div key={i} style={{
              background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.2)',
              borderRadius: 6, padding: '6px 12px', fontSize: 10, color: '#22c55e',
              display: 'flex', gap: 8, alignItems: 'center', animation: 'fadeIn 0.3s',
            }}>
              <CheckCircle2 size={12} />
              <span style={{ fontFamily: 'monospace' }}>{p.description}</span>
              <span style={{ color: '#4b5563', fontSize: 9 }}>+0x{p.offset.toString(16).toUpperCase()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
// FAZ 4.3 — Dashboard / İstatistik Sayfası
// ══════════════════════════════════════════════════════════════════════

export default DisassemblyPage;