import React, { useState, useCallback, useRef, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Terminal, Eye } from 'lucide-react';
import { Card } from './shared';

function DebuggerPage() {
  const [bps, setBps] = useState([]);
  const [newBp, setNewBp] = useState('');
  const [running, setRunning] = useState(false);
  const [targetPid, setTargetPid] = useState('');
  const [attachedPid, setAttachedPid] = useState(null);
  const [regs, setRegs] = useState(null);
  const [stack, setStack] = useState([]);
  const [disasm, setDisasm] = useState([]);
  const [lastEvent, setLastEvent] = useState(null);
  const [lastTid, setLastTid] = useState(null);
  const [dbgLog, setDbgLog] = useState(['[Debugger] Hazır — PID girin ve Attach\'e tıklayın']);
  const [disasmAddr, setDisasmAddr] = useState('');
  const [eventStream, setEventStream] = useState([]);
  // Watch expressions
  const [watches, setWatches] = useState([]);
  const [newWatch, setNewWatch] = useState('');
  const [watchType, setWatchType] = useState('reg'); // 'reg' | 'mem'
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [dbgLog]);

  const log = useCallback((msg) => setDbgLog(prev => [...prev.slice(-200), msg]), []);

  const addEvent = useCallback((evt) => {
    setEventStream(prev => [...prev.slice(-100), {
      time: new Date().toLocaleTimeString(),
      event: evt.event_desc || evt.event || 'unknown',
      tid: evt.thread_id,
      code: evt.exception_code,
      addr: evt.exception_address,
    }]);
  }, []);

  const refreshWatches = useCallback(async (currentRegs) => {
    if (!currentRegs) return;
    setWatches(prev => prev.map(w => {
      if (w.type === 'reg') {
        const key = w.expr.toLowerCase();
        const val = currentRegs[key];
        return { ...w, value: val !== undefined ? String(val) : 'N/A' };
      }
      return w;
    }));
  }, []);

  const refreshMemWatch = useCallback(async (pid) => {
    if (!pid) return;
    setWatches(prev => prev.map(async (w) => {
      if (w.type !== 'mem') return w;
      try {
        const bytes = await invoke('read_process_memory', { pid, address: w.expr, size: 8 });
        const val = bytes ? bytes.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' ') : 'N/A';
        return { ...w, value: val };
      } catch { return { ...w, value: 'Hata' }; }
    }));
  }, []);

  const refreshContext = useCallback(async (tid) => {
    if (!tid || !attachedPid) return;
    try {
      const r = await invoke('get_registers', { threadId: tid });
      setRegs(r);
      await refreshWatches(r);
      const rip = r.rip;
      if (rip) {
        try {
          const d = await invoke('disassemble_memory', { pid: attachedPid, address: rip, size: 256 });
          setDisasm(d.instructions || []);
        } catch (_) {}
      }
      try {
        const s = await invoke('read_stack', { threadId: tid, count: 16 });
        setStack(s || []);
      } catch (_) {}
      refreshMemWatch(attachedPid);
    } catch (e) { log(`[Hata] get_registers: ${e}`); }
  }, [attachedPid, log, refreshWatches, refreshMemWatch]);

  const doAttach = useCallback(async () => {
    const pid = parseInt(targetPid);
    if (!pid) return;
    try {
      const result = await invoke('attach_debugger', { pid });
      setAttachedPid(pid);
      log(`[Debugger] ${result.message}`);
      const evt = result.initial_event;
      if (evt) {
        setLastEvent(evt);
        addEvent(evt);
        if (evt.thread_id) {
          setLastTid(evt.thread_id);
          log(`[Olay] ${evt.event_desc || evt.event} — TID ${evt.thread_id}`);
          try {
            await invoke('continue_execution');
            const evt2 = await invoke('wait_debug_event', { timeoutMs: 1000 });
            if (evt2.event !== 'timeout') {
              setLastEvent(evt2);
              addEvent(evt2);
              setLastTid(evt2.thread_id || evt.thread_id);
              log(`[Olay] ${evt2.event_desc || evt2.event} — TID ${evt2.thread_id}`);
              await refreshContext(evt2.thread_id || evt.thread_id);
            }
          } catch (_) {}
        }
      }
    } catch (e) { log(`[Hata] ${e}`); }
  }, [targetPid, log, refreshContext, addEvent]);

  const doDetach = useCallback(async () => {
    try {
      const msg = await invoke('detach_debugger');
      setAttachedPid(null); setRegs(null); setDisasm([]); setStack([]);
      setLastEvent(null); setLastTid(null); setEventStream([]);
      log(`[Debugger] ${msg}`);
    } catch (e) { log(`[Hata] ${e}`); }
  }, [log]);

  const addBp = async () => {
    if (!newBp.match(/^0x[0-9a-fA-F]+$/)) return;
    if (attachedPid) {
      try {
        const msg = await invoke('set_breakpoint', { address: newBp });
        log(`[Debugger] ${msg}`);
      } catch (e) { log(`[Hata] ${e}`); }
    }
    setBps(prev => [...prev, { addr: newBp, enabled: true, hits: 0 }]);
    setNewBp('');
  };

  const addWatch = () => {
    const expr = newWatch.trim();
    if (!expr) return;
    setWatches(prev => [...prev, { expr, type: watchType, value: '—' }]);
    setNewWatch('');
  };

  const doStep = useCallback(async () => {
    if (!attachedPid) return;
    setRunning(true);
    try {
      const evt = await invoke('step_into');
      setLastEvent(evt);
      addEvent(evt);
      const tid = evt.thread_id || lastTid;
      if (tid) { setLastTid(tid); await refreshContext(tid); }
      log(`[Step] ${evt.event_desc || evt.event}${evt.exception_code ? ` (${evt.exception_code})` : ''}`);
      if (evt.user_breakpoint) {
        const bp = bps.find(b => b.enabled);
        if (bp) { bp.hits++; setBps([...bps]); }
        log(`[Break] Kullanıcı breakpoint'ine ulaşıldı`);
      }
    } catch (e) { log(`[Hata] ${e}`); }
    setRunning(false);
  }, [attachedPid, lastTid, bps, log, refreshContext, addEvent]);

  const doRun = useCallback(async () => {
    if (!attachedPid) return;
    setRunning(true);
    try {
      await invoke('continue_execution');
      log('[Run] Çalışıyor...');
      const evt = await invoke('wait_debug_event', { timeoutMs: 5000 });
      setLastEvent(evt);
      addEvent(evt);
      if (evt.event === 'timeout') {
        log('[Run] Zaman aşımı — süreç çalışmaya devam ediyor');
      } else {
        const tid = evt.thread_id || lastTid;
        if (tid) { setLastTid(tid); await refreshContext(tid); }
        log(`[Olay] ${evt.event_desc || evt.event}${evt.exception_code ? ` (${evt.exception_code})` : ''}`);
        if (evt.user_breakpoint) {
          const bp = bps.find(b => b.enabled);
          if (bp) { bp.hits++; setBps([...bps]); }
          log(`[Break] Kullanıcı breakpoint'ine ulaşıldı`);
        }
      }
    } catch (e) { log(`[Hata] ${e}`); }
    setRunning(false);
  }, [attachedPid, lastTid, bps, log, refreshContext, addEvent]);

  const doDisasmAt = async () => {
    if (!attachedPid || !disasmAddr) return;
    try {
      const d = await invoke('disassemble_memory', { pid: attachedPid, address: disasmAddr, size: 512 });
      setDisasm(d.instructions || []);
      log(`[Disasm] ${(d.instructions || []).length} komut @ ${disasmAddr}`);
    } catch (e) { log(`[Hata] ${e}`); }
  };

  const pc = regs?.rip || regs?.eip || null;

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Terminal size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Debugger</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Step · Breakpoint · Register · Watch</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 4, alignItems: 'center' }}>
          <input value={targetPid} onChange={e => setTargetPid(e.target.value)} placeholder="PID"
            style={{ width: 70, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '3px 6px', fontSize: 10, color: '#e6edf3', fontFamily: 'monospace', outline: 'none' }} />
          {!attachedPid ? (
            <button onClick={doAttach} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#22c55e', cursor: 'pointer' }}>Attach</button>
          ) : (
            <button onClick={doDetach} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>Detach ({attachedPid})</button>
          )}
          {attachedPid && lastTid && <span style={{ fontSize: 9, color: '#6b7280' }}>TID: {lastTid}</span>}
        </div>
      </div>

      {/* Kontroller */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
        <button onClick={doStep} disabled={running || !attachedPid} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: (running || !attachedPid) ? 'not-allowed' : 'pointer', opacity: (running || !attachedPid) ? 0.5 : 1, fontWeight: 600 }}>⏭ Step Into</button>
        <button onClick={doRun} disabled={running || !attachedPid} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.12)', color: '#22c55e', cursor: (running || !attachedPid) ? 'not-allowed' : 'pointer', opacity: (running || !attachedPid) ? 0.5 : 1, fontWeight: 600 }}>▶ Çalıştır</button>
        <div style={{ marginLeft: 8, display: 'flex', gap: 4, alignItems: 'center' }}>
          <input value={disasmAddr} onChange={e => setDisasmAddr(e.target.value)} placeholder="Disasm adresi (0x...)"
            style={{ width: 140, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '3px 6px', fontSize: 10, color: '#e6edf3', fontFamily: 'monospace', outline: 'none' }} />
          <button onClick={doDisasmAt} disabled={!attachedPid} style={{ fontSize: 9, padding: '3px 8px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.06)', color: '#818cf8', cursor: !attachedPid ? 'not-allowed' : 'pointer' }}>Disasm</button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        {/* Disassembly */}
        <Card style={{ flex: 2, minWidth: 380 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Disassembly {pc && <span style={{ fontWeight: 400, color: '#818cf8' }}>@ {pc}</span>}</div>
          {disasm.length === 0 ? (
            <div style={{ color: '#6b7280', fontSize: 11, padding: 20, textAlign: 'center' }}>
              {attachedPid ? 'Bekleniyor... Step veya Çalıştır ile devam edin.' : 'Bir sürece Attach olun.'}
            </div>
          ) : (
            <div style={{ fontFamily: 'monospace', fontSize: 11, maxHeight: 400, overflowY: 'auto', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}>
              {disasm.map((d, i) => {
                const isCur = pc && d.addr && (d.addr === pc || d.addr.toLowerCase() === pc.toLowerCase());
                const isBp = bps.some(b => b.addr.toLowerCase() === (d.addr || '').toLowerCase() && b.enabled);
                const inst = d.mnemonic ? `${d.mnemonic} ${d.operands || ''}` : d.inst || '';
                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '2px 8px', background: isCur ? 'rgba(99,102,241,0.15)' : isBp ? 'rgba(239,68,68,0.06)' : 'transparent', borderLeft: isCur ? '3px solid #818cf8' : isBp ? '3px solid #f87171' : '3px solid transparent' }}>
                    <span style={{ color: isBp ? '#f87171' : '#3b3b3b', fontSize: 8, minWidth: 10, cursor: 'pointer' }}
                      onClick={() => { if (isBp) setBps(bps.filter(b => b.addr.toLowerCase() !== (d.addr || '').toLowerCase())); else if (d.addr) setBps([...bps, { addr: d.addr, enabled: true, hits: 0 }]); }}>
                      {isBp ? '●' : '○'}
                    </span>
                    <span style={{ color: '#818cf8', minWidth: 130, fontSize: 10 }}>{d.addr}</span>
                    <span style={{ color: '#6e7681', minWidth: 80, fontSize: 9 }}>{d.bytes}</span>
                    <span style={{ color: isCur ? '#e6edf3' : '#c9d1d9', fontWeight: isCur ? 700 : 400 }}>{inst}</span>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Sağ panel */}
        <div style={{ flex: 1, minWidth: 220, display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Registerlar */}
          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Registerlar (x64)</div>
            {regs ? (
              <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 200, overflowY: 'auto' }}>
                {Object.entries(regs).map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '1px 4px', borderRadius: 3, background: (k === 'rip') ? 'rgba(99,102,241,0.1)' : 'transparent' }}>
                    <span style={{ color: k === 'rip' ? '#818cf8' : k === 'eflags' ? '#f59e0b' : '#8b949e', fontWeight: 600, minWidth: 52, textTransform: 'uppercase' }}>{k}</span>
                    <span style={{ color: '#e6edf3' }}>{v}</span>
                  </div>
                ))}
              </div>
            ) : <div style={{ color: '#6b7280', fontSize: 10, padding: 8 }}>Attach edilmedi</div>}
          </Card>

          {/* Watch Expressions */}
          <Card>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <Eye size={11} color="#a78bfa" />
              <span style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3' }}>Watch</span>
            </div>
            <div style={{ display: 'flex', gap: 3, marginBottom: 6 }}>
              <select value={watchType} onChange={e => setWatchType(e.target.value)}
                style={{ fontSize: 9, padding: '2px 4px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.04)', color: '#8b949e', outline: 'none' }}>
                <option value="reg">Register</option>
                <option value="mem">Bellek</option>
              </select>
              <input value={newWatch} onChange={e => setNewWatch(e.target.value)}
                placeholder={watchType === 'reg' ? 'rax, rbx...' : '0x1000...'} onKeyDown={e => e.key === 'Enter' && addWatch()}
                style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '3px 6px', fontSize: 10, color: '#e6edf3', fontFamily: 'monospace', outline: 'none' }} />
              <button onClick={addWatch} style={{ fontSize: 9, padding: '3px 7px', borderRadius: 4, border: '1px solid rgba(167,139,250,0.3)', background: 'rgba(167,139,250,0.08)', color: '#a78bfa', cursor: 'pointer' }}>+</button>
            </div>
            {watches.length === 0 ? (
              <div style={{ color: '#6b7280', fontSize: 9 }}>Watch yok — register veya bellek adresi ekleyin</div>
            ) : watches.map((w, i) => (
              <div key={i} style={{ display: 'flex', gap: 6, fontSize: 10, padding: '2px 0', alignItems: 'center' }}>
                <span style={{ fontSize: 8, color: w.type === 'reg' ? '#818cf8' : '#f59e0b' }}>{w.type === 'reg' ? '®' : 'M'}</span>
                <span style={{ fontFamily: 'monospace', color: '#8b949e', minWidth: 60, textTransform: 'uppercase' }}>{w.expr}</span>
                <span style={{ fontFamily: 'monospace', color: '#e6edf3', flex: 1 }}>{w.value}</span>
                <span style={{ cursor: 'pointer', color: '#6e7681', fontSize: 10 }} onClick={() => setWatches(watches.filter((_, j) => j !== i))}>✕</span>
              </div>
            ))}
          </Card>

          {/* Breakpoints */}
          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Breakpoints</div>
            <div style={{ display: 'flex', gap: 4, marginBottom: 6 }}>
              <input value={newBp} onChange={e => setNewBp(e.target.value)} placeholder="0x..." onKeyDown={e => e.key === 'Enter' && addBp()}
                style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '3px 6px', fontSize: 10, color: '#e6edf3', fontFamily: 'monospace', outline: 'none' }} />
              <button onClick={addBp} style={{ fontSize: 9, padding: '3px 8px', borderRadius: 4, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>+ BP</button>
            </div>
            {bps.map((b, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, padding: '2px 0' }}>
                <span style={{ cursor: 'pointer', color: b.enabled ? '#f87171' : '#6e7681' }}
                  onClick={() => { b.enabled = !b.enabled; setBps([...bps]); }}>{b.enabled ? '●' : '○'}</span>
                <span style={{ fontFamily: 'monospace', color: '#e6edf3' }}>{b.addr}</span>
                <span style={{ color: '#6e7681', fontSize: 9 }}>({b.hits}x)</span>
                <span style={{ marginLeft: 'auto', cursor: 'pointer', color: '#6e7681', fontSize: 10 }}
                  onClick={() => setBps(bps.filter((_, j) => j !== i))}>✕</span>
              </div>
            ))}
            {bps.length === 0 && <div style={{ color: '#6b7280', fontSize: 9 }}>Breakpoint yok</div>}
          </Card>

          {/* Stack */}
          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Stack</div>
            {stack.length > 0 ? (
              <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 160, overflowY: 'auto' }}>
                {stack.map((s, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, padding: '1px 0' }}>
                    <span style={{ color: '#818cf8', minWidth: 130 }}>{s.addr}</span>
                    <span style={{ color: '#e6edf3', minWidth: 130 }}>{s.value}</span>
                    <span style={{ color: '#6e7681', fontSize: 9 }}>{s.offset}</span>
                  </div>
                ))}
              </div>
            ) : <div style={{ color: '#6b7280', fontSize: 10, padding: 8 }}>Stack verisi yok</div>}
          </Card>
        </div>
      </div>

      {/* Alt satır — Event Stream + Debug Log yan yana */}
      <div style={{ display: 'flex', gap: 14, marginTop: 14, flexWrap: 'wrap' }}>
        {/* Event Stream */}
        <Card style={{ flex: 1, minWidth: 280 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Debug Olay Akışı</div>
          <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 140, overflowY: 'auto', background: '#0d1117', borderRadius: 6, padding: 6, border: '1px solid rgba(255,255,255,0.06)' }}>
            {eventStream.length === 0 ? (
              <div style={{ color: '#6b7280' }}>Henüz olay yok</div>
            ) : [...eventStream].reverse().map((e, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, padding: '1px 0', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                <span style={{ color: '#6e7681', minWidth: 70 }}>{e.time}</span>
                <span style={{ color: e.event.includes('exception') || e.event.includes('break') ? '#f87171' : e.event.includes('load') ? '#60a5fa' : e.event.includes('thread') ? '#a78bfa' : '#f59e0b', flex: 1 }}>{e.event}</span>
                {e.tid && <span style={{ color: '#6e7681', fontSize: 9 }}>TID:{e.tid}</span>}
                {e.addr && <span style={{ color: '#8b949e', fontSize: 9 }}>{e.addr}</span>}
              </div>
            ))}
          </div>
        </Card>

        {/* Debug Log */}
        <Card style={{ flex: 1, minWidth: 280 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Debug Log</div>
          <div ref={logRef} style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 140, overflowY: 'auto', background: '#0d1117', borderRadius: 6, padding: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
            {dbgLog.map((l, i) => (
              <div key={i} style={{ color: l.includes('[Break]') ? '#f87171' : l.includes('[Step]') ? '#818cf8' : l.includes('[Çalış') ? '#22c55e' : l.includes('[Hata]') ? '#ef4444' : l.includes('[Olay]') ? '#f59e0b' : '#8b949e', lineHeight: '16px' }}>{l}</div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

export default DebuggerPage;