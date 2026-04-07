import React, { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Terminal } from 'lucide-react';
import { Card } from './shared';

const MOCK_REGISTERS = {
  x64: { RAX: '0x00000001400010A0', RBX: '0x0000000000000000', RCX: '0x000000014000D230', RDX: '0x0000000000000001', RSI: '0x0000000000000000', RDI: '0x00000001400045B0', RSP: '0x00000000006FF8B0', RBP: '0x00000000006FF8E0', R8: '0x0000000000000040', R9: '0x0000000000000000', R10: '0x00007FFE74CB0000', R11: '0x00000000006FF848', R12: '0x0000000000000000', R13: '0x0000000000000000', R14: '0x00000001400045B0', R15: '0x0000000000000000', RIP: '0x00000001400012C4', RFLAGS: '0x0000000000000246' },
  x86: { EAX: '0x004010A0', EBX: '0x00000000', ECX: '0x0040D230', EDX: '0x00000001', ESI: '0x00000000', EDI: '0x004045B0', ESP: '0x0019FF80', EBP: '0x0019FF88', EIP: '0x004012C4', EFLAGS: '0x00000246' },
};

const MOCK_DEBUG_DISASM = [
  { addr: '0x004012C0', bytes: '55', inst: 'push ebp', label: 'sub_4012C0' },
  { addr: '0x004012C1', bytes: '8BEC', inst: 'mov ebp, esp' },
  { addr: '0x004012C3', bytes: '83EC10', inst: 'sub esp, 0x10' },
  { addr: '0x004012C6', bytes: '53', inst: 'push ebx' },
  { addr: '0x004012C7', bytes: '56', inst: 'push esi' },
  { addr: '0x004012C8', bytes: '57', inst: 'push edi' },
  { addr: '0x004012C9', bytes: '8D45F0', inst: 'lea eax, [ebp-0x10]' },
  { addr: '0x004012CC', bytes: '50', inst: 'push eax' },
  { addr: '0x004012CD', bytes: 'FF1500304000', inst: 'call dword [0x403000]', comment: '; GetModuleHandleA' },
  { addr: '0x004012D3', bytes: '8945FC', inst: 'mov [ebp-4], eax' },
  { addr: '0x004012D6', bytes: '837DFC00', inst: 'cmp dword [ebp-4], 0' },
  { addr: '0x004012DA', bytes: '7520', inst: 'jnz 0x4012FC' },
  { addr: '0x004012DC', bytes: '6A00', inst: 'push 0' },
  { addr: '0x004012DE', bytes: '6804504000', inst: 'push 0x405004', comment: '; "Error"' },
  { addr: '0x004012E3', bytes: '6810504000', inst: 'push 0x405010', comment: '; "Module not found"' },
  { addr: '0x004012E8', bytes: '6A00', inst: 'push 0' },
  { addr: '0x004012EA', bytes: 'FF1504304000', inst: 'call dword [0x403004]', comment: '; MessageBoxA' },
  { addr: '0x004012F0', bytes: '33C0', inst: 'xor eax, eax' },
  { addr: '0x004012F2', bytes: '5F', inst: 'pop edi' },
  { addr: '0x004012F3', bytes: '5E', inst: 'pop esi' },
  { addr: '0x004012F4', bytes: '5D', inst: 'pop ebp' },
  { addr: '0x004012F5', bytes: 'C3', inst: 'ret' },
];

const MOCK_STACK = [
  { addr: '0x0019FF80', value: '0x0019FF88', info: 'saved EBP' },
  { addr: '0x0019FF84', value: '0x004013A2', info: 'return address → main+0x12' },
  { addr: '0x0019FF88', value: '0x0019FFD0', info: 'caller EBP' },
  { addr: '0x0019FF8C', value: '0x00000001', info: 'argc' },
  { addr: '0x0019FF90', value: '0x00532480', info: 'argv' },
  { addr: '0x0019FF94', value: '0x00532540', info: 'envp' },
  { addr: '0x0019FF98', value: '0x00000000', info: '(padding)' },
  { addr: '0x0019FF9C', value: '0x7FFE0300', info: 'KUSER_SHARED_DATA' },
];

function DebuggerPage() {
  const [arch, setArch] = useState('x86');
  const [regs, setRegs] = useState({ ...MOCK_REGISTERS.x86 });
  const [bps, setBps] = useState([{ addr: '0x004012CD', enabled: true, hits: 3 }, { addr: '0x004012DA', enabled: true, hits: 1 }]);
  const [newBp, setNewBp] = useState('');
  const [pc, setPc] = useState('0x004012C4');
  const [running, setRunning] = useState(false);
  const [stepMode, setStepMode] = useState(null);
  const [targetPid, setTargetPid] = useState('');
  const [attachedPid, setAttachedPid] = useState(null);
  const [liveRegs, setLiveRegs] = useState(null);
  const [dbgLog, setDbgLog] = useState(['[Debugger] Ready — enter PID and click Attach']);

  const doAttach = useCallback(async () => {
    const pid = parseInt(targetPid);
    if (!pid) return;
    try {
      const msg = await invoke('attach_debugger', { pid });
      setAttachedPid(pid);
      setDbgLog(prev => [...prev, `[Debugger] ${msg}`]);
    } catch (e) { setDbgLog(prev => [...prev, `[Error] ${e}`]); }
  }, [targetPid]);

  const doDetach = useCallback(async () => {
    try {
      const msg = await invoke('detach_debugger');
      setAttachedPid(null); setLiveRegs(null);
      setDbgLog(prev => [...prev, `[Debugger] ${msg}`]);
    } catch (e) { setDbgLog(prev => [...prev, `[Error] ${e}`]); }
  }, []);

  const addBp = async () => {
    if (!newBp.match(/^0x[0-9a-fA-F]+$/)) return;
    if (attachedPid) {
      try {
        const msg = await invoke('set_breakpoint', { address: newBp });
        setDbgLog(prev => [...prev, `[Debugger] ${msg}`]);
      } catch (e) { setDbgLog(prev => [...prev, `[Error] ${e}`]); }
    }
    setBps(prev => [...prev, { addr: newBp, enabled: true, hits: 0 }]);
    setDbgLog(prev => [...prev, `[Debugger] Breakpoint at ${newBp} set`]);
    setNewBp('');
  };

  const doStep = () => {
    setStepMode('step');
    const curIdx = MOCK_DEBUG_DISASM.findIndex(d => d.addr === pc);
    if (curIdx >= 0 && curIdx < MOCK_DEBUG_DISASM.length - 1) {
      const next = MOCK_DEBUG_DISASM[curIdx + 1];
      setPc(next.addr);
      const regKey = arch === 'x64' ? 'RIP' : 'EIP';
      setRegs(prev => ({ ...prev, [regKey]: next.addr.replace('0x00', '0x00000001') }));
      setDbgLog(prev => [...prev, `[Step] ${next.addr}: ${next.inst}`]);
      const bp = bps.find(b => b.addr === next.addr && b.enabled);
      if (bp) {
        bp.hits++;
        setBps([...bps]);
        setDbgLog(prev => [...prev, `[Break] Hit breakpoint at ${next.addr} (${bp.hits}x)`]);
      }
    }
  };

  const doRun = () => {
    setRunning(true);
    setDbgLog(prev => [...prev, '[Run] Executing...']);
    setTimeout(() => {
      const bpAddrs = bps.filter(b => b.enabled).map(b => b.addr);
      const curIdx = MOCK_DEBUG_DISASM.findIndex(d => d.addr === pc);
      let hitIdx = -1;
      for (let i = curIdx + 1; i < MOCK_DEBUG_DISASM.length; i++) {
        if (bpAddrs.includes(MOCK_DEBUG_DISASM[i].addr)) { hitIdx = i; break; }
      }
      if (hitIdx >= 0) {
        const hit = MOCK_DEBUG_DISASM[hitIdx];
        setPc(hit.addr);
        const bp = bps.find(b => b.addr === hit.addr);
        if (bp) { bp.hits++; setBps([...bps]); }
        setDbgLog(prev => [...prev, `[Break] Hit breakpoint at ${hit.addr} — ${hit.inst}`]);
      } else {
        setDbgLog(prev => [...prev, '[Run] Reached end of function']);
      }
      setRunning(false);
    }, 500);
  };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Terminal size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Debugger</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Step · Breakpoint · Register</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 4, alignItems: 'center' }}>
          <input value={targetPid} onChange={e => setTargetPid(e.target.value)} placeholder="PID"
            style={{ width: 70, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '3px 6px', fontSize: 10, color: '#e6edf3', fontFamily: 'monospace', outline: 'none' }} />
          {!attachedPid ? (
            <button onClick={doAttach} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#22c55e', cursor: 'pointer' }}>Attach</button>
          ) : (
            <button onClick={doDetach} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>Detach ({attachedPid})</button>
          )}
          {['x86', 'x64'].map(a => (
            <button key={a} onClick={() => { setArch(a); setRegs({ ...MOCK_REGISTERS[a] }); }}
              style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: `1px solid ${arch === a ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: arch === a ? 'rgba(99,102,241,0.12)' : 'transparent', color: arch === a ? '#818cf8' : '#8b949e', cursor: 'pointer' }}>{a}</button>
          ))}
        </div>
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 14 }}>
        <button onClick={doStep} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: running ? 'not-allowed' : 'pointer', opacity: running ? 0.5 : 1, fontWeight: 600 }}>⏭ Step Into</button>
        <button onClick={doStep} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: running ? 'not-allowed' : 'pointer', opacity: running ? 0.5 : 1 }}>⏩ Step Over</button>
        <button onClick={doRun} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.12)', color: '#22c55e', cursor: running ? 'not-allowed' : 'pointer', opacity: running ? 0.5 : 1, fontWeight: 600 }}>▶ Run</button>
        <button onClick={() => { setPc('0x004012C0'); setRegs({ ...MOCK_REGISTERS[arch] }); setDbgLog(prev => [...prev, '[Debugger] Reset to entry']); }}
          style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#f59e0b', cursor: 'pointer' }}>↺ Restart</button>
      </div>

      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        {/* Disassembly */}
        <Card style={{ flex: 2, minWidth: 380 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Disassembly</div>
          <div style={{ fontFamily: 'monospace', fontSize: 11, maxHeight: 380, overflowY: 'auto', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}>
            {MOCK_DEBUG_DISASM.map((d, i) => {
              const isCur = d.addr === pc;
              const isBp = bps.some(b => b.addr === d.addr && b.enabled);
              return (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '2px 8px', background: isCur ? 'rgba(99,102,241,0.15)' : isBp ? 'rgba(239,68,68,0.06)' : 'transparent', borderLeft: isCur ? '3px solid #818cf8' : isBp ? '3px solid #f87171' : '3px solid transparent' }}>
                  <span style={{ color: isBp ? '#f87171' : 'transparent', fontSize: 8, minWidth: 10, cursor: 'pointer' }}
                    onClick={() => { if (isBp) setBps(bps.filter(b => b.addr !== d.addr)); else setBps([...bps, { addr: d.addr, enabled: true, hits: 0 }]); }}>
                    {isBp ? '●' : '○'}
                  </span>
                  {d.label && <span style={{ color: '#a78bfa', fontSize: 9, position: 'absolute', marginTop: -14 }}>{d.label}:</span>}
                  <span style={{ color: '#818cf8', minWidth: 80 }}>{d.addr}</span>
                  <span style={{ color: '#6e7681', minWidth: 90, fontSize: 10 }}>{d.bytes}</span>
                  <span style={{ color: isCur ? '#e6edf3' : '#c9d1d9', fontWeight: isCur ? 700 : 400 }}>{d.inst}</span>
                  {d.comment && <span style={{ color: '#22c55e', marginLeft: 8, fontSize: 10 }}>{d.comment}</span>}
                </div>
              );
            })}
          </div>
        </Card>

        {/* Registers + Stack */}
        <div style={{ flex: 1, minWidth: 220, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Registers ({arch})</div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 200, overflowY: 'auto' }}>
              {Object.entries(regs).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '1px 4px', borderRadius: 3, background: (k === 'RIP' || k === 'EIP') ? 'rgba(99,102,241,0.1)' : 'transparent' }}>
                  <span style={{ color: (k === 'RIP' || k === 'EIP') ? '#818cf8' : (k.includes('FLAGS') ? '#f59e0b' : '#8b949e'), fontWeight: 600, minWidth: 52 }}>{k}</span>
                  <span style={{ color: '#e6edf3' }}>{v}</span>
                </div>
              ))}
            </div>
          </Card>

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
                <span style={{ color: '#6e7681', fontSize: 9 }}>({b.hits}x hit)</span>
                <span style={{ marginLeft: 'auto', cursor: 'pointer', color: '#6e7681', fontSize: 10 }}
                  onClick={() => setBps(bps.filter((_, j) => j !== i))}>✕</span>
              </div>
            ))}
          </Card>

          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Call Stack</div>
            <div style={{ fontFamily: 'monospace', fontSize: 10 }}>
              {MOCK_STACK.map((s, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, padding: '1px 0' }}>
                  <span style={{ color: '#818cf8', minWidth: 80 }}>{s.addr}</span>
                  <span style={{ color: '#e6edf3', minWidth: 80 }}>{s.value}</span>
                  <span style={{ color: '#6e7681', fontSize: 9 }}>{s.info}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      {/* Debug Log */}
      <Card style={{ marginTop: 14 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Debug Log</div>
        <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 120, overflowY: 'auto', background: '#0d1117', borderRadius: 6, padding: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
          {dbgLog.map((l, i) => (
            <div key={i} style={{ color: l.includes('[Break]') ? '#f87171' : l.includes('[Step]') ? '#818cf8' : l.includes('[Run]') ? '#22c55e' : '#8b949e', lineHeight: '16px' }}>{l}</div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ── 6.3 Emülasyon Motoru ──────────────────────────────────────────


export { MOCK_DEBUG_DISASM };
export default DebuggerPage;