import React, { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Play } from 'lucide-react';
import { Card } from './shared';
import { MOCK_DEBUG_DISASM } from './DebuggerPage';

function EmulationPage() {
  const [hexInput, setHexInput] = useState('558BEC83EC105356578D45F050FF1500304000');
  const [arch, setArch] = useState('x86');
  const [startAddr, setStartAddr] = useState('0x004012C0');
  const [running, setRunning] = useState(false);
  const [step, setStep] = useState(-1);
  const [emuRegs, setEmuRegs] = useState(null);
  const [history, setHistory] = useState([]);
  const [memWrites, setMemWrites] = useState([]);
  const [speed, setSpeed] = useState(200);
  const [traceData, setTraceData] = useState([]);
  const [errMsg, setErrMsg] = useState(null);

  const doRun = useCallback(async () => {
    setRunning(true); setErrMsg(null); setStep(0); setHistory([]); setMemWrites([]); setTraceData([]);
    try {
      const addr = parseInt(startAddr, 16) || 0x004012C0;
      const result = await invoke('emulate_function', { hexBytes: hexInput, arch, startAddr: addr, maxSteps: 500 });
      const trace = result.trace || [];
      setTraceData(trace);
      if (trace.length > 0) {
        setEmuRegs(trace[0]);
        setHistory([trace[0].inst || '']);
        // Animate
        let i = 0;
        const iv = setInterval(() => {
          i++;
          if (i >= trace.length) { clearInterval(iv); setRunning(false); return; }
          setStep(i);
          setEmuRegs(trace[i]);
          setHistory(prev => [...prev, trace[i].inst || '']);
        }, speed);
      } else {
        setRunning(false);
      }
    } catch (e) { setErrMsg(String(e)); setRunning(false); }
  }, [hexInput, arch, startAddr, speed]);

  const doStepOne = () => {
    const next = step + 1;
    if (next >= traceData.length) return;
    setStep(next);
    setEmuRegs(traceData[next]);
    setHistory(prev => [...prev, traceData[next].inst || '']);
  };

  const doReset = () => { setStep(-1); setRunning(false); setEmuRegs(null); setHistory([]); setMemWrites([]); setTraceData([]); setErrMsg(null); };

  const fmtHex = (n) => typeof n === 'number' ? '0x' + n.toString(16).padStart(8, '0').toUpperCase() : String(n || '0');

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Play size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Emulation Engine</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— x86/x64 CPU Emulator (Capstone + Interpreter)</span>
      </div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div style={{ flex: 2, minWidth: 180 }}>
          <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 2 }}>Hex Bytes</div>
          <input value={hexInput} onChange={e => setHexInput(e.target.value)} placeholder="558BEC..." style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '4px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
        </div>
        <div style={{ width: 100 }}>
          <div style={{ fontSize: 9, color: '#8b949e', marginBottom: 2 }}>Start Addr</div>
          <input value={startAddr} onChange={e => setStartAddr(e.target.value)} style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '4px 8px', fontSize: 11, color: '#e6edf3', fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' }} />
        </div>
        <div style={{ display: 'flex', gap: 2 }}>
          {['x86','x64'].map(a => (
            <button key={a} onClick={() => setArch(a)} style={{ fontSize: 10, padding: '4px 8px', borderRadius: 5, border: `1px solid ${arch === a ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: arch === a ? 'rgba(99,102,241,0.12)' : 'transparent', color: arch === a ? '#818cf8' : '#8b949e', cursor: 'pointer' }}>{a}</button>
          ))}
        </div>
      </div>

      {errMsg && <div style={{ fontSize: 10, color: '#f87171', marginBottom: 8, padding: '4px 8px', background: 'rgba(239,68,68,0.08)', borderRadius: 4 }}>{errMsg}</div>}

      <div style={{ display: 'flex', gap: 4, marginBottom: 14, alignItems: 'center' }}>
        <button onClick={doRun} disabled={running} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.12)', color: '#22c55e', cursor: running ? 'not-allowed' : 'pointer', fontWeight: 600 }}>▶ Run All</button>
        <button onClick={doStepOne} disabled={running || traceData.length === 0} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: running ? 'not-allowed' : 'pointer' }}>⏭ Step</button>
        <button onClick={doReset} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#f59e0b', cursor: 'pointer' }}>↺ Reset</button>
        <div style={{ marginLeft: 16, display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 10, color: '#8b949e' }}>Hız:</span>
          <input type="range" min={50} max={1000} step={50} value={speed} onChange={e => setSpeed(Number(e.target.value))} style={{ width: 80 }} />
          <span style={{ fontSize: 10, color: '#8b949e', fontFamily: 'monospace' }}>{speed}ms</span>
        </div>
        {step >= 0 && <span style={{ marginLeft: 'auto', fontSize: 10, color: '#818cf8' }}>Step {step + 1} / {traceData.length}</span>}
      </div>

      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        {/* Emulation Code */}
        <Card style={{ flex: 2, minWidth: 350 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Emulation Trace</div>
          <div style={{ fontFamily: 'monospace', fontSize: 11, maxHeight: 340, overflowY: 'auto', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}>
            {EMU_STEPS.map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 10px',
                background: i === step ? 'rgba(99,102,241,0.15)' : i < step ? 'rgba(34,197,94,0.04)' : 'transparent',
                borderLeft: i === step ? '3px solid #818cf8' : i < step ? '3px solid rgba(34,197,94,0.3)' : '3px solid transparent'
              }}>
                <span style={{ color: i < step ? '#22c55e' : i === step ? '#818cf8' : '#6e7681', fontSize: 9, minWidth: 12 }}>
                  {i < step ? '✓' : i === step ? '▸' : ' '}
                </span>
                <span style={{ color: '#818cf8', minWidth: 80 }}>{MOCK_DEBUG_DISASM[i]?.addr || ''}</span>
                <span style={{ color: i === step ? '#e6edf3' : '#8b949e', fontWeight: i === step ? 700 : 400 }}>{s.inst}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Registers */}
        <div style={{ flex: 1, minWidth: 220, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Registers (x86)</div>
            {emuRegs ? (
              <div style={{ fontFamily: 'monospace', fontSize: 10 }}>
                {Object.entries(emuRegs).map(([k, v]) => {
                  const prev = step > 0 ? EMU_STEPS[step - 1]?.regs[k] : undefined;
                  const changed = prev !== undefined && prev !== v;
                  return (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '1px 4px', borderRadius: 3, background: changed ? 'rgba(245,158,11,0.1)' : (k === 'EIP' ? 'rgba(99,102,241,0.1)' : 'transparent') }}>
                      <span style={{ color: k === 'EIP' ? '#818cf8' : k === 'EFLAGS' ? '#f59e0b' : '#8b949e', fontWeight: 600, minWidth: 52 }}>{k}</span>
                      <span style={{ color: changed ? '#f59e0b' : '#e6edf3' }}>{fmtHex(v)}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ fontSize: 10, color: '#6e7681', padding: 10, textAlign: 'center' }}>Emülasyonu başlatın</div>
            )}
          </Card>

          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Bellek Yazmaları</div>
            {memWrites.length > 0 ? (
              <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 150, overflowY: 'auto' }}>
                {memWrites.map((m, i) => (
                  <div key={i} style={{ display: 'flex', gap: 6, padding: '1px 0' }}>
                    <span style={{ color: '#f87171', minWidth: 80 }}>{m.addr}</span>
                    <span style={{ color: '#e6edf3' }}>← {m.val}</span>
                    <span style={{ color: '#6e7681', fontSize: 9 }}>{m.note}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: 10, color: '#6e7681', textAlign: 'center', padding: 10 }}>Henüz yazma yok</div>
            )}
          </Card>

          <Card>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Execution Log</div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, maxHeight: 100, overflowY: 'auto', color: '#8b949e' }}>
              {history.length > 0 ? history.map((h, i) => (
                <div key={i} style={{ color: '#22c55e' }}>✓ {h}</div>
              )) : <div style={{ color: '#6e7681' }}>Bekleniyor...</div>}
            </div>
          </Card>
        </div>
      </div>

      <Card style={{ marginTop: 14 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>ℹ Emülasyon Hakkında</div>
        <div style={{ fontSize: 10, color: '#8b949e', lineHeight: '18px' }}>
          Bu panel, Unicorn Engine API üzerinden x86/x64 talimatlarını emüle eder. Obfuscated kod çözümlemesi, unpacking, API çağrı takibi ve dinamik analiz için kullanılır.
          Gerçek emülasyon için Rust tarafında <code style={{ color: '#818cf8' }}>unicorn-engine</code> crate'i entegre edilmelidir.
        </div>
      </Card>
    </div>
  );
}

// ── 6.4 Ağ Trafiği Yakalama ──────────────────────────────────────

export default EmulationPage;