import React, { useState, useEffect, lazy, Suspense } from 'react';
import { getCurrentWindow } from '@tauri-apps/api/window';
import {
  Microscope, Minus, Maximize2, Square, X,
  ShieldAlert, Binary, Code, MessageSquare, Cpu, Layers,
  BarChart2, Monitor, Terminal, Play, Network, FileSearch,
} from 'lucide-react';
import { getHistory, getPluginCommands } from './utils/peHelpers';
import { WinBtn, NavItem } from './components/shared';
import useStore, { VIEWS, THEMES, getAllThemes, addCustomTheme, removeCustomTheme } from './store/useStore';

// Lazy-loaded page components
const ScannerPage       = lazy(() => import('./components/ScannerPage'));
const PatcherPage       = lazy(() => import('./components/PatcherPage'));
const SystemPage        = lazy(() => import('./components/SystemPage'));
const ChatPage          = lazy(() => import('./components/ChatPage'));
const PluginPage        = lazy(() => import('./components/PluginPage'));
const DisassemblyPage   = lazy(() => import('./components/DisassemblyPage'));
const DashboardPage     = lazy(() => import('./components/DashboardPage'));
const ProcessAttachPage = lazy(() => import('./components/ProcessAttachPage'));
const DebuggerPage      = lazy(() => import('./components/DebuggerPage'));
const EmulationPage     = lazy(() => import('./components/EmulationPage'));
const NetworkCapturePage= lazy(() => import('./components/NetworkCapturePage'));
const FlirtPage         = lazy(() => import('./components/FlirtPage'));

// Suspense fallback
const PageLoader = () => (
  <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
    <div style={{ width: 24, height: 24, border: '2px solid #818cf8', borderTopColor: 'transparent', borderRadius: '50%', animation: '_sp 0.6s linear infinite' }} />
  </div>
);

export default function App() {
  const view = useStore(s => s.view);
  const setView = useStore(s => s.setView);
  const theme = useStore(s => s.theme);
  const setTheme = useStore(s => s.setTheme);
  const zoom = useStore(s => s.zoom);
  const setZoom = useStore(s => s.setZoom);
  const sidebarWidth = useStore(s => s.sidebarWidth);
  const setSidebarWidth = useStore(s => s.setSidebarWidth);
  const tourDone = useStore(s => s.tourDone);
  const setTourDone = useStore(s => s.setTourDone);
  const chatContexts = useStore(s => s.chatContexts);
  const setChatContexts = useStore(s => s.setChatContexts);
  const scanHistory = useStore(s => s.scanHistory);
  const sendToAI = useStore(s => s.sendToAI);
  const sendToChat = useStore(s => s.sendToChat);
  const disasmFilePath = useStore(s => s.disasmFilePath);
  const openInDisasm = useStore(s => s.openInDisasm);
  const cmdOpen = useStore(s => s.cmdOpen);
  const setCmdOpen = useStore(s => s.setCmdOpen);
  const cmdQuery = useStore(s => s.cmdQuery);
  const setCmdQuery = useStore(s => s.setCmdQuery);

  const [isMaximized, setIsMaximized] = useState(false);
  const [sidebarDragging, setSidebarDragging] = useState(false);
  const [tourStep, setTourStep] = useState(tourDone ? -1 : 0);
  const appWindow = getCurrentWindow();
  const allThemes = getAllThemes();
  const T = allThemes[theme] || THEMES.dark;

  // 12.4 — Theme editor state
  const [themeEditorOpen, setThemeEditorOpen] = useState(false);
  const [customThemeName, setCustomThemeName] = useState('');
  const [customColors, setCustomColors] = useState({ bg: '#0d1117', sidebar: '#010409', accent: '#6366f1', accentL: '#818cf8', border: 'rgba(255,255,255,0.06)' });

  const handleMaximize = async () => {
    await appWindow.toggleMaximize();
    setIsMaximized(await appWindow.isMaximized());
  };

  // 49 — Keyboard shortcuts
  useEffect(() => {
    const VLIST = [VIEWS.SCANNER, VIEWS.PATCHER, VIEWS.DISASM, VIEWS.CHAT, VIEWS.SYSTEM, VIEWS.PLUGINS, VIEWS.DASHBOARD];
    const handler = (e) => {
      if (e.ctrlKey && !e.altKey && !e.shiftKey && !e.metaKey) {
        if (e.key >= '1' && e.key <= '6') { e.preventDefault(); setView(VLIST[parseInt(e.key) - 1]); }
        if (e.key === 'k') { e.preventDefault(); setCmdOpen(!useStore.getState().cmdOpen); setCmdQuery(''); } // G6
      }
      if (e.key === 'Escape') { setCmdOpen(false); } // G6
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // 54 — Zoom with Ctrl+Wheel
  useEffect(() => {
    const handler = (e) => {
      if (e.ctrlKey) {
        e.preventDefault();
        const cur = useStore.getState().zoom;
        const next = Math.min(1.5, Math.max(0.7, cur + (e.deltaY < 0 ? 0.05 : -0.05)));
        setZoom(next);
      }
    };
    window.addEventListener('wheel', handler, { passive: false });
    return () => window.removeEventListener('wheel', handler);
  }, []);

  // 51 — Window size memory
  useEffect(() => {
    const saved = localStorage.getItem('dissect_winsize');
    if (saved) {
      try {
        const { w, h } = JSON.parse(saved);
        appWindow.setSize({ type: 'Logical', width: w, height: h }).catch(() => {});
      } catch {}
    }
    const onResize = async () => {
      try {
        const sz = await appWindow.innerSize();
        localStorage.setItem('dissect_winsize', JSON.stringify({ w: sz.width, h: sz.height }));
      } catch {}
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  // G1 — sidebar resize mouse events
  useEffect(() => {
    if (!sidebarDragging) return;
    const onMove = (e) => {
      const next = Math.min(340, Math.max(140, e.clientX));
      setSidebarWidth(next);
    };
    const onUp = () => setSidebarDragging(false);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); };
  }, [sidebarDragging]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', overflow: 'hidden', background: T.bg, color: '#e6edf3', fontFamily: "'Inter','SF Pro Display',system-ui,sans-serif", userSelect: 'none', transform: zoom !== 1 ? `scale(${zoom})` : undefined, transformOrigin: 'top left', ...(zoom !== 1 ? { width: `${100 / zoom}vw`, height: `${100 / zoom}vh` } : {}) }}>

      {/* �"��"� TITLEBAR �"��"� */}
      <style>{`@keyframes _sp { to { transform: rotate(360deg); } }`}</style>
      <div data-tauri-drag-region style={{ display: 'flex', alignItems: 'center', height: 42, flexShrink: 0, background: T.sidebar, borderBottom: `1px solid ${T.border}`, padding: '0 6px 0 14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, pointerEvents: 'none' }} data-tauri-drag-region>
          <div style={{ width: 22, height: 22, borderRadius: 6, background: T.accent, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Microscope size={13} color="white" /></div>
          <span style={{ fontSize: 12, fontWeight: 700, color: T.accent, letterSpacing: '0.06em' }}>DISSECT</span>
        </div>
        <div style={{ flex: 1 }} data-tauri-drag-region />
        {/* G6 — Ctrl+K hint in titlebar */}
        <button onClick={() => { setCmdOpen(true); setCmdQuery(''); }}
          style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.05)', color: '#374151', cursor: 'pointer', marginRight: 10, display: 'flex', alignItems: 'center', gap: 5 }}>
          ? <span style={{ letterSpacing: '0.05em' }}>Ctrl+K</span>
        </button>
        {/* 52 — Theme picker (12.4 enhanced) */}
        <div style={{ display: 'flex', gap: 4, marginRight: 12, alignItems: 'center' }}>
          {Object.entries(allThemes).map(([k, v]) => (
            <button key={k} onClick={() => setTheme(k)} title={k}
              style={{ width: 14, height: 14, borderRadius: '50%', background: v.accent, border: theme === k ? `2px solid white` : '2px solid transparent', cursor: 'pointer', padding: 0 }} />
          ))}
          <button onClick={() => setThemeEditorOpen(v => !v)} title="Theme Editor"
            style={{ width: 14, height: 14, borderRadius: '50%', background: 'transparent', border: '2px dashed rgba(255,255,255,0.2)', cursor: 'pointer', padding: 0, fontSize: 8, color: '#64748b', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>+</button>
          {/* zoom indicator */}
          {zoom !== 1 && <span style={{ fontSize: 9, color: '#374151', alignSelf: 'center', marginLeft: 4 }}>{Math.round(zoom * 100)}%</span>}
        </div>
        {/* Window Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <WinBtn onClick={() => appWindow.minimize()}><Minus size={13} /></WinBtn>
          <WinBtn onClick={handleMaximize}>{isMaximized ? <Square size={11} /> : <Maximize2 size={12} />}</WinBtn>
          <WinBtn onClick={() => appWindow.close()} danger><X size={13} /></WinBtn>
        </div>
      </div>

      {/* �"��"� BODY �"��"� */}
      {/* G1 — Resizable sidebar via state-driven width */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

        {/* Sidebar */}
        <aside style={{ width: sidebarWidth, flexShrink: 0, background: T.sidebar, borderRight: `1px solid ${T.border}`, display: 'flex', flexDirection: 'column', padding: '14px 8px', position: 'relative', userSelect: sidebarDragging ? 'none' : undefined }}>
          <NavItem active={view === VIEWS.SCANNER} onClick={() => setView(VIEWS.SCANNER)} icon={<ShieldAlert size={15} />} label="Collector Layer"  sub="PE · Entropy · Strings · Imports" />
          <NavItem active={view === VIEWS.PATCHER} onClick={() => setView(VIEWS.PATCHER)} icon={<Binary size={15} />}     label="Hex Patcher"     sub="Offsets · NOP injection" />
          <NavItem active={view === VIEWS.DISASM}  onClick={() => setView(VIEWS.DISASM)}  icon={<Code size={15} />}       label="Disassembly"     sub="x86/x64 · Functions · XRef" badge="NEW" />

          <NavItem active={view === VIEWS.CHAT}    onClick={() => setView(VIEWS.CHAT)}    icon={<MessageSquare size={15} />} label="AI Chat"       sub="Explain · Analyze · Guide · Hyp." badge="NEW" />
          <NavItem active={view === VIEWS.SYSTEM}  onClick={() => setView(VIEWS.SYSTEM)}  icon={<Cpu size={15} />}        label="System & Models" sub="GPU · CUDA · Model manager" />
          <NavItem active={view === VIEWS.PLUGINS} onClick={() => setView(VIEWS.PLUGINS)} icon={<Layers size={15} />}     label="Plugins"         sub="Mağaza · API · Sandbox" badge="v2" />
          <NavItem active={view === VIEWS.DASHBOARD} onClick={() => setView(VIEWS.DASHBOARD)} icon={<BarChart2 size={15} />} label="Dashboard"       sub="İstatistik · Rapor · Proje" badge="NEW" />

          <div style={{ height: 1, background: 'rgba(255,255,255,0.04)', margin: '8px 4px' }} />
          <div style={{ fontSize: 9, color: '#6e7681', padding: '2px 12px', marginBottom: 2 }}>ADVANCED</div>
          <NavItem active={view === VIEWS.ATTACH}    onClick={() => setView(VIEWS.ATTACH)}    icon={<Monitor size={15} />}      label="Process Attach"  sub="Bellek · Bölge · Okuma" badge="v6" />
          <NavItem active={view === VIEWS.DEBUGGER}  onClick={() => setView(VIEWS.DEBUGGER)}  icon={<Terminal size={15} />}     label="Debugger"        sub="Step · Break · Register" badge="v6" />
          <NavItem active={view === VIEWS.EMULATION} onClick={() => setView(VIEWS.EMULATION)} icon={<Play size={15} />}        label="Emulation"       sub="x86 Emülatör · Unicorn" badge="v6" />
          <NavItem active={view === VIEWS.NETWORK}   onClick={() => setView(VIEWS.NETWORK)}   icon={<Network size={15} />}     label="Net Capture"     sub="DNS · HTTP · TLS · Beacon" badge="v6" />
          <NavItem active={view === VIEWS.FLIRT}     onClick={() => setView(VIEWS.FLIRT)}     icon={<FileSearch size={15} />}  label="FLIRT Sigs"      sub="Kütüphane · İmza · IDA" badge="v6" />

          <div style={{ flex: 1 }} />
          <div style={{ padding: '10px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 5px #22c55e66' }} />
              <span style={{ fontSize: 10, color: '#2d3748', fontWeight: 500 }}>Dissect — Active</span>
            </div>
            <div style={{ fontSize: 9, color: '#1a1f2e' }}>Collector · Analyzer · AI Layer · Local</div>
          </div>
          {/* G1 — Drag handle */}
          <div
            onMouseDown={e => { e.preventDefault(); setSidebarDragging(true); }}
            style={{ position: 'absolute', right: 0, top: 0, bottom: 0, width: 5, cursor: 'col-resize', background: sidebarDragging ? 'rgba(99,102,241,0.4)' : 'transparent', transition: 'background 0.15s', zIndex: 10 }}
            title="Drag to resize sidebar" />
        </aside>

        {/* Main */}
        <main style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', background: T.bg }}>
          {view === VIEWS.SCANNER && <Suspense fallback={<PageLoader />}><ScannerPage onSendToAI={sendToAI} onSendToChat={sendToChat} onOpenDisasm={openInDisasm} /></Suspense>}
          {view === VIEWS.PATCHER && <Suspense fallback={<PageLoader />}><PatcherPage onSendToChat={sendToChat} /></Suspense>}
          {view === VIEWS.DISASM  && <Suspense fallback={<PageLoader />}><DisassemblyPage filePath={disasmFilePath} onSendToChat={sendToChat} /></Suspense>}

          <div style={{ flex: 1, display: view === VIEWS.CHAT ? 'flex' : 'none', flexDirection: 'column', overflow: 'hidden' }}>
            <Suspense fallback={<PageLoader />}><ChatPage chatContexts={chatContexts} setChatContexts={setChatContexts} scanHistory={scanHistory} /></Suspense>
          </div>
          {view === VIEWS.SYSTEM  && <Suspense fallback={<PageLoader />}><SystemPage /></Suspense>}
          {view === VIEWS.PLUGINS && <Suspense fallback={<PageLoader />}><PluginPage /></Suspense>}
          {view === VIEWS.DASHBOARD && <Suspense fallback={<PageLoader />}><DashboardPage /></Suspense>}
          {view === VIEWS.ATTACH    && <Suspense fallback={<PageLoader />}><ProcessAttachPage /></Suspense>}
          {view === VIEWS.DEBUGGER  && <Suspense fallback={<PageLoader />}><DebuggerPage /></Suspense>}
          {view === VIEWS.EMULATION && <Suspense fallback={<PageLoader />}><EmulationPage /></Suspense>}
          {view === VIEWS.NETWORK   && <Suspense fallback={<PageLoader />}><NetworkCapturePage /></Suspense>}
          {view === VIEWS.FLIRT     && <Suspense fallback={<PageLoader />}><FlirtPage /></Suspense>}
        </main>

      </div>

      {/* 12.4 — Theme Editor Modal */}
      {themeEditorOpen && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 9997, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ width: 400, borderRadius: 14, background: '#0d1117', border: '1px solid rgba(99,102,241,0.3)', boxShadow: '0 20px 60px rgba(0,0,0,0.8)', padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>Tema Editörü</span>
              <button onClick={() => setThemeEditorOpen(false)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}><X size={16} /></button>
            </div>
            <input value={customThemeName} onChange={e => setCustomThemeName(e.target.value)} placeholder="Tema adı..."
              style={{ width: '100%', padding: '6px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(0,0,0,0.3)', fontSize: 12, color: '#e2e8f0', marginBottom: 12, outline: 'none', boxSizing: 'border-box' }} />
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
              {Object.entries(customColors).filter(([k]) => k !== 'border').map(([key, val]) => (
                <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input type="color" value={val} onChange={e => setCustomColors(c => ({ ...c, [key]: e.target.value }))}
                    style={{ width: 28, height: 28, border: 'none', background: 'none', cursor: 'pointer', padding: 0 }} />
                  <span style={{ fontSize: 11, color: '#9ca3af' }}>{key}</span>
                </div>
              ))}
            </div>
            {/* Preview */}
            <div style={{ borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.08)', marginBottom: 16, display: 'flex', height: 60 }}>
              <div style={{ width: 60, background: customColors.sidebar }} />
              <div style={{ flex: 1, background: customColors.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                <div style={{ width: 40, height: 6, borderRadius: 3, background: customColors.accent }} />
                <div style={{ width: 30, height: 6, borderRadius: 3, background: customColors.accentL }} />
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => {
                if (!customThemeName.trim()) return;
                addCustomTheme(customThemeName.trim(), { ...customColors, border: `rgba(${parseInt(customColors.accent.slice(1,3),16)},${parseInt(customColors.accent.slice(3,5),16)},${parseInt(customColors.accent.slice(5,7),16)},0.12)` });
                setTheme(customThemeName.trim());
                setThemeEditorOpen(false);
              }}
                style={{ flex: 1, padding: '8px 0', borderRadius: 8, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>Kaydet</button>
              
              {/* Delete custom themes list */}
              {Object.keys(getAllThemes()).filter(k => !THEMES[k]).length > 0 && (
                <select onChange={e => { if (e.target.value) { removeCustomTheme(e.target.value); if (theme === e.target.value) setTheme('dark'); e.target.value = ''; } }}
                  style={{ padding: '8px', borderRadius: 8, border: '1px solid rgba(239,68,68,0.2)', background: 'rgba(239,68,68,0.05)', color: '#f87171', fontSize: 11, cursor: 'pointer' }}>
                  <option value="">Sil...</option>
                  {Object.keys(getAllThemes()).filter(k => !THEMES[k]).map(k => <option key={k} value={k}>{k}</option>)}
                </select>
              )}
            </div>
          </div>
        </div>
      )}

      {/* G7 — Onboarding Tour (first launch) */}
      {tourStep >= 0 && (() => {
        const STEPS = [
          { icon: '🔬', title: 'Hoş Geldiniz — Dissect v2', body: 'Dissect, Windows PE binary analizi ve AI destekli tersine mühendislik stüdyosudur. Beş ana modül içerir.' },
          { icon: '✎', title: 'Scanner', body: 'Herhangi bir .exe, .dll veya .sys dosyasını Scanner\'a sürükleyin. SHA-256, entropi, koruma tespiti, imphash ve daha fazlasını otomatik hesaplar.' },
          { icon: '🔧', title: 'Patcher', body: 'Hex Patcher\'da bir dosya açın, offset + patched bytes girerek NOP sled veya JMP patch uygulayın. Backup otomatik alınır.' },
          { icon: '🤖', title: 'AI Analyst', body: 'Scanner sonuçlarını "Send to AI" ile AI Analyst\'e gönderin. LM Studio\'ya bağlanarak yerel model kullanın.' },
          { icon: '⌘', title: 'Hızlı Erişim (Ctrl+K)', body: 'Her özelliğe Ctrl+K komut paleti ile erişin. Ctrl+1⬦6 ile sekmelere geçin. Temayı başlık çubuğundaki renkli noktalardan değiştirin.' },
        ];
        const step = STEPS[tourStep];
        const isLast = tourStep === STEPS.length - 1;
        const done = () => { setTourDone(true); setTourStep(-1); };
        return (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 9998, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ width: 440, borderRadius: 18, background: '#0d1117', border: '1px solid rgba(99,102,241,0.35)', boxShadow: '0 30px 80px rgba(0,0,0,0.9)', padding: 32, textAlign: 'center' }}>
              <div style={{ fontSize: 40, marginBottom: 14 }}>{step.icon}</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>{step.title}</div>
              <div style={{ fontSize: 13, color: '#4b5563', lineHeight: 1.7, marginBottom: 22 }}>{step.body}</div>
              {/* Progress dots */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: 6, marginBottom: 22 }}>
                {STEPS.map((_, i) => (
                  <div key={i} onClick={() => setTourStep(i)} style={{ width: i === tourStep ? 20 : 8, height: 8, borderRadius: 4, background: i === tourStep ? '#6366f1' : i < tourStep ? '#374151' : '#1f2937', cursor: 'pointer', transition: 'all 0.2s' }} />
                ))}
              </div>
              <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
                <button onClick={done} style={{ fontSize: 12, padding: '7px 18px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', background: 'transparent', color: '#374151', cursor: 'pointer' }}>Atla</button>
                <button onClick={() => isLast ? done() : setTourStep(s => s + 1)}
                  style={{ fontSize: 12, padding: '7px 22px', borderRadius: 8, border: '1px solid rgba(99,102,241,0.4)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>
                  {isLast ? '🚀 Başla' : 'İleri →'}
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* G6 — Command Palette (Ctrl+K) */}
      {cmdOpen && (() => {
        const CMD_LIST = [
          { label: '🔍 Scanner — PE Analiz',      action: () => { setView(VIEWS.SCANNER); setCmdOpen(false); } },
          { label: '🔧 Patcher — Hex Düzenle',    action: () => { setView(VIEWS.PATCHER); setCmdOpen(false); } },
          { label: 'u{1F52C} Analyst (AI Chat)',             action: () => { setView(VIEWS.CHAT);    setCmdOpen(false); } },
          { label: '💬 AI Chat',                   action: () => { setView(VIEWS.CHAT);    setCmdOpen(false); } },
          { label: '⚙️ System & Models',           action: () => { setView(VIEWS.SYSTEM);  setCmdOpen(false); } },
          { label: '🧩 Plugins',                   action: () => { setView(VIEWS.PLUGINS); setCmdOpen(false); } },
          { label: '📊 Dashboard',                  action: () => { setView(VIEWS.DASHBOARD); setCmdOpen(false); } },
          { label: '🎓 Onboarding Turunu Başlat (G7)', action: () => { setTourDone(false); setTourStep(0); setCmdOpen(false); } },
          ...getHistory().slice(0, 5).map(h => ({
            label: `📄 ${h.fileName} — Risk:${h.riskScore} · ${h.arch}`,
            action: () => { setCmdOpen(false); },
          })),
          ...getPluginCommands().map(c => ({
            label: `🧩 ${c.label}`,
            action: () => { c.fn(); setCmdOpen(false); },
          })),
        ];
        const filtered = cmdQuery
          ? CMD_LIST.filter(c => c.label.toLowerCase().includes(cmdQuery.toLowerCase()))
          : CMD_LIST;
        return (
          <div onClick={() => setCmdOpen(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 9999, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: 80 }}>
            <div onClick={e => e.stopPropagation()} style={{ width: 520, borderRadius: 14, background: '#0d1117', border: '1px solid rgba(99,102,241,0.35)', boxShadow: '0 24px 80px rgba(0,0,0,0.8)', overflow: 'hidden' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <span style={{ fontSize: 15 }}>?</span>
                <input autoFocus value={cmdQuery} onChange={e => setCmdQuery(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Escape') { setCmdOpen(false); }
                    if (e.key === 'Enter' && filtered.length > 0) { filtered[0].action(); }
                  }}
                  placeholder="Komut veya sayfa ara⬦ (Esc = kapat)"
                  style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', fontSize: 14, color: '#e2e8f0', fontFamily: 'inherit' }} />
                <span style={{ fontSize: 10, color: '#374151', flexShrink: 0 }}>Ctrl+K</span>
              </div>
              <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                {filtered.length === 0
                  ? <div style={{ padding: '20px', textAlign: 'center', fontSize: 12, color: '#374151' }}>Sonuç bulunamadı</div>
                  : filtered.map((c, i) => (
                    <div key={i} onClick={c.action}
                      style={{ padding: '10px 16px', cursor: 'pointer', fontSize: 13, color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 10, transition: 'background 0.1s' }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'rgba(99,102,241,0.1)'; e.currentTarget.style.color = '#e2e8f0'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#94a3b8'; }}>
                      {c.label}
                    </div>
                  ))
                }
              </div>
              <div style={{ padding: '7px 16px', borderTop: '1px solid rgba(255,255,255,0.04)', fontSize: 10, color: '#2d3748', display: 'flex', gap: 16 }}>
                <span>↕ Gezin</span><span>? Seç</span><span>Esc Kapat</span>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}