import React, { useState, useEffect, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import {
  Cpu, HardDrive, MemoryStick, Download, RefreshCw, FolderOpen,
  Search, CheckCircle2, XCircle, Zap, Play, Layers, ChevronDown, ChevronRight, AlertCircle, X
} from 'lucide-react';
import { Card, CardHeader, Spinner } from './shared';
import useStore from '../store/useStore';

function SystemPage() {
  const [sysInfo, setSysInfo]     = useState(null);
  const [loadingSys, setLoadingSys] = useState(false);
  const [modelsDir, setModelsDir] = useState(() => localStorage.getItem('dissect_models_dir') || '');
  const [models, setModels]       = useState([]);
  const [dlUrl, setDlUrl]         = useState('');
  const [dlName, setDlName]       = useState('');
  const [dlProgress, setDlProgress] = useState(null);
  const [dlError, setDlError]     = useState('');
  const [cudaInfo, setCudaInfo]   = useState(null);
  const [checkingCuda, setCheckingCuda] = useState(false);
  // HuggingFace GGUF arama
  const [hfQuery, setHfQuery]     = useState('');
  const [hfResults, setHfResults] = useState([]);
  const [hfSearching, setHfSearching] = useState(false);
  const [hfError, setHfError]     = useState('');
  const [hfExpanded, setHfExpanded] = useState(new Set()); // expanded model ids
  const [scanError, setScanError] = useState('');
  const [confirmDl, setConfirmDl] = useState(null); // {url, name, model} for confirm dialog
  const [folderReady, setFolderReady] = useState(''); // + butonu başarı mesajı

  // Global indirme state (sayfa değişince kaybolmaz)
  const gDlProgress    = useStore(s => s.gDlProgress);
  const setGDlProgress = useStore(s => s.setGDlProgress);
  const setGDlCancelling = useStore(s => s.setGDlCancelling);
  // Local alias for display inside this page
  const hfDlProgress = gDlProgress;

  const refreshSys = async () => {
    setLoadingSys(true);
    try { setSysInfo(await invoke('get_system_info')); }
    catch (e) { console.error(e); }
    finally { setLoadingSys(false); }
  };

  const scanModels = async () => {
    if (!modelsDir.trim()) { setScanError('Lütfen önce bir klasör yolu girin.'); return; }
    setScanError('');
    localStorage.setItem('dissect_models_dir', modelsDir);
    try {
      const result = await invoke('list_models', { dir: modelsDir });
      setModels(result || []);
      if (!result || result.length === 0) setScanError('Bu klasörde .gguf dosyası bulunamadı.');
    } catch (e) { setScanError(String(e)); setModels([]); }
  };

  const toggleHfExpand = (mid) => {
    setHfExpanded(prev => {
      const next = new Set(prev);
      if (next.has(mid)) next.delete(mid); else next.add(mid);
      return next;
    });
  };

  const searchHfGguf = async () => {
    if (!hfQuery.trim()) return;
    setHfSearching(true); setHfError(''); setHfResults([]);
    try {
      const results = await invoke('search_hf_gguf', { query: hfQuery.trim() });
      setHfResults(Array.isArray(results) ? results : []);
      if (!Array.isArray(results) || results.length === 0) setHfError('Sonuç bulunamadı. Farklı bir arama terimi deneyin.');
    } catch (e) { setHfError(String(e)); }
    finally { setHfSearching(false); }
  };

  const startHfDownload = async () => {
    if (!confirmDl || !modelsDir) return;
    const { url, name } = confirmDl;
    const dest = `${modelsDir}\\${name}`;
    setConfirmDl(null);
    setGDlProgress({ name, pct: 0, mb: 0, total_mb: 0, speed_mbs: 0, eta_secs: 0, dest });
    setGDlCancelling(false);
    setDlError('');
    // Guard: ignore dl-progress events while cancel is in-flight (prevents bar re-appearing)
    const unlisten = await listen('dl-progress', (e) => {
      if (useStore.getState().gDlCancelling) return;
      setGDlProgress({ name, dest, ...e.payload });
    });
    const unlistenCancel = await listen('dl-cancelled', () => {
      setGDlProgress(null);
      setGDlCancelling(false);
      unlisten();
      unlistenCancel();
    });
    try {
      await invoke('download_model', { url, dest });
      await scanModels();
    } catch (e) {
      if (!String(e).includes('İptal edildi')) setDlError(String(e));
    } finally {
      setGDlProgress(null);
      setGDlCancelling(false);
      unlisten();
      unlistenCancel();
    }
  };

  const cancelDownload = async () => {
    setGDlCancelling(true);          // immediately stop progress updates
    try { await invoke('cancel_download'); } catch {}
    // gDlProgress will be cleared by dl-cancelled event or the finally block above
  };

  const startDownload = async () => {
    if (!dlUrl || !dlName || !modelsDir) return;
    const dest = `${modelsDir}\\${dlName}`;
    setDlProgress({ pct: 0, mb: 0, total_mb: 0 });
    setDlError('');
    const unlisten = await listen('dl-progress', (e) => setDlProgress(e.payload));
    try {
      await invoke('download_model', { url: dlUrl, dest });
      await scanModels();
      setDlUrl(''); setDlName('');
    } catch (e) { setDlError(String(e)); }
    finally { setDlProgress(null); unlisten(); }
  };

  const checkCuda = async () => {
    setCheckingCuda(true);
    try { setCudaInfo(await invoke('get_cuda_version')); }
    catch { setCudaInfo(null); }
    finally { setCheckingCuda(false); }
  };

  useEffect(() => { refreshSys(); checkCuda(); }, []);

  const UNCENSORED_KEYWORDS = ['uncensored', 'abliterated', 'unfiltered', 'no-censor', 'aggressive'];
  const isUncensored = (id) => {
    const lower = (id || '').toLowerCase();
    return UNCENSORED_KEYWORDS.some(k => lower.includes(k));
  };

  const dedupedResults = useMemo(() => {
    if (!hfResults.length) return [];
    const grouped = {};
    hfResults.forEach(m => {
      const mid = m.id || m.modelId || '';
      // Base name: extract repo base (before quantization suffixes)
      const baseName = mid.replace(/-GGUF$/i, '').replace(/-gguf$/i, '');
      if (!grouped[baseName] || (m.downloads || 0) > (grouped[baseName].downloads || 0)) {
        grouped[baseName] = m;
      }
    });
    return Object.values(grouped).sort((a, b) => (b.downloads || 0) - (a.downloads || 0));
  }, [hfResults]);

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 22 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(20,184,166,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Cpu size={17} color="#2dd4bf" /></div>
          <div>
            <h1 style={{ fontSize: 19, fontWeight: 700, margin: 0, color: '#f1f5f9' }}>System</h1>
            <p style={{ fontSize: 12, color: '#374151', margin: 0 }}>Hardware info · GPU/CUDA · GGUF model manager</p>
          </div>
        </div>
        <button onClick={refreshSys} disabled={loadingSys} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#4b5563', cursor: 'pointer' }}>
          <RefreshCw size={13} style={loadingSys ? { animation: '_sp 0.75s linear infinite' } : {}} /> Refresh
        </button>
      </div>

      {loadingSys && !sysInfo && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spinner /></div>
      )}

      {sysInfo && (
        <>
          {/* Hardware row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20 }}>
            {[
              { icon: <Cpu size={16} color="#818cf8" />, label: 'Processor', value: sysInfo.cpu, sub: `${sysInfo.cores} logical cores`, bg: 'rgba(99,102,241,0.09)', border: 'rgba(99,102,241,0.18)' },
              { icon: <MemoryStick size={16} color="#2dd4bf" />, label: 'Memory', value: `${sysInfo.ram_gb.toFixed(1)} GB`, sub: 'Total system RAM', bg: 'rgba(20,184,166,0.07)', border: 'rgba(20,184,166,0.15)' },
              { icon: <HardDrive size={16} color="#f59e0b" />, label: 'Operating System', value: sysInfo.os || 'Windows', sub: 'Platform', bg: 'rgba(245,158,11,0.07)', border: 'rgba(245,158,11,0.15)' },
            ].map(({ icon, label, value, sub, bg, border }) => (
              <div key={label} style={{ borderRadius: 12, padding: '14px 16px', background: bg, border: `1px solid ${border}` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>{icon}<span style={{ fontSize: 10, fontWeight: 600, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{label}</span></div>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0', marginBottom: 3, wordBreak: 'break-word' }}>{value}</div>
                <div style={{ fontSize: 10, color: '#2d3748' }}>{sub}</div>
              </div>
            ))}
          </div>

          {/* GPU Cards */}
          <div style={{ marginBottom: 8, fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.08em' }}>GPU / Compute</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 12, marginBottom: 24 }}>
            {sysInfo.gpus.length === 0 && (
              <div style={{ borderRadius: 12, padding: 16, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', color: '#374151', fontSize: 12 }}>
                No GPU detected via nvidia-smi or WMIC. If you have a discrete GPU, make sure drivers are installed.
              </div>
            )}
            {sysInfo.gpus.map((gpu, i) => (
              <div key={i} style={{ borderRadius: 12, padding: 16, background: gpu.cuda ? 'rgba(34,197,94,0.04)' : 'rgba(255,255,255,0.02)', border: `1px solid ${gpu.cuda ? 'rgba(34,197,94,0.2)' : 'rgba(255,255,255,0.07)'}` }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0', flex: 1, marginRight: 8 }}>{gpu.name}</div>
                  <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 5, background: gpu.cuda ? 'rgba(34,197,94,0.15)' : 'rgba(99,102,241,0.12)', color: gpu.cuda ? '#4ade80' : '#818cf8', whiteSpace: 'nowrap', flexShrink: 0 }}>
                    {gpu.cuda ? '? CUDA' : 'No CUDA'}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {[
                    { label: 'VRAM',    value: gpu.vram_mb > 0 ? `${(gpu.vram_mb / 1024).toFixed(1)} GB` : '—' },
                    { label: 'Driver',  value: gpu.driver   || '—' },
                    { label: 'Compute', value: gpu.compute_cap || '—' },
                  ].map(({ label, value }) => (
                    <div key={label} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 10, color: '#374151' }}>{label}</span>
                      <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#6b7280' }}>{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Model Manager */}
      <div style={{ marginBottom: 8, fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.08em' }}>GGUF Model Manager</div>
      <Card style={{ marginBottom: 16 }}>
        <div style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: '#374151', marginBottom: 10 }}>
            Point to a folder containing <code style={{ fontFamily: 'monospace', color: '#818cf8' }}>.gguf</code> files. Ollama will use models you add via <code style={{ fontFamily: 'monospace', color: '#818cf8' }}>ollama create</code>.
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <input value={modelsDir} onChange={e => setModelsDir(e.target.value)} placeholder="C:\Users\you\models" style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 11px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <button onClick={scanModels} style={{ padding: '7px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}><FolderOpen size={14} /> Scan</button>            <button
              title="Masaüstünde Dissect_GGUF klasörü oluştur — indirdiğin GGUF'lar buraya kaydedilir"
              onClick={async () => {
                try {
                  const dir = await invoke('setup_models_dir');
                  setModelsDir(dir);
                  localStorage.setItem('dissect_models_dir', dir);
                  setScanError('');
                  setFolderReady(dir);
                  setTimeout(() => setFolderReady(''), 4000);
                } catch (e) { setScanError(String(e)); }
              }}
              style={{ padding: '7px 14px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1 }}
            >+</button>          </div>
          {folderReady && (
            <div style={{ fontSize: 11, color: '#4ade80', marginBottom: 8, padding: '8px 12px', borderRadius: 6, background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.2)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <CheckCircle2 size={13} />
              <span><strong>Klasör hazır:</strong> <span style={{ fontFamily: 'monospace', color: '#e2e8f0' }}>{folderReady}</span></span>
              <span style={{ marginLeft: 4, color: '#64748b' }}>— HF’den inen GGUF’lar buraya kaydedilir. Sonra <strong style={{color:'#818cf8'}}>Scan</strong> ile yükle.</span>
            </div>
          )}
          {scanError && <div style={{ fontSize: 11, color: '#f87171', marginBottom: 8, padding: '6px 10px', borderRadius: 6, background: 'rgba(248,113,113,0.06)', border: '1px solid rgba(248,113,113,0.12)', display: 'flex', alignItems: 'center', gap: 6 }}><AlertCircle size={13} /> {scanError}</div>}

          {models.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8 }}>Found ({models.length})</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {models.map((m, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', padding: '9px 12px', borderRadius: 8, background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.12)' }}>
                    <Layers size={14} color="#6366f1" style={{ marginRight: 10, flexShrink: 0 }} />
                    <span style={{ flex: 1, fontSize: 12, fontFamily: 'monospace', color: '#94a3b8' }}>{m.name}</span>
                    <span style={{ fontSize: 11, color: '#374151' }}>{m.size_mb.toFixed(0)} MB</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* HuggingFace GGUF Arama */}
          <div style={{ marginBottom: 16, borderRadius: 12, background: 'linear-gradient(135deg, rgba(99,102,241,0.06) 0%, rgba(168,85,247,0.06) 100%)', border: '1px solid rgba(99,102,241,0.15)', padding: '16px 18px', position: 'relative', overflow: 'hidden' }}>
            {/* Decorative glow */}
            <div style={{ position: 'absolute', top: -30, right: -30, width: 80, height: 80, borderRadius: '50%', background: 'radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 70%)', pointerEvents: 'none' }} />

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
              <div style={{ width: 28, height: 28, borderRadius: 8, background: 'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <Search size={14} color="#fff" />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0', letterSpacing: '-0.01em' }}>HuggingFace GGUF Arama</div>
                <div style={{ fontSize: 9, color: '#64748b' }}>Binlerce GGUF modeli arasında arayın ve doğrudan indirin</div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              <div style={{ flex: 1, position: 'relative' }}>
                <Search size={13} color="#64748b" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
                <input value={hfQuery} onChange={e => setHfQuery(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && searchHfGguf()}
                  placeholder="qwen2.5, llama-3, mistral-7b, phi-3..."
                  style={{ width: '100%', boxSizing: 'border-box', paddingLeft: 32, background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 8, padding: '9px 12px 9px 32px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace', transition: 'border 0.2s' }} />
              </div>
              <button onClick={searchHfGguf} disabled={hfSearching || !hfQuery.trim()}
                style={{ padding: '9px 20px', borderRadius: 8, border: 'none', background: hfSearching ? 'rgba(99,102,241,0.15)' : 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)', color: '#fff', cursor: hfSearching ? 'wait' : 'pointer', fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap', boxShadow: '0 2px 8px rgba(99,102,241,0.25)', transition: 'all 0.2s' }}>
                {hfSearching ? <><RefreshCw size={13} style={{ animation: '_sp 0.75s linear infinite' }} /> Aranıyor...</> : <><Search size={13} /> Ara</>}
              </button>
            </div>
            {hfError && <div style={{ fontSize: 11, color: '#f87171', marginBottom: 8, padding: '6px 10px', borderRadius: 6, background: 'rgba(248,113,113,0.06)', border: '1px solid rgba(248,113,113,0.12)' }}>{hfError}</div>}

            {/* Confirmation Dialog */}
            {confirmDl && (
              <div style={{ position: 'fixed', inset: 0, zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
                onClick={() => setConfirmDl(null)}>
                <div onClick={e => e.stopPropagation()} style={{ width: 420, background: '#1a1b2e', borderRadius: 14, border: '1px solid rgba(99,102,241,0.2)', boxShadow: '0 20px 60px rgba(0,0,0,0.5)', padding: '24px 28px', animation: 'fadeIn 0.2s' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                    <div style={{ width: 36, height: 36, borderRadius: 10, background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Download size={18} color="#fff" />
                    </div>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>Model İndir</div>
                      <div style={{ fontSize: 10, color: '#64748b' }}>İndirme onayı</div>
                    </div>
                  </div>
                  <div style={{ marginBottom: 18, padding: '12px 14px', borderRadius: 8, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ fontSize: 10, color: '#64748b', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Model</div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#a78bfa', marginBottom: 8 }}>{confirmDl.model}</div>
                    <div style={{ fontSize: 10, color: '#64748b', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Dosya</div>
                    <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#e2e8f0', wordBreak: 'break-all' }}>{confirmDl.name}</div>
                  </div>
                  <div style={{ marginBottom: 16, padding: '8px 12px', borderRadius: 6, background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.15)', fontSize: 10, color: '#fbbf24' }}>
                    ⚠ Hedef: <span style={{ fontFamily: 'monospace', color: '#e2e8f0' }}>{modelsDir || '(Klasör seçilmedi)'}</span>
                    {!modelsDir && <span style={{ display: 'block', marginTop: 4, color: '#f87171' }}>Önce yukarıdan bir models klasörü belirleyin!</span>}
                  </div>
                  <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                    <button onClick={() => setConfirmDl(null)}
                      style={{ padding: '8px 18px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#8b949e', cursor: 'pointer', fontSize: 12, fontWeight: 500 }}>
                      İptal
                    </button>
                    <button onClick={startHfDownload} disabled={!modelsDir}
                      style={{ padding: '8px 22px', borderRadius: 8, border: 'none', background: modelsDir ? 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)' : '#374151', color: '#fff', cursor: modelsDir ? 'pointer' : 'not-allowed', fontSize: 12, fontWeight: 600, boxShadow: modelsDir ? '0 2px 10px rgba(34,197,94,0.3)' : 'none', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <Download size={14} /> İndir
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Active HF Download Progress */}
            {hfDlProgress && (
              <div style={{ marginBottom: 12, padding: '12px 14px', borderRadius: 10, background: 'rgba(34,197,94,0.04)', border: '1px solid rgba(34,197,94,0.15)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, flex: 1 }}>
                    <Download size={13} color="#22c55e" style={{ animation: '_sp 2s linear infinite', flexShrink: 0 }} />
                    <span style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{hfDlProgress.name}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0, marginLeft: 8 }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: '#22c55e', fontFamily: 'monospace' }}>{hfDlProgress.pct}%</span>
                    <button onClick={cancelDownload}
                      title="İndirmeyi iptal et"
                      style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 22, height: 22, borderRadius: 5, border: '1px solid rgba(239,68,68,0.35)', background: 'rgba(239,68,68,0.1)', color: '#f87171', cursor: 'pointer', padding: 0 }}>
                      <X size={12} />
                    </button>
                  </div>
                </div>
                <div style={{ height: 8, borderRadius: 4, background: 'rgba(255,255,255,0.06)', overflow: 'hidden', position: 'relative' }}>
                  <div style={{
                    height: '100%', borderRadius: 4, transition: 'width 0.4s ease',
                    width: `${hfDlProgress.pct}%`,
                    background: `linear-gradient(90deg, #6366f1 0%, #8b5cf6 ${Math.min(50, hfDlProgress.pct)}%, #22c55e ${Math.max(80, hfDlProgress.pct)}%, #4ade80 100%)`,
                    boxShadow: '0 0 12px rgba(99,102,241,0.4)',
                  }} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 5 }}>
                  <span style={{ fontSize: 9, color: '#64748b', fontFamily: 'monospace' }}>{hfDlProgress.mb.toFixed(1)} MB indirildi</span>
                  <span style={{ fontSize: 9, color: '#64748b', fontFamily: 'monospace' }}>{hfDlProgress.total_mb.toFixed(1)} MB toplam</span>
                </div>
              </div>
            )}

            {dedupedResults.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 500, overflowY: 'auto', paddingRight: 4 }}>
                {dedupedResults.map((m) => {
                  const mid = m.id || m.modelId || '';
                  const ggufFiles = (m.siblings || []).filter(s => s.rfilename?.endsWith('.gguf'));
                  const uncensored = isUncensored(mid);
                  return (
                    <div key={mid} style={{ borderRadius: 10, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                      {/* Header - clickable to expand */}
                      <div onClick={() => toggleHfExpand(mid)} style={{ padding: '12px 14px', display: 'flex', alignItems: 'flex-start', gap: 12, cursor: 'pointer', transition: 'background 0.15s' }}
                        onMouseOver={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                        onMouseOut={e => e.currentTarget.style.background = 'transparent'}>
                        <div style={{ width: 34, height: 34, borderRadius: 8, background: uncensored ? 'linear-gradient(135deg, rgba(239,68,68,0.2) 0%, rgba(251,146,60,0.2) 100%)' : 'linear-gradient(135deg, rgba(99,102,241,0.15) 0%, rgba(168,85,247,0.15) 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                          <Layers size={16} color={uncensored ? '#fb923c' : '#818cf8'} />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', wordBreak: 'break-word', overflowWrap: 'anywhere', lineHeight: 1.5, marginBottom: 4 }}>
                            {mid}
                            {uncensored && <span style={{ marginLeft: 6, fontSize: 9, padding: '1px 7px', borderRadius: 4, background: 'rgba(239,68,68,0.15)', color: '#f87171', fontWeight: 700, border: '1px solid rgba(239,68,68,0.2)', whiteSpace: 'nowrap', verticalAlign: 'middle' }}>🔓 Sansürsüz</span>}
                          </div>
                          <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 2, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>❤️ <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{m.likes || 0}</span></span>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>⬇ <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{(m.downloads || 0).toLocaleString()}</span></span>
                            <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, background: 'rgba(99,102,241,0.12)', color: '#a78bfa', fontWeight: 600 }}>{ggufFiles.length} GGUF</span>
                            {(m.tags || []).filter(t => t.startsWith('base_model')).slice(0,1).map(t => <span key={t} style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, background: 'rgba(168,85,247,0.1)', color: '#c084fc' }}>{t.replace('base_model:transform:','').replace('base_model:','')}</span>)}
                          </div>
                        </div>
                        <a href={`https://huggingface.co/${mid}`} target="_blank" rel="noreferrer"
                          onClick={e => e.stopPropagation()}
                          style={{ fontSize: 10, padding: '5px 12px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.06)', color: '#818cf8', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                          🤗 HF
                        </a>
                        <div style={{ flexShrink: 0, display: 'flex', alignItems: 'center', transition: 'transform 0.2s', transform: hfExpanded.has(mid) ? 'rotate(90deg)' : 'rotate(0deg)' }}>
                          <ChevronRight size={16} color="#64748b" />
                        </div>
                      </div>
                      {/* GGUF Files - shown when expanded */}
                      {hfExpanded.has(mid) && ggufFiles.length > 0 && (
                        <div style={{ borderTop: '1px solid rgba(255,255,255,0.04)', padding: '8px 14px 10px', maxHeight: 320, overflowY: 'auto' }}>
                          {ggufFiles.map(f => {
                            const dlLink = `https://huggingface.co/${mid}/resolve/main/${f.rfilename}`;
                            const isDownloading = hfDlProgress?.name === f.rfilename;
                            return (
                              <div key={f.rfilename} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', borderRadius: 7, background: isDownloading ? 'rgba(34,197,94,0.06)' : 'rgba(0,0,0,0.15)', border: `1px solid ${isDownloading ? 'rgba(34,197,94,0.15)' : 'rgba(255,255,255,0.03)'}`, marginBottom: 4 }}>
                                <Layers size={11} color="#64748b" style={{ flexShrink: 0 }} />
                                <a href={dlLink} target="_blank" rel="noreferrer"
                                  onClick={e => e.stopPropagation()}
                                  style={{ flex: 1, fontSize: 11, fontFamily: 'monospace', color: '#94a3b8', wordBreak: 'break-all', lineHeight: 1.4, textDecoration: 'none' }}
                                  onMouseOver={e => e.currentTarget.style.color = '#818cf8'}
                                  onMouseOut={e => e.currentTarget.style.color = '#94a3b8'}>
                                  {f.rfilename}
                                </a>
                                {f.size != null && <span style={{ fontSize: 9, color: '#64748b', fontFamily: 'monospace', flexShrink: 0, background: 'rgba(255,255,255,0.04)', padding: '2px 6px', borderRadius: 4 }}>{(f.size / (1024*1024*1024)).toFixed(2)} GB</span>}
                                <button
                                  onClick={e => { e.stopPropagation(); setConfirmDl({ url: dlLink, name: f.rfilename, model: mid }); }}
                                  disabled={!!hfDlProgress}
                                  style={{ fontSize: 10, padding: '4px 12px', borderRadius: 6, border: 'none', background: hfDlProgress ? '#1e293b' : 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)', color: hfDlProgress ? '#475569' : '#fff', cursor: hfDlProgress ? 'not-allowed' : 'pointer', whiteSpace: 'nowrap', flexShrink: 0, fontWeight: 600, boxShadow: hfDlProgress ? 'none' : '0 1px 6px rgba(34,197,94,0.2)', display: 'flex', alignItems: 'center', gap: 4 }}>
                                  <Download size={11} /> İndir
                                </button>
                              </div>
                            );
                          })}
                        </div>
                      )}
                      {hfExpanded.has(mid) && ggufFiles.length === 0 && (
                        <div style={{ borderTop: '1px solid rgba(255,255,255,0.04)', padding: '8px 14px', fontSize: 11, color: '#475569', textAlign: 'center' }}>GGUF dosyası yok — <a href={`https://huggingface.co/${mid}`} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()} style={{ color: '#818cf8', textDecoration: 'none' }}>HF sayfasına git</a></div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Download from URL */}
          <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 16 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 10 }}>URL'den İndir</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, marginBottom: 8 }}>
              <input value={dlUrl} onChange={e => setDlUrl(e.target.value)} placeholder="https://huggingface.co/⬦/resolve/main/model.gguf" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 11px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
              <input value={dlName} onChange={e => setDlName(e.target.value)} placeholder="filename.gguf" style={{ width: 160, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '7px 11px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            </div>
            <button onClick={startDownload} disabled={!dlUrl || !dlName || !modelsDir || !!dlProgress}
              style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '7px 16px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: dlProgress ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 500 }}>
              <Download size={14} /> {dlProgress ? `Downloading ${dlProgress.pct}%⬦` : 'Download'}
            </button>
            {dlProgress && (
              <div style={{ marginTop: 10 }}>
                <div style={{ height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${dlProgress.pct}%`, background: 'linear-gradient(90deg,#6366f1,#22c55e)', borderRadius: 2, transition: 'width 0.4s' }} />
                </div>
                <div style={{ fontSize: 10, color: '#374151', marginTop: 5, fontFamily: 'monospace' }}>
                  {dlProgress.mb.toFixed(1)} MB / {dlProgress.total_mb.toFixed(1)} MB
                </div>
              </div>
            )}
            {dlError && <div style={{ marginTop: 8, fontSize: 11, color: '#f87171', fontFamily: 'monospace' }}>{dlError}</div>}
          </div>
        </div>
      </Card>

      {/* —�—�—� CUDA Management —�—�—� */}
      <div style={{ marginBottom: 8, fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.08em' }}>CUDA Yönetimi</div>
      <Card style={{ marginBottom: 16 }}>
        <div style={{ padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 38, height: 38, borderRadius: 10, background: cudaInfo ? 'rgba(34,197,94,0.12)' : 'rgba(239,68,68,0.09)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Cpu size={18} color={cudaInfo ? '#4ade80' : '#f87171'} />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: cudaInfo ? '#4ade80' : '#f87171' }}>
                  {cudaInfo ? 'CUDA Kurulu' : 'CUDA Bulunamadı'}
                </div>
                <div style={{ fontSize: 11, color: '#4b5563', marginTop: 2, fontFamily: 'monospace' }}>
                  {cudaInfo || 'nvcc bulunamadı — Toolkit kurulmamış olabilir'}
                </div>
              </div>
            </div>
            <button onClick={checkCuda} disabled={checkingCuda}
              style={{ padding: '5px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.07)', background: 'transparent', color: '#4b5563', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 5 }}>
              <RefreshCw size={12} style={checkingCuda ? { animation: '_sp 0.75s linear infinite' } : {}} /> Kontrol Et
            </button>
          </div>

          {sysInfo?.gpus.some(g => g.cuda) && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8 }}>CUDA GPU'lar</div>
              {sysInfo.gpus.filter(g => g.cuda).map((gpu, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 12px', background: 'rgba(34,197,94,0.04)', borderRadius: 7, marginBottom: 5, border: '1px solid rgba(34,197,94,0.1)' }}>
                  <span style={{ fontSize: 12, color: '#6b7280' }}>{gpu.name}</span>
                  <div style={{ display: 'flex', gap: 14 }}>
                    <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#4ade80' }}>SM {gpu.compute_cap || '—'}</span>
                    <span style={{ fontSize: 11, color: '#374151' }}>{gpu.vram_mb > 0 ? `${(gpu.vram_mb / 1024).toFixed(1)} GB VRAM` : ''}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {!cudaInfo && (
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: '#2d3748', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 12 }}>Kurulum Adımları</div>
              {[
                { n: '1', title: 'GPU Sürücüsü',        desc: 'En güncel NVIDIA sürücüsünü kurun (GeForce Experience veya nvidia.com)' },
                { n: '2', title: 'VS C++ Build Tools',   desc: 'CUDA derleyicisi için gerekli — Microsoft Build Tools 2022 kurun' },
                { n: '3', title: 'CUDA Toolkit',         desc: 'GPU Compute Capability\'nize uygun sürümü NVIDIA sitesinden indirin ve kurun' },
                { n: '4', title: 'Terminali Yeniden Başlat', desc: 'CUDA_PATH ve PATH değişkenleri otomatik eklenir — yeni terminal açın' },
                { n: '5', title: 'Doğrula',              desc: '"Kontrol Et" butonuna basın ya da terminalde: nvcc --version' },
              ].map(({ n, title, desc }) => (
                <div key={n} style={{ display: 'flex', gap: 12, marginBottom: 10 }}>
                  <div style={{ width: 22, height: 22, borderRadius: 6, background: 'rgba(99,102,241,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontSize: 10, fontWeight: 700, color: '#818cf8' }}>{n}</div>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#6b7280' }}>{title}</div>
                    <div style={{ fontSize: 11, color: '#374151', marginTop: 2 }}>{desc}</div>
                  </div>
                </div>
              ))}
              <a href="https://developer.nvidia.com/cuda-downloads" target="_blank" rel="noreferrer"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 6, padding: '7px 15px', borderRadius: 8, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', textDecoration: 'none', fontSize: 12, fontWeight: 500 }}>
                <Download size={13} /> CUDA Toolkit İndir
              </a>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

// —�—�—� Chat Page (LM Studio + GGUF Direct) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

export default SystemPage;