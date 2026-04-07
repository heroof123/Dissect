import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import {
  Cpu, HardDrive, MemoryStick, Download, RefreshCw, FolderOpen,
  Search, CheckCircle2, XCircle, Zap, Play, Layers
} from 'lucide-react';
import { Card, CardHeader, Spinner } from './shared';

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
  const [hfExpanded, setHfExpanded] = useState(null); // expanded model id

  const refreshSys = async () => {
    setLoadingSys(true);
    try { setSysInfo(await invoke('get_system_info')); }
    catch (e) { console.error(e); }
    finally { setLoadingSys(false); }
  };

  const scanModels = async () => {
    if (!modelsDir) return;
    localStorage.setItem('dissect_models_dir', modelsDir);
    try { setModels(await invoke('list_models', { dir: modelsDir })); }
    catch (e) { console.error(e); }
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
            <button onClick={scanModels} style={{ padding: '7px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}><FolderOpen size={14} /> Scan</button>
          </div>

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
          <div style={{ marginBottom: 16, borderRadius: 10, background: 'rgba(251,191,36,0.04)', border: '1px solid rgba(251,191,36,0.15)', padding: '12px 14px' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#fbbf24', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 10 }}>🔍 HuggingFace GGUF Arama</div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
              <input value={hfQuery} onChange={e => setHfQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && searchHfGguf()}
                 placeholder="Örn: qwen2.5, llama-3, mistral-7b, phi-3&"
                style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(251,191,36,0.2)', borderRadius: 7, padding: '7px 11px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
              <button onClick={searchHfGguf} disabled={hfSearching || !hfQuery.trim()}
                style={{ padding: '7px 16px', borderRadius: 7, border: '1px solid rgba(251,191,36,0.3)', background: 'rgba(251,191,36,0.08)', color: '#fbbf24', cursor: hfSearching ? 'wait' : 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
                {hfSearching ? <><RefreshCw size={13} style={{ animation: '_sp 0.75s linear infinite' }} /> Aranıyor⬦</> : '🔍 Ara'}
              </button>
            </div>
            {hfError && <div style={{ fontSize: 11, color: '#f87171', marginBottom: 8 }}>{hfError}</div>}
            {hfResults.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 340, overflowY: 'auto' }}>
                {hfResults.map((m) => {
                  const mid = m.id || m.modelId || '';
                  const isExp = hfExpanded === mid;
                  const ggufFiles = (m.siblings || []).filter(s => s.rfilename?.endsWith('.gguf'));
                  return (
                    <div key={mid} style={{ borderRadius: 8, background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.12)', overflow: 'hidden' }}>
                      <div style={{ padding: '9px 12px', display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}
                        onClick={() => setHfExpanded(isExp ? null : mid)}>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{mid}</div>
                          <div style={{ fontSize: 10, color: '#64748b', marginTop: 1, display: 'flex', gap: 10 }}>
                            <span>👍 {m.likes || 0}</span>
                            <span>? {(m.downloads || 0).toLocaleString()}</span>
                            {(m.tags || []).filter(t => t.startsWith('base_model')).slice(0,1).map(t => <span key={t} style={{ color: '#818cf8' }}>{t.replace('base_model:transform:','').replace('base_model:','')}</span>)}
                          </div>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                          <a href={`https://huggingface.co/${mid}`} target="_blank" rel="noreferrer"
                            onClick={e => e.stopPropagation()}
                            style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', textDecoration: 'none' }}>
                            HF ↓
                          </a>
                          <span style={{ fontSize: 11, color: isExp ? '#818cf8' : '#4b5563' }}>{isExp ? '📂' : '📁'}</span>
                        </div>
                      </div>
                      {isExp && (
                        <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', padding: '8px 12px 10px' }}>
                          {ggufFiles.length === 0 ? (
                            <div style={{ fontSize: 11, color: '#4b5563' }}>Bu model i?in GGUF dosyası listelenmemiş. HuggingFace sayfasından manuel indirin.</div>
                          ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                              <div style={{ fontSize: 10, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>GGUF Dosyaları ({ggufFiles.length})</div>
                              {ggufFiles.map(f => {
                                const dlLink = `https://huggingface.co/${mid}/resolve/main/${f.rfilename}`;
                                return (
                                  <div key={f.rfilename} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 8px', borderRadius: 6, background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.08)' }}>
                                    <span style={{ flex: 1, fontSize: 11, fontFamily: 'monospace', color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.rfilename}</span>
                                    <button onClick={() => { setDlUrl(dlLink); setDlName(f.rfilename); }}
                                      style={{ fontSize: 10, padding: '3px 9px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.07)', color: '#4ade80', cursor: 'pointer', whiteSpace: 'nowrap', flexShrink: 0 }}>
                                      ↓ İndir
                                    </button>
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
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