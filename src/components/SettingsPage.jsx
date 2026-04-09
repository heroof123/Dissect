import React, { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Settings, Palette, Layout, Keyboard, Maximize2, Monitor,
  Save, Download, Upload, RefreshCw, ChevronRight, Type, Eye
} from 'lucide-react';
import { Card, CardHeader } from './shared';

// ─── Varsayılan temalar ───────────────────────────────────────────────────
const DEFAULT_THEMES = {
  dark: {
    name: 'Koyu (Varsayılan)',
    bg: '#0d1117', sidebar: '#111827', card: '#1a1f2e',
    accent: '#6366f1', accentLight: '#818cf8', success: '#22c55e',
    warning: '#f59e0b', danger: '#ef4444', text: '#e2e8f0', textMuted: '#6b7280',
    border: 'rgba(255,255,255,0.06)', fontSize: 12, fontFamily: 'Inter, sans-serif'
  },
  midnight: {
    name: 'Gece Yarısı',
    bg: '#000000', sidebar: '#0a0a0a', card: '#111111',
    accent: '#7c3aed', accentLight: '#a78bfa', success: '#16a34a',
    warning: '#d97706', danger: '#dc2626', text: '#f8fafc', textMuted: '#4b5563',
    border: 'rgba(255,255,255,0.04)', fontSize: 12, fontFamily: 'JetBrains Mono, monospace'
  },
  github: {
    name: 'GitHub Koyu',
    bg: '#0d1117', sidebar: '#161b22', card: '#21262d',
    accent: '#58a6ff', accentLight: '#79c0ff', success: '#3fb950',
    warning: '#d29922', danger: '#f85149', text: '#c9d1d9', textMuted: '#8b949e',
    border: 'rgba(48,54,61,1)', fontSize: 12, fontFamily: 'Segoe UI, sans-serif'
  },
  solarized: {
    name: 'Solarized Koyu',
    bg: '#002b36', sidebar: '#073642', card: '#073642',
    accent: '#268bd2', accentLight: '#2aa198', success: '#859900',
    warning: '#b58900', danger: '#dc322f', text: '#839496', textMuted: '#586e75',
    border: 'rgba(7,54,66,1)', fontSize: 12, fontFamily: 'Consolas, monospace'
  }
};

// ─── Klavye kısayol haritası ─────────────────────────────────────────────
const DEFAULT_SHORTCUTS = [
  { action: 'Tarama Başlat', keys: 'Ctrl+R', category: 'Analiz' },
  { action: 'Disassembly Görünümü', keys: 'Ctrl+D', category: 'Gezinti' },
  { action: 'Hex Editor', keys: 'Ctrl+H', category: 'Gezinti' },
  { action: 'Import Tablosu', keys: 'Ctrl+I', category: 'Analiz' },
  { action: 'String Görünümü', keys: 'Ctrl+S', category: 'Analiz' },
  { action: 'AI Sohbet', keys: 'Ctrl+/', category: 'AI' },
  { action: 'Sidebar Gizle/Göster', keys: 'Ctrl+B', category: 'Arayüz' },
  { action: 'Önceki Sekme', keys: 'Ctrl+←', category: 'Gezinti' },
  { action: 'Sonraki Sekme', keys: 'Ctrl+→', category: 'Gezinti' },
  { action: 'Yeni Pencere', keys: 'Ctrl+N', category: 'Arayüz' },
];

// ─── Hex Viewer Tablo bileşeni ────────────────────────────────────────────
function HexViewerTable({ rows, fontSize }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ borderCollapse: 'collapse', fontSize: fontSize || 11, fontFamily: 'JetBrains Mono, Consolas, monospace', width: '100%' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
            <th style={{ padding: '4px 10px', textAlign: 'left', color: '#374151', fontWeight: 600, minWidth: 90 }}>Ofset</th>
            <th style={{ padding: '4px 10px', textAlign: 'left', color: '#374151', fontWeight: 600 }}>Hex</th>
            <th style={{ padding: '4px 10px', textAlign: 'left', color: '#374151', fontWeight: 600, minWidth: 130 }}>ASCII</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', background: i % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent' }}>
              <td style={{ padding: '2px 10px', color: '#6366f1', fontWeight: 600 }}>{`0x${row.offset.toString(16).toUpperCase().padStart(8, '0')}`}</td>
              <td style={{ padding: '2px 10px', color: '#94a3b8', letterSpacing: 1 }}>
                {row.hex.map((b, j) => (
                  <span key={j} style={{ marginRight: j % 8 === 7 ? 12 : 6, color: b === '00' ? '#374151' : '#94a3b8' }}>{b}</span>
                ))}
              </td>
              <td style={{ padding: '2px 10px', color: '#6b7280' }}>{row.ascii}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Renk seçici satır ───────────────────────────────────────────────────
function ColorRow({ label, value, onChange }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 0' }}>
      <span style={{ fontSize: 11, color: '#94a3b8', minWidth: 110 }}>{label}</span>
      <input type="color" value={value} onChange={e => onChange(e.target.value)}
        style={{ width: 32, height: 22, border: 'none', background: 'none', cursor: 'pointer', padding: 0 }} />
      <span style={{ fontSize: 10, color: '#374151', fontFamily: 'monospace' }}>{value}</span>
    </div>
  );
}

export default function SettingsPage({ filePath }) {
  const [tab, setTab] = useState('theme');
  const [themeName, setThemeName] = useState('dark');
  const [customTheme, setCustomTheme] = useState({ ...DEFAULT_THEMES.dark });
  const [savedThemes, setSavedThemes] = useState([]);
  const [newThemeName, setNewThemeName] = useState('');
  const [layouts, setLayouts] = useState([]);
  const [layoutName, setLayoutName] = useState('');
  const [msg, setMsg] = useState('');
  const [msgType, setMsgType] = useState('info');
  const [hexRows, setHexRows] = useState([]);
  const [hexOffset, setHexOffset] = useState(0);
  const [hexLoading, setHexLoading] = useState(false);
  const [fileInfo, setFileInfo] = useState(null);
  const [dataInspect, setDataInspect] = useState(null);
  const [selectedByte, setSelectedByte] = useState(null);
  const [fontSize, setFontSize] = useState(12);
  const [fontFamily, setFontFamily] = useState('Inter, sans-serif');
  const [shortcuts] = useState(DEFAULT_SHORTCUTS);

  const showMsg = (text, type = 'info') => { setMsg(text); setMsgType(type); setTimeout(() => setMsg(''), 3500); };

  // Tema ve layout listelerini yükle
  useEffect(() => {
    invoke('list_themes').then(r => setSavedThemes(r.themes || [])).catch(() => {});
    invoke('list_layouts').then(r => setLayouts(r.layouts || [])).catch(() => {});
  }, []);

  // Dosya değişince hex bilgi yükle
  useEffect(() => {
    if (!filePath) return;
    invoke('large_file_info', { filePath }).then(setFileInfo).catch(() => {});
    loadHexChunk(0);
  }, [filePath]);

  const loadHexChunk = useCallback((offset) => {
    if (!filePath) return;
    setHexLoading(true);
    invoke('read_file_chunk', { filePath, offset: typeof offset === 'bigint' ? Number(offset) : offset, length: 512 })
      .then(r => { setHexRows(r.rows || []); setHexOffset(offset); })
      .catch(e => showMsg('Chunk okunamadı: ' + e, 'error'))
      .finally(() => setHexLoading(false));
  }, [filePath]);

  const handleThemeSelect = (key) => {
    setThemeName(key);
    if (DEFAULT_THEMES[key]) setCustomTheme({ ...DEFAULT_THEMES[key] });
  };

  const handleSaveTheme = async () => {
    const name = newThemeName || customTheme.name;
    try {
      await invoke('save_theme', { name, themeJson: customTheme });
      const r = await invoke('list_themes');
      setSavedThemes(r.themes || []);
      showMsg(`Tema '${name}' kaydedildi`, 'success');
    } catch (e) { showMsg('Kaydetme hatası: ' + e, 'error'); }
  };

  const handleSaveLayout = async () => {
    if (!layoutName.trim()) { showMsg('Layout adı girin', 'error'); return; }
    const layout = {
      fontSize, fontFamily, themeName,
      savedAt: new Date().toISOString(),
      activePanel: 'disassembly', sidebarWidth: 220
    };
    try {
      await invoke('save_layout', { name: layoutName, layoutJson: layout });
      const r = await invoke('list_layouts');
      setLayouts(r.layouts || []);
      showMsg(`Layout '${layoutName}' kaydedildi`, 'success');
    } catch (e) { showMsg('Hata: ' + e, 'error'); }
  };

  const inspectBytes = (row) => {
    setSelectedByte(row.offset);
    const hex = row.hex;
    if (hex.length < 8) return;
    const b = hex.slice(0, 8).map(h => parseInt(h, 16));
    const buf = new Uint8Array(b);
    const view = new DataView(buf.buffer);
    setDataInspect({
      int8: view.getInt8(0),
      uint8: view.getUint8(0),
      int16le: view.getInt16(0, true),
      uint16le: view.getUint16(0, true),
      int32le: view.getInt32(0, true),
      uint32le: view.getUint32(0, true),
      float32le: view.getFloat32(0, true).toFixed(6),
      hexStr: b.map(x => x.toString(16).padStart(2, '0')).join(' ')
    });
  };

  const TabBtn = ({ id, label }) => (
    <button onClick={() => setTab(id)} style={{ fontSize: 11, padding: '6px 14px', borderRadius: '7px 7px 0 0', border: '1px solid ' + (tab === id ? 'rgba(99,102,241,0.3)' : 'rgba(255,255,255,0.04)'), borderBottom: tab === id ? '2px solid #6366f1' : '1px solid rgba(255,255,255,0.04)', background: tab === id ? 'rgba(99,102,241,0.08)' : 'transparent', color: tab === id ? '#818cf8' : '#4b5563', cursor: 'pointer', fontWeight: tab === id ? 700 : 400 }}>
      {label}
    </button>
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px' }}>
      {/* Başlık */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Settings size={17} color="#818cf8" />
        </div>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: '#e2e8f0', margin: 0 }}>Ayarlar & UI/UX</h1>
          <p style={{ fontSize: 11, color: '#374151', margin: 0 }}>FAZ F — Tema Editörü · Layout · Hex Editor Pro · Kısayollar</p>
        </div>
      </div>

      {msg && (
        <div style={{ marginBottom: 12, padding: '8px 14px', borderRadius: 8, background: msgType === 'success' ? 'rgba(34,197,94,0.08)' : msgType === 'error' ? 'rgba(239,68,68,0.08)' : 'rgba(99,102,241,0.08)', border: '1px solid ' + (msgType === 'success' ? 'rgba(34,197,94,0.2)' : msgType === 'error' ? 'rgba(239,68,68,0.2)' : 'rgba(99,102,241,0.2)'), fontSize: 11, color: msgType === 'success' ? '#4ade80' : msgType === 'error' ? '#f87171' : '#818cf8' }}>
          {msg}
        </div>
      )}

      {/* Sekmeler */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 0, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <TabBtn id="theme" label="🎨 Tema Editörü" />
        <TabBtn id="layout" label="⬡ Layout" />
        <TabBtn id="hex" label="🔢 Hex Editor Pro" />
        <TabBtn id="shortcuts" label="⌨️ Kısayollar" />
        <TabBtn id="font" label="Aa Font & Boyut" />
      </div>

      {/* ── FAZ F3: Tema Editörü ─────────────────────────────────── */}
      {tab === 'theme' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 12 }}>
          <Card>
            <CardHeader>Hazır Temalar</CardHeader>
            <div style={{ padding: '10px 16px' }}>
              {Object.entries(DEFAULT_THEMES).map(([key, t]) => (
                <div key={key} onClick={() => handleThemeSelect(key)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 8, cursor: 'pointer', background: themeName === key ? 'rgba(99,102,241,0.08)' : 'transparent', border: '1px solid ' + (themeName === key ? 'rgba(99,102,241,0.3)' : 'transparent'), marginBottom: 4 }}>
                  <div style={{ width: 20, height: 20, borderRadius: 4, background: t.accent }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{t.name}</div>
                    <div style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace' }}>{t.bg} / {t.accent}</div>
                  </div>
                  {themeName === key && <span style={{ fontSize: 9, color: '#818cf8', fontWeight: 700 }}>AKTİF</span>}
                </div>
              ))}
              {savedThemes.map(name => (
                <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 8, cursor: 'pointer', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', marginBottom: 4 }}>
                  <div style={{ width: 20, height: 20, borderRadius: 4, background: '#6366f1' }} />
                  <div style={{ flex: 1, fontSize: 12, color: '#94a3b8' }}>{name} <span style={{ fontSize: 9, color: '#374151' }}>(özel)</span></div>
                  <button onClick={() => invoke('load_theme', { name }).then(t => { setCustomTheme(t); showMsg(`'${name}' yüklendi`, 'success'); }).catch(e => showMsg(e, 'error'))} style={{ fontSize: 9, padding: '3px 8px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.06)', color: '#818cf8', cursor: 'pointer' }}>Yükle</button>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader>Renk Editörü</CardHeader>
            <div style={{ padding: '12px 16px' }}>
              <ColorRow label="Arkaplan" value={customTheme.bg || '#0d1117'} onChange={v => setCustomTheme(p => ({ ...p, bg: v }))} />
              <ColorRow label="Sidebar" value={customTheme.sidebar || '#111827'} onChange={v => setCustomTheme(p => ({ ...p, sidebar: v }))} />
              <ColorRow label="Kart Arkaplan" value={customTheme.card || '#1a1f2e'} onChange={v => setCustomTheme(p => ({ ...p, card: v }))} />
              <ColorRow label="Vurgu Rengi" value={customTheme.accent || '#6366f1'} onChange={v => setCustomTheme(p => ({ ...p, accent: v }))} />
              <ColorRow label="Vurgu (Açık)" value={customTheme.accentLight || '#818cf8'} onChange={v => setCustomTheme(p => ({ ...p, accentLight: v }))} />
              <ColorRow label="Başarı" value={customTheme.success || '#22c55e'} onChange={v => setCustomTheme(p => ({ ...p, success: v }))} />
              <ColorRow label="Uyarı" value={customTheme.warning || '#f59e0b'} onChange={v => setCustomTheme(p => ({ ...p, warning: v }))} />
              <ColorRow label="Tehlike" value={customTheme.danger || '#ef4444'} onChange={v => setCustomTheme(p => ({ ...p, danger: v }))} />
              <ColorRow label="Metin" value={customTheme.text || '#e2e8f0'} onChange={v => setCustomTheme(p => ({ ...p, text: v }))} />

              <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
                <input value={newThemeName} onChange={e => setNewThemeName(e.target.value)} placeholder="Tema adı..." style={{ flex: 1, fontSize: 11, padding: '6px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e2e8f0', outline: 'none' }} />
                <button onClick={handleSaveTheme} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 5 }}>
                  <Save size={12} /> Kaydet
                </button>
              </div>

              {/* Önizleme */}
              <div style={{ marginTop: 12, borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ background: customTheme.sidebar, padding: '6px 12px', fontSize: 10, color: customTheme.accentLight, fontWeight: 700 }}>Tema Önizleme</div>
                <div style={{ background: customTheme.bg, padding: 12 }}>
                  <div style={{ background: customTheme.card, borderRadius: 6, padding: '8px 12px', border: `1px solid ${customTheme.border || 'rgba(255,255,255,0.06)'}` }}>
                    <div style={{ fontSize: 11, color: customTheme.text, fontWeight: 600, marginBottom: 4 }}>Örnek Başlık</div>
                    <div style={{ fontSize: 10, color: customTheme.textMuted || '#6b7280' }}>Örnek açıklama metni</div>
                    <div style={{ marginTop: 8, display: 'flex', gap: 6 }}>
                      <div style={{ padding: '3px 10px', borderRadius: 4, background: customTheme.accent, color: '#fff', fontSize: 10 }}>Buton</div>
                      <div style={{ padding: '3px 10px', borderRadius: 4, background: 'rgba(34,197,94,0.1)', color: customTheme.success, fontSize: 10 }}>Başarı</div>
                      <div style={{ padding: '3px 10px', borderRadius: 4, background: 'rgba(239,68,68,0.1)', color: customTheme.danger, fontSize: 10 }}>Tehlike</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* ── FAZ F1: Layout Yönetimi ───────────────────────────────── */}
      {tab === 'layout' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 12 }}>
          <Card>
            <CardHeader>Kayıtlı Layoutlar</CardHeader>
            <div style={{ padding: '10px 16px' }}>
              {layouts.length === 0 && (
                <div style={{ fontSize: 11, color: '#374151', textAlign: 'center', padding: '16px 0' }}>Henüz kaydedilmiş layout yok.</div>
              )}
              {layouts.map(name => (
                <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', marginBottom: 6 }}>
                  <Layout size={14} color="#818cf8" />
                  <span style={{ flex: 1, fontSize: 12, color: '#e2e8f0' }}>{name}</span>
                  <button onClick={() => invoke('load_layout', { name }).then(l => showMsg(`Layout yüklendi: ${JSON.stringify(l).slice(0, 60)}...`, 'success')).catch(e => showMsg(e, 'error'))} style={{ fontSize: 9, padding: '3px 10px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.07)', color: '#818cf8', cursor: 'pointer' }}>Yükle</button>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader>Yeni Layout Kaydet</CardHeader>
            <div style={{ padding: '16px' }}>
              <div style={{ fontSize: 11, color: '#6b7280', marginBottom: 12, lineHeight: 1.6 }}>
                Mevcut pencere düzeninizi (tema, font, panel boyutları) bir profil olarak kaydedin.
              </div>
              <input value={layoutName} onChange={e => setLayoutName(e.target.value)} placeholder="Layout adı (örn: RE Workspace)" style={{ width: '100%', fontSize: 12, padding: '8px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e2e8f0', outline: 'none', marginBottom: 10 }} />
              <div style={{ fontSize: 10, color: '#374151', marginBottom: 10 }}>
                Kaydedilecekler: <span style={{ color: '#94a3b8' }}>Tema ({themeName}), Font ({fontSize}px {fontFamily.split(',')[0]}), Aktif panel referansı</span>
              </div>
              <button onClick={handleSaveLayout} style={{ fontSize: 12, padding: '8px 18px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Save size={13} /> Layout Kaydet
              </button>

              <div style={{ marginTop: 20, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Monitor size={13} color="#818cf8" /> Panel Yapılandırması
                </div>
                {[
                  { label: 'Sidebar Genişliği', val: '220px', note: 'Daralt: 48px / Geniş: 280px' },
                  { label: 'Split View', val: 'Kapalı', note: 'Yan yana iki panel görünümü' },
                  { label: 'Disassembly Pano', val: 'Ana Panel', note: 'Merkez konumda' },
                  { label: 'Terminal Pano', val: 'Alt Panel', note: '200px yükseklik' },
                ].map((item, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <span style={{ fontSize: 11, color: '#94a3b8', minWidth: 150 }}>{item.label}</span>
                    <span style={{ fontSize: 11, color: '#818cf8', fontFamily: 'monospace' }}>{item.val}</span>
                    <span style={{ fontSize: 9, color: '#374151', marginLeft: 8 }}>{item.note}</span>
                  </div>
                ))}
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* ── FAZ F2: Hex Editor Pro ───────────────────────────────── */}
      {tab === 'hex' && (
        <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 280px', gap: 12 }}>
          <Card>
            <CardHeader>
              Hex Editor Pro — {filePath ? filePath.split(/[/\\]/).pop() : 'Dosya Seçilmedi'}
              {fileInfo && (
                <span style={{ marginLeft: 8, fontSize: 9, color: '#374151' }}>
                  {fileInfo.size_mb}MB · {fileInfo.format}
                  {fileInfo.is_large && <span style={{ color: '#f59e0b', marginLeft: 8 }}>⚠ Büyük dosya — streaming mod</span>}
                </span>
              )}
            </CardHeader>
            {!filePath ? (
              <div style={{ padding: '24px', textAlign: 'center', fontSize: 11, color: '#374151' }}>Bir dosya seçin (sol paneldeki "Dosya Yolu" alanından)</div>
            ) : (
              <div style={{ padding: '8px 0' }}>
                {/* Navigasyon */}
                <div style={{ display: 'flex', gap: 8, padding: '4px 16px 10px', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <button onClick={() => loadHexChunk(Math.max(0, hexOffset - 512))} disabled={hexOffset === 0 || hexLoading} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#94a3b8', cursor: 'pointer' }}>◀ Önceki</button>
                  <span style={{ fontSize: 10, color: '#374151', fontFamily: 'monospace' }}>Ofset: 0x{hexOffset.toString(16).toUpperCase().padStart(8, '0')}</span>
                  <button onClick={() => loadHexChunk(hexOffset + 512)} disabled={hexLoading} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#94a3b8', cursor: 'pointer' }}>Sonraki ▶</button>
                  <button onClick={() => loadHexChunk(0)} disabled={hexLoading} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#94a3b8', cursor: 'pointer' }}>Başa Git</button>
                  {hexLoading && <RefreshCw size={12} color="#818cf8" style={{ animation: 'spin 1s linear infinite' }} />}
                </div>

                {hexRows.length > 0 ? (
                  <div onClick={e => {
                    const row = hexRows.find(r => r.offset === hexOffset + Math.floor((e.nativeEvent.offsetY) / 18) * 16);
                    if (row) inspectBytes(row);
                  }}>
                    <HexViewerTable rows={hexRows} fontSize={fontSize - 1} />
                  </div>
                ) : (
                  <div style={{ padding: 16, fontSize: 11, color: '#374151', textAlign: 'center' }}>Yükleniyor...</div>
                )}
              </div>
            )}
          </Card>

          {/* Data Inspector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <Card>
              <CardHeader>Data Inspector</CardHeader>
              <div style={{ padding: '10px 16px' }}>
                {!dataInspect ? (
                  <div style={{ fontSize: 10, color: '#374151', textAlign: 'center', padding: '12px 0' }}>Bir satıra tıklayın</div>
                ) : (
                  <div>
                    <div style={{ fontSize: 10, color: '#6366f1', fontFamily: 'monospace', marginBottom: 8 }}>
                      Seçili: {dataInspect.hexStr}
                    </div>
                    {[
                      ['Int8', dataInspect.int8],
                      ['UInt8', dataInspect.uint8],
                      ['Int16 LE', dataInspect.int16le],
                      ['UInt16 LE', dataInspect.uint16le],
                      ['Int32 LE', dataInspect.int32le],
                      ['UInt32 LE', dataInspect.uint32le],
                      ['Float32 LE', dataInspect.float32le],
                    ].map(([label, val]) => (
                      <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.03)', fontSize: 10 }}>
                        <span style={{ color: '#6b7280' }}>{label}</span>
                        <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{val}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>

            <Card>
              <CardHeader>Dosya Bilgisi</CardHeader>
              <div style={{ padding: '10px 16px' }}>
                {fileInfo ? (
                  [
                    ['Format', fileInfo.format],
                    ['Boyut', `${fileInfo.size_mb} MB`],
                    ['Blok (4K)', fileInfo.block_count_4k],
                    ['Büyük Dosya', fileInfo.is_large ? 'Evet' : 'Hayır'],
                    ['Streaming', fileInfo.streaming_supported ? 'Aktif' : 'Pasif'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.03)', fontSize: 10 }}>
                      <span style={{ color: '#6b7280' }}>{k}</span>
                      <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{v}</span>
                    </div>
                  ))
                ) : (
                  <div style={{ fontSize: 10, color: '#374151', textAlign: 'center', padding: '10px 0' }}>Dosya seçilmedi</div>
                )}
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* ── Klavye Kısayolları ────────────────────────────────────── */}
      {tab === 'shortcuts' && (
        <Card style={{ marginTop: 12 }}>
          <CardHeader>Klavye Kısayolları (IDA/x64dbg Uyumlu)</CardHeader>
          <div style={{ padding: '0 0 8px' }}>
            {['Analiz', 'Gezinti', 'AI', 'Arayüz'].map(cat => (
              <div key={cat}>
                <div style={{ padding: '8px 16px 4px', fontSize: 10, fontWeight: 700, color: '#4b5563', textTransform: 'uppercase', letterSpacing: 1, background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>{cat}</div>
                {shortcuts.filter(s => s.category === cat).map((s, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '7px 16px', borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                    <span style={{ fontSize: 11, color: '#94a3b8' }}>{s.action}</span>
                    <kbd style={{ fontSize: 11, padding: '3px 10px', borderRadius: 5, background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.25)', color: '#818cf8', fontFamily: 'monospace', fontWeight: 600 }}>{s.keys}</kbd>
                  </div>
                ))}
              </div>
            ))}
          </div>
          <div style={{ padding: '12px 16px', fontSize: 10, color: '#374151', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
            * Kısayollar yalnızca referans amaçlıdır. Tauri uygulamasında global shortcut kaydı için ayrı implementasyon gereklidir.
          </div>
        </Card>
      )}

      {/* ── Font & Boyut ──────────────────────────────────────────── */}
      {tab === 'font' && (
        <Card style={{ marginTop: 12 }}>
          <CardHeader>Font & Görünüm Ayarları</CardHeader>
          <div style={{ padding: '16px' }}>
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0', marginBottom: 8 }}>Arayüz Font Ailesi</div>
              {[
                { label: 'Inter (Varsayılan)', css: 'Inter, sans-serif' },
                { label: 'JetBrains Mono', css: 'JetBrains Mono, monospace' },
                { label: 'Consolas', css: 'Consolas, monospace' },
                { label: 'Segoe UI', css: 'Segoe UI, sans-serif' },
                { label: 'System UI', css: 'system-ui, sans-serif' },
              ].map(f => (
                <div key={f.css} onClick={() => setFontFamily(f.css)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 8, cursor: 'pointer', background: fontFamily === f.css ? 'rgba(99,102,241,0.08)' : 'transparent', border: '1px solid ' + (fontFamily === f.css ? 'rgba(99,102,241,0.3)' : 'transparent'), marginBottom: 4 }}>
                  <span style={{ fontSize: 13, fontFamily: f.css, color: '#e2e8f0' }}>Aa Bb Cc 0123</span>
                  <span style={{ fontSize: 10, color: '#6b7280', marginLeft: 8 }}>{f.label}</span>
                  {fontFamily === f.css && <span style={{ fontSize: 9, color: '#818cf8', fontWeight: 700, marginLeft: 'auto' }}>SEÇİLİ</span>}
                </div>
              ))}
            </div>

            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0', marginBottom: 8 }}>Font Boyutu: <span style={{ color: '#818cf8' }}>{fontSize}px</span></div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <button onClick={() => setFontSize(p => Math.max(9, p - 1))} style={{ fontSize: 14, width: 28, height: 28, borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#94a3b8', cursor: 'pointer' }}>−</button>
                <input type="range" min="9" max="18" value={fontSize} onChange={e => setFontSize(Number(e.target.value))} style={{ flex: 1 }} />
                <button onClick={() => setFontSize(p => Math.min(18, p + 1))} style={{ fontSize: 14, width: 28, height: 28, borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#94a3b8', cursor: 'pointer' }}>+</button>
                <button onClick={() => setFontSize(12)} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.06)', color: '#818cf8', cursor: 'pointer' }}>Sıfırla</button>
              </div>

              {/* Önizleme */}
              <div style={{ marginTop: 16, padding: 16, borderRadius: 8, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ fontSize, fontFamily, color: '#e2e8f0', lineHeight: 1.6 }}>
                  Arayüz metin önizlemesi — {fontSize}px {fontFamily.split(',')[0]}<br />
                  <span style={{ fontFamily: 'monospace', fontSize: fontSize - 1, color: '#94a3b8' }}>
                    0x00401000: push ebp; mov ebp, esp; sub esp, 0x20
                  </span>
                </div>
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
