import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert, Binary, FileSearch, Bot, Layers, Terminal, Cpu,
  Plus, Trash2, Play, Search, Download, RefreshCw, Code, Globe, Share2, Star
} from 'lucide-react';
import { _pluginHooks } from '../utils/peHelpers';
import { Card, CardHeader } from './shared';

const DissectPluginAPI = {
  onScan(fn)          { if (typeof fn === 'function') _pluginHooks.onScan.push(fn); },
  onPatch(fn)         { if (typeof fn === 'function') _pluginHooks.onPatch.push(fn); },
  onDisassemble(fn)   { if (typeof fn === 'function') _pluginHooks.onDisassemble.push(fn); },
  registerCommand(label, fn) { if (label && typeof fn === 'function') _pluginHooks.commands.push({ label, fn }); },
  registerView(id, label, renderFn) { if (id && typeof renderFn === 'function') _pluginHooks.views.push({ id, label, renderFn }); },
  accessAI(prompt)    { _pluginHooks.aiQueries.push(prompt); return prompt; },
  log(...args)        { console.log('[Plugin]', ...args); },
  getHistory()        { try { return JSON.parse(localStorage.getItem('dissect_scan_history') || '[]'); } catch { return []; } },
};

// ── 5.1 Plugin Loader — sandboxed execution ──────────────────────
const PLUGIN_STORE_KEY = 'dissect_plugins_v2';
function loadInstalledPlugins() { try { return JSON.parse(localStorage.getItem(PLUGIN_STORE_KEY) || '[]'); } catch { return []; } }
function saveInstalledPlugins(list) { localStorage.setItem(PLUGIN_STORE_KEY, JSON.stringify(list)); }
function executePluginCode(code, pluginId) {
  try {
    const sandbox = new Function('Dissect', 'console', '"use strict";\n' + code);
    const safeConsole = { log: (...a) => console.log('[Plugin:' + pluginId + ']', ...a), warn: (...a) => console.warn('[Plugin:' + pluginId + ']', ...a), error: (...a) => console.error('[Plugin:' + pluginId + ']', ...a) };
    sandbox(DissectPluginAPI, safeConsole);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
}

// ── 5.4 Example Plugins ─────────────────────────────────────────

const EXAMPLE_PLUGINS = [
  {
    id: 'string_decoder', name: 'String Decoder', version: '1.0.0', author: 'Dissect Team',
    desc: 'Base64, XOR, ROT13 encoded stringleri otomatik decode eder.',
    stars: 4.7, downloads: 1240, tags: ['strings', 'decoder', 'obfuscation'],
    code: `
Dissect.onScan(function(result) {
  var decoded = [];
  (result.strings || []).forEach(function(s) {
    var text = s.text || s;
    if (/^[A-Za-z0-9+\\/]{16,}={0,2}$/.test(text)) {
      try { var d = atob(text); if (/^[\\x20-\\x7e]+$/.test(d)) decoded.push({original:text,method:'Base64',decoded:d}); } catch(e){}
    }
    if (/^[A-Za-z]{8,}$/.test(text)) {
      var r = text.replace(/[a-zA-Z]/g, function(c) { return String.fromCharCode((c<='Z'?90:122)>=(c.charCodeAt(0)+13)?c.charCodeAt(0)+13:c.charCodeAt(0)-13); });
      if (r !== text && /(?:http|dll|exe|cmd|reg|key)/i.test(r)) decoded.push({original:text,method:'ROT13',decoded:r});
    }
  });
  if (decoded.length > 0) Dissect.log('Decoded ' + decoded.length + ' strings:', decoded);
});
Dissect.registerCommand('Decode Strings', function() { Dissect.log('String decoder active'); });`,
  },
  {
    id: 'crypto_identifier', name: 'Crypto Identifier', version: '1.0.0', author: 'Dissect Team',
    desc: 'Kriptografik sabit degerlerden (magic numbers) algoritma tespiti.',
    stars: 4.5, downloads: 890, tags: ['crypto', 'detection', 'constants'],
    code: `
var CRYPTO_SIGS = [
  {name:'AES S-Box',hex:'637c777bf26b6fc5',algo:'AES'},
  {name:'SHA-256 Init',hex:'6a09e667bb67ae85',algo:'SHA-256'},
  {name:'MD5 T[1]',hex:'d76aa478',algo:'MD5'},
  {name:'Blowfish P',hex:'243f6a8885a308d3',algo:'Blowfish'},
  {name:'CRC32 Poly',hex:'edb88320',algo:'CRC32'},
  {name:'TEA Delta',hex:'9e3779b9',algo:'TEA/XTEA'},
];
Dissect.onScan(function(result) {
  var found = [];
  var allText = (result.strings||[]).map(function(s){return(s.text||s).toLowerCase();}).join(' ');
  CRYPTO_SIGS.forEach(function(sig){if(allText.indexOf(sig.hex)>=0) found.push(sig);});
  (result.imports||[]).forEach(function(imp){
    var dll=(imp.dll||'').toLowerCase();
    if(dll.indexOf('bcrypt')>=0||dll.indexOf('ncrypt')>=0) found.push({name:dll,algo:'Windows CNG'});
    if(dll.indexOf('crypt32')>=0) found.push({name:dll,algo:'CryptoAPI'});
  });
  if(found.length>0) Dissect.log('Crypto detected:',found);
});
Dissect.registerCommand('Crypto Report', function(){Dissect.log('Crypto identifier active');});`,
  },
  {
    id: 'import_highlighter', name: 'Import Highlighter', version: '1.0.0', author: 'Dissect Team',
    desc: 'Tehlikeli Windows API cagilarini tespit edip kategorize eder.',
    stars: 4.8, downloads: 1580, tags: ['imports', 'security', 'api'],
    code: `
var DANGEROUS={
  'Injection':['VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','NtCreateThreadEx','QueueUserAPC','SetWindowsHookEx'],
  'Execution':['ShellExecuteA','ShellExecuteW','WinExec','CreateProcessA','CreateProcessW'],
  'Persistence':['RegSetValueExA','RegSetValueExW','CreateServiceA','CreateServiceW'],
  'Anti-Debug':['IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess'],
  'Network':['InternetOpenA','HttpSendRequestA','URLDownloadToFileA','WSAStartup','connect','send','recv'],
};
Dissect.onScan(function(result){
  var hits={};
  (result.imports||[]).forEach(function(imp){
    (imp.functions||[]).forEach(function(fn){
      Object.keys(DANGEROUS).forEach(function(cat){
        if(DANGEROUS[cat].some(function(api){return fn.indexOf(api)>=0;})){
          if(!hits[cat])hits[cat]=[];
          hits[cat].push(fn+' ('+((imp.dll)||'?')+')');
        }
      });
    });
  });
  var total=Object.values(hits).reduce(function(s,a){return s+a.length;},0);
  if(total>0) Dissect.log('Dangerous APIs: '+total+' hits',hits);
});
Dissect.registerCommand('Show Dangerous APIs', function(){Dissect.log('Import highlighter active');});`,
  },
];

// ── Builtin display list ─────────────────────────────────────────

const BUILTIN_PLUGINS = [
  { id:'pe_scanner',  name:'PE Scanner',       desc:'PE header, entropy, section, string, import analizi.', icon:<ShieldAlert size={15}/>, version:'2.0.0', status:'active', builtin:true },
  { id:'hex_patcher', name:'Hex Patcher',       desc:'Binary offset yamalama, NOP injection, backup.',      icon:<Binary size={15}/>,      version:'2.0.0', status:'active', builtin:true },
  { id:'yara_engine', name:'YARA Engine',       desc:'JS tabanli davranissal kural motoru, 15 kural.',      icon:<FileSearch size={15}/>,  version:'1.0.0', status:'active', builtin:true },
  { id:'ai_analyst',  name:'AI Analyst',        desc:'LM Studio streaming PE analiz entegrasyonu.',         icon:<Bot size={15}/>,         version:'2.2.0', status:'active', builtin:true },
  { id:'binary_diff', name:'Binary Diff',       desc:'Iki PE dosyasini yan yana karsilastirma.',            icon:<Layers size={15}/>,      version:'1.0.0', status:'active', builtin:true },
  { id:'hex_viewer',  name:'Hex Region Viewer', desc:'Bolge bazli ham hex okuma (Rust destekli).',          icon:<Terminal size={15}/>,    version:'1.0.0', status:'active', builtin:true },
  { id:'sig_scanner', name:'Packer Signatures', desc:'UPX/MPRESS/ASPack/Petite imza tanima.',               icon:<Cpu size={15}/>,         version:'1.0.0', status:'active', builtin:true },
];

// ── 5.2 Plugin Marketplace + Full UI ─────────────────────────────

function PluginPage() {
  const [tab, setTab] = useState('installed');
  const [installed, setInstalled] = useState(loadInstalledPlugins);
  const [customCode, setCustomCode] = useState('');
  const [customName, setCustomName] = useState('');
  const [loadMsg, setLoadMsg] = useState('');
  const [msgType, setMsgType] = useState('info');
  const [search, setSearch] = useState('');
  const [ratings, setRatings] = useState(() => { try { return JSON.parse(localStorage.getItem('dissect_plugin_ratings') || '{}'); } catch { return {}; } });

  // 12.5 — Community hub state
  const [communityYara, setCommunityYara] = useState(() => { try { return JSON.parse(localStorage.getItem('dissect_community_yara') || '[]'); } catch { return []; } });
  const [sharedPlugins, setSharedPlugins] = useState(() => { try { return JSON.parse(localStorage.getItem('dissect_shared_plugins') || '[]'); } catch { return []; } });
  const [yaraInput, setYaraInput] = useState('');
  const [yaraAuthor, setYaraAuthor] = useState('');
  const [leaderboard, setLeaderboard] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_leaderboard') || '[]'); } catch { return []; }
  });

  const showMsg = (msg, type = 'info') => { setLoadMsg(msg); setMsgType(type); setTimeout(() => setLoadMsg(''), 4000); };

  useEffect(() => { installed.forEach(p => { if (p.enabled) executePluginCode(p.code, p.id); }); }, []);

  const installPlugin = (plugin) => {
    if (installed.find(p => p.id === plugin.id)) { showMsg(plugin.name + ' zaten yuklu.', 'error'); return; }
    const entry = { id: plugin.id, name: plugin.name, version: plugin.version, author: plugin.author || 'Unknown', desc: plugin.desc, code: plugin.code, enabled: true, installedAt: new Date().toISOString(), tags: plugin.tags || [] };
    const res = executePluginCode(entry.code, entry.id);
    if (res.success) { const u = [entry, ...installed]; setInstalled(u); saveInstalledPlugins(u); showMsg(plugin.name + ' basariyla kuruldu.', 'success'); }
    else showMsg('Plugin hata: ' + res.error, 'error');
  };
  const uninstallPlugin = (id) => { const u = installed.filter(p => p.id !== id); setInstalled(u); saveInstalledPlugins(u); showMsg('Plugin kaldirildi.', 'info'); };
  const togglePlugin = (id) => {
    const u = installed.map(p => { if (p.id !== id) return p; const ns = !p.enabled; if (ns) executePluginCode(p.code, p.id); return { ...p, enabled: ns }; });
    setInstalled(u); saveInstalledPlugins(u);
  };
  const installCustom = () => {
    if (!customCode.trim()) { showMsg('Kod bos olamaz.', 'error'); return; }
    const id = 'custom_' + Date.now(), name = customName.trim() || 'Custom Plugin';
    const entry = { id, name, version: '1.0.0', author: 'User', desc: 'Kullanici tanimli plugin', code: customCode, enabled: true, installedAt: new Date().toISOString(), tags: ['custom'] };
    const res = executePluginCode(entry.code, entry.id);
    if (res.success) { const u = [entry, ...installed]; setInstalled(u); saveInstalledPlugins(u); setCustomCode(''); setCustomName(''); showMsg(name + ' kuruldu.', 'success'); }
    else showMsg('Hata: ' + res.error, 'error');
  };
  const handleFileLoad = () => {
    const input = document.createElement('input'); input.type = 'file'; input.accept = '.js,.txt';
    input.onchange = async (e) => { const f = e.target.files?.[0]; if (!f) return; setCustomCode(await f.text()); setCustomName(f.name.replace(/\.(js|txt)$/, '')); showMsg(f.name + ' yuklendi.', 'info'); };
    input.click();
  };
  const ratePlugin = (pid, stars) => { const u = { ...ratings, [pid]: stars }; setRatings(u); localStorage.setItem('dissect_plugin_ratings', JSON.stringify(u)); };

  const StarRating = ({ pluginId, readonly, value }) => {
    const v = readonly ? value : (ratings[pluginId] || 0);
    return (<div style={{ display: 'flex', gap: 2 }}>{[1,2,3,4,5].map(s => (<span key={s} onClick={() => !readonly && ratePlugin(pluginId, s)} style={{ cursor: readonly ? 'default' : 'pointer', fontSize: 12, color: s <= v ? '#fbbf24' : '#1f2937' }}>&#9733;</span>))}{!readonly && v > 0 && <span style={{ fontSize: 9, color: '#374151', marginLeft: 4 }}>{v}/5</span>}</div>);
  };
  const TabBtn = ({ id, label, count }) => (
    <button onClick={() => setTab(id)} style={{ fontSize: 11, padding: '6px 14px', borderRadius: '7px 7px 0 0', border: '1px solid ' + (tab === id ? 'rgba(99,102,241,0.3)' : 'rgba(255,255,255,0.04)'), borderBottom: tab === id ? '2px solid #6366f1' : '1px solid rgba(255,255,255,0.04)', background: tab === id ? 'rgba(99,102,241,0.08)' : 'transparent', color: tab === id ? '#818cf8' : '#4b5563', cursor: 'pointer', fontWeight: tab === id ? 700 : 400 }}>
      {label} {count !== undefined && <span style={{ fontSize: 9, opacity: 0.6 }}>({count})</span>}
    </button>
  );
  const PluginCard = ({ p, actions, dimmed }) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)', opacity: dimmed ? 0.45 : 1 }}>
      <div style={{ width: 32, height: 32, borderRadius: 8, background: 'rgba(99,102,241,0.09)', border: '1px solid rgba(99,102,241,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#818cf8', flexShrink: 0, fontSize: 14 }}>{p.icon || '🧩'}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{p.name} <span style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace' }}>v{p.version}</span></div>
        <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>{p.desc}</div>
        {p.tags && <div style={{ display: 'flex', gap: 4, marginTop: 3 }}>{p.tags.map(t => <span key={t} style={{ fontSize: 8, padding: '1px 6px', borderRadius: 3, background: 'rgba(99,102,241,0.06)', color: '#6366f1', fontWeight: 500 }}>{t}</span>)}</div>}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>{actions}</div>
    </div>
  );
  const marketplace = EXAMPLE_PLUGINS.filter(p => !search || p.name.toLowerCase().includes(search.toLowerCase()) || p.tags.some(t => t.includes(search.toLowerCase())));

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Layers size={17} color="#818cf8" /></div>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: '#e2e8f0', margin: 0 }}>Plugin Ecosystem</h1>
          </div>
          <p style={{ fontSize: 11, color: '#374151', margin: 0 }}>FAZ 5 — Magaza · Yukleyici · Sandbox API · Hook sistemi</p>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <span style={{ fontSize: 10, padding: '4px 10px', borderRadius: 6, background: 'rgba(34,197,94,0.08)', color: '#4ade80', fontWeight: 600 }}>{installed.filter(p => p.enabled).length} aktif</span>
          <span style={{ fontSize: 10, padding: '4px 10px', borderRadius: 6, background: 'rgba(99,102,241,0.08)', color: '#818cf8', fontWeight: 600 }}>{_pluginHooks.commands.length} cmd</span>
        </div>
      </div>
      {loadMsg && <div style={{ marginBottom: 12, padding: '8px 14px', borderRadius: 8, background: msgType==='success'?'rgba(34,197,94,0.08)':msgType==='error'?'rgba(239,68,68,0.08)':'rgba(99,102,241,0.08)', border: '1px solid '+(msgType==='success'?'rgba(34,197,94,0.2)':msgType==='error'?'rgba(239,68,68,0.2)':'rgba(99,102,241,0.2)'), fontSize: 11, color: msgType==='success'?'#4ade80':msgType==='error'?'#f87171':'#818cf8' }}>{loadMsg}</div>}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 0, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <TabBtn id="installed" label="Yuklu" count={installed.length} />
        <TabBtn id="marketplace" label="Magaza" count={EXAMPLE_PLUGINS.length} />
        <TabBtn id="builtin" label="Dahili" count={BUILTIN_PLUGINS.length} />
        <TabBtn id="custom" label="Ozel Plugin Yukle" />
        <TabBtn id="api" label="API Dokumantasyon" />
        <TabBtn id="community" label="Topluluk" count={communityYara.length + sharedPlugins.length} />
      </div>

      {/* Installed */}
      {tab === 'installed' && (
        <Card>
          <CardHeader>Kurulu Pluginler — {installed.length}</CardHeader>
          {installed.length === 0 ? (
            <div style={{ padding: '20px 16px', textAlign: 'center', fontSize: 11, color: '#374151' }}>Henuz plugin kurulmamis. Magazadan veya ozel plugin yukleyebilirsiniz.</div>
          ) : installed.map(p => (
            <PluginCard key={p.id} p={p} actions={<>
              <StarRating pluginId={p.id} />
              <button onClick={() => togglePlugin(p.id)} style={{ fontSize: 9, padding: '3px 10px', borderRadius: 5, border: '1px solid '+(p.enabled?'rgba(34,197,94,0.3)':'rgba(239,68,68,0.2)'), background: p.enabled?'rgba(34,197,94,0.08)':'rgba(239,68,68,0.06)', color: p.enabled?'#4ade80':'#f87171', cursor: 'pointer', fontWeight: 600 }}>{p.enabled?'ON':'OFF'}</button>
              <button onClick={() => uninstallPlugin(p.id)} style={{ fontSize: 9, padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.2)', background: 'transparent', color: '#f87171', cursor: 'pointer' }}>X</button>
            </>} />
          ))}
        </Card>
      )}

      {/* Marketplace (5.2) */}
      {tab === 'marketplace' && (
        <Card>
          <CardHeader>Plugin Magazasi</CardHeader>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Plugin ara... (isim veya etiket)" style={{ width: '100%', fontSize: 12, padding: '7px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e5e7eb', outline: 'none' }} />
          </div>
          {marketplace.map(p => {
            const isInst = installed.find(i => i.id === p.id);
            return (
              <PluginCard key={p.id} p={p} actions={<>
                <div style={{ textAlign: 'right', marginRight: 4 }}>
                  <StarRating pluginId={p.id} readonly value={p.stars} />
                  <div style={{ fontSize: 8, color: '#374151' }}>{p.downloads} indirme</div>
                </div>
                {isInst ? <span style={{ fontSize: 9, padding: '3px 10px', borderRadius: 5, background: 'rgba(34,197,94,0.08)', color: '#4ade80', fontWeight: 700 }}>Yuklu</span>
                  : <button onClick={() => installPlugin(p)} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>Kur</button>}
              </>} />
            );
          })}
        </Card>
      )}

      {/* Built-in */}
      {tab === 'builtin' && (
        <Card>
          <CardHeader>Dahili Moduller — {BUILTIN_PLUGINS.length}</CardHeader>
          <div style={{ padding: '4px 0 8px' }}>
            {BUILTIN_PLUGINS.map(p => (
              <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '9px 16px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                <div style={{ width: 30, height: 30, borderRadius: 7, background: 'rgba(99,102,241,0.09)', border: '1px solid rgba(99,102,241,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#818cf8', flexShrink: 0 }}>{p.icon}</div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{p.name} <span style={{ fontSize: 9, color: '#374151', fontFamily: 'monospace' }}>v{p.version}</span></div>
                  <div style={{ fontSize: 10, color: '#374151', marginTop: 1 }}>{p.desc}</div>
                </div>
                <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 4, background: 'rgba(34,197,94,0.1)', color: '#4ade80', fontWeight: 700 }}>ACTIVE</span>
                <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, background: 'rgba(99,102,241,0.1)', color: '#818cf8', fontWeight: 600 }}>built-in</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Custom Plugin Loader (5.1) */}
      {tab === 'custom' && (
        <Card>
          <CardHeader>Ozel Plugin Yukle (5.1)</CardHeader>
          <div style={{ padding: '16px' }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
              <input value={customName} onChange={e => setCustomName(e.target.value)} placeholder="Plugin adi..." style={{ flex: 1, fontSize: 12, padding: '7px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e5e7eb', outline: 'none' }} />
              <button onClick={handleFileLoad} style={{ fontSize: 11, padding: '7px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.07)', color: '#818cf8', cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}><Download size={13} /> .js Dosyadan Yukle</button>
              <button onClick={installCustom} style={{ fontSize: 11, padding: '7px 14px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontWeight: 600 }}>Kur</button>
            </div>
            <textarea value={customCode} onChange={e => setCustomCode(e.target.value)} placeholder={'// Plugin kodunuzu buraya yazin veya yukleyin\n// API: Dissect.onScan(fn), Dissect.onPatch(fn),\n// Dissect.onDisassemble(fn), Dissect.registerCommand(label,fn),\n// Dissect.registerView(id,label,renderFn), Dissect.accessAI(prompt),\n// Dissect.log(...), Dissect.getHistory()\n\nDissect.onScan(function(result) {\n  Dissect.log("Scan:", result.fileName, "Risk:", result.riskScore);\n});\nDissect.registerCommand("My Command", function() {\n  Dissect.log("Custom command executed!");\n});'}
              style={{ width: '100%', height: 260, fontSize: 11, fontFamily: 'monospace', padding: '12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.3)', color: '#e5e7eb', outline: 'none', resize: 'vertical', lineHeight: 1.6 }} />
            <div style={{ marginTop: 10, padding: '10px 14px', borderRadius: 8, background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.15)' }}>
              <div style={{ fontSize: 10, color: '#fbbf24', fontWeight: 600, marginBottom: 4 }}>Guvenlik Notu</div>
              <div style={{ fontSize: 10, color: '#92400e', lineHeight: 1.5 }}>Pluginler sandbox ortaminda calisir. Sadece Dissect API ve console objesine erisebilirler. DOM, fetch, localStorage, eval gibi global APIlere erisimleri yoktur.</div>
            </div>
          </div>
        </Card>
      )}

      {/* API Documentation (5.3) */}
      {tab === 'api' && (
        <Card>
          <CardHeader>Plugin API v2.0 (FAZ 5.3)</CardHeader>
          <div style={{ padding: '16px' }}>
            <pre style={{ fontSize: 10, fontFamily: 'monospace', color: '#94a3b8', margin: 0, lineHeight: 1.7, background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 8, overflowX: 'auto' }}>
{`// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Dissect Plugin API v2.0 (FAZ 5)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Hook: tarama sonucu
Dissect.onScan(function(result) {
  // result: {fileName,arch,riskScore,
  //  sections,imports,strings,entropy,
  //  sha256,md5,packers,denuvo,vmp,...}
  console.log('Scan:', result);
});

// Hook: patch uygulandi
Dissect.onPatch(function(info) {
  // info: {offset,oldBytes,newBytes,fileName}
});

// Hook: disassembly
Dissect.onDisassemble(function(data) {
  // data: {address,instructions,functionName}
});

// Komut paleti (Ctrl+K) komutu ekle
Dissect.registerCommand('My Cmd', function() {
  Dissect.log('Executed!');
});

// Ozel panel kaydet
Dissect.registerView('my_view', 'Panel', fn);

// AI'a soru gonder
Dissect.accessAI('prompt text');

// Yardimci
Dissect.log('msg', {data: 123});
var h = Dissect.getHistory(); // read-only

// Plugin Manifest:
// { id, name, version, author, desc,
//   tags, code }
`}
            </pre>
          </div>
        </Card>
      )}

      {/* Plugin-registered views (5.3) */}
      {getPluginViews().length > 0 && (
        <Card style={{ marginTop: 16 }}>
          <CardHeader>Plugin Panelleri ({getPluginViews().length})</CardHeader>
          <div style={{ padding: '8px 16px' }}>
            {getPluginViews().map(v => (
              <div key={v.id} style={{ padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 11, color: '#94a3b8' }}>
                <span style={{ fontWeight: 600, color: '#e2e8f0' }}>{v.label}</span>
                <span style={{ fontSize: 9, color: '#374151', marginLeft: 8 }}>ID: {v.id}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* 12.5 — Community Hub */}
      {tab === 'community' && (
        <Card>
          <CardHeader>Topluluk Hub</CardHeader>
          <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* YARA Rule Share */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <FileSearch size={13} color="#818cf8" /> YARA Kural Paylaşımı
              </div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <input value={yaraAuthor} onChange={e => setYaraAuthor(e.target.value)} placeholder="Yazar adı"
                  style={{ width: 120, padding: '5px 8px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.3)', fontSize: 11, color: '#e2e8f0', outline: 'none' }} />
                <button onClick={() => {
                  if (!yaraInput.trim()) return;
                  const entry = { id: Date.now(), author: yaraAuthor || 'anonymous', rule: yaraInput, date: new Date().toISOString(), likes: 0 };
                  const updated = [entry, ...communityYara].slice(0, 100);
                  setCommunityYara(updated);
                  localStorage.setItem('dissect_community_yara', JSON.stringify(updated));
                  setYaraInput('');
                  // Update leaderboard
                  const lb = [...leaderboard];
                  const existing = lb.find(l => l.author === entry.author);
                  if (existing) { existing.yaraCount = (existing.yaraCount || 0) + 1; }
                  else { lb.push({ author: entry.author, yaraCount: 1, pluginCount: 0 }); }
                  setLeaderboard(lb);
                  localStorage.setItem('dissect_leaderboard', JSON.stringify(lb));
                  showMsg('YARA kuralı paylaşıldı!', 'success');
                }}
                  style={{ padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', fontSize: 11, cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Share2 size={11} /> Paylaş
                </button>
              </div>
              <textarea value={yaraInput} onChange={e => setYaraInput(e.target.value)} placeholder="rule example_rule { ... }" rows={4}
                style={{ width: '100%', padding: 8, borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.3)', fontSize: 11, color: '#e2e8f0', fontFamily: 'monospace', outline: 'none', resize: 'vertical', boxSizing: 'border-box' }} />
              {/* Community YARA list */}
              <div style={{ maxHeight: 200, overflowY: 'auto', marginTop: 8 }}>
                {communityYara.map(y => (
                  <div key={y.id} style={{ padding: '6px 8px', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                      <span style={{ color: '#818cf8', fontWeight: 600 }}>{y.author}</span>
                      <span style={{ color: '#374151', fontSize: 9 }}>{new Date(y.date).toLocaleDateString()}</span>
                      <button onClick={() => {
                        const updated = communityYara.map(r => r.id === y.id ? { ...r, likes: (r.likes || 0) + 1 } : r);
                        setCommunityYara(updated);
                        localStorage.setItem('dissect_community_yara', JSON.stringify(updated));
                      }} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer', fontSize: 10, display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Star size={10} /> {y.likes || 0}
                      </button>
                    </div>
                    <pre style={{ margin: 0, color: '#9ca3af', fontFamily: 'monospace', fontSize: 9, whiteSpace: 'pre-wrap', maxHeight: 60, overflow: 'hidden' }}>{y.rule.slice(0, 200)}</pre>
                  </div>
                ))}
                {communityYara.length === 0 && <div style={{ color: '#374151', textAlign: 'center', padding: 16, fontSize: 11 }}>Henüz paylaşılan kural yok</div>}
              </div>
            </div>

            {/* Plugin Share */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Globe size={13} color="#22c55e" /> Plugin Paylaşımı
              </div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <button onClick={() => {
                  const toShare = installed.filter(p => p.enabled);
                  if (toShare.length === 0) { showMsg('Paylaşılacak aktif plugin yok', 'error'); return; }
                  const shareData = toShare.map(p => ({ name: p.name, id: p.id, version: p.version, code: p.code, author: p.author || 'anonymous' }));
                  const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(shareData))));
                  navigator.clipboard.writeText(encoded).then(() => showMsg(`${toShare.length} plugin kodu panoya kopyalandı`, 'success'));
                  // Update leaderboard
                  const lb = [...leaderboard];
                  const existing = lb.find(l => l.author === 'me');
                  if (existing) { existing.pluginCount = (existing.pluginCount || 0) + toShare.length; }
                  else { lb.push({ author: 'me', yaraCount: 0, pluginCount: toShare.length }); }
                  setLeaderboard(lb);
                  localStorage.setItem('dissect_leaderboard', JSON.stringify(lb));
                }}
                  style={{ padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', fontSize: 11, cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Share2 size={11} /> Pluginleri Dışa Aktar
                </button>
                <button onClick={() => {
                  const code = prompt('Plugin kodunu yapıştırın (base64):');
                  if (!code) return;
                  try {
                    const decoded = JSON.parse(decodeURIComponent(escape(atob(code))));
                    const arr = Array.isArray(decoded) ? decoded : [decoded];
                    let count = 0;
                    arr.forEach(p => {
                      if (p.code && p.name) {
                        const id = p.id || 'imported_' + Date.now();
                        const existing = installed.find(i => i.id === id);
                        if (!existing) {
                          const newPlugin = { id, name: p.name, version: p.version || '1.0.0', author: p.author || 'imported', desc: 'İçe aktarılmış plugin', code: p.code, enabled: false, installedAt: new Date().toISOString() };
                          installed.push(newPlugin);
                          count++;
                        }
                      }
                    });
                    if (count > 0) {
                      setInstalled([...installed]);
                      saveInstalledPlugins(installed);
                      showMsg(`${count} plugin içe aktarıldı`, 'success');
                    } else { showMsg('İçe aktarılacak yeni plugin bulunamadı', 'info'); }
                  } catch { showMsg('Geçersiz plugin kodu', 'error'); }
                }}
                  style={{ padding: '5px 14px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', fontSize: 11, cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Download size={11} /> İçe Aktar
                </button>
              </div>
            </div>

            {/* Leaderboard */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Star size={13} color="#fbbf24" /> Leaderboard
              </div>
              {leaderboard.length > 0 ? (
                <div style={{ display: 'grid', gridTemplateColumns: '40px 1fr 80px 80px', gap: '4px 8px', fontSize: 10 }}>
                  <span style={{ color: '#6b7280', fontWeight: 600 }}>#</span>
                  <span style={{ color: '#6b7280', fontWeight: 600 }}>Yazar</span>
                  <span style={{ color: '#6b7280', fontWeight: 600 }}>YARA</span>
                  <span style={{ color: '#6b7280', fontWeight: 600 }}>Plugin</span>
                  {leaderboard
                    .sort((a, b) => ((b.yaraCount || 0) + (b.pluginCount || 0)) - ((a.yaraCount || 0) + (a.pluginCount || 0)))
                    .slice(0, 10)
                    .map((l, i) => (
                      <React.Fragment key={i}>
                        <span style={{ color: i < 3 ? '#fbbf24' : '#9ca3af', fontWeight: i < 3 ? 700 : 400 }}>{i + 1}</span>
                        <span style={{ color: '#e2e8f0' }}>{l.author}</span>
                        <span style={{ color: '#818cf8' }}>{l.yaraCount || 0}</span>
                        <span style={{ color: '#22c55e' }}>{l.pluginCount || 0}</span>
                      </React.Fragment>
                    ))}
                </div>
              ) : (
                <div style={{ color: '#374151', textAlign: 'center', padding: 16, fontSize: 11 }}>Henüz liderlik tablosu verisi yok. Paylaşım yaparak tabloyu doldurun!</div>
              )}
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

// ── CFG Panel (1.3) ──────────────────────────────────────────────────────────

export default PluginPage;