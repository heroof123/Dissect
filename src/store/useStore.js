import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export const VIEWS = {
  SCANNER: 'scanner', PATCHER: 'patcher', DISASM: 'disasm',
  SYSTEM: 'system', CHAT: 'chat', PLUGINS: 'plugins',
  DASHBOARD: 'dashboard', ATTACH: 'attach', DEBUGGER: 'debugger',
  EMULATION: 'emulation', NETWORK: 'network', FLIRT: 'flirt',
};

export const THEMES = {
  dark:       { bg: '#0d1117', sidebar: '#010409', accent: '#6366f1', accentL: '#818cf8', border: 'rgba(255,255,255,0.06)' },
  red:        { bg: '#0d0707', sidebar: '#080101', accent: '#ef4444', accentL: '#f87171', border: 'rgba(239,68,68,0.12)' },
  ocean:      { bg: '#030c18', sidebar: '#020810', accent: '#0ea5e9', accentL: '#38bdf8', border: 'rgba(14,165,233,0.12)' },
  hicontrast: { bg: '#000000', sidebar: '#0a0a0a', accent: '#ffffff', accentL: '#ffffff', border: 'rgba(255,255,255,0.3)' },
};

// 12.4 — Custom theme support
const CUSTOM_THEME_KEY = 'dissect_custom_themes';
function loadCustomThemes() { try { return JSON.parse(localStorage.getItem(CUSTOM_THEME_KEY) || '{}'); } catch { return {}; } }
function saveCustomThemes(t) { localStorage.setItem(CUSTOM_THEME_KEY, JSON.stringify(t)); }
export function getAllThemes() {
  return { ...THEMES, ...loadCustomThemes() };
}
export function addCustomTheme(name, colors) {
  const t = loadCustomThemes();
  t[name] = colors;
  saveCustomThemes(t);
}
export function removeCustomTheme(name) {
  const t = loadCustomThemes();
  delete t[name];
  saveCustomThemes(t);
}

const LANGS = {
  tr: {
    scanner: 'Collector Layer', patcher: 'Hex Patcher', disasm: 'Disassembly', chat: 'AI Chat',
    system: 'System & Models', plugins: 'Plugins', dashboard: 'Dashboard',
    scanComplete: 'Tarama Tamamlandı', risk: 'Risk', clean: 'Temiz', moderate: 'Orta', high: 'Yüksek',
    overview: 'Genel Bakış', strings: 'Stringler', imports: 'İmportlar', sections: 'Bölümler',
    entropy: 'Entropi', yara: 'YARA', hashes: 'Hash\'ler', diff: 'Fark',
    search: 'Ara', filter: 'Filtre', export: 'Dışa Aktar', report: 'Rapor',
    totalScans: 'Toplam Tarama', avgRisk: 'Ortalama Risk', timeline: 'Zaman Çizelgesi',
    projects: 'Projeler', create: 'Oluştur', delete: 'Sil', noData: 'Veri yok',
  },
  en: {
    scanner: 'Collector Layer', patcher: 'Hex Patcher', disasm: 'Disassembly', chat: 'AI Chat',
    system: 'System & Models', plugins: 'Plugins', dashboard: 'Dashboard',
    scanComplete: 'Scan Complete', risk: 'Risk', clean: 'Clean', moderate: 'Moderate', high: 'High',
    overview: 'Overview', strings: 'Strings', imports: 'Imports', sections: 'Sections',
    entropy: 'Entropy', yara: 'YARA', hashes: 'Hashes', diff: 'Diff',
    search: 'Search', filter: 'Filter', export: 'Export', report: 'Report',
    totalScans: 'Total Scans', avgRisk: 'Average Risk', timeline: 'Timeline',
    projects: 'Projects', create: 'Create', delete: 'Delete', noData: 'No data',
  },
};

const useStore = create(
  persist(
    (set, get) => ({
      // — Navigation —
      view: VIEWS.SCANNER,
      setView: (v) => set({ view: v }),
      disasmFilePath: null,
      openInDisasm: (filePath) => set({ disasmFilePath: filePath, view: VIEWS.DISASM }),

      // — UI Preferences (persisted) —
      theme: 'dark',
      setTheme: (t) => set({ theme: t }),
      lang: 'tr',
      setLang: (l) => set({ lang: l }),
      get t() { return LANGS[get().lang] || LANGS.tr; },
      zoom: 1,
      setZoom: (z) => set({ zoom: Math.round(z * 100) / 100 }),
      sidebarWidth: 196,
      setSidebarWidth: (w) => set({ sidebarWidth: w }),
      tourDone: false,
      setTourDone: (v) => set({ tourDone: v }),

      // — Chat Contexts —
      chatContexts: [],
      setChatContexts: (fn) => set((s) => ({
        chatContexts: typeof fn === 'function' ? fn(s.chatContexts) : fn,
      })),
      sendToChat: (ctx) => {
        const id = Date.now() + '_' + Math.random().toString(36).slice(2, 7);
        set((s) => ({
          chatContexts: [...s.chatContexts, { ...ctx, _id: id, _selected: true, _ts: Date.now() }],
          view: VIEWS.CHAT,
        }));
      },

      // — Scan History (contextual) —
      scanHistory: [],
      sendToAI: (result, fileName) => {
        set((s) => {
          const entry = { fileName, sha256: result.sha256, riskScore: result.riskScore, arch: result.arch, denuvo: result.denuvo, vmp: result.vmp, antiDebug: result.antiDebug, packers: result.packers };
          return { scanHistory: [entry, ...s.scanHistory].slice(0, 5) };
        });
        // also send to chat
        get().sendToChat({ type: 'pe_analyst', fileName, ...result });
      },

      // — Command Palette —
      cmdOpen: false,
      setCmdOpen: (v) => set({ cmdOpen: v }),
      cmdQuery: '',
      setCmdQuery: (q) => set({ cmdQuery: q }),
    }),
    {
      name: 'dissect-store',
      partialize: (state) => ({
        theme: state.theme,
        lang: state.lang,
        zoom: state.zoom,
        sidebarWidth: state.sidebarWidth,
        tourDone: state.tourDone,
      }),
    }
  )
);

// Hook shortcut for translations
export function useLang() {
  const lang = useStore((s) => s.lang);
  const setLang = useStore((s) => s.setLang);
  const t = LANGS[lang] || LANGS.tr;
  return { lang, setLang, t };
}

export default useStore;
