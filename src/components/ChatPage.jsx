import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import {
  Send, Bot, MemoryStick, XCircle, CheckCircle2, MessageSquare,
  Plus, Trash2, RefreshCw, Copy, Search, Download,
  ChevronDown, Zap, AlertTriangle, CircleDot
} from 'lucide-react';
import { Card, CardHeader, Spinner, MdText } from './shared';

// AI Mode definitions (used by ChatPage render)
const QUICK_PROMPTS = [
  { label: '🛡 Koruma mekanizması',  text: 'Bu binary\'deki koruma mekanizmalarını detaylıca açıkla. Hangi katmanlar var ve nasıl çalışıyor?' },
  { label: '⚠️ Risk faktörleri',     text: 'Bu analizin tüm risk faktörlerini öncelik sırasına göre listele ve her birini açıkla.' },
  { label: '✎ Import analizi',       text: 'Import tablosundaki en şüpheli fonksiyonları listele. Anti-debug, network, crypto olanları özellikle işaretle.' },
  { label: '📊 Entropy yorumu',       text: 'Yüksek entropi değerleri ne anlama gelir? Bu binary\'de packer veya şifreleme var mı?' },
  { label: '🗺 Nereden başlamalıyım?',   text: 'Bu binary\'yi tersine mühendislik ile incelemek istesem nereden başlamalıyım? Adım adım anlat.' },
  { label: '🧠 Hipotez üret',         text: 'Mevcut verilere dayanarak bu binary\'nin amacı ve davranışı hakkında 3 farklı hipotez üret.' },
  { label: '🔍 Anti-debug detay',     text: 'Tespit edilen anti-debug tekniklerini açıkla. Her biri debugger\'ı nasıl etkiler?' },
  { label: '📋 Özet rapor',           text: 'Tüm bulguları kısa ve net bir executive summary olarak özetle. Teknik olmayan bir okuyucuya hitap et.' },
  { label: '🎯 YARA kuralı üret',      text: 'Bu PE analizindeki benzersiz özelliklere dayanarak tam ve geçerli YARA kuralları oluştur. Meta, strings ve condition bölümlerini dahil et. SHA256, import imzaları, section özellikleri ve şüpheli stringleri kullan. Sadece geçerli YARA sözdizimi çıktısında ver.' },
];

const FOLLOWUP_BY_MODE = {
  explain:    ['Bu davranışı daha basit anlat', 'Benzer bir örnek ver', 'Hangi araçlarla incelenebilir?'],
  analyze:    ['Ba?ka hangi protectionlar olabilir?', 'Risk skorunu detaylandır', 'False positive olabilir mi?'],
  guide:      ['Bir sonraki adım ne?', 'Hangi aracı kullanmalıyım?', 'Nereye dikkat etmeliyim?'],
  hypothesis: ['Bu hipotezi nasıl do?rularım?', 'Alternatif senaryo var mı?', 'En olası hangisi ve neden?'],
};

// —�—�—� AI Modes (CoreXAI 2 Blueprint) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

const AI_MODES = [
  {
    id: 'explain',
    label: 'Explain',
    color: '#818cf8',
    bg: 'rgba(99,102,241,0.10)',
    border: 'rgba(99,102,241,0.28)',
    desc: 'Describe behavior & logic',
    system: 'You are Dissect, a local AI-powered reverse engineering and security analysis assistant. You are in EXPLAIN mode. Your goal is to clearly describe what the analyzed binary/code does, how it behaves, what patterns and functions are present, and what the overall logic means. Be structured, educational, and clear. Highlight important patterns. Do NOT provide direct bypass, crack, or patch solutions — focus on understanding and explanation.',
  },
  {
    id: 'analyze',
    label: 'Analyze',
    color: '#f59e0b',
    bg: 'rgba(245,158,11,0.08)',
    border: 'rgba(245,158,11,0.28)',
    desc: 'Detect patterns & classify',
    system: 'You are Dissect, a local AI-powered reverse engineering and security analysis assistant. You are in ANALYZE mode. Your goal is to detect patterns, identify protection mechanisms (Denuvo, VMProtect, Themida, etc.), classify suspicious behaviors, assess risk, and build a technical profile of the binary. Be precise and technical. List your findings clearly and explain why each one matters. Do NOT provide direct bypass or cracking solutions.',
  },
  {
    id: 'guide',
    label: 'Guide',
    color: '#4ade80',
    bg: 'rgba(34,197,94,0.07)',
    border: 'rgba(34,197,94,0.22)',
    desc: 'Step-by-step mentoring',
    system: 'You are Dissect, a local AI-powered reverse engineering and security analysis assistant. You are in GUIDE mode. Act as a mentor and guide the user step-by-step through understanding the binary. Ask clarifying questions. Break the problem into manageable steps. Suggest what to investigate next. Use the Socratic method — help the user discover answers themselves rather than giving direct solutions. Do NOT provide bypass, crack, or patch solutions.',
  },
  {
    id: 'hypothesis',
    label: 'Hypothesis',
    color: '#f472b6',
    bg: 'rgba(244,114,182,0.07)',
    border: 'rgba(244,114,182,0.22)',
    desc: 'Generate assumptions',
    system: 'You are Dissect, a local AI-powered reverse engineering and security analysis assistant. You are in HYPOTHESIS mode. Generate educated assumptions about the binary based on available evidence. Use phrases like "This might indicate...", "A likely hypothesis is...", "This pattern could suggest...". Build a theory from the data. Be speculative but grounded in the evidence. Do NOT provide direct bypass or cracking solutions.',
  },
  {
    id: 'yara',
    label: 'YARA',
    color: '#34d399',
    bg: 'rgba(52,211,153,0.07)',
    border: 'rgba(52,211,153,0.22)',
    desc: 'Generate YARA detection rules',
    system: 'You are Dissect, a local AI binary analysis assistant. You are in YARA mode. Based on the provided PE analysis data, generate professional, complete, and immediately usable YARA rules. Each rule must include: rule name (snake_case), meta section (description, author="Dissect", date, hash), strings section (hex byte patterns, notable text strings, imports), and a condition section. Use unique indicators from the analysis such as section characteristics, import signatures, entropy values, and suspicious strings. Output only valid YARA syntax with comments. Do NOT add any prose outside the rule blocks.',
  },
  // FAZ 9.3 — Report mode
  {
    id: 'report',
    label: 'Report',
    color: '#06b6d4',
    bg: 'rgba(6,182,212,0.07)',
    border: 'rgba(6,182,212,0.22)',
    desc: 'Auto-generate structured report',
    system: 'You are Dissect, a professional binary analysis report generator. Generate a well-structured analysis report with these sections:\n1. **Executive Summary** (2-3 sentences, non-technical)\n2. **Technical Overview** (architecture, entry point, sections, imports)\n3. **Risk Assessment** (risk score, threat classification, confidence)\n4. **Protection Mechanisms** (packers, anti-debug, VM detection)\n5. **Indicators of Compromise (IOC)** (hashes, IPs, domains, paths)\n6. **Recommendations** (next steps, mitigation)\n\nUse markdown formatting. Be concise but thorough. Include all data from the provided context.',
  },
  // FAZ 9.4 — Agent mode
  {
    id: 'agent',
    label: 'Agent',
    color: '#a855f7',
    bg: 'rgba(168,85,247,0.07)',
    border: 'rgba(168,85,247,0.22)',
    desc: 'Autonomous multi-step analysis',
    system: `You are Dissect Agent, an autonomous AI reverse engineering assistant. You perform multi-step analysis by reasoning through each step.

For each step, output in this format:
**[THINK]** Your reasoning about what to do next
**[ACT]** The action you are performing (e.g., "Analyzing PE headers", "Examining imports", "Checking entropy")
**[RESULT]** What you found

After all steps, output:
**[FINAL]** Complete summary of findings

Analyze all provided data systematically:
1. First examine PE structure and metadata
2. Then analyze imports and exports for suspicious APIs
3. Check entropy and section characteristics
4. Look for protection mechanisms
5. Identify potential IOCs
6. Generate risk assessment
7. Suggest YARA rules if applicable

Be thorough and show your reasoning at each step.`,
  },
];

// ══════════════════════════════════════════════════════════════════════
// FAZ 5 — Plugin Ekosistemi
// ══════════════════════════════════════════════════════════════════════

// ── 5.3 Plugin API ────────────────────────────────────────────────

function ChatPage({ chatContexts, setChatContexts, scanHistory }) {
  // —— Bağlantı modu: 'lms' = LM Studio, 'gguf' = Doğrudan GGUF ——
  const [chatMode, setChatMode]           = useState(() => localStorage.getItem('dissect_chat_mode') || 'lms');
  const [lmsUrl, setLmsUrl]               = useState(() => localStorage.getItem('dissect_lms_url') || 'http://localhost:1234');
  const [apiKey, setApiKey]               = useState(() => localStorage.getItem('dissect_lms_key') || '');
  const [models, setModels]               = useState([]);
  const [selectedModel, setSelectedModel] = useState(() => localStorage.getItem('dissect_lms_model') || '');
  const [connected, setConnected]         = useState(false);
  const [connecting, setConnecting]       = useState(false);
  const [connectError, setConnectError]   = useState('');
  // —— GGUF Direct state ——
  const [ggufPath, setGgufPath]           = useState(() => localStorage.getItem('dissect_gguf_path') || '');
  const [ggufPort, setGgufPort]           = useState(() => parseInt(localStorage.getItem('dissect_gguf_port') || '9999'));
  const [ggufServerUrl, setGgufServerUrl] = useState(null);
  const [ggufStarting, setGgufStarting]   = useState(false);
  const [ggufError, setGgufError]         = useState('');
  // —— FAZ 10.4 — Cloud AI state ——
  const [cloudProvider, setCloudProvider] = useState(() => localStorage.getItem('dissect_cloud_provider') || 'openai');
  const [cloudApiKey, setCloudApiKey]     = useState(() => localStorage.getItem('dissect_cloud_key') || '');
  const [cloudModel, setCloudModel]       = useState(() => localStorage.getItem('dissect_cloud_model') || 'gpt-4o-mini');
  const [cloudConnected, setCloudConnected] = useState(false);
  // —— Sohbet state ——
  const [messages, setMessages]           = useState([]);
  const [input, setInput]                 = useState('');
  const [streaming, setStreaming]         = useState(false);
  const [streamContent, setStreamContent] = useState('');
  const [mode, setMode]                   = useState('analyze');
  const contentRef = useRef('');
  const chatEndRef = useRef(null);
  // —— 2.1 Context Memory ——
  const [contextMemory, setContextMemory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_ctx_memory') || '[]'); } catch { return []; }
  });
  const [ctxMemoryEnabled, setCtxMemoryEnabled] = useState(() => localStorage.getItem('dissect_ctx_mem_on') !== 'false');
  const [ctxMemoryMax, setCtxMemoryMax]         = useState(() => parseInt(localStorage.getItem('dissect_ctx_mem_max') || '5'));
  const [ctxMemoryOpen, setCtxMemoryOpen]       = useState(false);

  // 2.4 — IOC extraction state
  const [extractedIOCs, setExtractedIOCs] = useState([]);
  const [iocPanelOpen, setIocPanelOpen]   = useState(false);

  // ── FAZ 9.1 — Multi-model comparison ──
  const [compareMode, setCompareMode] = useState(false);
  const [secondModel, setSecondModel] = useState('');
  const [compareResult, setCompareResult] = useState(null); // { modelA: '', modelB: '' }

  // ── FAZ 9.2 — RAG Analysis History ──
  const [analysisHistory, setAnalysisHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_rag_history') || '[]'); } catch { return []; }
  });
  const [ragSearchOpen, setRagSearchOpen] = useState(false);
  const [ragQuery, setRagQuery] = useState('');
  const ragResults = useMemo(() => {
    if (!ragQuery.trim()) return [];
    const q = ragQuery.toLowerCase().split(/\s+/);
    return analysisHistory.filter(h =>
      q.every(w => (h.query + ' ' + h.answer + ' ' + (h.fileName || '')).toLowerCase().includes(w))
    ).slice(0, 10);
  }, [ragQuery, analysisHistory]);

  // ── FAZ 9.5 — Knowledge Graph data ──
  const [knowledgeGraph, setKnowledgeGraph] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_kg') || '{"nodes":[],"edges":[]}'); } catch { return { nodes: [], edges: [] }; }
  });

  // ── FAZ 9.6 — Feedback + Fine-tune ──
  const [feedback, setFeedback] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_feedback') || '[]'); } catch { return []; }
  });

  // 2.4 — IOC extractor: parse AI messages for IPs, domains, hashes, file paths, URLs
  const extractIOCs = useCallback((text) => {
    if (!text) return [];
    const iocs = [];
    const seen = new Set();
    const add = (type, value) => { const k = type + ':' + value; if (!seen.has(k)) { seen.add(k); iocs.push({ type, value }); } };
    // IPv4
    const ipRe = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
    for (const m of text.matchAll(ipRe)) { if (!/^(?:0\.|127\.|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(m[0])) add('ip', m[0]); }
    // MD5
    for (const m of text.matchAll(/\b[a-fA-F0-9]{32}\b/g)) add('hash-md5', m[0]);
    // SHA1
    for (const m of text.matchAll(/\b[a-fA-F0-9]{40}\b/g)) add('hash-sha1', m[0]);
    // SHA256
    for (const m of text.matchAll(/\b[a-fA-F0-9]{64}\b/g)) add('hash-sha256', m[0]);
    // Domain
    for (const m of text.matchAll(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|io|ru|cn|xyz|top|tk|ml|ga|cf|cc|co|biz|me|pro|pw|ws|in|de|uk|fr|it|nl|br|au|kr|jp)\b/gi))
      add('domain', m[0].toLowerCase());
    // URL
    for (const m of text.matchAll(/https?:\/\/[^\s"'<>\]){},;]+/gi)) add('url', m[0]);
    // Windows paths
    for (const m of text.matchAll(/[A-Z]:\\(?:[^\s"'<>|*?\\]+\\)*[^\s"'<>|*?\\]+/g)) add('path', m[0]);
    // Unix paths
    for (const m of text.matchAll(/\/(?:usr|etc|var|tmp|opt|home|root|bin|sbin|dev|proc|sys)\/[^\s"'<>|*?]+/g)) add('path', m[0]);
    // Registry keys
    for (const m of text.matchAll(/HK(?:LM|CU|CR|U|CC)\\[^\s"'<>|*?]+/g)) add('registry', m[0]);
    return iocs;
  }, []);

  // 2.4 — Auto-extract IOCs from new assistant messages
  useEffect(() => {
    const assistantMsgs = messages.filter(m => m.role === 'assistant');
    if (assistantMsgs.length === 0) return;
    const allText = assistantMsgs.map(m => m.content).join('\n');
    const iocs = extractIOCs(allText);
    setExtractedIOCs(iocs);
    if (iocs.length > 0) setIocPanelOpen(true);
  }, [messages, extractIOCs]);

  // 2.1 — Persist context memory
  useEffect(() => { localStorage.setItem('dissect_ctx_memory', JSON.stringify(contextMemory)); }, [contextMemory]);
  useEffect(() => { localStorage.setItem('dissect_ctx_mem_on', ctxMemoryEnabled); }, [ctxMemoryEnabled]);
  useEffect(() => { localStorage.setItem('dissect_ctx_mem_max', ctxMemoryMax); }, [ctxMemoryMax]);

  // ── FAZ 9 — Persist RAG / KG / Feedback ──
  useEffect(() => { localStorage.setItem('dissect_rag_history', JSON.stringify(analysisHistory.slice(0, 200))); }, [analysisHistory]);
  useEffect(() => { localStorage.setItem('dissect_kg', JSON.stringify(knowledgeGraph)); }, [knowledgeGraph]);
  useEffect(() => { localStorage.setItem('dissect_feedback', JSON.stringify(feedback.slice(0, 500))); }, [feedback]);

  // ── FAZ 9.2 — Auto-save Q&A to RAG history ──
  const lastMsgCountRef = useRef(0);
  useEffect(() => {
    if (messages.length <= lastMsgCountRef.current) { lastMsgCountRef.current = messages.length; return; }
    lastMsgCountRef.current = messages.length;
    const last = messages[messages.length - 1];
    if (last?.role === 'assistant' && messages.length >= 2) {
      const userMsg = messages[messages.length - 2];
      if (userMsg?.role === 'user') {
        const entry = { query: userMsg.content.slice(0, 500), answer: last.content.slice(0, 1000), mode, ts: Date.now(), fileName: scanHistory?.[0]?.fileName || '' };
        setAnalysisHistory(prev => [entry, ...prev].slice(0, 200));
      }
    }
  }, [messages, mode, scanHistory]);

  // ── FAZ 9.5 — Auto-build knowledge graph from scans ──
  useEffect(() => {
    if (!scanHistory || scanHistory.length === 0) return;
    const latest = scanHistory[0];
    if (!latest?.sha256) return;
    setKnowledgeGraph(prev => {
      const existing = prev.nodes.find(n => n.id === latest.sha256);
      if (existing) return prev;
      const node = { id: latest.sha256, label: latest.fileName || 'unknown', type: 'file', risk: latest.riskScore || 0, arch: latest.arch, ts: Date.now() };
      const newEdges = [];
      // Find relationships: same imports, same C2 domains, same packers
      for (const n of prev.nodes) {
        if (latest.arch && n.arch === latest.arch) newEdges.push({ from: latest.sha256, to: n.id, label: 'same_arch' });
        if (latest.denuvo && n.denuvo) newEdges.push({ from: latest.sha256, to: n.id, label: 'both_denuvo' });
        if (latest.vmp && n.vmp) newEdges.push({ from: latest.sha256, to: n.id, label: 'both_vmp' });
      }
      return { nodes: [node, ...prev.nodes].slice(0, 100), edges: [...newEdges, ...prev.edges].slice(0, 300) };
    });
  }, [scanHistory]);

  // ── FAZ 9.6 — Feedback handler ──
  const addFeedback = useCallback((msgIdx, isPositive) => {
    const msg = messages[msgIdx];
    if (!msg || msg.role !== 'assistant') return;
    const userMsg = msgIdx > 0 ? messages[msgIdx - 1] : null;
    const entry = { positive: isPositive, query: userMsg?.content?.slice(0, 500) || '', response: msg.content.slice(0, 1000), mode, model: activeModel || '', ts: Date.now() };
    setFeedback(prev => [entry, ...prev].slice(0, 500));
  }, [messages, mode]);

  // ── FAZ 9.6 — Export JSONL for fine-tuning ──
  const exportFeedbackJsonl = useCallback(() => {
    const lines = feedback.map(f => JSON.stringify({
      messages: [
        { role: 'system', content: AI_MODES.find(m => m.id === f.mode)?.system || '' },
        { role: 'user', content: f.query },
        { role: 'assistant', content: f.response },
      ],
      label: f.positive ? 'good' : 'bad',
    }));
    const blob = new Blob([lines.join('\n')], { type: 'application/jsonl' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'dissect_finetune.jsonl'; a.click();
    URL.revokeObjectURL(url);
  }, [feedback]);

  // 2.1 — Auto-add scan summaries to context memory
  useEffect(() => {
    if (!scanHistory || scanHistory.length === 0) return;
    const latest = scanHistory[0];
    if (!latest?.sha256) return;
    setContextMemory(prev => {
      if (prev.some(m => m.sha256 === latest.sha256)) return prev;
      const entry = {
        sha256: latest.sha256,
        fileName: latest.fileName || '?',
        riskScore: latest.riskScore,
        arch: latest.arch,
        denuvo: latest.denuvo,
        vmp: latest.vmp,
        antiDebug: latest.antiDebug,
        packers: latest.packers,
        ts: Date.now(),
      };
      return [entry, ...prev].slice(0, 20);
    });
  }, [scanHistory]);

  // 2.1 — Build context memory prompt
  const buildContextPrompt = useCallback(() => {
    if (!ctxMemoryEnabled || contextMemory.length === 0) return '';
    const items = contextMemory.slice(0, ctxMemoryMax);
    const lines = items.map((m, i) => {
      const parts = [`#${i + 1} ${m.fileName} (SHA256: ${m.sha256?.slice(0, 16)}...)`];
      parts.push(`  Arch: ${m.arch || '?'}, Risk: ${m.riskScore ?? '?'}/100`);
      if (m.denuvo) parts.push('  Denuvo: YES');
      if (m.vmp)    parts.push('  VMProtect: YES');
      if (m.antiDebug) parts.push('  Anti-Debug: YES');
      if (m.packers?.length) parts.push(`  Packers: ${m.packers.join(', ')}`);
      return parts.join('\n');
    });
    return `\n\n--- CONTEXT MEMORY (${items.length} recent scans) ---\nThe user has previously analyzed these binaries:\n${lines.join('\n\n')}\n--- END CONTEXT MEMORY ---`;
  }, [ctxMemoryEnabled, contextMemory, ctxMemoryMax]);






  // Aktif endpoint: LMS veya GGUF sunucusu veya Cloud
  const activeUrl   = chatMode === 'gguf' ? (ggufServerUrl || `http://127.0.0.1:${ggufPort}`) : chatMode === 'cloud' ? cloudProvider : lmsUrl;
  const activeModel = chatMode === 'gguf' ? 'local-model' : chatMode === 'cloud' ? cloudModel : selectedModel;
  const isReady     = chatMode === 'gguf' ? !!ggufServerUrl : chatMode === 'cloud' ? (!!cloudApiKey && !!cloudModel) : (connected && !!selectedModel);

  const startGgufServer = async () => {
    if (!ggufPath) { setGgufError('GGUF dosya yolu boş'); return; }
    setGgufStarting(true); setGgufError('');
    try {
      const url = await invoke('start_gguf_server', { ggufPath, port: ggufPort });
      // Sunucunun hazır olmasını bekle (poll)
      for (let i = 0; i < 15; i++) {
        await new Promise(r => setTimeout(r, 1000));
        try {
          const r = await fetch(`${url}/v1/models`);
          if (r.ok) { setGgufServerUrl(url); setGgufStarting(false); return; }
        } catch {}
      }
      // Timeout — gene de URL'i set et, kullanıcı denesin
      setGgufServerUrl(url);
      setGgufError('Sunucu yanıt vermedi — yine de deneyebilirsiniz.');
    } catch (e) { setGgufError(String(e)); }
    finally { setGgufStarting(false); }
  };

  // Helper: format a single context item to text
  const formatContextItem = useCallback((ctx) => {
    if (ctx.type === 'pe_analyst') {
      const { type, _id, _selected, _ts, ...rest } = ctx;
      return `[PE/Binary Analizi]\nDosya: ${ctx.fileName || '?'}\n${JSON.stringify(rest, null, 2)}`;
    }
    if (ctx.type === 'scanner') {
      const d = ctx.data;
      return `[Scanner Sonucu]\nDosya: ${ctx.fileName || '?'}\nMimari: ${d.arch}  EP: 0x${d.ep?.toString(16).toUpperCase()}  Risk: ${d.riskScore}/100\nDenuvo: ${d.denuvo ? 'EVET' : 'Hayır'}  VMProtect: ${d.vmp ? 'EVET' : 'Hayır'}  Themida: ${d.themida ? 'EVET' : 'Hayır'}\nEntropi: ${d.overallEntropy?.toFixed(3)} H  Şüpheli section: ${d.suspiciousCount}\nSectionlar:\n${d.sections?.map(s => `  ${s.name.padEnd(12)} entropi=${s.entropy.toFixed(3)} boyut=${(s.rsize/1024).toFixed(0)}KB${s.suspicious ? ' ⚠' : ''}`).join('\n') || ''}`;
    }
    if (ctx.type === 'patcher') {
      const patches = ctx.data;
      return `[Hex Patch Listesi]\nHedef: ${ctx.fileName || '?'}\n${patches.map(p => `- ${p.name}  @${p.offset}  ${p.original || '—'} → ${p.patched || '—'}  ${p.applied ? 'Uygulandı' : p.enabled ? 'Aktif' : 'Devre dışı'}`).join('\n')}`;
    }
    if (ctx.type === 'ai_analyst') {
      return `[AI Analyst Raporu]\n${ctx.data?.output || ''}`;
    }
    if (ctx.type === 'hex_region') {
      return `[Hex Bölge]\nDosya: ${ctx.fileName || '?'}  Offset: ${ctx.offset}  Boyut: ${ctx.hex?.trim().split(/\s+/).length || '?'} byte\n${ctx.hex}`;
    }
    if (ctx.type === 'disasm_func') {
      return `[Disassembly — ${ctx.funcName || '?'}]\nDosya: ${ctx.fileName || '?'}  Adres: ${ctx.funcAddr}  Mimari: ${ctx.arch || 'x86-64'}\n${ctx.assembly}`;
    }
    return JSON.stringify(ctx, null, 2);
  }, []);

  // Context label helper
  const contextLabel = useCallback((ctx) => {
    const icons = { pe_analyst: '🔬', scanner: '🛡', patcher: '🔧', ai_analyst: '🤖', hex_region: '📦', disasm_func: '💻' };
    const names = { pe_analyst: 'PE Analiz', scanner: 'Scanner', patcher: 'Patcher', ai_analyst: 'AI Rapor', hex_region: 'Hex Bölge', disasm_func: 'Decompile' };
    const icon = icons[ctx.type] || '📄';
    const name = names[ctx.type] || ctx.type;
    const file = ctx.fileName || ctx.funcName || '';
    return `${icon} ${name}${file ? ': ' + file : ''}`;
  }, []);

  // Toggle a context selection
  const toggleContext = useCallback((id) => {
    setChatContexts(prev => prev.map(c => c._id === id ? { ...c, _selected: !c._selected } : c));
  }, [setChatContexts]);

  // Remove a context
  const removeContext = useCallback((id) => {
    setChatContexts(prev => prev.filter(c => c._id !== id));
  }, [setChatContexts]);

  // Build merged prompt from selected contexts
  const buildSelectedContextPrompt = useCallback(() => {
    const selected = chatContexts.filter(c => c._selected);
    if (selected.length === 0) return '';
    const parts = selected.map((ctx, i) => `─── Kaynak ${i + 1}: ${contextLabel(ctx)} ───\n${formatContextItem(ctx)}`);
    return parts.join('\n\n');
  }, [chatContexts, formatContextItem, contextLabel]);

  // Track last processed contexts length to auto-detect new items
  const lastCtxLenRef = useRef(0);

  useEffect(() => {
    if (chatContexts.length <= lastCtxLenRef.current) {
      lastCtxLenRef.current = chatContexts.length;
      return;
    }
    lastCtxLenRef.current = chatContexts.length;
    // New context(s) added — build prompt from all selected
    const selected = chatContexts.filter(c => c._selected);
    if (selected.length === 0) return;
    const isDecompile = selected.some(c => c.type === 'disasm_func');
    if (isDecompile) setMode('explain');

    if (selected.length === 1) {
      const ctx = selected[0];
      // Single context — use descriptive prompt
      let text = formatContextItem(ctx);
      if (ctx.type === 'hex_region') text += '\n\nBu baytlar ne olabilir? Struct olarak tahmin et.';
      else if (ctx.type === 'disasm_func') text += '\n\nBu assembly kodunu C/C++ pseudocode\'a çevir.';
      else text += '\n\nBu veriler hakkında detaylı analiz yap.';
      setInput(text);
    } else {
      // Multiple contexts — merged view
      const merged = buildSelectedContextPrompt();
      setInput(merged + '\n\nYukarıdaki tüm verileri birlikte analiz et. Her kaynağı açıkla ve aralarındaki ilişkileri belirle.');
    }
  }, [chatContexts]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, streamContent]);

  // Context summarize: long conversation
  const summarizeConversation = async () => {
    if (!connected || !selectedModel || streaming) return;
    const digest = messages.map(m => `${m.role === 'user' ? 'Kullanıcı' : 'AI'}: ${m.content}`).join('\n');
    const prompt = `Aşağıdaki sohbetin kısa bir özetini çıkar (3-5 madde). Teknik bulguları ve önemli kararları listele:\n\n${digest}`;
    setStreaming(true);
    contentRef.current = '';
    setStreamContent('');
    const unChunk = await listen('chat-chunk', (e) => { contentRef.current += e.payload; setStreamContent(contentRef.current); });
    const unDone  = await listen('chat-done', () => {
      setMessages([{ role: 'assistant', content: `**Sohbet Özeti (${new Date().toLocaleTimeString('tr-TR')})**\n\n${contentRef.current}` }]);
      setStreamContent(''); setStreaming(false); unChunk(); unDone();
    });
    try {
      await invoke('lms_chat_stream', {
        messages: [
          { role: 'system', content: 'You are a helpful assistant that summarizes technical AI reverse engineering conversations in Turkish, concisely.' },
          { role: 'user', content: prompt },
        ],
        model: selectedModel, baseUrl: lmsUrl, apiKey,
      });
    } catch (e) {
      setMessages([{ role: 'assistant', content: `Özet hatası: ${e}` }]);
      setStreamContent(''); setStreaming(false); unChunk(); unDone();
    }
  };

  // ── FAZ 9.1 — Multi-model compare send ──
  const sendCompareMessage = async () => {
    if (!input.trim() || streaming || !compareMode || !secondModel) return;
    if (!isReady) return;
    const userMsg = { role: 'user', content: input.trim() };
    const history = [...messages, userMsg];
    setMessages(history);
    setInput('');
    setStreaming(true);
    setCompareResult(null);

    const curMode = AI_MODES.find(m => m.id === mode);
    const ctxPrompt = buildContextPrompt();
    const selectedCtx = chatContexts.filter(c => c._selected);
    let dataCtx = '';
    if (selectedCtx.length > 0) {
      dataCtx = '\n\n--- ACTIVE DATA SOURCES ---\n' +
        selectedCtx.map((ctx, i) => `[Source ${i + 1}: ${contextLabel(ctx)}]\n${formatContextItem(ctx)}`).join('\n\n') +
        '\n--- END DATA SOURCES ---';
    }
    const systemContent = (curMode?.system || AI_MODES[1].system) + ctxPrompt + dataCtx;
    const apiMsgs = [{ role: 'system', content: systemContent }, ...history.map(m => ({ role: m.role, content: m.content }))];

    // Send to Model A
    let resultA = '';
    try {
      const pA = new Promise((resolve) => {
        let content = '';
        const doFetchA = async () => {
          const unC = await listen('chat-chunk', (e) => { content += e.payload; });
          const unD = await listen('chat-done', () => { unC(); unD(); resolve(content); });
          await invoke('lms_chat_stream', { messages: apiMsgs, model: activeModel, baseUrl: activeUrl, apiKey: chatMode === 'gguf' ? '' : apiKey });
        };
        doFetchA().catch(() => resolve('Model A error'));
      });
      resultA = await pA;
    } catch { resultA = 'Model A error'; }

    // Send to Model B
    let resultB = '';
    try {
      const pB = new Promise((resolve) => {
        let content = '';
        const doFetchB = async () => {
          const unC = await listen('chat-chunk', (e) => { content += e.payload; });
          const unD = await listen('chat-done', () => { unC(); unD(); resolve(content); });
          await invoke('lms_chat_stream', { messages: apiMsgs, model: secondModel, baseUrl: activeUrl, apiKey: chatMode === 'gguf' ? '' : apiKey });
        };
        doFetchB().catch(() => resolve('Model B error'));
      });
      resultB = await pB;
    } catch { resultB = 'Model B error'; }

    setCompareResult({ modelA: resultA, modelB: resultB, nameA: activeModel, nameB: secondModel });
    setMessages(prev => [...prev, { role: 'assistant', content: `**Model Karşılaştırması**\n\n---\n**${activeModel}:**\n${resultA}\n\n---\n**${secondModel}:**\n${resultB}` }]);
    setStreaming(false);
  };

  // 2.7 — YARA Rule Wizard state and logic
  const [yaraWizardOpen, setYaraWizardOpen] = useState(false);
  const [yaraRule, setYaraRule]       = useState('');
  const [yaraGenerating, setYaraGenerating] = useState(false);
  const [yaraRuleName, setYaraRuleName] = useState('custom_rule');

  const generateYaraFromContext = async () => {
    if (!connected || !selectedModel) return;
    setYaraGenerating(true); setYaraRule('');
    const selectedCtx = chatContexts.filter(c => c._selected);
    const ctxText = selectedCtx.length > 0
      ? selectedCtx.map((c, i) => `[Source ${i + 1}]\n${formatContextItem(c)}`).join('\n\n')
      : (scanHistory?.[0] ? JSON.stringify(scanHistory[0], null, 2).slice(0, 4000) : '');
    if (!ctxText) { setYaraGenerating(false); return; }
    let content = '';
    const unChunk = await listen('chat-chunk', (e) => { content += e.payload; setYaraRule(content); });
    const unDone  = await listen('chat-done', () => { setYaraGenerating(false); unChunk(); unDone(); });
    try {
      await invoke('lms_chat_stream', {
        messages: [
          { role: 'system', content: `You are an expert YARA rule writer. Generate a valid, well-structured YARA rule based on the provided binary analysis data. The rule name should be "${yaraRuleName}". Include:
- Proper meta section (author, date, description)
- Relevant strings (hex patterns, text strings, imports)
- A sound condition section
Output ONLY the YARA rule, no explanation.` },
          { role: 'user', content: `Generate a YARA rule from this binary analysis data:\n\n${ctxText}` },
        ],
        model: selectedModel, baseUrl: lmsUrl, apiKey,
      });
    } catch (e) {
      setYaraRule(`// Hata: ${e}`); setYaraGenerating(false); unChunk(); unDone();
    }
  };

  // 2.7 — YARA library (saved rules)
  const [yaraLibrary, setYaraLibrary] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_yara_lib') || '[]'); } catch { return []; }
  });
  useEffect(() => { localStorage.setItem('dissect_yara_lib', JSON.stringify(yaraLibrary)); }, [yaraLibrary]);

  const saveYaraRule = () => {
    if (!yaraRule.trim()) return;
    setYaraLibrary(prev => [{ name: yaraRuleName, rule: yaraRule, ts: Date.now() }, ...prev].slice(0, 50));
  };
  const deleteYaraRule = (idx) => setYaraLibrary(prev => prev.filter((_, i) => i !== idx));

  const connect = async () => {
    setConnecting(true); setConnectError(''); setConnected(false);
    try {
      const list = await invoke('lms_list_models', { baseUrl: lmsUrl, apiKey });
      setModels(list);
      setSelectedModel(list[0] || '');
      setConnected(true);
    } catch (e) { setConnectError(String(e)); }
    finally { setConnecting(false); }
  };

  const sendMessage = async () => {
    if (!input.trim() || streaming) return;
    if (!isReady) { setConnectError(chatMode === 'gguf' ? 'Önce GGUF sunucusunu başlatın.' : 'Önce LM Studio\'ya bağlanın ve model seçin.'); return; }
    const userMsg = { role: 'user', content: input.trim() };
    const history = [...messages, userMsg];
    setMessages(history);
    setInput('');
    setStreaming(true);
    contentRef.current = '';
    setStreamContent('');

    const unChunk = await listen('chat-chunk', (e) => {
      contentRef.current += e.payload;
      setStreamContent(contentRef.current);
    });
    const unDone = await listen('chat-done', () => {
      setMessages(prev => [...prev, { role: 'assistant', content: contentRef.current }]);
      setStreamContent('');
      setStreaming(false);
      unChunk(); unDone();
    });

    const curMode = AI_MODES.find(m => m.id === mode);
    const ctxPrompt = buildContextPrompt();
    // Inject selected context sources into system prompt
    const selectedCtx = chatContexts.filter(c => c._selected);
    let dataCtx = '';
    if (selectedCtx.length > 0) {
      dataCtx = '\n\n--- ACTIVE DATA SOURCES ---\n' +
        selectedCtx.map((ctx, i) => `[Source ${i + 1}: ${contextLabel(ctx)}]\n${formatContextItem(ctx)}`).join('\n\n') +
        '\n--- END DATA SOURCES ---\nUse the above data to provide informed, contextual answers.';
    }
    const systemContent = (curMode?.system || AI_MODES[1].system) + ctxPrompt + dataCtx +
      '\n\nIMPORTANT: At the very end of every response, on a new line, output a confidence line in format: [CONFIDENCE:XX%] where XX is 0-100 representing how confident you are in your analysis. Do not explain this line.';
    try {
      const apiMsgs = [
        { role: 'system', content: systemContent },
        ...history.map(m => ({ role: m.role, content: m.content })),
      ];
      if (chatMode === 'cloud') {
        await invoke('cloud_ai_chat', {
          messages: apiMsgs,
          model: cloudModel,
          provider: cloudProvider,
          apiKey: cloudApiKey,
        });
      } else {
        await invoke('lms_chat_stream', {
          messages: apiMsgs,
          model: activeModel,
          baseUrl: activeUrl,
          apiKey: chatMode === 'gguf' ? '' : apiKey,
        });
      }
    } catch (e) {
      setMessages(prev => [...prev, { role: 'assistant', content: `Hata: ${e}` }]);
      setStreamContent('');
      setStreaming(false);
      unChunk(); unDone();
    }
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <style>{`@keyframes cursor-blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>

      {/* —� Connection bar —� */}
      <div style={{ padding: '14px 20px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(99,102,241,0.13)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <MessageSquare size={17} color="#818cf8" />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>AI Chat</span>
            </div>
            <p style={{ fontSize: 11, color: '#4b5563', margin: 0 }}>
              LM Studio entegrasyonu — analiz yap, konuş, keşfet.
            </p>
          </div>
        </div>

        {/* -- AI Chat Mode selector -- */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 10, flexWrap: 'wrap' }}>
          {AI_MODES.map(m => (
            <button key={m.id} onClick={() => setMode(m.id)}
              style={{ padding: '4px 12px', borderRadius: 7, border: `1px solid ${mode === m.id ? m.border : 'rgba(255,255,255,0.07)'}`, background: mode === m.id ? m.bg : 'transparent', color: mode === m.id ? m.color : '#374151', cursor: 'pointer', fontSize: 11, fontWeight: mode === m.id ? 600 : 400, transition: 'all 0.13s' }}>
              {m.label}
            </button>
          ))}
          <span style={{ fontSize: 10, color: '#4b5563', marginLeft: 2 }}>{AI_MODES.find(m => m.id === mode)?.desc}</span>
          {/* FAZ 9.1 — Compare toggle */}
          <button onClick={() => setCompareMode(v => !v)}
            style={{ padding: '4px 11px', borderRadius: 7, border: `1px solid ${compareMode ? 'rgba(168,85,247,0.4)' : 'rgba(255,255,255,0.07)'}`, background: compareMode ? 'rgba(168,85,247,0.08)' : 'transparent', color: compareMode ? '#a855f7' : '#374151', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
            ⚖ Compare
          </button>
          {/* FAZ 9.2 — RAG toggle */}
          <button onClick={() => setRagSearchOpen(v => !v)}
            style={{ padding: '4px 11px', borderRadius: 7, border: `1px solid ${ragSearchOpen ? 'rgba(6,182,212,0.4)' : 'rgba(255,255,255,0.07)'}`, background: ragSearchOpen ? 'rgba(6,182,212,0.08)' : 'transparent', color: ragSearchOpen ? '#06b6d4' : '#374151', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
            🔎 RAG ({analysisHistory.length})
          </button>
          {/* FAZ 9.6 — Feedback export */}
          {feedback.length > 0 && (
            <button onClick={exportFeedbackJsonl}
              style={{ padding: '4px 11px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.07)', background: 'transparent', color: '#374151', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}>
              📤 Export JSONL ({feedback.length})
            </button>
          )}
          {/* 2.7 — YARA Wizard toggle */}
          <button onClick={() => setYaraWizardOpen(v => !v)}
            style={{ marginLeft: 'auto', padding: '4px 11px', borderRadius: 7, border: `1px solid ${yaraWizardOpen ? 'rgba(245,158,11,0.4)' : 'rgba(255,255,255,0.07)'}`, background: yaraWizardOpen ? 'rgba(245,158,11,0.08)' : 'transparent', color: yaraWizardOpen ? '#fbbf24' : '#374151', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 5, fontWeight: yaraWizardOpen ? 600 : 400 }}>
            <ShieldAlert size={12} /> YARA Sihirbazı
          </button>
        </div>

        {/* FAZ 9.1 — Compare Mode: Second model selector */}
        {compareMode && models.length > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, padding: '6px 10px', background: 'rgba(168,85,247,0.04)', border: '1px solid rgba(168,85,247,0.12)', borderRadius: 7 }}>
            <span style={{ fontSize: 10, color: '#a855f7', fontWeight: 600 }}>⚖ Compare Mode</span>
            <span style={{ fontSize: 10, color: '#8b949e' }}>Model B:</span>
            <select value={secondModel} onChange={e => setSecondModel(e.target.value)}
              style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(168,85,247,0.2)', borderRadius: 5, color: '#e6edf3', fontSize: 10, padding: '2px 6px' }}>
              <option value="">Seçin...</option>
              {models.filter(m => m !== selectedModel).map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <span style={{ fontSize: 9, color: '#6b7280' }}>Aynı soruyu 2 modele gönderir</span>
          </div>
        )}

        {/* FAZ 9.2 — RAG Search Panel */}
        {ragSearchOpen && (
          <div style={{ marginBottom: 8, padding: '8px 10px', background: 'rgba(6,182,212,0.04)', border: '1px solid rgba(6,182,212,0.12)', borderRadius: 7 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <span style={{ fontSize: 10, color: '#06b6d4', fontWeight: 600 }}>🔎 Geçmiş Analiz Arama (RAG)</span>
              <input value={ragQuery} onChange={e => setRagQuery(e.target.value)} placeholder="Anahtar kelime ara..."
                style={{ flex: 1, background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(6,182,212,0.15)', borderRadius: 5, padding: '3px 8px', fontSize: 10, color: '#e6edf3', outline: 'none' }} />
            </div>
            {ragResults.length > 0 && (
              <div style={{ maxHeight: 150, overflow: 'auto', fontSize: 10 }}>
                {ragResults.map((r, i) => (
                  <div key={i} onClick={() => setInput(r.query)} style={{ padding: '4px 6px', cursor: 'pointer', borderBottom: '1px solid rgba(255,255,255,0.04)', color: '#8b949e' }}>
                    <span style={{ color: '#06b6d4' }}>{r.fileName || '?'}</span> — {r.query.slice(0, 80)}...
                    <span style={{ fontSize: 9, color: '#4b5563', marginLeft: 6 }}>{new Date(r.ts).toLocaleDateString()}</span>
                  </div>
                ))}
              </div>
            )}
            {ragQuery && ragResults.length === 0 && <span style={{ fontSize: 10, color: '#4b5563' }}>Sonuç bulunamadı</span>}
          </div>
        )}

        {/* 2.7 — YARA Wizard Panel */}
        {yaraWizardOpen && (
          <div style={{ borderRadius: 10, padding: '12px 14px', background: 'rgba(245,158,11,0.03)', border: '1px solid rgba(245,158,11,0.15)', display: 'flex', flexDirection: 'column', gap: 10, flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <ShieldAlert size={14} color="#fbbf24" />
                <span style={{ fontSize: 12, fontWeight: 700, color: '#fbbf24' }}>YARA Kural Sihirbazı</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 10, color: '#4b5563' }}>Kural adı:</span>
                <input value={yaraRuleName} onChange={e => setYaraRuleName(e.target.value.replace(/[^a-zA-Z0-9_]/g, '_'))}
                  style={{ padding: '3px 8px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(0,0,0,0.2)', color: '#e5e7eb', fontSize: 10, width: 130, fontFamily: 'monospace' }} />
                <button onClick={generateYaraFromContext} disabled={yaraGenerating || !connected}
                  style={{ padding: '4px 12px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.1)', color: !connected ? '#374151' : '#fbbf24', cursor: connected ? 'pointer' : 'not-allowed', fontSize: 10, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                  {yaraGenerating ? <><RefreshCw size={10} className="spin" /> Üretiliyor...</> : <><Zap size={10} /> AI ile Üret</>}
                </button>
                {yaraRule && (
                  <>
                    <button onClick={saveYaraRule}
                      style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontSize: 10, display: 'flex', alignItems: 'center', gap: 3 }}>
                      <Download size={9} /> Kaydet
                    </button>
                    <button onClick={() => navigator.clipboard.writeText(yaraRule)}
                      style={{ padding: '4px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#4b5563', cursor: 'pointer', fontSize: 10, display: 'flex', alignItems: 'center', gap: 3 }}>
                      <Copy size={9} /> Kopyala
                    </button>
                  </>
                )}
              </div>
            </div>
            <textarea value={yaraRule} onChange={e => setYaraRule(e.target.value)} placeholder="Seçili bağlam kaynaklarından YARA kuralı üretmek için 'AI ile Üret' butonuna tıklayın veya burada elle yazın..."
              style={{ resize: 'vertical', minHeight: 120, maxHeight: 300, padding: '10px 12px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.12)', background: 'rgba(0,0,0,0.25)', color: '#e5e7eb', fontSize: 11, fontFamily: 'monospace', lineHeight: 1.5 }} />
            {/* YARA Library */}
            {yaraLibrary.length > 0 && (
              <div style={{ borderTop: '1px solid rgba(245,158,11,0.1)', paddingTop: 8 }}>
                <span style={{ fontSize: 10, fontWeight: 600, color: '#92400e' }}>Kural Kütüphanesi ({yaraLibrary.length})</span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6, maxHeight: 150, overflow: 'auto' }}>
                  {yaraLibrary.map((r, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 8px', borderRadius: 6, background: 'rgba(0,0,0,0.15)', border: '1px solid rgba(255,255,255,0.04)' }}>
                      <span style={{ fontSize: 10, color: '#d4d4d8', fontFamily: 'monospace' }}>{r.name}</span>
                      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <span style={{ fontSize: 9, color: '#4b5563' }}>{new Date(r.ts).toLocaleDateString('tr-TR')}</span>
                        <button onClick={() => setYaraRule(r.rule)}
                          style={{ padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer', fontSize: 9 }}>Yükle</button>
                        <button onClick={() => deleteYaraRule(idx)}
                          style={{ padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(239,68,68,0.2)', background: 'transparent', color: '#f87171', cursor: 'pointer', fontSize: 9 }}>Sil</button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>

          {/* —— Mod seçici: LM Studio | GGUF Direct | Cloud AI —— */}
          <div style={{ display: 'flex', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', overflow: 'hidden', marginRight: 4 }}>
            {[{id:'lms', label:'LM Studio', color:'#818cf8'}, {id:'gguf', label:'📦 GGUF Direct', color:'#fbbf24'}, {id:'cloud', label:'☁ Cloud AI', color:'#06b6d4'}].map(opt => (
              <button key={opt.id} onClick={() => { setChatMode(opt.id); localStorage.setItem('dissect_chat_mode', opt.id); }}
                style={{ padding: '5px 14px', border: 'none', background: chatMode === opt.id ? (opt.id==='gguf' ? 'rgba(245,158,11,0.12)' : opt.id==='cloud' ? 'rgba(6,182,212,0.12)' : 'rgba(99,102,241,0.12)') : 'transparent', color: chatMode === opt.id ? opt.color : '#4b5563', cursor: 'pointer', fontSize: 11, fontWeight: chatMode === opt.id ? 700 : 400, transition: 'all 0.13s' }}>
                {opt.label}
              </button>
            ))}
          </div>

          {chatMode === 'lms' && (<>
            <input value={lmsUrl} onChange={e => { setLmsUrl(e.target.value); localStorage.setItem('dissect_lms_url', e.target.value); }}
              style={{ width: 200, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 7, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <input value={apiKey} onChange={e => { setApiKey(e.target.value); localStorage.setItem('dissect_lms_key', e.target.value); }} placeholder="API Key (opsiyonel)"
              type="password"
              style={{ width: 168, background: 'rgba(0,0,0,0.3)', border: `1px solid ${apiKey ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.08)'}`, borderRadius: 7, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <button onClick={connect} disabled={connecting}
              style={{ padding: '6px 15px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.1)', color: '#818cf8', cursor: connecting ? 'wait' : 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}>
              {connecting ? <><RefreshCw size={13} style={{ animation: '_sp 0.75s linear infinite' }} /> Bağlanıyor…</> : connected ? <><RefreshCw size={13} /> Yenile</> : 'Bağlan'}
            </button>
            {connected && models.length > 0 && (
              <select value={selectedModel} onChange={e => { setSelectedModel(e.target.value); localStorage.setItem('dissect_lms_model', e.target.value); }}
                style={{ flex: 1, minWidth: 200, maxWidth: 380, background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 7, padding: '6px 10px', fontSize: 12, color: '#e2e8f0', outline: 'none' }}>
                {models.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 'auto' }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: connected ? '#22c55e' : '#ef4444', boxShadow: connected ? '0 0 6px #22c55e88' : 'none' }} />
              <span style={{ fontSize: 11, color: connected ? '#4ade80' : '#94a3b8' }}>{connected ? `${models.length} model` : 'Bağlı değil'}</span>
            </div>
          </>)}

          {chatMode === 'gguf' && (<>
            <input value={ggufPath} onChange={e => { setGgufPath(e.target.value); localStorage.setItem('dissect_gguf_path', e.target.value); }}
              placeholder="C:\models\qwen2.5-7b-q4.gguf"
              style={{ flex: 1, minWidth: 260, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 7, padding: '6px 10px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <input value={ggufPort} onChange={e => { const v = parseInt(e.target.value)||9999; setGgufPort(v); localStorage.setItem('dissect_gguf_port', v); }}
              type="number" min="1024" max="65535"
              style={{ width: 78, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(245,158,11,0.15)', borderRadius: 7, padding: '6px 8px', fontSize: 12, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <button onClick={startGgufServer} disabled={ggufStarting || !ggufPath}
              style={{ padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(245,158,11,0.35)', background: ggufServerUrl ? 'rgba(34,197,94,0.1)' : 'rgba(245,158,11,0.1)', color: ggufServerUrl ? '#4ade80' : '#fbbf24', cursor: (ggufStarting || !ggufPath) ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
              {ggufStarting ? <><RefreshCw size={13} style={{ animation: '_sp 0.75s linear infinite' }} /> Başlatılıyor…</> : ggufServerUrl ? '✅ Sunucu Aktif' : '▶ Başlat'}
            </button>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 4 }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: ggufServerUrl ? '#22c55e' : '#f59e0b', boxShadow: ggufServerUrl ? '0 0 6px #22c55e88' : 'none' }} />
              <span style={{ fontSize: 11, color: ggufServerUrl ? '#4ade80' : '#94a3b8' }}>{ggufServerUrl ? `localhost:${ggufPort}` : 'Kapalı'}</span>
            </div>
          </>)}

          {/* FAZ 10.4 — Cloud AI connection */}
          {chatMode === 'cloud' && (<>
            <select value={cloudProvider} onChange={e => { setCloudProvider(e.target.value); localStorage.setItem('dissect_cloud_provider', e.target.value); }}
              style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(6,182,212,0.2)', borderRadius: 7, padding: '6px 10px', fontSize: 11, color: '#e2e8f0' }}>
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="groq">Groq</option>
            </select>
            <input value={cloudModel} onChange={e => { setCloudModel(e.target.value); localStorage.setItem('dissect_cloud_model', e.target.value); }}
              placeholder="gpt-4o-mini"
              style={{ width: 160, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(6,182,212,0.2)', borderRadius: 7, padding: '6px 10px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <input value={cloudApiKey} onChange={e => { setCloudApiKey(e.target.value); localStorage.setItem('dissect_cloud_key', e.target.value); }}
              placeholder="API Key" type="password"
              style={{ flex: 1, minWidth: 180, background: 'rgba(0,0,0,0.3)', border: `1px solid ${cloudApiKey ? 'rgba(34,197,94,0.3)' : 'rgba(6,182,212,0.15)'}`, borderRadius: 7, padding: '6px 10px', fontSize: 11, color: '#e2e8f0', outline: 'none', fontFamily: 'monospace' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: cloudApiKey ? '#22c55e' : '#f59e0b' }} />
              <span style={{ fontSize: 11, color: cloudApiKey ? '#4ade80' : '#94a3b8' }}>{cloudApiKey ? 'Hazır' : 'API Key girin'}</span>
            </div>
          </>)}
        </div>

        {connectError && <div style={{ marginTop: 8, fontSize: 11, color: '#f87171', fontFamily: 'monospace' }}>{connectError}</div>}
        {ggufError   && <div style={{ marginTop: 8, fontSize: 11, color: '#f87171', fontFamily: 'monospace' }}>{ggufError}</div>}

        {chatMode === 'lms' && !connected && (
          <div style={{ marginTop: 10, fontSize: 11, color: '#94a3b8', background: 'rgba(99,102,241,0.04)', borderRadius: 8, padding: '8px 12px', border: '1px solid rgba(99,102,241,0.1)', lineHeight: 1.65 }}>
            LM Studio → <strong style={{ color: '#818cf8' }}>Developer</strong> sekmesi → <strong style={{ color: '#818cf8' }}>Start Server</strong> (port 1234) → "Bağlan". İstediğiniz modeli LM Studio'dan yükleyin.
          </div>
        )}
        {chatMode === 'gguf' && !ggufServerUrl && (
          <div style={{ marginTop: 10, fontSize: 11, color: '#94a3b8', background: 'rgba(245,158,11,0.04)', borderRadius: 8, padding: '8px 12px', border: '1px solid rgba(245,158,11,0.12)', lineHeight: 1.65 }}>
            <strong style={{ color: '#fbbf24' }}>GGUF Direct:</strong> System &amp; Models sayfasından GGUF indirin → Dosya yolunu girin → "Başlat". llama-server PATH'te kurulu olmalı. <br />
            <span style={{ color: '#64748b' }}>İndir: <a href="https://github.com/ggerganov/llama.cpp/releases" target="_blank" rel="noreferrer" style={{ color: '#818cf8' }}>llama.cpp Releases</a></span>
          </div>
        )}
        {/* 2.1 — Context Memory indicator + management */}
        <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
          <button onClick={() => setCtxMemoryOpen(v => !v)}
            style={{ padding: '4px 11px', borderRadius: 7, border: `1px solid ${ctxMemoryEnabled && contextMemory.length > 0 ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.08)'}`, background: ctxMemoryEnabled && contextMemory.length > 0 ? 'rgba(34,197,94,0.06)' : 'transparent', color: ctxMemoryEnabled && contextMemory.length > 0 ? '#4ade80' : '#4b5563', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', gap: 5, transition: 'all 0.13s' }}>
            <MemoryStick size={12} />
            Bellek {contextMemory.length > 0 ? `(${Math.min(contextMemory.length, ctxMemoryMax)})` : ''}
          </button>
          {ctxMemoryEnabled && contextMemory.length > 0 && (
            <span style={{ fontSize: 10, color: '#22c55e' }}>
              {Math.min(contextMemory.length, ctxMemoryMax)} tarama hatırlanıyor
            </span>
          )}
        </div>

        {/* 2.1 — Context Memory expanded panel */}
        {ctxMemoryOpen && (
          <div style={{ marginTop: 4, borderRadius: 9, padding: '10px 14px', background: 'rgba(34,197,94,0.03)', border: '1px solid rgba(34,197,94,0.15)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#4ade80' }}>Bağlamsal Bellek (Context Memory)</span>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <label style={{ fontSize: 10, color: '#64748b', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
                  <input type="checkbox" checked={ctxMemoryEnabled} onChange={e => setCtxMemoryEnabled(e.target.checked)}
                    style={{ width: 13, height: 13, cursor: 'pointer' }} />
                  Aktif
                </label>
                <span style={{ fontSize: 10, color: '#4b5563' }}>Max:</span>
                <select value={ctxMemoryMax} onChange={e => setCtxMemoryMax(parseInt(e.target.value))}
                  style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 5, padding: '2px 6px', fontSize: 10, color: '#e2e8f0', outline: 'none' }}>
                  {[1,2,3,5,8,10,15,20].map(n => <option key={n} value={n}>{n}</option>)}
                </select>
                <button onClick={() => setContextMemory([])}
                  style={{ padding: '2px 8px', borderRadius: 5, border: '1px solid rgba(239,68,68,0.2)', background: 'rgba(239,68,68,0.06)', color: '#f87171', cursor: 'pointer', fontSize: 9, fontWeight: 600 }}>
                  Temizle
                </button>
              </div>
            </div>
            {contextMemory.length === 0 ? (
              <div style={{ fontSize: 10, color: '#374151', textAlign: 'center', padding: 8 }}>Henüz bellek yok — bir dosya tarayın, otomatik kaydedilir.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3, maxHeight: 160, overflowY: 'auto' }}>
                {contextMemory.slice(0, ctxMemoryMax).map((m, i) => (
                  <div key={m.sha256 || i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderRadius: 5, background: 'rgba(0,0,0,0.15)', fontSize: 10, fontFamily: 'monospace' }}>
                    <span style={{ color: '#4ade80', fontWeight: 600, minWidth: 14 }}>#{i + 1}</span>
                    <span style={{ color: '#e2e8f0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.fileName}</span>
                    <span style={{ color: m.riskScore > 60 ? '#f87171' : m.riskScore > 30 ? '#fbbf24' : '#4ade80' }}>R:{m.riskScore ?? '?'}</span>
                    <span style={{ color: '#64748b' }}>{m.arch}</span>
                    {m.denuvo && <span style={{ color: '#f87171', fontSize: 8, background: 'rgba(248,113,113,0.1)', padding: '0 4px', borderRadius: 3 }}>DEN</span>}
                    {m.vmp && <span style={{ color: '#e879f9', fontSize: 8, background: 'rgba(232,121,249,0.1)', padding: '0 4px', borderRadius: 3 }}>VMP</span>}
                    <button onClick={() => setContextMemory(prev => prev.filter(x => x.sha256 !== m.sha256))}
                      style={{ border: 'none', background: 'transparent', color: '#374151', cursor: 'pointer', padding: 0, lineHeight: 1 }}>
                      <X size={10} />
                    </button>
                  </div>
                ))}
              </div>
            )}
            {!ctxMemoryEnabled && contextMemory.length > 0 && (
              <div style={{ fontSize: 10, color: '#f59e0b', marginTop: 6 }}>⚠ Bellek devre dışı — tarama geçmişi system prompt'a eklenmeyecek.</div>
            )}
          </div>
        )}
      </div>{/* end connection bar */}
      {/* — Messages — */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* 33 — Context window uyarısı */}
        {messages.length >= 15 && !streaming && (
          <div style={{ borderRadius: 9, padding: '9px 14px', background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.22)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            <AlertTriangle size={14} color="#fbbf24" style={{ flexShrink: 0 }} />
            <span style={{ fontSize: 11, color: '#92400e', flex: 1 }}>Konuşma <strong style={{ color: '#fbbf24' }}>{messages.length} mesaja</strong> ula?t? — context window dolabilir, yanıtlar kayabilir.</span>
            <button onClick={summarizeConversation}
              style={{ padding: '4px 12px', borderRadius: 6, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.1)', color: '#fbbf24', cursor: 'pointer', fontSize: 10, fontWeight: 600, whiteSpace: 'nowrap' }}>
              Özetle & Temizle
            </button>
          </div>
        )}

        {/* Context Tray — multi-select data sources */}
        {chatContexts.length > 0 && (
          <div style={{ borderRadius: 10, padding: '8px 12px', background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.15)', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Layers size={12} color="#818cf8" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#818cf8' }}>Bağlam Kaynakları</span>
                <span style={{ fontSize: 9, color: '#4b5563' }}>({chatContexts.filter(c => c._selected).length}/{chatContexts.length} seçili)</span>
              </div>
              <div style={{ display: 'flex', gap: 4 }}>
                <button onClick={() => setChatContexts(prev => prev.map(c => ({ ...c, _selected: true })))}
                  style={{ padding: '2px 7px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer', fontSize: 9 }}>
                  Tümünü Seç
                </button>
                <button onClick={() => setChatContexts(prev => prev.map(c => ({ ...c, _selected: false })))}
                  style={{ padding: '2px 7px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#4b5563', cursor: 'pointer', fontSize: 9 }}>
                  Hiçbiri
                </button>
                <button onClick={() => {
                  const merged = buildSelectedContextPrompt();
                  if (merged) setInput(merged + '\n\nYukarıdaki tüm verileri birlikte analiz et. Her kaynağı açıkla ve aralarındaki ilişkileri belirle.');
                }}
                  disabled={chatContexts.filter(c => c._selected).length === 0}
                  style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(139,92,246,0.3)', background: 'rgba(139,92,246,0.08)', color: chatContexts.filter(c => c._selected).length > 0 ? '#a78bfa' : '#374151', cursor: chatContexts.filter(c => c._selected).length > 0 ? 'pointer' : 'not-allowed', fontSize: 9, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 3 }}>
                  <Send size={8} /> Seçilenleri Yükle
                </button>
                {/* 2.2 — Compare button (appears when 2+ scan sources selected) */}
                {chatContexts.filter(c => c._selected && (c.type === 'scanner' || c.type === 'pe_analyst')).length >= 2 && (
                  <button onClick={() => {
                    const comparables = chatContexts.filter(c => c._selected && (c.type === 'scanner' || c.type === 'pe_analyst'));
                    const merged = comparables.map((ctx, i) => `─── Binary ${i + 1}: ${ctx.fileName || '?'} ───\n${formatContextItem(ctx)}`).join('\n\n');
                    setInput(merged + '\n\nBu iki binary arasındaki farkları ve benzerlikleri detaylıca karşılaştır. Section yapıları, import tabloları, koruma mekanizmaları, entropi değerleri ve risk skorları açısından analiz et.');
                  }}
                    style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#fbbf24', cursor: 'pointer', fontSize: 9, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 3 }}>
                    <Microscope size={8} /> Karşılaştır
                  </button>
                )}
                <button onClick={() => setChatContexts([])}
                  style={{ padding: '2px 7px', borderRadius: 4, border: '1px solid rgba(239,68,68,0.15)', background: 'transparent', color: '#f87171', cursor: 'pointer', fontSize: 9 }}>
                  Temizle
                </button>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
              {chatContexts.map(ctx => (
                <div key={ctx._id} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px', borderRadius: 6,
                  border: `1px solid ${ctx._selected ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`,
                  background: ctx._selected ? 'rgba(99,102,241,0.1)' : 'rgba(255,255,255,0.02)',
                  cursor: 'pointer', transition: 'all 0.12s', userSelect: 'none' }}
                  onClick={() => toggleContext(ctx._id)}>
                  <input type="checkbox" checked={ctx._selected} readOnly
                    style={{ width: 11, height: 11, cursor: 'pointer', accentColor: '#6366f1' }} />
                  <span style={{ fontSize: 10, color: ctx._selected ? '#c7d2fe' : '#4b5563', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {contextLabel(ctx)}
                  </span>
                  <button onClick={(e) => { e.stopPropagation(); removeContext(ctx._id); }}
                    style={{ border: 'none', background: 'transparent', color: '#374151', cursor: 'pointer', padding: 0, lineHeight: 1, display: 'flex' }}>
                    <X size={9} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {chatContexts.length > 0 && messages.length === 0 && !streaming && (
          <div style={{ borderRadius: 10, padding: '10px 14px', background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.2)', display: 'flex', alignItems: 'center', gap: 10 }}>
            <MessageSquare size={14} color="#a78bfa" style={{ flexShrink: 0 }} />
            <div style={{ fontSize: 11, color: '#6b7280' }}>
              <strong style={{ color: '#a78bfa' }}>{chatContexts.filter(c => c._selected).length} kaynak</strong> seçili — textarea dolduruldu, gönder butonuna bas. Seçimi değiştirip "Seçilenleri Yükle" ile yeniden oluşturabilirsin.
            </div>
          </div>
        )}
        {messages.length === 0 && !streaming && chatContexts.length === 0 && (
          <div style={{ textAlign: 'center', padding: '64px 0' }}>
            <MessageSquare size={40} color="#1e2330" style={{ margin: '0 auto 14px', display: 'block' }} />
            <div style={{ fontSize: 14, color: '#2d3748' }}>Henüz mesaj yok</div>
            <div style={{ fontSize: 12, color: '#1e2330', marginTop: 5 }}>LM Studio'da bir model yükleyin, sunucuyu başlatın, bağlanın</div>
          </div>
        )}

        {/* 2.4 — IOC extraction panel */}
        {extractedIOCs.length > 0 && (
          <div style={{ borderRadius: 10, padding: '8px 12px', background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.15)', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
              onClick={() => setIocPanelOpen(v => !v)}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <AlertTriangle size={12} color="#f87171" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#f87171' }}>IOC Tespiti</span>
                <span style={{ fontSize: 9, color: '#4b5563', background: 'rgba(239,68,68,0.1)', padding: '1px 6px', borderRadius: 4 }}>
                  {extractedIOCs.length} bulgu
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <button onClick={(e) => {
                  e.stopPropagation();
                  const yaraStrings = extractedIOCs.map((ioc, idx) => {
                    if (ioc.type.startsWith('hash')) return `    $hash_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'ip') return `    $ip_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'domain') return `    $domain_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'url') return `    $url_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'path') return `    $path_${idx} = "${ioc.value}"`;
                    if (ioc.type === 'registry') return `    $reg_${idx} = "${ioc.value}"`;
                    return null;
                  }).filter(Boolean).join('\n');
                  const rule = `rule AI_Extracted_IOCs {\n  meta:\n    author = "Dissect AI"\n    date = "${new Date().toISOString().slice(0,10)}"\n    description = "Auto-generated from AI chat IOC extraction"\n  strings:\n${yaraStrings}\n  condition:\n    any of them\n}`;
                  setInput(rule);
                }}
                  style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(245,158,11,0.2)', background: 'rgba(245,158,11,0.06)', color: '#fbbf24', cursor: 'pointer', fontSize: 9, display: 'flex', alignItems: 'center', gap: 3 }}>
                  YARA Dönüştür
                </button>
                <button onClick={(e) => {
                  e.stopPropagation();
                  const text = extractedIOCs.map(ioc => `[${ioc.type}] ${ioc.value}`).join('\n');
                  navigator.clipboard.writeText(text);
                }}
                  style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#4b5563', cursor: 'pointer', fontSize: 9, display: 'flex', alignItems: 'center', gap: 3 }}>
                  <Copy size={8} /> Kopyala
                </button>
                <ChevronDown size={12} color="#4b5563" style={{ transform: iocPanelOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
              </div>
            </div>
            {iocPanelOpen && (
              <div style={{ marginTop: 8, maxHeight: 200, overflow: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                      <th style={{ textAlign: 'left', padding: '3px 8px', color: '#4b5563', fontWeight: 600 }}>Tip</th>
                      <th style={{ textAlign: 'left', padding: '3px 8px', color: '#4b5563', fontWeight: 600 }}>Değer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {extractedIOCs.map((ioc, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ padding: '3px 8px', color: ioc.type.startsWith('hash') ? '#fbbf24' : ioc.type === 'ip' ? '#f87171' : ioc.type === 'domain' ? '#fb923c' : ioc.type === 'url' ? '#818cf8' : '#4ade80' }}>
                          {{ 'hash-md5': 'MD5', 'hash-sha1': 'SHA1', 'hash-sha256': 'SHA256', ip: 'IP', domain: 'Domain', url: 'URL', path: 'Dosya Yolu', registry: 'Registry' }[ioc.type] || ioc.type}
                        </td>
                        <td style={{ padding: '3px 8px', color: '#9ca3af', fontFamily: 'monospace', wordBreak: 'break-all' }}>{ioc.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {messages.map((msg, i) => {
          // 2.5 — Parse confidence score from assistant messages
          let msgContent = msg.content;
          let confidence = null;
          if (msg.role === 'assistant') {
            const confMatch = msgContent.match(/\[CONFIDENCE:(\d{1,3})%?\]/i);
            if (confMatch) {
              confidence = parseInt(confMatch[1]);
              msgContent = msgContent.replace(/\n?\[CONFIDENCE:\d{1,3}%?\]/gi, '').trim();
            }
          }
          const confColor = confidence != null ? (confidence >= 80 ? '#22c55e' : confidence >= 50 ? '#eab308' : '#ef4444') : null;
          return (
          <div key={i} style={{ display: 'flex', justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start', alignItems: 'flex-start', gap: 10 }}>
            {msg.role === 'assistant' && (
              <div style={{ width: 30, height: 30, borderRadius: 9, background: 'rgba(139,92,246,0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                <Bot size={15} color="#a78bfa" />
              </div>
            )}
            <div style={{ maxWidth: '74%', padding: '10px 15px', borderRadius: msg.role === 'user' ? '14px 14px 4px 14px' : '14px 14px 14px 4px', background: msg.role === 'user' ? 'rgba(99,102,241,0.16)' : 'rgba(255,255,255,0.038)', border: `1px solid ${msg.role === 'user' ? 'rgba(99,102,241,0.28)' : 'rgba(255,255,255,0.07)'}` }}>
              {msg.role === 'user'
                ? <div style={{ fontSize: 13, color: '#c7d2fe', lineHeight: 1.65, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{msg.content}</div>
                : <MdText text={msgContent} />
              }
              {/* 2.5 — Confidence badge */}
              {msg.role === 'assistant' && confidence != null && (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, marginTop: 8, padding: '3px 10px', borderRadius: 6, border: `1px solid ${confColor}33`, background: `${confColor}0d` }}>
                  <div style={{ width: 7, height: 7, borderRadius: '50%', background: confColor }} />
                  <span style={{ fontSize: 10, fontWeight: 600, color: confColor }}>Güven: %{confidence}</span>
                  <span style={{ fontSize: 9, color: '#4b5563' }}>
                    {confidence >= 80 ? '— Yüksek olasılıkla' : confidence >= 50 ? '— Orta kesinlik' : '— Düşük güven'}
                  </span>
                </div>
              )}
              {/* FAZ 9.6 — Feedback buttons */}
              {msg.role === 'assistant' && !streaming && (
                <div style={{ display: 'inline-flex', gap: 4, marginTop: 6, marginLeft: 8 }}>
                  <button onClick={() => addFeedback(i, true)} title="İyi yanıt"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, opacity: 0.5, padding: '2px 4px' }}
                    onMouseEnter={e => e.currentTarget.style.opacity = 1} onMouseLeave={e => e.currentTarget.style.opacity = 0.5}>👍</button>
                  <button onClick={() => addFeedback(i, false)} title="Kötü yanıt"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, opacity: 0.5, padding: '2px 4px' }}
                    onMouseEnter={e => e.currentTarget.style.opacity = 1} onMouseLeave={e => e.currentTarget.style.opacity = 0.5}>👎</button>
                </div>
              )}
              {/* 31 — Follow-up suggestions on last assistant message */}
              {msg.role === 'assistant' && i === messages.length - 1 && !streaming && (
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 10, paddingTop: 9, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                  {(FOLLOWUP_BY_MODE[mode] || FOLLOWUP_BY_MODE['analyze']).map(s => (
                    <button key={s} onClick={() => setInput(s)}
                      style={{ padding: '3px 10px', borderRadius: 6, border: '1px solid rgba(139,92,246,0.2)', background: 'rgba(139,92,246,0.05)', color: '#6b7280', cursor: 'pointer', fontSize: 10, transition: 'all 0.12s' }}
                      onMouseEnter={e => { e.currentTarget.style.color = '#a78bfa'; e.currentTarget.style.borderColor = 'rgba(139,92,246,0.4)'; }}
                      onMouseLeave={e => { e.currentTarget.style.color = '#6b7280'; e.currentTarget.style.borderColor = 'rgba(139,92,246,0.2)'; }}>
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>
            {msg.role === 'user' && (
              <div style={{ width: 30, height: 30, borderRadius: 9, background: 'rgba(99,102,241,0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1, fontSize: 13, color: '#818cf8', fontWeight: 700 }}>S</div>
            )}
          </div>
          );
        })}

        {streaming && (
          <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'flex-start', gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 9, background: 'rgba(139,92,246,0.14)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
              <Bot size={15} color="#a78bfa" />
            </div>
            <div style={{ maxWidth: '74%', padding: '10px 15px', borderRadius: '14px 14px 14px 4px', background: 'rgba(255,255,255,0.038)', border: '1px solid rgba(255,255,255,0.07)' }}>
              {streamContent
                ? <><MdText text={streamContent} /><span style={{ display: 'inline-block', width: 2, height: 13, background: '#a78bfa', marginLeft: 2, verticalAlign: 'middle', animation: 'cursor-blink 1s steps(1) infinite' }} /></>
                : <span style={{ fontSize: 13, color: '#374151' }}>Düşünüyor⬦<span style={{ display: 'inline-block', width: 2, height: 13, background: '#a78bfa', marginLeft: 2, verticalAlign: 'middle', animation: 'cursor-blink 1s steps(1) infinite' }} /></span>
              }
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* —� Input —� */}
      <div style={{ padding: '10px 20px 16px', borderTop: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
        {/* Quick Actions — 36 */}
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>
          {QUICK_PROMPTS.map(p => (
            <button key={p.label} onClick={() => setInput(p.text)} disabled={streaming}
              style={{ padding: '3px 9px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.03)', color: '#374151', cursor: streaming ? 'not-allowed' : 'pointer', fontSize: 10, transition: 'all 0.12s' }}
              onMouseEnter={e => { if (!streaming) { e.currentTarget.style.color = '#818cf8'; e.currentTarget.style.borderColor = 'rgba(99,102,241,0.3)'; } }}
              onMouseLeave={e => { e.currentTarget.style.color = '#374151'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'; }}>
              {p.label}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); compareMode && secondModel ? sendCompareMessage() : sendMessage(); } }}
            placeholder={connected ? `${selectedModel}${compareMode ? ' ⚖ ' + secondModel : ''} — Mesaj yaz` : 'Önce LM Studio\'ya bağlanın⬦'}
            disabled={streaming}
            rows={2}
            style={{ flex: 1, background: 'rgba(0,0,0,0.35)', border: '1px solid rgba(255,255,255,0.09)', borderRadius: 10, padding: '10px 13px', fontSize: 13, color: '#e2e8f0', outline: 'none', resize: 'none', fontFamily: 'inherit', lineHeight: 1.5 }}
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <button onClick={compareMode && secondModel ? sendCompareMessage : sendMessage} disabled={streaming || !input.trim() || !isReady}
              style={{ width: 44, height: 44, borderRadius: 10, border: 'none', background: (!streaming && input.trim() && connected && selectedModel) ? 'rgba(99,102,241,0.22)' : 'rgba(99,102,241,0.06)', color: (!streaming && input.trim() && connected && selectedModel) ? '#818cf8' : '#2d3748', cursor: (!streaming && input.trim() && connected && selectedModel) ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.13s' }}>
              <Send size={17} />
            </button>
            {messages.length > 0 && !streaming && (
              <button onClick={() => setMessages([])}
                style={{ width: 44, height: 22, borderRadius: 7, border: '1px solid rgba(255,255,255,0.06)', background: 'transparent', color: '#2d3748', cursor: 'pointer', fontSize: 9, fontWeight: 600, textTransform: 'uppercase' }}>
                Sil
              </button>
            )}
          </div>
        </div>
      </div>


































































































































































































































    </div>
  );
}

export default ChatPage;