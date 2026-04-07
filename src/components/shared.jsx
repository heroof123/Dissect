import React, { useState } from 'react';

function WinBtn({ onClick, danger, children }) {
  const [h, setH] = useState(false);
  return (
    <button onClick={onClick} onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)}
      style={{ width: 34, height: 34, border: 'none', cursor: 'pointer', borderRadius: 8, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: h ? (danger ? 'rgba(239,68,68,0.16)' : 'rgba(255,255,255,0.09)') : 'transparent', color: h ? (danger ? '#f87171' : '#e2e8f0') : '#4b5563', transition: 'all 0.13s' }}>
      {children}
    </button>
  );
}

function NavItem({ active, onClick, icon, label, sub, badge }) {
  const [h, setH] = useState(false);
  return (
    <button onClick={onClick} onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)}
      style={{ width: '100%', border: 'none', cursor: 'pointer', borderRadius: 8, padding: '10px 11px', textAlign: 'left', display: 'flex', alignItems: 'center', gap: 10, background: active ? 'rgba(99,102,241,0.11)' : h ? 'rgba(255,255,255,0.04)' : 'transparent', borderLeft: `2px solid ${active ? '#6366f1' : 'transparent'}`, marginBottom: 3, transition: 'all 0.13s' }}>
      <span style={{ color: active ? '#818cf8' : '#64748b' }}>{icon}</span>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12, fontWeight: 500, color: active ? '#e2e8f0' : '#94a3b8', lineHeight: 1.3 }}>{label}</div>
        <div style={{ fontSize: 10, color: active ? '#6366f1' : '#64748b', marginTop: 1 }}>{sub}</div>
      </div>
      {badge && <span style={{ fontSize: 9, background: 'rgba(99,102,241,0.25)', color: '#818cf8', padding: '1px 5px', borderRadius: 4, fontWeight: 700 }}>{badge}</span>}
      {active && <ChevronRight size={12} color="#3d4451" />}
    </button>
  );
}

function Card({ children, style }) {
  return <div style={{ borderRadius: 12, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', ...style }}>{children}</div>;
}

function CardHeader({ children }) {
  return <div style={{ padding: '11px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: 10, fontWeight: 600, color: '#374151', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{children}</div>;
}

function Spinner() {
  return <>
    <style>{`@keyframes _sp { to { transform: rotate(360deg); } }`}</style>
    <div style={{ width: 36, height: 36, borderRadius: '50%', border: '2px solid rgba(99,102,241,0.18)', borderTop: '2px solid #6366f1', animation: '_sp 0.75s linear infinite' }} />
  </>;
}

// —�—�—� Markdown renderer (53) —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

function MdText({ text }) {
  if (!text) return null;
  const lines = text.split('\n');
  const nodes = [];
  let inCode = false;
  let codeBuf = [];
  let codeLang = '';

  const renderInline = (str) => {
    // Patterns: bold **x**, code `x`, italic *x*, hex 0x⬦, dll/exe names, known protections
    const PROTECT_RE = /\b(Denuvo|VMProtect|Themida|UPX|MPRESS|Obsidium|ASPack|Enigma|Arxan|SafeDisc|SecuROM)\b/i;
    const HEX_RE     = /\b0x[0-9A-Fa-f]{2,}\b/;
    const DLL_RE     = /\b[\w-]+\.(dll|exe|sys|drv)\b/i;
    const parts = [];
    let rest = str;
    let key = 0;
    while (rest.length) {
      const boldM    = rest.match(/\*\*(.+?)\*\*/);
      const codeM    = rest.match(/`([^`]+)`/);
      const italM    = rest.match(/\*([^*]+)\*/);
      const hexM     = rest.match(HEX_RE);
      const dllM     = rest.match(DLL_RE);
      const protM    = rest.match(PROTECT_RE);
      const matches  = [boldM, codeM, italM, hexM, dllM, protM].filter(Boolean).sort((a, b) => a.index - b.index);
      if (!matches.length) { parts.push(<React.Fragment key={key++}>{rest}</React.Fragment>); break; }
      const m = matches[0];
      if (m.index > 0) parts.push(<React.Fragment key={key++}>{rest.slice(0, m.index)}</React.Fragment>);
      if (m === boldM)  parts.push(<strong key={key++} style={{ color: '#e2e8f0', fontWeight: 700 }}>{m[1]}</strong>);
      else if (m === codeM)  parts.push(<code key={key++} style={{ fontFamily: 'monospace', fontSize: '0.9em', padding: '1px 5px', borderRadius: 3, background: 'rgba(99,102,241,0.15)', color: '#c4b5fd' }}>{m[1]}</code>);
      else if (m === italM)  parts.push(<em key={key++} style={{ color: '#a78bfa', fontStyle: 'italic' }}>{m[1]}</em>);
      else if (m === hexM)   parts.push(<code key={key++} style={{ fontFamily: 'monospace', fontSize: '0.9em', padding: '1px 5px', borderRadius: 3, background: 'rgba(245,158,11,0.12)', color: '#fbbf24', fontWeight: 600 }}>{m[0]}</code>);
      else if (m === dllM)   parts.push(<code key={key++} style={{ fontFamily: 'monospace', fontSize: '0.9em', padding: '1px 5px', borderRadius: 3, background: 'rgba(34,197,94,0.09)', color: '#4ade80' }}>{m[0]}</code>);
      else if (m === protM)  parts.push(<span key={key++} style={{ padding: '1px 6px', borderRadius: 3, background: 'rgba(239,68,68,0.15)', color: '#f87171', fontWeight: 700, fontSize: '0.88em' }}>{m[0]}</span>);
      rest = rest.slice(m.index + m[0].length);
    }
    return parts;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('```')) {
      if (!inCode) { inCode = true; codeBuf = []; codeLang = line.slice(3).trim(); }
      else {
        nodes.push(
          <div key={i} style={{ margin: '8px 0', borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.08)' }}>
            {codeLang && <div style={{ padding: '3px 12px', background: 'rgba(99,102,241,0.12)', fontSize: 10, color: '#818cf8', fontWeight: 600 }}>{codeLang}</div>}
            <pre style={{ margin: 0, padding: '10px 14px', background: 'rgba(0,0,0,0.35)', fontSize: 11, color: '#94a3b8', fontFamily: 'monospace', overflowX: 'auto', lineHeight: 1.6 }}>{codeBuf.join('\n')}</pre>
          </div>
        );
        inCode = false; codeBuf = [];
      }
      continue;
    }
    if (inCode) { codeBuf.push(line); continue; }

    if (line.startsWith('### '))      nodes.push(<h3 key={i} style={{ margin: '14px 0 4px', fontSize: 13, fontWeight: 700, color: '#c4b5fd' }}>{renderInline(line.slice(4))}</h3>);
    else if (line.startsWith('## '))  nodes.push(<h2 key={i} style={{ margin: '18px 0 5px', fontSize: 15, fontWeight: 700, color: '#a78bfa', borderBottom: '1px solid rgba(139,92,246,0.2)', paddingBottom: 4 }}>{renderInline(line.slice(3))}</h2>);
    else if (line.startsWith('# '))   nodes.push(<h1 key={i} style={{ margin: '20px 0 6px', fontSize: 17, fontWeight: 800, color: '#818cf8' }}>{renderInline(line.slice(2))}</h1>);
    else if (/^[-*] /.test(line))     nodes.push(<div key={i} style={{ display: 'flex', gap: 7, margin: '3px 0', paddingLeft: 8 }}><span style={{ color: '#6366f1', flexShrink: 0, marginTop: 1 }}>⬺</span><span style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.65 }}>{renderInline(line.slice(2))}</span></div>);
    else if (/^\d+\. /.test(line)) {
      const dotIdx = line.indexOf('. ');
      nodes.push(<div key={i} style={{ display: 'flex', gap: 7, margin: '3px 0', paddingLeft: 8 }}><span style={{ color: '#6366f1', flexShrink: 0, fontWeight: 700, fontSize: 11 }}>{line.slice(0, dotIdx + 1)}</span><span style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.65 }}>{renderInline(line.slice(dotIdx + 2))}</span></div>);
    }
    else if (line.trim() === '')      nodes.push(<div key={i} style={{ height: 8 }} />);
    else                              nodes.push(<p key={i} style={{ margin: '4px 0', fontSize: 13, color: '#94a3b8', lineHeight: 1.7 }}>{renderInline(line)}</p>);
  }
  return <div>{nodes}</div>;
}

// —�—�—� Scanner Page —�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�—�

export { WinBtn, NavItem, Card, CardHeader, Spinner, MdText };