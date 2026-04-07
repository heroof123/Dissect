import React, { useState, useMemo } from 'react';
import { getHistory } from '../utils/peHelpers';
import { Card, CardHeader } from './shared';

function DashboardPage() {
  const [history] = useState(getHistory);
  const [searchQ, setSearchQ] = useState('');
  const [searchRegex, setSearchRegex] = useState(false);
  const [filterArch, setFilterArch] = useState('all');
  const [filterRisk, setFilterRisk] = useState('all');
  const [filterPacker, setFilterPacker] = useState('all');
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');
  const [projectName, setProjectName] = useState('');
  const [projects, setProjects] = useState(() => {
    try { return JSON.parse(localStorage.getItem('dissect_projects') || '[]'); } catch { return []; }
  });
  const [activeProject, setActiveProject] = useState(null);

  const saveProjects = (p) => { setProjects(p); localStorage.setItem('dissect_projects', JSON.stringify(p)); };

  // ── 4.4 Advanced search with filters ───────────────────────────
  const filtered = useMemo(() => {
    let items = activeProject
      ? history.filter(h => (activeProject.fileIds || []).includes(h.id))
      : history;

    if (searchQ) {
      if (searchRegex) {
        try {
          const rx = new RegExp(searchQ, 'i');
          items = items.filter(h => rx.test(h.fileName) || rx.test(h.result?.sha256 || '') || rx.test(h.result?.md5 || '') || (h.result?.strings || []).some(s => rx.test(s.text || s)));
        } catch { /* invalid regex */ }
      } else {
        const q = searchQ.toLowerCase();
        items = items.filter(h => h.fileName?.toLowerCase().includes(q) || String(h.riskScore).includes(q) || h.arch?.includes(q) || (h.result?.sha256 || '').includes(q) || (h.result?.md5 || '').includes(q) || (h.packers || []).some(p => p.toLowerCase().includes(q)));
      }
    }
    if (filterArch !== 'all') items = items.filter(h => h.arch === filterArch);
    if (filterRisk === 'high') items = items.filter(h => h.riskScore >= 60);
    else if (filterRisk === 'moderate') items = items.filter(h => h.riskScore >= 30 && h.riskScore < 60);
    else if (filterRisk === 'clean') items = items.filter(h => h.riskScore < 30);
    if (filterPacker !== 'all') items = items.filter(h => (h.packers || []).includes(filterPacker));
    if (filterDateFrom) items = items.filter(h => h.ts >= filterDateFrom);
    if (filterDateTo) items = items.filter(h => h.ts <= filterDateTo + 'T23:59:59');
    return items;
  }, [history, searchQ, searchRegex, filterArch, filterRisk, filterPacker, filterDateFrom, filterDateTo, activeProject]);

  // ── Stats ──────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const total = filtered.length;
    const riskH = filtered.filter(h => h.riskScore >= 60).length;
    const riskM = filtered.filter(h => h.riskScore >= 30 && h.riskScore < 60).length;
    const riskL = filtered.filter(h => h.riskScore < 30).length;
    const avgRisk = total ? Math.round(filtered.reduce((s,h) => s + (h.riskScore||0), 0) / total) : 0;
    const x64 = filtered.filter(h => h.arch === 'x64').length;
    const x86 = filtered.filter(h => h.arch === 'x86').length;

    // Packer dist
    const packerMap = {};
    filtered.forEach(h => (h.packers || []).forEach(p => { packerMap[p] = (packerMap[p] || 0) + 1; }));
    const topPackers = Object.entries(packerMap).sort((a,b) => b[1]-a[1]).slice(0, 8);

    // DLL frequency from imports
    const dllMap = {};
    filtered.forEach(h => (h.result?.imports || []).forEach(imp => {
      const dll = (imp.dll || '').toLowerCase();
      if (dll) dllMap[dll] = (dllMap[dll] || 0) + 1;
    }));
    const topDlls = Object.entries(dllMap).sort((a,b) => b[1]-a[1]).slice(0, 10);

    // Timeline: scans per day
    const dayMap = {};
    filtered.forEach(h => {
      const d = (h.ts || '').slice(0, 10);
      if (d) dayMap[d] = (dayMap[d] || 0) + 1;
    });
    const timeline = Object.entries(dayMap).sort((a,b) => a[0].localeCompare(b[0])).slice(-14); // last 14 days

    // Protection breakdown
    const protections = { Denuvo: 0, VMProtect: 0, Themida: 0, AntiDebug: 0, AntiVM: 0 };
    filtered.forEach(h => {
      if (h.denuvo || h.result?.denuvo) protections.Denuvo++;
      if (h.vmp || h.result?.vmp) protections.VMProtect++;
      if (h.result?.themida) protections.Themida++;
      if (h.antiDebug || h.result?.antiDebug) protections.AntiDebug++;
      if (h.result?.antiVM) protections.AntiVM++;
    });

    return { total, riskH, riskM, riskL, avgRisk, x64, x86, topPackers, topDlls, timeline, protections };
  }, [filtered]);

  // ── PDF Export (4.1) ───────────────────────────────────────────
  const exportPDF = () => {
    const w = window.open('', '_blank');
    const rows = filtered.map(h => `<tr>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:12px;font-family:monospace">${h.fileName || '?'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:center">${h.arch || '?'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:center;color:${h.riskScore>=60?'#dc2626':h.riskScore>=30?'#d97706':'#16a34a'};font-weight:700">${h.riskScore ?? '—'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:11px">${(h.packers||[]).join(', ')||'—'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:10px;font-family:monospace;color:#666">${(h.result?.sha256||'').slice(0,16)||'—'}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:10px;color:#888">${(h.ts||'').slice(0,10)}</td>
    </tr>`).join('');
    w.document.write(`<!DOCTYPE html><html><head><title>Dissect Report — ${new Date().toLocaleDateString('tr-TR')}</title>
    <style>body{font-family:Inter,Arial,sans-serif;margin:30px 40px;color:#111}h1{font-size:22px;margin-bottom:4px}h2{font-size:14px;color:#6366f1;margin-top:24px}
    table{border-collapse:collapse;width:100%;margin-top:8px}th{background:#f3f4f6;padding:8px 10px;text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;border-bottom:2px solid #e5e7eb}
    .stat{display:inline-block;text-align:center;padding:12px 20px;margin:4px;border-radius:8px;background:#f9fafb;border:1px solid #e5e7eb}
    .stat .n{font-size:24px;font-weight:800}.stat .l{font-size:10px;color:#6b7280;margin-top:2px}
    @media print{body{margin:15px 20px}}</style></head><body>
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:24px">
      <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:flex;align-items:center;justify-content:center;color:white;font-size:22px;font-weight:900">D</div>
      <div><h1 style="margin:0">Dissect — Analysis Report</h1>
      <div style="font-size:12px;color:#6b7280">${new Date().toLocaleDateString('tr-TR', {year:'numeric',month:'long',day:'numeric'})} · ${filtered.length} dosya · Avg Risk: ${stats.avgRisk}</div></div>
    </div>
    <div style="margin-bottom:20px">
      <div class="stat"><div class="n">${stats.total}</div><div class="l">Total Scans</div></div>
      <div class="stat"><div class="n" style="color:#dc2626">${stats.riskH}</div><div class="l">High Risk</div></div>
      <div class="stat"><div class="n" style="color:#d97706">${stats.riskM}</div><div class="l">Moderate</div></div>
      <div class="stat"><div class="n" style="color:#16a34a">${stats.riskL}</div><div class="l">Clean</div></div>
      <div class="stat"><div class="n">${stats.x64}</div><div class="l">x64</div></div>
      <div class="stat"><div class="n">${stats.x86}</div><div class="l">x86</div></div>
    </div>
    ${stats.topPackers.length ? `<h2>Packer Distribution</h2><table><tr>${stats.topPackers.map(([p,c]) => `<td style="padding:6px 12px;text-align:center"><div style="font-weight:700;font-size:16px">${c}</div><div style="font-size:10px;color:#6b7280">${p}</div></td>`).join('')}</tr></table>` : ''}
    ${stats.topDlls.length ? `<h2>Most Common DLLs</h2><table><tr>${stats.topDlls.map(([d,c]) => `<td style="padding:6px 12px;text-align:center"><div style="font-weight:700;font-size:14px">${c}</div><div style="font-size:10px;font-family:monospace;color:#6b7280">${d}</div></td>`).join('')}</tr></table>` : ''}
    <h2>Scan Details</h2>
    <table><thead><tr><th>File</th><th>Arch</th><th>Risk</th><th>Packers</th><th>SHA-256</th><th>Date</th></tr></thead><tbody>${rows}</tbody></table>
    <div style="margin-top:30px;padding-top:12px;border-top:1px solid #e5e7eb;font-size:10px;color:#9ca3af;text-align:center">Generated by Dissect v1.0 · ${new Date().toISOString()}</div>
    </body></html>`);
    w.document.close();
    setTimeout(() => w.print(), 500);
  };

  const StatCard = ({ value, label, color }) => (
    <div style={{ padding: '14px 18px', borderRadius: 10, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', textAlign: 'center', minWidth: 80 }}>
      <div style={{ fontSize: 24, fontWeight: 800, color: color || '#e5e7eb', fontFamily: 'monospace' }}>{value}</div>
      <div style={{ fontSize: 10, color: '#4b5563', marginTop: 2 }}>{label}</div>
    </div>
  );

  const BarH = ({ value, max, color, label }) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
      <span style={{ fontSize: 10, color: '#94a3b8', minWidth: 80, textAlign: 'right', fontFamily: 'monospace' }}>{label}</span>
      <div style={{ flex: 1, height: 14, borderRadius: 4, background: 'rgba(255,255,255,0.04)', overflow: 'hidden' }}>
        <div style={{ width: `${max > 0 ? (value/max*100) : 0}%`, height: '100%', background: color || '#6366f1', borderRadius: 4, transition: 'width 0.6s' }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color: '#e5e7eb', minWidth: 24, fontFamily: 'monospace' }}>{value}</span>
    </div>
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 800, color: '#e5e7eb', margin: 0, letterSpacing: '-0.02em' }}>📊 Dashboard</h2>
          <div style={{ fontSize: 11, color: '#4b5563', marginTop: 2 }}>FAZ 4 — İstatistikler · Arama · Projeler · Raporlama</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={exportPDF} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', fontWeight: 600 }}>📄 PDF Report</button>
        </div>
      </div>

      {/* Stats cards row */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap' }}>
        <StatCard value={stats.total} label="Toplam Tarama" color="#818cf8" />
        <StatCard value={stats.riskH} label="High Risk" color="#f87171" />
        <StatCard value={stats.riskM} label="Moderate" color="#fbbf24" />
        <StatCard value={stats.riskL} label="Clean" color="#4ade80" />
        <StatCard value={stats.avgRisk} label="Avg Risk" color={stats.avgRisk >= 60 ? '#f87171' : stats.avgRisk >= 30 ? '#fbbf24' : '#4ade80'} />
        <StatCard value={stats.x64} label="x64" color="#60a5fa" />
        <StatCard value={stats.x86} label="x86" color="#a78bfa" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        {/* Timeline chart */}
        <Card>
          <CardHeader>Tarama Zaman Çizelgesi (son 14 gün)</CardHeader>
          <div style={{ padding: '12px 16px' }}>
            {stats.timeline.length === 0 ? <div style={{ fontSize: 11, color: '#374151' }}>Yeterli veri yok</div> : (
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 80 }}>
                {stats.timeline.map(([day, count], i) => {
                  const maxC = Math.max(...stats.timeline.map(t => t[1]));
                  return (
                    <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                      <span style={{ fontSize: 9, color: '#818cf8', fontWeight: 700 }}>{count}</span>
                      <div style={{ width: '100%', height: `${maxC > 0 ? count/maxC*60 : 0}px`, background: 'linear-gradient(to top, #6366f1, #818cf8)', borderRadius: '3px 3px 0 0', minHeight: 2 }} />
                      <span style={{ fontSize: 8, color: '#374151', whiteSpace: 'nowrap' }}>{day.slice(5)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </Card>

        {/* Protection breakdown */}
        <Card>
          <CardHeader>Koruma Tespiti Dağılımı</CardHeader>
          <div style={{ padding: '12px 16px' }}>
            {(() => {
              const maxP = Math.max(...Object.values(stats.protections), 1);
              const colors = { Denuvo: '#f87171', VMProtect: '#fb923c', Themida: '#fbbf24', AntiDebug: '#60a5fa', AntiVM: '#a78bfa' };
              return Object.entries(stats.protections).map(([k, v]) => <BarH key={k} label={k} value={v} max={maxP} color={colors[k]} />);
            })()}
          </div>
        </Card>

        {/* Top packers */}
        <Card>
          <CardHeader>Packer Dağılımı</CardHeader>
          <div style={{ padding: '12px 16px' }}>
            {stats.topPackers.length === 0 ? <div style={{ fontSize: 11, color: '#374151' }}>Packer tespit edilmemiş</div> : (() => {
              const maxP = Math.max(...stats.topPackers.map(p => p[1]), 1);
              return stats.topPackers.map(([packer, count]) => <BarH key={packer} label={packer} value={count} max={maxP} color="#f59e0b" />);
            })()}
          </div>
        </Card>

        {/* Top DLLs */}
        <Card>
          <CardHeader>En Sık Görülen DLL'ler</CardHeader>
          <div style={{ padding: '12px 16px' }}>
            {stats.topDlls.length === 0 ? <div style={{ fontSize: 11, color: '#374151' }}>Import verisi yok</div> : (() => {
              const maxD = Math.max(...stats.topDlls.map(d => d[1]), 1);
              return stats.topDlls.map(([dll, count]) => <BarH key={dll} label={dll} value={count} max={maxD} color="#60a5fa" />);
            })()}
          </div>
        </Card>
      </div>

      {/* ── 4.4 Advanced Search + Filters ──────────────────────────── */}
      <Card>
        <CardHeader>Gelişmiş Arama & Filtreler (FAZ 4.4)</CardHeader>
        <div style={{ padding: '12px 16px' }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <input value={searchQ} onChange={e => setSearchQ(e.target.value)} placeholder={searchRegex ? 'Regex pattern...' : 'Dosya adı, hash, packer...'} style={{ flex: 1, minWidth: 200, fontSize: 12, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e5e7eb', outline: 'none' }} />
            <label style={{ fontSize: 10, color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
              <input type="checkbox" checked={searchRegex} onChange={e => setSearchRegex(e.target.checked)} style={{ accentColor: '#6366f1' }} /> Regex
            </label>
            <select value={filterArch} onChange={e => setFilterArch(e.target.value)} style={{ fontSize: 11, padding: '5px 8px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#e5e7eb' }}>
              <option value="all">Tüm Arch</option>
              <option value="x64">x64</option>
              <option value="x86">x86</option>
            </select>
            <select value={filterRisk} onChange={e => setFilterRisk(e.target.value)} style={{ fontSize: 11, padding: '5px 8px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#e5e7eb' }}>
              <option value="all">Tüm Risk</option>
              <option value="high">High (60+)</option>
              <option value="moderate">Moderate (30-59)</option>
              <option value="clean">Clean (&lt;30)</option>
            </select>
            {(() => {
              const allPackers = [...new Set(history.flatMap(h => h.packers || []))];
              return allPackers.length > 0 ? (
                <select value={filterPacker} onChange={e => setFilterPacker(e.target.value)} style={{ fontSize: 11, padding: '5px 8px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#e5e7eb' }}>
                  <option value="all">Tüm Packer</option>
                  {allPackers.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              ) : null;
            })()}
            <input type="date" value={filterDateFrom} onChange={e => setFilterDateFrom(e.target.value)} style={{ fontSize: 10, padding: '4px 6px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#94a3b8' }} />
            <span style={{ fontSize: 10, color: '#374151' }}>—</span>
            <input type="date" value={filterDateTo} onChange={e => setFilterDateTo(e.target.value)} style={{ fontSize: 10, padding: '4px 6px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)', background: '#111', color: '#94a3b8' }} />
          </div>

          <div style={{ fontSize: 10, color: '#4b5563', marginBottom: 8 }}>{filtered.length} / {history.length} sonuç</div>

          {/* Results table */}
          <div style={{ maxHeight: 320, overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#6b7280', textTransform: 'uppercase' }}>Dosya</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>Arch</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>Risk</th>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>Packers</th>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>SHA-256</th>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: '#6b7280' }}>Tarih</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((h, i) => (
                  <tr key={h.id || i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '5px 10px', color: '#e5e7eb', fontFamily: 'monospace', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.fileName}</td>
                    <td style={{ padding: '5px 10px', textAlign: 'center', color: '#94a3b8' }}>{h.arch}</td>
                    <td style={{ padding: '5px 10px', textAlign: 'center', fontWeight: 700, color: h.riskScore >= 60 ? '#f87171' : h.riskScore >= 30 ? '#fbbf24' : '#4ade80' }}>{h.riskScore}</td>
                    <td style={{ padding: '5px 10px', color: '#94a3b8', fontSize: 10 }}>{(h.packers || []).join(', ') || '—'}</td>
                    <td style={{ padding: '5px 10px', color: '#4b5563', fontFamily: 'monospace', fontSize: 9 }}>{(h.result?.sha256 || '').slice(0, 16) || '—'}</td>
                    <td style={{ padding: '5px 10px', color: '#4b5563', fontSize: 10 }}>{(h.ts || '').slice(0, 10)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Card>

      {/* ── 4.5 Workspace / Proje ──────────────────────────────────── */}
      <Card style={{ marginTop: 16 }}>
        <CardHeader>Workspace / Projeler (FAZ 4.5)</CardHeader>
        <div style={{ padding: '12px 16px' }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
            <input value={projectName} onChange={e => setProjectName(e.target.value)} placeholder="Yeni proje adı..." style={{ flex: 1, fontSize: 12, padding: '6px 12px', borderRadius: 7, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.03)', color: '#e5e7eb', outline: 'none' }} />
            <button onClick={() => {
              if (!projectName.trim()) return;
              const p = { id: Date.now(), name: projectName.trim(), fileIds: [], notes: '', created: new Date().toISOString() };
              saveProjects([p, ...projects]);
              setProjectName('');
            }} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#4ade80', cursor: 'pointer', fontWeight: 600 }}>+ Oluştur</button>
            {activeProject && <button onClick={() => setActiveProject(null)} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 7, border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#f87171', cursor: 'pointer' }}>✕ Proje filtresi kaldır</button>}
          </div>

          {projects.length === 0 ? <div style={{ fontSize: 11, color: '#374141' }}>Henüz proje yok. Yukarıdan oluşturabilirsiniz.</div> : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {projects.map(p => (
                <div key={p.id} style={{ padding: '8px 14px', borderRadius: 8, background: activeProject?.id === p.id ? 'rgba(99,102,241,0.15)' : 'rgba(255,255,255,0.03)', border: `1px solid ${activeProject?.id === p.id ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }} onClick={() => setActiveProject(activeProject?.id === p.id ? null : p)}>
                  <span style={{ fontSize: 12, color: '#e5e7eb', fontWeight: 600 }}>{p.name}</span>
                  <span style={{ fontSize: 9, color: '#4b5563' }}>{(p.fileIds || []).length} dosya</span>
                  {/* Add scans to project */}
                  <button onClick={e => {
                    e.stopPropagation();
                    const ids = filtered.map(h => h.id);
                    const updated = projects.map(pp => pp.id === p.id ? { ...pp, fileIds: [...new Set([...(pp.fileIds || []), ...ids])] } : pp);
                    saveProjects(updated);
                  }} style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, border: '1px solid rgba(99,102,241,0.2)', background: 'transparent', color: '#818cf8', cursor: 'pointer' }} title="Filtrelenen sonuçları projeye ekle">+ekle</button>
                  <button onClick={e => {
                    e.stopPropagation();
                    if (activeProject?.id === p.id) setActiveProject(null);
                    saveProjects(projects.filter(pp => pp.id !== p.id));
                  }} style={{ fontSize: 9, padding: '2px 5px', borderRadius: 4, border: 'none', background: 'transparent', color: '#f87171', cursor: 'pointer' }}>✕</button>
                </div>
              ))}
            </div>
          )}

          {/* Project export */}
          {activeProject && (
            <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
              <button onClick={() => {
                const blob = new Blob([JSON.stringify({ project: activeProject, scans: filtered }, null, 2)], { type: 'application/json' });
                const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
                a.download = `dissect_project_${activeProject.name.replace(/\s+/g, '_')}_${Date.now()}.json`;
                a.click(); URL.revokeObjectURL(a.href);
              }} style={{ fontSize: 10, padding: '5px 12px', borderRadius: 6, border: '1px solid rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.06)', color: '#818cf8', cursor: 'pointer' }}>📦 Export Project JSON</button>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════
// FAZ 6 — İleri Seviye Analiz Araçları
// ══════════════════════════════════════════════════════════════════════

// ── 6.1 Canlı Süreç Bağlanma (Process Attach) ────────────────────

export default DashboardPage;