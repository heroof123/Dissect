import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { FileText, Download } from 'lucide-react';
import { Card } from './shared';

function ReportPage() {
  const [filePath, setFilePath] = useState('');
  const [title, setTitle] = useState('Malware Analiz Raporu');
  const [analyst, setAnalyst] = useState('');
  const [lang, setLang] = useState('tr');
  const [includeImports, setIncludeImports] = useState(true);
  const [includeStrings, setIncludeStrings] = useState(false);
  const [includeAntiAnalysis, setIncludeAntiAnalysis] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const doGenerate = async () => {
    if (!filePath.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await invoke('generate_analysis_report', {
        filePath: filePath.trim(),
        title,
        analyst: analyst || 'Dissect Analyst',
        lang,
        includeImports,
        includeStrings,
        includeAntiAnalysis,
      });
      setResult(r);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const downloadHtml = () => {
    if (!result?.html) return;
    const blob = new Blob([result.html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dissect_report_${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const summaryData = result?.summary;

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <FileText size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Otomatik Rapor Üretimi</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Özet · Teknik Detay · IOC · HTML Export (D3)</span>
      </div>

      {/* Rapor ayarları */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3', marginBottom: 12 }}>Rapor Ayarları</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div>
            <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 4 }}>PE DOSYA YOLU</div>
            <input value={filePath} onChange={e => setFilePath(e.target.value)}
              placeholder="C:\malware.exe"
              style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', fontFamily: 'monospace', boxSizing: 'border-box' }} />
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <div style={{ flex: 2 }}>
              <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 4 }}>RAPOR BAŞLIĞI</div>
              <input value={title} onChange={e => setTitle(e.target.value)}
                placeholder="Malware Analiz Raporu"
                style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', boxSizing: 'border-box' }} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 4 }}>ANALİST ADI</div>
              <input value={analyst} onChange={e => setAnalyst(e.target.value)}
                placeholder="Ad Soyad"
                style={{ width: '100%', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none', boxSizing: 'border-box' }} />
            </div>
            <div style={{ flex: 0.8 }}>
              <div style={{ fontSize: 9, color: '#6e7681', marginBottom: 4 }}>DİL</div>
              <select value={lang} onChange={e => setLang(e.target.value)}
                style={{ width: '100%', background: '#161b22', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '7px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }}>
                <option value="tr">Türkçe</option>
                <option value="en">English</option>
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
            <div style={{ fontSize: 9, color: '#8b949e' }}>İçerik:</div>
            {[['includeImports', 'Şüpheli API Listesi', includeImports, setIncludeImports],
              ['includeAntiAnalysis', 'Anti-Analiz Skoru', includeAntiAnalysis, setIncludeAntiAnalysis],
              ['includeStrings', 'String Analizi (Yavaş)', includeStrings, setIncludeStrings]].map(([key, lbl, val, setter]) => (
              <label key={key} style={{ display: 'flex', gap: 5, alignItems: 'center', cursor: 'pointer' }}>
                <input type="checkbox" checked={val} onChange={e => setter(e.target.checked)}
                  style={{ accentColor: '#818cf8' }} />
                <span style={{ fontSize: 10, color: '#a8b3c4' }}>{lbl}</span>
              </label>
            ))}
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button onClick={doGenerate} disabled={loading || !filePath.trim()}
              style={{ fontSize: 10, padding: '8px 24px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.12)', color: '#818cf8', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 600 }}>
              {loading ? '⏳ Rapor oluşturuluyor...' : '📄 Rapor Oluştur'}
            </button>
          </div>
        </div>
      </Card>

      {error && <div style={{ color: '#f87171', fontSize: 11, marginBottom: 14, padding: '8px 12px', background: 'rgba(248,113,113,0.08)', borderRadius: 6 }}>❌ {error}</div>}

      {result && (
        <>
          {/* Özet */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
            {[
              ['Mimari', summaryData?.is_64 ? 'x64' : 'x86', '#818cf8'],
              ['Tür', summaryData?.is_dll ? 'DLL' : 'EXE', '#a3e635'],
              ['Boyut', `${(summaryData?.size / 1024).toFixed(1)} KB`, '#38bdf8'],
              ['Import', summaryData?.imports, '#c084fc'],
              ['Export', summaryData?.exports, '#fde68a'],
              ['Şüpheli API', summaryData?.suspicious_count, summaryData?.suspicious_count > 5 ? '#ef4444' : summaryData?.suspicious_count > 1 ? '#f59e0b' : '#22c55e'],
            ].map(([lbl, val, col]) => (
              <Card key={lbl} style={{ textAlign: 'center', minWidth: 80 }}>
                <div style={{ fontSize: 18, fontWeight: 700, color: col, fontFamily: 'monospace' }}>{val}</div>
                <div style={{ fontSize: 9, color: '#6e7681' }}>{lbl}</div>
              </Card>
            ))}
          </div>

          {/* HTML Önizleme ve İndir */}
          <Card>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#e6edf3' }}>HTML Rapor Önizleme</div>
              <button onClick={downloadHtml}
                style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, padding: '6px 14px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.08)', color: '#22c55e', cursor: 'pointer', fontWeight: 600 }}>
                <Download size={11} />
                HTML İndir
              </button>
            </div>
            <div style={{ borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden', height: 500 }}>
              <iframe
                srcDoc={result.html}
                style={{ width: '100%', height: '100%', border: 'none', background: '#0d1117' }}
                title="Rapor Önizleme"
                sandbox="allow-same-origin"
              />
            </div>
          </Card>
        </>
      )}

      {!result && !loading && (
        <Card>
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#6b7280' }}>
            <FileText size={32} color="#4b5563" style={{ margin: '0 auto 10px' }} />
            <div style={{ fontSize: 12, marginBottom: 4, color: '#8b949e' }}>PE dosyasından otomatik analiz raporu oluştur</div>
            <div style={{ fontSize: 10, lineHeight: 1.6 }}>Yürütücü özeti, PE bilgileri, şüpheli API listesi ve anti-analiz tespiti birleştirilerek HTML rapor üretilir. Tarayıcıda açılabilir veya PDF olarak yazdırılabilir.</div>
          </div>
        </Card>
      )}
    </div>
  );
}

export default ReportPage;
