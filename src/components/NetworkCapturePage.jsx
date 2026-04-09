import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Network, Search, Download } from 'lucide-react';
import { Card } from './shared';

function PacketRow({ index, style, filtered, selectedPkt, setSelectedPkt, protoColor, flagColor }) {
  const p = filtered[index];
  return (
    <div onClick={() => setSelectedPkt(p)} style={{
      ...style,
      display: 'grid', gridTemplateColumns: '40px 70px 55px 140px 140px 1fr 80px',
      borderBottom: '1px solid rgba(255,255,255,0.03)', cursor: 'pointer', padding: '4px 8px', fontSize: 11, alignItems: 'center',
      background: selectedPkt?.id === p.id ? 'rgba(99,102,241,0.08)' : '',
    }}>
      <span style={{ fontFamily: 'monospace', color: '#6e7681' }}>{p.id}</span>
      <span style={{ fontFamily: 'monospace', color: '#8b949e', fontSize: 10 }}>{p.time}</span>
      <span><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${protoColor(p.proto)}15`, color: protoColor(p.proto) }}>{p.proto}</span></span>
      <span style={{ fontFamily: 'monospace', color: '#e6edf3', fontSize: 10 }}>{p.src}:{p.srcPort || p.port}</span>
      <span style={{ fontFamily: 'monospace', color: '#e6edf3', fontSize: 10 }}>{p.dst}:{p.dstPort || p.port}</span>
      <span style={{ color: '#c9d1d9', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.data}</span>
      <span><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${flagColor(p.flag)}18`, color: flagColor(p.flag), fontWeight: 600 }}>{p.flag}</span></span>
    </div>
  );
}

function NetworkCapturePage() {
  const [packets, setPackets] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedPkt, setSelectedPkt] = useState(null);
  const [capturing, setCapturing] = useState(false);
  const [capturePid, setCapturePid] = useState('0');
  const [pollInterval, setPollInterval] = useState(2000);
  const [activeTab, setActiveTab] = useState('paketler'); // paketler | dns | tcp | timeline
  const intervalRef = useRef(null);
  const seenRef = useRef(new Set());
  const idRef = useRef(1);
  const startTimeRef = useRef(null);

  const fetchConnections = useCallback(async () => {
    try {
      const pid = parseInt(capturePid) || 0;
      const conns = await invoke('get_process_connections', { pid });
      if (!conns || !Array.isArray(conns)) return;
      const now = Date.now();
      if (!startTimeRef.current) startTimeRef.current = now;
      const newPackets = [];
      for (const c of conns) {
        const key = `${c.protocol || 'TCP'}|${c.local_addr || ''}|${c.remote_addr || ''}|${c.state || ''}|${c.pid || 0}`;
        if (seenRef.current.has(key)) continue;
        seenRef.current.add(key);
        const localParts = (c.local_addr || '').split(':');
        const remoteParts = (c.remote_addr || '').split(':');
        const dstPort = parseInt(remoteParts[remoteParts.length - 1]) || 0;
        const proto = dstPort === 53 ? 'DNS' : (c.protocol || 'TCP');
        newPackets.push({
          id: idRef.current++,
          time: new Date().toLocaleTimeString(),
          ts: now - startTimeRef.current, // ms since capture start
          proto,
          src: localParts.slice(0, -1).join(':') || c.local_addr || '',
          dst: remoteParts.slice(0, -1).join(':') || c.remote_addr || '',
          srcPort: localParts[localParts.length - 1] || '',
          dstPort: String(dstPort),
          port: dstPort,
          data: `${c.state || 'UNKNOWN'} — ${c.local_addr} → ${c.remote_addr}`,
          size: 0,
          flag: 'clean',
          pid: c.pid,
        });
      }
      if (newPackets.length > 0) {
        setPackets(prev => [...prev, ...newPackets]);
      }
    } catch (e) { console.error('Network capture:', e); }
  }, [capturePid]);

  const toggleCapture = useCallback(() => {
    if (!capturing) {
      setCapturing(true);
      seenRef.current.clear();
      startTimeRef.current = null;
      fetchConnections();
    } else {
      setCapturing(false);
    }
  }, [capturing, fetchConnections]);

  // Auto-polling
  useEffect(() => {
    if (capturing) {
      intervalRef.current = setInterval(fetchConnections, pollInterval);
      return () => clearInterval(intervalRef.current);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
  }, [capturing, fetchConnections, pollInterval]);

  const clearPackets = () => {
    setPackets([]); seenRef.current.clear(); idRef.current = 1;
    startTimeRef.current = null;
    setSelectedPkt(null);
  };

  const exportJSON = () => {
    const data = JSON.stringify(packets, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `network_capture_${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const filtered = useMemo(() => {
    return packets.filter(p => {
      if (filter !== 'all' && p.flag !== filter) return false;
      if (search && !p.data.toLowerCase().includes(search.toLowerCase()) && !p.src.includes(search) && !p.dst.includes(search) && !p.proto.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [packets, filter, search]);

  // DNS sorguları: port 53 bağlantıları
  const dnsQueries = useMemo(() => packets.filter(p => p.proto === 'DNS' || p.port === 53 || p.dstPort === '53'), [packets]);

  // TCP stream'leri: aynı src-dst çiftini grupla
  const tcpStreams = useMemo(() => {
    const streams = {};
    packets.forEach(p => {
      const key = [p.src, p.srcPort, p.dst, p.dstPort].sort().join('-');
      if (!streams[key]) streams[key] = { key, packets: [], src: `${p.src}:${p.srcPort}`, dst: `${p.dst}:${p.dstPort}`, proto: p.proto };
      streams[key].packets.push(p);
    });
    return Object.values(streams);
  }, [packets]);

  const stats = useMemo(() => {
    const mal = packets.filter(p => p.flag === 'malicious').length;
    const sus = packets.filter(p => p.flag === 'suspicious').length;
    const cln = packets.filter(p => p.flag === 'clean').length;
    const totalSize = packets.reduce((a, p) => a + p.size, 0);
    const protos = {};
    packets.forEach(p => { protos[p.proto] = (protos[p.proto] || 0) + 1; });
    return { mal, sus, cln, total: packets.length, totalSize, protos };
  }, [packets]);

  const flagColor = (f) => f === 'malicious' ? '#f87171' : f === 'suspicious' ? '#f59e0b' : '#22c55e';
  const protoColor = (p) => ({ DNS: '#60a5fa', TCP: '#8b949e', TLS: '#a78bfa', HTTP: '#f59e0b', UDP: '#22c55e', ICMP: '#f87171' }[p] || '#8b949e');

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <Network size={18} color="#818cf8" />
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Ağ Yakalama</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Sandbox Ağ Analizi</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          {capturing && <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#f87171', boxShadow: '0 0 6px #f8717166', display: 'inline-block' }} />}
          <input value={capturePid} onChange={e => setCapturePid(e.target.value)} placeholder="PID (0=tümü)"
            style={{ width: 80, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '3px 6px', fontSize: 10, color: '#e6edf3', fontFamily: 'monospace', outline: 'none' }} />
          <button onClick={toggleCapture}
            style={{ fontSize: 10, padding: '4px 12px', borderRadius: 5, border: `1px solid ${capturing ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`, background: capturing ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)', color: capturing ? '#f87171' : '#22c55e', cursor: 'pointer', fontWeight: 600 }}>
            {capturing ? '⏹ Durdur' : '● Yakala'}
          </button>
          <select value={pollInterval} onChange={e => setPollInterval(Number(e.target.value))}
            style={{ fontSize: 10, padding: '3px 6px', borderRadius: 5, border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.04)', color: '#8b949e', outline: 'none' }}>
            <option value={1000}>1s</option><option value={2000}>2s</option><option value={5000}>5s</option><option value={10000}>10s</option>
          </select>
          <button onClick={clearPackets} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 5, border: '1px solid rgba(245,158,11,0.3)', background: 'rgba(245,158,11,0.08)', color: '#f59e0b', cursor: 'pointer' }}>Temizle</button>
          <button onClick={exportJSON} style={{ fontSize: 10, padding: '4px 10px', borderRadius: 5, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', color: '#818cf8', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Download size={11} /> JSON
          </button>
        </div>
      </div>

      {/* İstatistikler */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        {[
          { label: 'Toplam', value: stats.total, color: '#818cf8' },
          { label: 'Kötü', value: stats.mal, color: '#f87171' },
          { label: 'Şüpheli', value: stats.sus, color: '#f59e0b' },
          { label: 'Temiz', value: stats.cln, color: '#22c55e' },
          { label: 'DNS', value: dnsQueries.length, color: '#60a5fa' },
          { label: 'TCP Akış', value: tcpStreams.length, color: '#a78bfa' },
        ].map((s, i) => (
          <div key={i} style={{ padding: '8px 16px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', textAlign: 'center', minWidth: 70 }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: s.color, fontFamily: 'monospace' }}>{s.value}</div>
            <div style={{ fontSize: 9, color: '#6e7681' }}>{s.label}</div>
          </div>
        ))}
        {Object.entries(stats.protos).map(([p, c]) => (
          <div key={p} style={{ padding: '8px 14px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', textAlign: 'center' }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: protoColor(p), fontFamily: 'monospace' }}>{c}</div>
            <div style={{ fontSize: 9, color: '#6e7681' }}>{p}</div>
          </div>
        ))}
      </div>

      {/* Sekmeler */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 12 }}>
        {[['paketler','Paketler'], ['dns','DNS Sorguları'], ['tcp','TCP Akışları'], ['timeline','Zaman Çizelgesi']].map(([key, lbl]) => (
          <button key={key} onClick={() => setActiveTab(key)} style={{ fontSize: 10, padding: '5px 14px', borderRadius: 5, border: `1px solid ${activeTab === key ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.06)'}`, background: activeTab === key ? 'rgba(99,102,241,0.12)' : 'transparent', color: activeTab === key ? '#818cf8' : '#8b949e', cursor: 'pointer', fontWeight: activeTab === key ? 700 : 400 }}>{lbl}</button>
        ))}
      </div>

      {/* Paketler Sekmesi */}
      {activeTab === 'paketler' && (
        <Card>
          <div style={{ display: 'flex', gap: 6, marginBottom: 10, alignItems: 'center' }}>
            <Search size={13} color="#8b949e" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="IP, protokol veya içerik ara..." style={{ flex: 1, maxWidth: 320, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
            {['all', 'malicious', 'suspicious', 'clean'].map(f => (
              <button key={f} onClick={() => setFilter(f)} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: `1px solid ${filter === f ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: filter === f ? 'rgba(99,102,241,0.12)' : 'transparent', color: filter === f ? '#818cf8' : '#8b949e', cursor: 'pointer', textTransform: 'capitalize' }}>
                {{ all: 'Tümü', malicious: 'Kötü', suspicious: 'Şüpheli', clean: 'Temiz' }[f]}
              </button>
            ))}
          </div>
          <div style={{ borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '40px 70px 55px 140px 140px 1fr 80px', background: 'rgba(255,255,255,0.02)', padding: '5px 8px', fontSize: 10, color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              <span>#</span><span>Zaman</span><span>Proto</span><span>Kaynak</span><span>Hedef</span><span>Veri</span><span>Durum</span>
            </div>
            <div style={{ maxHeight: 350, overflowY: 'auto' }}>
              {filtered.length > 0 ? filtered.map((p, i) => (
                <PacketRow key={p.id} index={i} style={{}} filtered={filtered} selectedPkt={selectedPkt} setSelectedPkt={setSelectedPkt} protoColor={protoColor} flagColor={flagColor} />
              )) : (
                <div style={{ textAlign: 'center', padding: 30, color: '#8b949e', fontSize: 11 }}>Paket bulunamadı</div>
              )}
            </div>
          </div>
          {selectedPkt && (
            <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: '#0d1117', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Paket Detayı — #{selectedPkt.id}</div>
              <div style={{ fontFamily: 'monospace', fontSize: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
                <div><span style={{ color: '#8b949e' }}>Proto: </span><span style={{ color: protoColor(selectedPkt.proto) }}>{selectedPkt.proto}</span></div>
                <div><span style={{ color: '#8b949e' }}>PID: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.pid}</span></div>
                <div><span style={{ color: '#8b949e' }}>Kaynak: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.src}:{selectedPkt.srcPort}</span></div>
                <div><span style={{ color: '#8b949e' }}>Hedef: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.dst}:{selectedPkt.dstPort}</span></div>
                <div style={{ gridColumn: '1/3' }}><span style={{ color: '#8b949e' }}>Veri: </span><span style={{ color: flagColor(selectedPkt.flag) }}>{selectedPkt.data}</span></div>
                <div><span style={{ color: '#8b949e' }}>Zaman: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.time}</span></div>
                <div><span style={{ color: '#8b949e' }}>Gecikme: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.ts}ms</span></div>
              </div>
            </div>
          )}
        </Card>
      )}

      {/* DNS Sekmesi */}
      {activeTab === 'dns' && (
        <Card>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 10 }}>DNS Sorgu Kaydı ({dnsQueries.length} sorgu)</div>
          {dnsQueries.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 40, color: '#6e7681', fontSize: 11 }}>Henüz DNS sorgusu yakalanmadı. Port 53 bağlantıları DNS olarak işaretlenir.</div>
          ) : (
            <div style={{ fontFamily: 'monospace', fontSize: 11, display: 'grid', gridTemplateColumns: '70px 60px 140px 1fr', gap: 0 }}>
              <div style={{ color: '#8b949e', fontSize: 9, padding: '4px 8px', background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>Zaman</div>
              <div style={{ color: '#8b949e', fontSize: 9, padding: '4px 8px', background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>PID</div>
              <div style={{ color: '#8b949e', fontSize: 9, padding: '4px 8px', background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>DNS Sunucu</div>
              <div style={{ color: '#8b949e', fontSize: 9, padding: '4px 8px', background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>Yerel Adres</div>
              {dnsQueries.map((p, i) => (
                <React.Fragment key={i}>
                  <div style={{ color: '#8b949e', padding: '4px 8px', borderBottom: '1px solid rgba(255,255,255,0.03)', fontSize: 10 }}>{p.time}</div>
                  <div style={{ color: '#e6edf3', padding: '4px 8px', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>{p.pid}</div>
                  <div style={{ color: '#60a5fa', padding: '4px 8px', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>{p.dst}:{p.dstPort}</div>
                  <div style={{ color: '#8b949e', padding: '4px 8px', borderBottom: '1px solid rgba(255,255,255,0.03)', fontSize: 10 }}>{p.src}:{p.srcPort}</div>
                </React.Fragment>
              ))}
            </div>
          )}
        </Card>
      )}

      {/* TCP Akışları Sekmesi */}
      {activeTab === 'tcp' && (
        <Card>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 10 }}>TCP Akış Grupları ({tcpStreams.length} akış)</div>
          {tcpStreams.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 40, color: '#6e7681', fontSize: 11 }}>Henüz TCP akışı yakalanmadı.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {tcpStreams.map((stream, i) => (
                <div key={i} style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 6 }}>
                    <span style={{ fontSize: 10, color: protoColor(stream.proto), fontWeight: 700 }}>{stream.proto}</span>
                    <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#e6edf3' }}>{stream.src}</span>
                    <span style={{ color: '#6e7681', fontSize: 10 }}>→</span>
                    <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#818cf8' }}>{stream.dst}</span>
                    <span style={{ marginLeft: 'auto', fontSize: 9, color: '#6e7681' }}>{stream.packets.length} paket</span>
                  </div>
                  <div style={{ maxHeight: 80, overflowY: 'auto', fontFamily: 'monospace', fontSize: 9, color: '#6e7681' }}>
                    {stream.packets.map((p, j) => (
                      <div key={j} style={{ display: 'flex', gap: 8, padding: '1px 0' }}>
                        <span style={{ color: '#8b949e', minWidth: 55 }}>{p.time}</span>
                        <span>{p.data}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {/* Zaman Çizelgesi Sekmesi */}
      {activeTab === 'timeline' && (
        <Card>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 10 }}>Bağlantı Zaman Çizelgesi</div>
          {packets.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 40, color: '#6e7681', fontSize: 11 }}>Zaman çizelgesi için yakalama başlatın.</div>
          ) : (() => {
            const maxTs = Math.max(...packets.map(p => p.ts || 0)) || 1;
            return (
              <div style={{ position: 'relative', height: 240, background: 'rgba(0,0,0,0.2)', borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.05)' }}>
                {/* Zaman ekseni çizgileri */}
                {[0, 25, 50, 75, 100].map(pct => (
                  <div key={pct} style={{ position: 'absolute', left: `${pct}%`, top: 0, bottom: 0, borderLeft: '1px solid rgba(255,255,255,0.04)' }}>
                    <span style={{ position: 'absolute', bottom: 4, fontSize: 8, color: '#6e7681', transform: 'translateX(-50%)' }}>
                      {Math.round(maxTs * pct / 100)}ms
                    </span>
                  </div>
                ))}
                {/* Bağlantı noktaları */}
                {packets.map((p, i) => {
                  const x = ((p.ts || 0) / maxTs) * 100;
                  const colors = { DNS: '#60a5fa', TCP: '#8b949e', TLS: '#a78bfa', UDP: '#22c55e', HTTP: '#f59e0b' };
                  const col = colors[p.proto] || '#8b949e';
                  const y = 20 + (i % 10) * 20; // stagger so they don't all overlap
                  return (
                    <div key={p.id} title={`${p.proto} ${p.src}→${p.dst} (${p.time})`} style={{
                      position: 'absolute', left: `${x}%`, top: y,
                      width: 8, height: 8, borderRadius: '50%', background: col, cursor: 'pointer',
                      transform: 'translateX(-4px)', boxShadow: `0 0 4px ${col}88`,
                    }} />
                  );
                })}
                {/* Protokol açıklamaları */}
                <div style={{ position: 'absolute', top: 8, right: 12, display: 'flex', gap: 8 }}>
                  {[['TCP','#8b949e'],['DNS','#60a5fa'],['TLS','#a78bfa'],['UDP','#22c55e']].map(([pr, cl]) => (
                    <span key={pr} style={{ fontSize: 9, color: cl, display: 'flex', alignItems: 'center', gap: 3 }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: cl, display: 'inline-block' }} />{pr}
                    </span>
                  ))}
                </div>
              </div>
            );
          })()}
        </Card>
      )}
    </div>
  );
}

export default NetworkCapturePage;