import React, { useState, useMemo, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { List as VirtualList } from 'react-window';
import { Network, Search } from 'lucide-react';
import { Card } from './shared';

const MOCK_NETWORK = [
  { id: 1, time: '00:00.124', proto: 'DNS', src: '192.168.1.100', dst: '8.8.8.8', port: 53, data: 'A malware-c2.evil.com', size: 62, flag: 'suspicious' },
  { id: 2, time: '00:00.340', proto: 'DNS', src: '8.8.8.8', dst: '192.168.1.100', port: 53, data: 'A → 185.234.72.19', size: 78, flag: 'suspicious' },
  { id: 3, time: '00:00.512', proto: 'TCP', src: '192.168.1.100', dst: '185.234.72.19', port: 443, data: 'SYN → :443 (TLS handshake)', size: 54, flag: 'suspicious' },
  { id: 4, time: '00:00.680', proto: 'TLS', src: '192.168.1.100', dst: '185.234.72.19', port: 443, data: 'Client Hello — SNI: malware-c2.evil.com', size: 284, flag: 'malicious' },
  { id: 5, time: '00:01.020', proto: 'TLS', src: '185.234.72.19', dst: '192.168.1.100', port: 443, data: 'Server Hello — Self-signed cert (CN=localhost)', size: 1024, flag: 'malicious' },
  { id: 6, time: '00:01.340', proto: 'HTTP', src: '192.168.1.100', dst: '185.234.72.19', port: 443, data: 'POST /gate.php — {"id":"BOT-3104","os":"Win10","arch":"x86"}', size: 186, flag: 'malicious' },
  { id: 7, time: '00:01.780', proto: 'HTTP', src: '185.234.72.19', dst: '192.168.1.100', port: 443, data: '200 OK — {"cmd":"download","url":"http://dl.evil.com/payload.bin"}', size: 342, flag: 'malicious' },
  { id: 8, time: '00:02.100', proto: 'DNS', src: '192.168.1.100', dst: '8.8.8.8', port: 53, data: 'A dl.evil.com', size: 48, flag: 'suspicious' },
  { id: 9, time: '00:02.450', proto: 'HTTP', src: '192.168.1.100', dst: '91.215.100.42', port: 80, data: 'GET /payload.bin — downloading 2nd stage', size: 48, flag: 'malicious' },
  { id: 10, time: '00:03.200', proto: 'HTTP', src: '91.215.100.42', dst: '192.168.1.100', port: 80, data: '200 OK — Content-Length: 245760 (MZ header detected)', size: 245760, flag: 'malicious' },
  { id: 11, time: '00:04.000', proto: 'TCP', src: '192.168.1.100', dst: '185.234.72.19', port: 443, data: 'POST /gate.php — {"status":"stage2_loaded","size":245760}', size: 124, flag: 'malicious' },
  { id: 12, time: '00:05.500', proto: 'DNS', src: '192.168.1.100', dst: '8.8.8.8', port: 53, data: 'A update.microsoft.com (legitimate check)', size: 56, flag: 'clean' },
  { id: 13, time: '00:06.200', proto: 'TCP', src: '192.168.1.100', dst: '52.184.220.48', port: 443, data: 'TLS → update.microsoft.com (Windows Update)', size: 512, flag: 'clean' },
  { id: 14, time: '00:08.100', proto: 'UDP', src: '192.168.1.100', dst: '185.234.72.19', port: 4444, data: 'Encrypted beacon — 32 bytes (possible heartbeat)', size: 32, flag: 'malicious' },
  { id: 15, time: '00:10.300', proto: 'ICMP', src: '192.168.1.100', dst: '185.234.72.19', port: 0, data: 'Echo request — covert channel (unusual ICMP payload size: 256)', size: 256, flag: 'suspicious' },
];

function NetworkCapturePage() {
  const [packets, setPackets] = useState(MOCK_NETWORK);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedPkt, setSelectedPkt] = useState(null);
  const [capturing, setCapturing] = useState(false);
  const [capturePid, setCapturePid] = useState('0');

  const fetchConnections = useCallback(async () => {
    try {
      const pid = parseInt(capturePid) || 0;
      const conns = await invoke('get_process_connections', { pid });
      const mapped = conns.map((c, i) => ({
        id: packets.length + i + 1,
        time: new Date().toLocaleTimeString(),
        proto: c.protocol || 'TCP',
        src: c.local_addr || '',
        dst: c.remote_addr || '',
        port: 0,
        data: `${c.state || ''} ${c.local_addr} → ${c.remote_addr}`,
        size: 0,
        flag: 'clean',
        pid: c.pid,
      }));
      setPackets(prev => [...prev, ...mapped]);
    } catch (e) { console.error('Network capture:', e); }
  }, [capturePid, packets.length]);

  const toggleCapture = useCallback(() => {
    if (!capturing) {
      setCapturing(true);
      fetchConnections();
    } else {
      setCapturing(false);
    }
  }, [capturing, fetchConnections]);

  const filtered = useMemo(() => {
    return packets.filter(p => {
      if (filter !== 'all' && p.flag !== filter) return false;
      if (search && !p.data.toLowerCase().includes(search.toLowerCase()) && !p.src.includes(search) && !p.dst.includes(search) && !p.proto.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [packets, filter, search]);

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
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e6edf3' }}>Network Capture</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>— Sandbox Ağ Analizi</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          {capturing && <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#f87171', boxShadow: '0 0 6px #f8717166', animation: '_sp 1s linear infinite', display: 'inline-block' }} />}
          <input value={capturePid} onChange={e => setCapturePid(e.target.value)} placeholder="PID (0=all)"
            style={{ width: 70, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 5, padding: '3px 6px', fontSize: 10, color: '#e6edf3', fontFamily: 'monospace', outline: 'none' }} />
          <button onClick={toggleCapture}
            style={{ fontSize: 10, padding: '4px 12px', borderRadius: 5, border: `1px solid ${capturing ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`, background: capturing ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)', color: capturing ? '#f87171' : '#22c55e', cursor: 'pointer', fontWeight: 600 }}>
            {capturing ? '⏹ Stop' : '● Capture'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        {[
          { label: 'Toplam', value: stats.total, color: '#818cf8' },
          { label: 'Malicious', value: stats.mal, color: '#f87171' },
          { label: 'Suspicious', value: stats.sus, color: '#f59e0b' },
          { label: 'Clean', value: stats.cln, color: '#22c55e' },
          { label: 'Boyut', value: stats.totalSize > 1024 ? (stats.totalSize / 1024).toFixed(1) + ' KB' : stats.totalSize + ' B', color: '#8b949e' },
        ].map((s, i) => (
          <div key={i} style={{ padding: '8px 16px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', textAlign: 'center', minWidth: 80 }}>
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

      {/* Filters */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 12, alignItems: 'center' }}>
        <Search size={13} color="#8b949e" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="IP, protokol veya içerik ara..." style={{ flex: 1, maxWidth: 320, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 6, padding: '5px 10px', fontSize: 11, color: '#e6edf3', outline: 'none' }} />
        {['all', 'malicious', 'suspicious', 'clean'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5, border: `1px solid ${filter === f ? 'rgba(99,102,241,0.4)' : 'rgba(255,255,255,0.08)'}`, background: filter === f ? 'rgba(99,102,241,0.12)' : 'transparent', color: filter === f ? '#818cf8' : '#8b949e', cursor: 'pointer', textTransform: 'capitalize' }}>{f}</button>
        ))}
      </div>

      {/* Packet Table */}
      <Card>
        <div style={{ borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
          {/* Sticky header row */}
          <div style={{ display: 'grid', gridTemplateColumns: '40px 70px 55px 140px 140px 1fr 80px', background: 'rgba(255,255,255,0.02)', padding: '5px 8px', fontSize: 10, color: '#8b949e', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <span>#</span><span>Time</span><span>Proto</span><span>Source</span><span>Destination</span><span>Data</span><span>Flag</span>
          </div>
          <VirtualList
            height={Math.min(400, filtered.length * 28)}
            width="100%"
            itemCount={filtered.length}
            itemSize={28}
          >
            {({ index, style: rowStyle }) => {
              const p = filtered[index];
              return (
                <div key={p.id} onClick={() => setSelectedPkt(p)} style={{
                  ...rowStyle,
                  display: 'grid', gridTemplateColumns: '40px 70px 55px 140px 140px 1fr 80px',
                  borderBottom: '1px solid rgba(255,255,255,0.03)', cursor: 'pointer', padding: '4px 8px', fontSize: 11, alignItems: 'center',
                  background: selectedPkt?.id === p.id ? 'rgba(99,102,241,0.08)' : '',
                }}>
                  <span style={{ fontFamily: 'monospace', color: '#6e7681' }}>{p.id}</span>
                  <span style={{ fontFamily: 'monospace', color: '#8b949e', fontSize: 10 }}>{p.time}</span>
                  <span><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${protoColor(p.proto)}15`, color: protoColor(p.proto) }}>{p.proto}</span></span>
                  <span style={{ fontFamily: 'monospace', color: '#e6edf3', fontSize: 10 }}>{p.src}:{p.port}</span>
                  <span style={{ fontFamily: 'monospace', color: '#e6edf3', fontSize: 10 }}>{p.dst}:{p.port}</span>
                  <span style={{ color: '#c9d1d9', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.data}</span>
                  <span><span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: `${flagColor(p.flag)}18`, color: flagColor(p.flag), fontWeight: 600 }}>{p.flag}</span></span>
                </div>
              );
            }}
          </VirtualList>
        </div>

        {selectedPkt && (
          <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: '#0d1117', border: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#e6edf3', marginBottom: 6 }}>Paket Detayı — #{selectedPkt.id}</div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
              <div><span style={{ color: '#8b949e' }}>Proto: </span><span style={{ color: protoColor(selectedPkt.proto) }}>{selectedPkt.proto}</span></div>
              <div><span style={{ color: '#8b949e' }}>Size: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.size} bytes</span></div>
              <div><span style={{ color: '#8b949e' }}>Src: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.src}:{selectedPkt.port}</span></div>
              <div><span style={{ color: '#8b949e' }}>Dst: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.dst}:{selectedPkt.port}</span></div>
              <div style={{ gridColumn: '1/3' }}><span style={{ color: '#8b949e' }}>Data: </span><span style={{ color: flagColor(selectedPkt.flag) }}>{selectedPkt.data}</span></div>
              <div><span style={{ color: '#8b949e' }}>Flag: </span><span style={{ color: flagColor(selectedPkt.flag), fontWeight: 700 }}>{selectedPkt.flag.toUpperCase()}</span></div>
              <div><span style={{ color: '#8b949e' }}>Time: </span><span style={{ color: '#e6edf3' }}>{selectedPkt.time}</span></div>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

// ── 6.5 FLIRT İmza Veritabanı ─────────────────────────────────────

export default NetworkCapturePage;