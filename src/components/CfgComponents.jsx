import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { GitBranch, X } from 'lucide-react';
import {
  ReactFlow, Background, Controls, MiniMap,
  useNodesState, useEdgesState, MarkerType,
} from '@xyflow/react';
import dagre from 'dagre';
import '@xyflow/react/dist/style.css';

const CFG_BLOCK_COLORS = {
  entry:  { bg: 'rgba(99,102,241,0.15)',  border: '#6366f1' },
  exit:   { bg: 'rgba(248,113,113,0.15)', border: '#f87171' },
  branch: { bg: 'rgba(251,191,36,0.12)',  border: '#fbbf24' },
  call:   { bg: 'rgba(96,165,250,0.12)',  border: '#60a5fa' },
  normal: { bg: 'rgba(255,255,255,0.04)', border: '#374151' },
};

const CFG_EDGE_COLORS = {
  branch_true:   '#22c55e',
  branch_false:  '#ef4444',
  unconditional: '#f59e0b',
  fallthrough:   '#475569',
  call:          '#60a5fa',
};

function CfgBlockNode({ data }) {
  const colors = CFG_BLOCK_COLORS[data.block_type] || CFG_BLOCK_COLORS.normal;
  return (
    <div style={{
      background: colors.bg,
      border: `1.5px solid ${colors.border}`,
      borderRadius: 6,
      padding: 0,
      minWidth: 220,
      maxWidth: 340,
      fontFamily: '"JetBrains Mono", monospace',
      overflow: 'hidden',
    }}>
      <div style={{
        padding: '4px 8px',
        background: 'rgba(0,0,0,0.25)',
        borderBottom: `1px solid ${colors.border}`,
        display: 'flex', alignItems: 'center', gap: 6,
        fontSize: 9, fontWeight: 700, color: colors.border,
      }}>
        <span>{data.label}</span>
        <span style={{ marginLeft: 'auto', fontSize: 8, color: '#64748b' }}>{data.block_type}</span>
      </div>
      <div style={{ padding: '3px 0', maxHeight: 180, overflowY: 'auto' }}>
        {(data.instructions || []).map((ins, i) => (
          <div key={i} style={{
            display: 'flex', gap: 6, padding: '1px 8px', fontSize: 10, lineHeight: '16px',
            background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
          }}>
            <span style={{ color: '#4b5563', minWidth: 24, flexShrink: 0 }}>{ins.addr?.slice(-4)}</span>
            <span style={{
              fontWeight: 700, minWidth: 32, flexShrink: 0,
              color: ins.kind === 'call' ? '#60a5fa' : ins.kind === 'jmp' ? '#f59e0b' : ins.kind === 'jcc' ? '#fbbf24' : ins.kind === 'ret' ? '#f87171' : ins.kind === 'nop' ? '#374151' : ins.kind === 'cmp' ? '#c084fc' : '#e2e8f0',
            }}>{ins.mnemonic}</span>
            <span style={{ color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ins.operands}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const cfgNodeTypes = { cfgBlock: CfgBlockNode };

function layoutCfgGraph(blocks, edges) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'TB', nodesep: 40, ranksep: 60, marginx: 30, marginy: 30 });
  g.setDefaultEdgeLabel(() => ({}));

  blocks.forEach(b => {
    const insCount = (b.instructions || []).length;
    const h = Math.min(36 + insCount * 17, 220);
    g.setNode(b.id, { width: 280, height: h });
  });

  edges.forEach(e => {
    g.setEdge(e.source, e.target);
  });

  dagre.layout(g);

  const nodes = blocks.map(b => {
    const pos = g.node(b.id);
    return {
      id: b.id,
      type: 'cfgBlock',
      position: { x: pos.x - 140, y: pos.y - pos.height / 2 },
      data: { ...b },
      style: { width: 280 },
    };
  });

  const flowEdges = edges.map((e, i) => ({
    id: `e${i}`,
    source: e.source,
    target: e.target,
    type: 'smoothstep',
    animated: e.edge_type === 'branch_true' || e.edge_type === 'unconditional',
    label: e.edge_type === 'branch_true' ? 'T' : e.edge_type === 'branch_false' ? 'F' : '',
    labelStyle: { fontSize: 9, fontWeight: 700, fill: CFG_EDGE_COLORS[e.edge_type] || '#475569' },
    style: { stroke: CFG_EDGE_COLORS[e.edge_type] || '#475569', strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: CFG_EDGE_COLORS[e.edge_type] || '#475569', width: 14, height: 14 },
  }));

  return { nodes, edges: flowEdges };
}

function CFGPanel({ filePath, funcAddr, funcName, onBlockClick, onClose }) {
  const [cfgData, setCfgData]       = useState(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (!filePath || !funcAddr) return;
    let cancel = false;
    setLoading(true);
    setError(null);
    invoke('get_cfg', { filePath, funcAddr, maxInsns: 1000 })
      .then(r => {
        if (cancel) return;
        setCfgData(r);
        const layout = layoutCfgGraph(r.blocks, r.edges);
        setNodes(layout.nodes);
        setEdges(layout.edges);
      })
      .catch(e => { if (!cancel) setError(String(e)); })
      .finally(() => { if (!cancel) setLoading(false); });
    return () => { cancel = true; };
  }, [filePath, funcAddr]);

  const handleNodeClick = useCallback((_, node) => {
    if (onBlockClick && node.data?.start_addr) {
      onBlockClick(node.data.start_addr);
    }
  }, [onBlockClick]);

  const proOptions = useMemo(() => ({ hideAttribution: true }), []);

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column', background: 'rgba(0,0,0,0.2)', overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 8,
        borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.15)', flexShrink: 0,
      }}>
        <GitBranch size={13} color="#818cf8" />
        <span style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0' }}>CFG</span>
        <span style={{ fontSize: 10, color: '#818cf8', fontFamily: 'monospace' }}>{funcName || `sub_${(funcAddr || 0).toString(16).toUpperCase()}`}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          {cfgData && <span style={{ fontSize: 9, color: '#4b5563' }}>{cfgData.blocks.length} blok · {cfgData.edges.length} kenar</span>}
          <button onClick={onClose} style={{ padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.08)', background: 'transparent', color: '#64748b', fontSize: 10, cursor: 'pointer' }}>
            <X size={10} />
          </button>
        </div>
      </div>

      {/* Graph area */}
      <div style={{ flex: 1, position: 'relative' }}>
        {loading && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 5, background: 'rgba(0,0,0,0.4)' }}>
            <span style={{ fontSize: 12, color: '#818cf8' }}>CFG oluşturuluyor...</span>
          </div>
        )}
        {error && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 5 }}>
            <span style={{ fontSize: 12, color: '#f87171' }}>Hata: {error}</span>
          </div>
        )}
        {nodes.length > 0 && (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            nodeTypes={cfgNodeTypes}
            fitView
            minZoom={0.1}
            maxZoom={2}
            proOptions={proOptions}
            style={{ background: 'transparent' }}
          >
            <Background variant="dots" gap={20} size={0.5} color="rgba(255,255,255,0.04)" />
            <Controls showInteractive={false} style={{ background: 'rgba(0,0,0,0.5)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)' }} />
            <MiniMap
              nodeColor={n => {
                const c = CFG_BLOCK_COLORS[n.data?.block_type];
                return c ? c.border : '#374151';
              }}
              maskColor="rgba(0,0,0,0.7)"
              style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}
            />
          </ReactFlow>
        )}
        {!loading && !error && nodes.length === 0 && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, color: '#374151' }}>Fonksiyon seçin → CFG görüntüleyin</span>
          </div>
        )}
      </div>

      {/* Legend */}
      <div style={{
        padding: '4px 12px', borderTop: '1px solid rgba(255,255,255,0.04)',
        display: 'flex', gap: 12, flexWrap: 'wrap', flexShrink: 0,
      }}>
        {[
          { label: 'Entry', color: '#6366f1' },
          { label: 'Exit/RET', color: '#f87171' },
          { label: 'Branch', color: '#fbbf24' },
          { label: 'Call', color: '#60a5fa' },
          { label: 'Normal', color: '#374151' },
        ].map(l => (
          <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: '#64748b' }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: l.color }} />
            {l.label}
          </div>
        ))}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <span style={{ fontSize: 9, color: '#22c55e' }}>── T (taken)</span>
          <span style={{ fontSize: 9, color: '#ef4444' }}>── F (fall)</span>
          <span style={{ fontSize: 9, color: '#f59e0b' }}>── JMP</span>
        </div>
      </div>
    </div>
  );
}

// ── DisassemblyPage (1.1 + 1.2) ─────────────────────────────────────────────

export { CFG_BLOCK_COLORS, CFG_EDGE_COLORS, CfgBlockNode, CFGPanel };