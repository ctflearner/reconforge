import React, { useMemo } from 'react';

const TYPE_COLORS = {
  domain: '#3b82f6',
  subdomain: '#6366f1',
  ip: '#8b5cf6',
  port: '#a855f7',
  url: '#06b6d4',
  email: '#14b8a6',
  endpoint: '#22c55e',
  secret: '#ef4444',
  technology: '#f97316',
  certificate: '#eab308',
  dns_record: '#64748b',
  social_profile: '#ec4899',
  cloud_resource: '#0ea5e9',
  component: '#84cc16',
  file: '#78716c',
  person: '#f43f5e',
  service: '#d946ef',
  permission: '#fb923c',
  sdk: '#a3e635',
};

export default function AssetGraph({ assets = [] }) {
  const graph = useMemo(() => {
    if (!assets.length) return { nodes: [], edges: [] };

    // Group assets by type, take first 80
    const shown = assets.slice(0, 80);
    const types = {};
    shown.forEach(a => {
      if (!types[a.asset_type]) types[a.asset_type] = [];
      types[a.asset_type].push(a);
    });

    const nodes = [];
    const edges = [];
    const centerX = 400;
    const centerY = 300;

    // Center node
    nodes.push({ id: 'center', x: centerX, y: centerY, label: 'Target', color: '#3b82f6', r: 20 });

    const typeKeys = Object.keys(types);
    const angleStep = (2 * Math.PI) / (typeKeys.length || 1);

    typeKeys.forEach((type, ti) => {
      const angle = angleStep * ti - Math.PI / 2;
      const typeX = centerX + Math.cos(angle) * 160;
      const typeY = centerY + Math.sin(angle) * 160;
      const typeId = `type-${type}`;
      const color = TYPE_COLORS[type] || '#64748b';

      nodes.push({ id: typeId, x: typeX, y: typeY, label: `${type} (${types[type].length})`, color, r: 14 });
      edges.push({ from: 'center', to: typeId });

      // Individual assets around the type node (max 8 per type)
      const items = types[type].slice(0, 8);
      const subAngleStep = (2 * Math.PI) / (items.length || 1);
      items.forEach((asset, ai) => {
        const subAngle = subAngleStep * ai - Math.PI / 2;
        const ax = typeX + Math.cos(subAngle) * 70;
        const ay = typeY + Math.sin(subAngle) * 70;
        const aid = `asset-${asset.id}`;
        nodes.push({ id: aid, x: ax, y: ay, label: asset.value.substring(0, 24), color, r: 6 });
        edges.push({ from: typeId, to: aid });
      });
    });

    return { nodes, edges };
  }, [assets]);

  if (!assets.length) {
    return <div className="text-center text-gray-500 py-8">No assets to visualize</div>;
  }

  const nodeMap = {};
  graph.nodes.forEach(n => { nodeMap[n.id] = n; });

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 overflow-auto">
      <svg viewBox="0 0 800 600" className="w-full" style={{ minHeight: 400 }}>
        {/* Edges */}
        {graph.edges.map((e, i) => {
          const from = nodeMap[e.from];
          const to = nodeMap[e.to];
          if (!from || !to) return null;
          return (
            <line
              key={i}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              stroke="#334155"
              strokeWidth={1}
            />
          );
        })}
        {/* Nodes */}
        {graph.nodes.map((n) => (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r={n.r} fill={n.color} opacity={0.85} />
            {n.r >= 10 && (
              <text
                x={n.x}
                y={n.y + n.r + 14}
                textAnchor="middle"
                fill="#94a3b8"
                fontSize={n.r >= 18 ? 11 : 9}
              >
                {n.label}
              </text>
            )}
          </g>
        ))}
      </svg>
    </div>
  );
}
