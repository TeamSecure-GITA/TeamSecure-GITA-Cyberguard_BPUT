import React from 'react';

export default function DigitalTwin({ twin }) {
  const nodes = twin?.nodes || [];
  return <section className="twin-map" aria-label="Digital twin network">
    {nodes.map((node, index) => <div className={`twin-node twin-${node.kind}`} style={{ left: `${12 + (index % 3) * 34}%`, top: `${20 + Math.floor(index / 3) * 32}%` }} key={node.id}>
      <span>{node.kind === 'threat' ? '!' : '+'}</span><small>{node.label}</small>
    </div>)}
  </section>;
}
