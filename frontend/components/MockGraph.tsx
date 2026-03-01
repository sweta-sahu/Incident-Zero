type Node = {
  id: string;
  label: string;
  type: string;
};

type Edge = {
  from: string;
  to: string;
  label: string;
};

type Graph = {
  nodes: Node[];
  edges: Edge[];
};

type MockGraphProps = {
  graph: Graph;
};

export default function MockGraph({ graph }: MockGraphProps) {
  return (
    <div className="graph">
      <div className="graph-nodes">
        {graph.nodes.map((node) => (
          <div key={node.id} className={`node ${node.type}`}>
            <span>{node.label}</span>
          </div>
        ))}
      </div>
      <div className="graph-edges muted">
        {graph.edges.map((edge, idx) => (
          <div key={`${edge.from}-${edge.to}-${idx}`}>
            {edge.from} -> {edge.to} ({edge.label})
          </div>
        ))}
      </div>
    </div>
  );
}
