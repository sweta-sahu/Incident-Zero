type Node = {
  id: string;
  label: string;
  type: string;
  finding_id?: string;
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
  selectedNodeId?: string | null;
  onNodeClick?: (node: Node) => void;
};

export default function MockGraph({
  graph,
  selectedNodeId,
  onNodeClick,
}: MockGraphProps) {
  return (
    <div className="graph">
      <div className="graph-nodes">
        {graph.nodes.map((node) => (
          <button
            key={node.id}
            className={`node ${node.type} ${
              selectedNodeId === node.id ? "selected" : ""
            }`}
            type="button"
            onClick={() => onNodeClick?.(node)}
          >
            <span>{node.label}</span>
          </button>
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
