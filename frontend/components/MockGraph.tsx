import { useMemo } from "react";
import ReactFlow, { Background, MarkerType, Position } from "reactflow";
import type { Edge, Node } from "reactflow";
import "reactflow/dist/style.css";

type GraphNode = {
  id: string;
  label: string;
  type: string;
  finding_id?: string;
};

type GraphEdge = {
  from: string;
  to: string;
  label: string;
};

type GraphPath = {
  id: string;
  node_ids: string[];
  score: number;
};

type Graph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  top_paths?: GraphPath[];
};

type MockGraphProps = {
  graph: Graph;
  selectedFindingId?: string | null;
};

type Role = "entry" | "vulnerability" | "impact" | "other";

function prettifyLabel(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) return "Unknown";
  const normalized = raw.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim();
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

function roleFromType(type: string): Role {
  const normalized = String(type || "").toLowerCase();
  if (normalized.includes("entry")) return "entry";
  if (
    normalized.includes("vuln") ||
    normalized.includes("finding") ||
    normalized.includes("issue")
  ) {
    return "vulnerability";
  }
  if (normalized.includes("impact")) return "impact";
  return "other";
}

function roleFromLabel(label: string): Role {
  const normalized = String(label || "").toLowerCase();
  if (normalized.includes("entry") || normalized.includes("internet")) return "entry";
  if (
    normalized.includes("sql injection") ||
    normalized.includes("hardcoded") ||
    normalized.includes("secret") ||
    normalized.includes("command injection") ||
    normalized.includes("vulnerability")
  ) {
    return "vulnerability";
  }
  if (
    normalized.includes("impact") ||
    normalized.includes("exposure") ||
    normalized.includes("compromise") ||
    normalized.includes("exfiltration")
  ) {
    return "impact";
  }
  return "other";
}

function roleClass(role: Role): string {
  if (role === "entry") return "entry";
  if (role === "vulnerability") return "vulnerability";
  if (role === "impact") return "impact";
  return "other";
}

function columnForRole(role: Role): number {
  if (role === "entry") return 0;
  if (role === "vulnerability") return 1;
  if (role === "impact") return 2;
  return 3;
}

export default function MockGraph({ graph, selectedFindingId }: MockGraphProps) {
  const { nodes, edges } = useMemo(() => {
    const focusId = String(selectedFindingId || "").trim();
    const nodeIndex = new Map<string, GraphNode>();
    (graph.nodes || []).forEach((node) => nodeIndex.set(node.id, node));

    const allEdges = graph.edges || [];
    allEdges.forEach((edge) => {
      if (!nodeIndex.has(edge.from)) {
        nodeIndex.set(edge.from, { id: edge.from, label: edge.from, type: "other" });
      }
      if (!nodeIndex.has(edge.to)) {
        nodeIndex.set(edge.to, { id: edge.to, label: edge.to, type: "other" });
      }
    });

    (graph.top_paths || []).forEach((path) => {
      (path.node_ids || []).forEach((nodeId) => {
        if (!nodeIndex.has(nodeId)) {
          nodeIndex.set(nodeId, { id: nodeId, label: nodeId, type: "other" });
        }
      });
    });

    const allNodes = Array.from(nodeIndex.values());

    let scopedNodeIds = new Set<string>(allNodes.map((node) => node.id));
    let scopedEdges = [...allEdges];

    if (focusId) {
      const focusedVulnIds = new Set(
        allNodes
          .filter((node) => node.finding_id === focusId || node.id === `vuln_${focusId}`)
          .map((node) => node.id)
      );

      const preferredPath = (graph.top_paths || []).find((path) => {
        if (path.id === `path_${focusId}`) return true;
        return (path.node_ids || []).some((nodeId) => {
          const node = nodeIndex.get(nodeId);
          return Boolean(node && (node.finding_id === focusId || node.id === `vuln_${focusId}`));
        });
      });

      if (preferredPath && preferredPath.node_ids?.length) {
        const pathNodeIds = new Set(preferredPath.node_ids);
        scopedNodeIds = pathNodeIds;
        scopedEdges = allEdges.filter(
          (edge) => pathNodeIds.has(edge.from) && pathNodeIds.has(edge.to)
        );
      } else if (focusedVulnIds.size) {
        const relatedNodeIds = new Set<string>(focusedVulnIds);
        allEdges.forEach((edge) => {
          if (focusedVulnIds.has(edge.from) || focusedVulnIds.has(edge.to)) {
            relatedNodeIds.add(edge.from);
            relatedNodeIds.add(edge.to);
          }
        });

        scopedNodeIds = relatedNodeIds;
        scopedEdges = allEdges.filter(
          (edge) => relatedNodeIds.has(edge.from) && relatedNodeIds.has(edge.to)
        );
      } else {
        scopedNodeIds = new Set();
        scopedEdges = [];
      }
    }

    const pathEdgeWeights = new Map<string, number>();
    (graph.top_paths || []).forEach((path) => {
      const ids = path.node_ids || [];
      for (let idx = 0; idx < ids.length - 1; idx += 1) {
        const key = `${ids[idx]}::${ids[idx + 1]}`;
        pathEdgeWeights.set(key, (pathEdgeWeights.get(key) || 0) + 1);
      }
    });

    const buckets: Record<Role, GraphNode[]> = {
      entry: [],
      vulnerability: [],
      impact: [],
      other: [],
    };

    allNodes
      .filter((node) => scopedNodeIds.has(node.id))
      .forEach((node) => {
        const typedRole = roleFromType(node.type);
        const inferredRole = typedRole === "other" ? roleFromLabel(node.label) : typedRole;
        buckets[inferredRole].push(node);
      });

    const columnX = [70, 290, 510, 710];
    const rowSpacing = 95;
    const startY = 65;
    const nodeOrder: GraphNode[] = [
      ...buckets.entry,
      ...buckets.vulnerability,
      ...buckets.impact,
      ...buckets.other,
    ];

    const positionedNodes: Node[] = nodeOrder.map((node) => {
      const typedRole = roleFromType(node.type);
      const inferredRole = typedRole === "other" ? roleFromLabel(node.label) : typedRole;
      const peers = buckets[inferredRole];
      const row = peers.findIndex((item) => item.id === node.id);
      const x = columnX[columnForRole(inferredRole)] || 980;
      const y = startY + row * rowSpacing;

      return {
        id: node.id,
        position: { x, y },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        draggable: false,
        selectable: true,
        data: {
          label: (
            <div className="rf-node-content">
              <span className={`rf-node-kicker ${roleClass(inferredRole)}`}>{inferredRole}</span>
              <strong>{prettifyLabel(node.label || node.id)}</strong>
            </div>
          ),
        },
        className: `rf-node ${roleClass(inferredRole)}`,
      };
    });

    const mergedEdges = new Map<string, GraphEdge>();
    scopedEdges.forEach((edge) => {
      const key = `${edge.from}::${edge.to}::${String(edge.label || "").toLowerCase()}`;
      if (!mergedEdges.has(key)) mergedEdges.set(key, edge);
    });

    const flowEdges: Edge[] = Array.from(mergedEdges.values()).map((edge, idx) => {
      const emphasis = pathEdgeWeights.get(`${edge.from}::${edge.to}`) || 0;
      const isTopPathEdge = emphasis > 0;
      const color = isTopPathEdge ? "#f4c770" : "#5a77ad";
      return {
        id: `edge_${idx}_${edge.from}_${edge.to}`,
        source: edge.from,
        target: edge.to,
        animated: isTopPathEdge,
        label:
          edge.label && String(edge.label).trim().toLowerCase() !== "path"
            ? String(edge.label)
            : undefined,
        style: {
          stroke: color,
          strokeWidth: isTopPathEdge ? Math.min(4.8, 2 + emphasis * 0.35) : 1.6,
        },
        labelStyle: {
          fill: "#a9bee7",
          fontSize: 11,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color,
        },
      };
    });

    return { nodes: positionedNodes, edges: flowEdges };
  }, [graph, selectedFindingId]);

  if (!nodes.length) {
    return <p className="muted">No attack graph available yet.</p>;
  }

  return (
    <div className="attack-graph-flow-shell">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        fitViewOptions={{ padding: 0.28, includeHiddenNodes: false }}
        minZoom={0.5}
        maxZoom={1.35}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnScroll
        zoomOnPinch
        zoomOnScroll
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={24} size={1} color="rgba(80, 110, 172, 0.25)" />
      </ReactFlow>
    </div>
  );
}
