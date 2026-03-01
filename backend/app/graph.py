from __future__ import annotations

from typing import Dict, List, Tuple


_SEVERITY_SCORE = {"low": 10, "medium": 40, "high": 70, "critical": 90}
_IMPACT_LABEL = {
    "hardcoded-secret": "Credential Exposure",
    "sql-injection": "DB Exfiltration",
}


def build_attack_graph(findings: List[Dict]) -> Dict:
    nodes: List[Dict] = []
    edges: List[Dict] = []
    top_paths: List[Dict] = []

    node_ids = set()
    entry_id = "entry_public"
    entry_label = "Public Entry"
    if entry_id not in node_ids:
        nodes.append({"id": entry_id, "label": entry_label, "type": "entry"})
        node_ids.add(entry_id)

    impact_nodes: Dict[str, str] = {}

    for idx, finding in enumerate(findings, start=1):
        vuln_id = f"v_{idx}"
        impact_label = _IMPACT_LABEL.get(
            finding.get("type", ""), "Security Impact"
        )
        impact_id = impact_nodes.get(impact_label)
        if not impact_id:
            impact_id = f"impact_{len(impact_nodes) + 1}"
            impact_nodes[impact_label] = impact_id
            if impact_id not in node_ids:
                nodes.append(
                    {"id": impact_id, "label": impact_label, "type": "impact"}
                )
                node_ids.add(impact_id)
        if vuln_id not in node_ids:
            nodes.append(
                {
                    "id": vuln_id,
                    "label": finding.get("title") or finding.get("type", "Vuln"),
                    "type": "vuln",
                }
            )
            node_ids.add(vuln_id)

        edges.append({"from": entry_id, "to": vuln_id, "label": "input"})
        edges.append({"from": vuln_id, "to": impact_id, "label": "exploit"})

        score = _SEVERITY_SCORE.get(finding.get("severity", "low"), 10)
        path_id = f"p_{idx}"
        top_paths.append(
            {"id": path_id, "node_ids": [entry_id, vuln_id, impact_id], "score": score}
        )

    top_paths.sort(key=lambda p: p.get("score", 0), reverse=True)
    top_paths = top_paths[:3]

    return {"nodes": nodes, "edges": edges, "top_paths": top_paths}
