import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";

type TimelineEvent = {
  ts: string;
  stage: string;
  message: string;
  status: string;
};

type Evidence = {
  id: string;
  kind: string;
  file_path: string;
  line: number;
  snippet: string;
  note: string;
};

type Finding = {
  id: string;
  type: string;
  title: string;
  severity: string;
  confidence: string;
  description: string;
  file_path: string;
  line: number;
  evidence: Evidence[];
  signals?: Record<string, unknown>;
};

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
  top_paths: GraphPath[];
};

type Patch = {
  id: string;
  finding_id: string;
  file_path: string;
  diff: string;
  summary: string;
};

type StageStatus = "pending" | "in_progress" | "done" | "error";

const STAGE_ORDER: { stage: string; label: string }[] = [
  { stage: "ingest", label: "Repo Ingested" },
  { stage: "scan", label: "CodeScan MCP Complete" },
  { stage: "correlate", label: "Correlating Findings" },
  { stage: "graph", label: "Building Attack Graph" },
  { stage: "patch", label: "Generating Patches" },
  { stage: "finalize", label: "Finalizing Report" },
];

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const defaultGraph: Graph = { nodes: [], edges: [], top_paths: [] };

function hasRuntimeProof(finding: Finding): boolean {
  if (Boolean(finding.signals?.runtime_proof)) {
    return true;
  }
  return (finding.evidence || []).some(
    (evidence) => evidence.kind === "runtime" || evidence.kind === "log"
  );
}

function titleFromType(type: string): string {
  const normalized = type.replace(/[_-]/g, " ").toLowerCase();
  if (normalized === "sql injection") return "SQL Injection";
  if (normalized === "hardcoded secret") return "Hardcoded Secret";
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

function diffLineType(line: string): "add" | "remove" | "meta" | "context" {
  if (line.startsWith("+++ ") || line.startsWith("--- ") || line.startsWith("diff --git")) {
    return "meta";
  }
  if (line.startsWith("@@")) return "meta";
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "remove";
  return "context";
}

export default function Run() {
  const { query } = useRouter();
  const jobId = Array.isArray(query.jobId) ? query.jobId[0] : query.jobId;
  const apiBase = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [jobStatus, setJobStatus] = useState("running");
  const [jobSummary, setJobSummary] = useState("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graph, setGraph] = useState<Graph>(defaultGraph);
  const [patches, setPatches] = useState<Patch[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");

  useEffect(() => {
    if (!jobId) return;
    if (jobStatus === "done" || jobStatus === "error") return;

    const interval = setInterval(async () => {
      try {
        const statusResp = await fetch(`${apiBase}/status/${jobId}`);
        if (!statusResp.ok) return;
        const statusJson = await statusResp.json();
        setJobStatus(statusJson.status || "running");
        setTimeline(statusJson.timeline || []);
      } catch (_) {
        // Ignore transient polling errors.
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [apiBase, jobId, jobStatus]);

  useEffect(() => {
    if (!jobId) return;
    if (jobStatus !== "done" && jobStatus !== "error") return;

    const fetchResult = async () => {
      try {
        const resultResp = await fetch(`${apiBase}/result/${jobId}`);
        if (!resultResp.ok) return;
        const resultJson = await resultResp.json();
        setJobStatus(resultJson.status || "running");
        setJobSummary(resultJson.summary || "");
        setTimeline(resultJson.timeline || []);

        if (resultJson.status === "done") {
          setFindings(resultJson.findings || []);
          setGraph(resultJson.graph || defaultGraph);
          setPatches(resultJson.patches || []);
          return;
        }
        setFindings([]);
        setGraph(defaultGraph);
        setPatches([]);
      } catch (_) {
        // Ignore result errors.
      }
    };

    fetchResult();
  }, [apiBase, jobId, jobStatus]);

  useEffect(() => {
    if (!findings.length) {
      setSelectedFindingId(null);
      return;
    }
    const hasSelection = selectedFindingId && findings.some((finding) => finding.id === selectedFindingId);
    if (!hasSelection) {
      setSelectedFindingId(findings[0].id);
    }
  }, [findings, selectedFindingId]);

  const summary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((finding) => {
      if (finding.severity in counts) {
        counts[finding.severity as keyof typeof counts] += 1;
      }
    });
    return counts;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const base = [...findings].sort(
      (left, right) =>
        (SEVERITY_RANK[right.severity] || 0) - (SEVERITY_RANK[left.severity] || 0)
    );
    if (severityFilter === "all") return base;
    return base.filter((finding) => finding.severity === severityFilter);
  }, [findings, severityFilter]);

  const selectedFinding = useMemo(() => {
    if (!selectedFindingId) return filteredFindings[0] || findings[0] || null;
    return (
      findings.find((finding) => finding.id === selectedFindingId) ||
      filteredFindings[0] ||
      null
    );
  }, [filteredFindings, findings, selectedFindingId]);

  const selectedPatchList = useMemo(() => {
    if (!selectedFinding) return [];
    return patches.filter((patch) => patch.finding_id === selectedFinding.id);
  }, [patches, selectedFinding]);

  const selectedPatch = selectedPatchList[0] || null;
  const diffLines = useMemo(() => {
    if (!selectedPatch?.diff) return [];
    return selectedPatch.diff.split(/\r?\n/);
  }, [selectedPatch]);

  const codeEvidence = useMemo(() => {
    if (!selectedFinding) return null;
    return (
      selectedFinding.evidence.find((evidence) => evidence.kind === "code") ||
      selectedFinding.evidence.find((evidence) => Boolean(evidence.snippet)) ||
      null
    );
  }, [selectedFinding]);

  const logEvidence = useMemo(() => {
    if (!selectedFinding) return null;
    return (
      selectedFinding.evidence.find(
        (evidence) => evidence.kind === "log" || evidence.kind === "runtime"
      ) || null
    );
  }, [selectedFinding]);

  const screenshotEvidence = useMemo(() => {
    if (!selectedFinding) return null;
    return (
      selectedFinding.evidence.find((evidence) => evidence.kind === "screenshot") || null
    );
  }, [selectedFinding]);

  const progressItems = useMemo(() => {
    const stateByStage: Record<string, StageStatus> = {};
    STAGE_ORDER.forEach((item) => {
      stateByStage[item.stage] = "pending";
    });

    timeline.forEach((event) => {
      if (!(event.stage in stateByStage)) return;
      if (event.status === "error") {
        stateByStage[event.stage] = "error";
        return;
      }
      if (event.status === "done") {
        stateByStage[event.stage] = "done";
        return;
      }
      if (stateByStage[event.stage] === "pending") {
        stateByStage[event.stage] = "in_progress";
      }
    });

    return STAGE_ORDER.map((item) => ({
      ...item,
      status: stateByStage[item.stage],
    }));
  }, [timeline]);

  const riskScore = useMemo(() => {
    if (!findings.length) return 0;
    const weighted =
      summary.critical * 10 + summary.high * 8 + summary.medium * 5 + summary.low * 2;
    return Number((weighted / findings.length).toFixed(1));
  }, [findings.length, summary.critical, summary.high, summary.low, summary.medium]);

  const safeJobId = typeof jobId === "string" ? jobId : "";
  const runtimeVerified = Boolean(selectedFinding && hasRuntimeProof(selectedFinding));

  const attackPathNodes = useMemo(() => {
    const nodeById: Record<string, GraphNode> = {};
    graph.nodes.forEach((node) => {
      nodeById[node.id] = node;
    });

    if (graph.top_paths.length) {
      const selectedVulnNodeId = selectedFinding ? `vuln_${selectedFinding.id}` : "";
      const bestPath =
        graph.top_paths.find((path) => path.node_ids.includes(selectedVulnNodeId)) ||
        graph.top_paths[0];

      const nodes = (bestPath?.node_ids || [])
        .map((nodeId) => nodeById[nodeId])
        .filter((node): node is GraphNode => Boolean(node));
      if (nodes.length) return nodes;
    }

    const entry = graph.nodes.find((node) => node.type === "entry");
    const vuln =
      (selectedFinding && graph.nodes.find((node) => node.finding_id === selectedFinding.id)) ||
      graph.nodes.find((node) => node.type === "vuln");
    const impact = graph.nodes.find((node) => node.type === "impact");
    const fallback = [entry, vuln, impact].filter((node): node is GraphNode => Boolean(node));
    if (fallback.length) return fallback;

    if (selectedFinding) {
      return [
        { id: "entry_fallback", label: "Internet", type: "entry" },
        {
          id: `vuln_${selectedFinding.id}`,
          label: titleFromType(selectedFinding.type),
          type: "vuln",
          finding_id: selectedFinding.id,
        },
        { id: "impact_fallback", label: "User Database", type: "impact" },
      ];
    }
    return [];
  }, [graph, selectedFinding]);

  const handleCopyDiff = async () => {
    if (!selectedPatch?.diff) return;
    try {
      await navigator.clipboard.writeText(selectedPatch.diff);
      setCopyState("copied");
      setTimeout(() => setCopyState("idle"), 1400);
    } catch (_) {
      setCopyState("error");
      setTimeout(() => setCopyState("idle"), 1400);
    }
  };

  return (
    <main className="workbench-page">
      <section className="panel-shell analysis-shell">
        <header className="panel-header">
          <div className="panel-brand">
            <span className="brand-mark">IZ</span>
            <strong>Incident Zero</strong>
            <span className="muted">Active Analysis: {safeJobId || "loading"}</span>
          </div>
          <span className={`status-chip ${jobStatus}`}>{jobStatus}</span>
        </header>

        <div className="analysis-columns">
          <article className="panel-block progress-block">
            <h2>Progress</h2>
            <ul className="progress-list">
              {progressItems.map((item) => (
                <li key={item.stage} className={`progress-item ${item.status}`}>
                  <span className={`progress-dot ${item.status}`} />
                  <span>{item.label}</span>
                </li>
              ))}
            </ul>
          </article>

          <article className="panel-block findings-block">
            <div className="findings-head">
              <h2>Findings</h2>
              <label>
                Severity
                <select
                  value={severityFilter}
                  onChange={(event) => setSeverityFilter(event.target.value)}
                >
                  <option value="all">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </label>
            </div>
            <div className="finding-list">
              {filteredFindings.length ? (
                filteredFindings.map((finding) => (
                  <button
                    key={finding.id}
                    type="button"
                    className={`finding-row ${
                      selectedFinding?.id === finding.id ? "selected" : ""
                    }`}
                    onClick={() => setSelectedFindingId(finding.id)}
                  >
                    <span className={`severity-dot ${finding.severity}`} />
                    <div className="finding-copy">
                      <strong>{titleFromType(finding.type)}</strong>
                      <span className="muted">
                        {finding.file_path}:{finding.line}
                      </span>
                    </div>
                    <span className={`severity-label ${finding.severity}`}>{finding.severity}</span>
                    {hasRuntimeProof(finding) && <span className="runtime-chip">runtime</span>}
                  </button>
                ))
              ) : (
                <p className="muted">No findings yet. Waiting for pipeline output.</p>
              )}
            </div>
          </article>

          <article className="panel-block patch-block">
            <div className="patch-head">
              <h2>Patch</h2>
              <button
                type="button"
                className="copy-btn"
                onClick={handleCopyDiff}
                disabled={!selectedPatch?.diff}
              >
                {copyState === "copied"
                  ? "Copied"
                  : copyState === "error"
                  ? "Copy Failed"
                  : "Copy Diff"}
              </button>
            </div>
            <p className="patch-file-row">
              File: <strong>{selectedPatch?.file_path || "No file available"}</strong>
            </p>
            <p className="muted patch-summary-row">
              {selectedPatch?.summary || "No patch has been generated for this finding yet."}
            </p>

            <div className="diff-board">
              <div className="diff-toolbar">
                <strong>Patch Diff</strong>
                <span className="muted">{selectedPatch ? selectedPatch.id : "pending"}</span>
              </div>
              <div className="diff-lines">
                {diffLines.length ? (
                  diffLines.map((line, index) => {
                    const type = diffLineType(line);
                    return (
                      <div key={`${index}-${line}`} className={`diff-line ${type}`}>
                        <span className="line-no">{index + 1}</span>
                        <code>{line || " "}</code>
                      </div>
                    );
                  })
                ) : (
                  <p className="muted">No diff to display.</p>
                )}
              </div>
            </div>

            <div className="patch-cta-row">
              <button type="button" className="action-btn patch-cta" disabled={!selectedPatch}>
                Create Pull Request
              </button>
            </div>
          </article>
        </div>
      </section>

      <div className="two-panel-grid">
        <section className="panel-shell detail-shell">
          <header className="panel-header">
            <div className="panel-brand">
              <span className="brand-mark">IZ</span>
              <strong>
                Details:{" "}
                {selectedFinding
                  ? `${titleFromType(selectedFinding.type)} in ${selectedFinding.file_path}`
                  : "Waiting for finding selection"}
              </strong>
            </div>
            <span className="status-chip neutral">Progress</span>
          </header>

          <div className="detail-layout">
            <aside className="detail-metrics">
              <div className="metric-card">
                <span className="muted">Severity</span>
                <strong className={selectedFinding?.severity || ""}>
                  {selectedFinding?.severity || "-"}
                </strong>
              </div>
              <div className="metric-card">
                <span className="muted">Confidence</span>
                <strong>{selectedFinding?.confidence || "-"}</strong>
              </div>
              <div className="metric-card">
                <span className="muted">Runtime Verified</span>
                <strong className={runtimeVerified ? "high" : ""}>
                  {runtimeVerified ? "Yes" : "No"}
                </strong>
              </div>
            </aside>

            <div className="detail-story">
              <h3>Exploit Story</h3>
              <p>{selectedFinding?.description || "No narrative available yet."}</p>
              <h3>Suggested Fix</h3>
              <p>
                {selectedPatchList[0]?.summary ||
                  "No patch generated yet. Continue investigation to derive remediation."}
              </p>
            </div>
          </div>

          <div className="evidence-board">
            <h3>Evidence</h3>
            <div className="evidence-entry">
              <strong>Code Snippet</strong>
              <pre>{codeEvidence?.snippet || "No code evidence attached."}</pre>
            </div>
            <div className="evidence-entry">
              <strong>Log Entry</strong>
              <pre>{logEvidence?.snippet || "No runtime log evidence attached."}</pre>
            </div>
            <div className="evidence-entry">
              <strong>Screenshot</strong>
              {screenshotEvidence && safeJobId ? (
                <div className="screenshot-frame">
                  <img
                    src={`${apiBase}/evidence/${encodeURIComponent(
                      safeJobId
                    )}/${encodeURIComponent(screenshotEvidence.id)}`}
                    alt="Screenshot evidence"
                  />
                  <p>{screenshotEvidence.note || screenshotEvidence.file_path}</p>
                </div>
              ) : (
                <p className="muted">No screenshot evidence attached.</p>
              )}
            </div>
          </div>
        </section>

        <section className="panel-shell report-shell">
          <header className="panel-header">
            <div className="panel-brand">
              <span className="brand-mark">IZ</span>
              <strong>Incident Zero Report</strong>
              <span className="muted">{safeJobId || "pending job"}</span>
            </div>
            <span className="status-chip neutral">Report</span>
          </header>

          <div className="report-layout">
            <div className="summary-card">
              <h2>Executive Summary</h2>
              <ul className="summary-list">
                <li>{findings.length} findings detected</li>
                <li>
                  {summary.critical > 0 ? "Critical attack path identified" : "No critical path yet"}
                </li>
                <li>{patches.length > 0 ? "Patch generated" : "Patch pending"}</li>
              </ul>
              <p className="top-risk">
                Top Risk:{" "}
                {selectedFinding
                  ? `${titleFromType(selectedFinding.type)} in ${selectedFinding.file_path}`
                  : "No confirmed risk."}
              </p>
              <p className="risk-score">
                Overall Risk Score: <strong>{riskScore.toFixed(1)}</strong> / 10
              </p>
              {jobStatus === "error" && <p className="error-note">Job failed: {jobSummary}</p>}
            </div>

            <div className="map-card">
              <div className="attack-graph-board">
                <div className="attack-graph-stack">
                  {attackPathNodes.length ? (
                    attackPathNodes.map((node, index) => (
                      <div key={node.id} className="attack-node-wrap">
                        <div className={`attack-node-card ${node.type}`}>{node.label}</div>
                        {index < attackPathNodes.length - 1 && (
                          <div className="attack-connector" aria-hidden="true" />
                        )}
                      </div>
                    ))
                  ) : (
                    <p className="muted">Attack graph unavailable.</p>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="patch-summary-card">
            <h2>Patch Summary</h2>
            {selectedPatchList.length ? (
              <ul>
                {selectedPatchList.map((patch) => (
                  <li key={patch.id}>
                    <strong>{patch.file_path}</strong>: {patch.summary}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No patch generated for the selected finding yet.</p>
            )}
          </div>
        </section>
      </div>
    </main>
  );
}
