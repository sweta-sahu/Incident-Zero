import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";

import MockGraph from "../../components/MockGraph";
import PatchViewer from "../../components/PatchViewer";

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

type Graph = {
  nodes: GraphNode[];
  edges: { from: string; to: string; label: string }[];
};

type Patch = {
  id: string;
  finding_id: string;
  file_path: string;
  diff: string;
  summary: string;
};

const defaultGraph: Graph = { nodes: [], edges: [] };

function hasRuntimeProof(finding: Finding): boolean {
  if (Boolean(finding.signals?.runtime_proof)) {
    return true;
  }
  return (finding.evidence || []).some(
    (evidence) => evidence.kind === "runtime" || evidence.kind === "log"
  );
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
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");

  useEffect(() => {
    if (!jobId) return;
    if (jobStatus === "done" || jobStatus === "error") return;

    const interval = setInterval(async () => {
      try {
        const statusResp = await fetch(`${apiBase}/status/${jobId}`);
        if (statusResp.ok) {
          const statusJson = await statusResp.json();
          setJobStatus(statusJson.status || "running");
          setTimeline(statusJson.timeline || []);
        }
      } catch (_) {
        // Ignore polling errors in Phase 2
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
        if (resultJson.status === "done") {
          setFindings(resultJson.findings || []);
          setGraph(resultJson.graph || defaultGraph);
          setPatches(resultJson.patches || []);
        } else {
          setFindings([]);
          setGraph(defaultGraph);
          setPatches([]);
        }
      } catch (_) {
        // Ignore result errors in Phase 2
      }
    };
    fetchResult();
  }, [apiBase, jobId, jobStatus]);

  const types = useMemo(() => {
    const unique = new Set(findings.map((f) => f.type));
    return ["all", ...Array.from(unique)];
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      if (severityFilter !== "all" && finding.severity !== severityFilter) {
        return false;
      }
      if (typeFilter !== "all" && finding.type !== typeFilter) {
        return false;
      }
      return true;
    });
  }, [findings, severityFilter, typeFilter]);

  const selectedLogEvidence = useMemo(() => {
    if (!selectedFinding) return [];
    return (selectedFinding.evidence || []).filter(
      (evidence) => evidence.kind === "log" || evidence.kind === "runtime"
    );
  }, [selectedFinding]);

  const selectedScreenshotEvidence = useMemo(() => {
    if (!selectedFinding) return [];
    return (selectedFinding.evidence || []).filter(
      (evidence) => evidence.kind === "screenshot"
    );
  }, [selectedFinding]);

  const selectedOtherEvidence = useMemo(() => {
    if (!selectedFinding) return [];
    return (selectedFinding.evidence || []).filter(
      (evidence) =>
        evidence.kind !== "log" &&
        evidence.kind !== "runtime" &&
        evidence.kind !== "screenshot"
    );
  }, [selectedFinding]);

  const summary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((finding) => {
      const sev = finding.severity as keyof typeof counts;
      if (counts[sev] !== undefined) {
        counts[sev] += 1;
      }
    });
    return counts;
  }, [findings]);

  const handleNodeClick = (node: GraphNode) => {
    setSelectedNodeId(node.id);
    if (node.finding_id) {
      const match = findings.find((finding) => finding.id === node.finding_id);
      if (match) {
        setSelectedFinding(match);
      }
    }
  };

  const handleFindingClick = (finding: Finding) => {
    setSelectedFinding(finding);
    const node = graph.nodes.find((n) => n.finding_id === finding.id);
    if (node) {
      setSelectedNodeId(node.id);
    }
  };

  return (
    <main className="page">
      <header className="hero compact">
        <p className="eyebrow">Investigation</p>
        <h1>Run Status</h1>
        <p className="subhead">Job ID: {jobId || "loading"}</p>
        <p className="muted">Status: {jobStatus}</p>
        {jobStatus === "error" && (
          <p className="muted">Job failed: {jobSummary || "Check timeline for details."}</p>
        )}
      </header>
      <section className="cards">
        <div className="card wide">
          <h2>Executive Summary</h2>
          <div className="summary">
            <div>
              <strong>{findings.length}</strong>
              <span>Total findings</span>
            </div>
            <div>
              <strong>{summary.critical}</strong>
              <span>Critical</span>
            </div>
            <div>
              <strong>{summary.high}</strong>
              <span>High</span>
            </div>
            <div>
              <strong>{summary.medium}</strong>
              <span>Medium</span>
            </div>
            <div>
              <strong>{summary.low}</strong>
              <span>Low</span>
            </div>
          </div>
        </div>
        <div className="card wide">
          <h2>Timeline Stream</h2>
          <p className="muted">
            Polling /status/{"{jobId}"} for updates until done/error (SSE ready).
          </p>
          <ul className="timeline">
            {timeline.map((event) => (
              <li key={`${event.ts}-${event.stage}`}>
                <span className={`badge ${event.status}`}>{event.stage}</span>
                <div>
                  <strong>{event.message}</strong>
                  <p className="muted">{event.ts}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
        <div className="card wide">
          <div className="card-header">
            <h2>Findings</h2>
            <div className="filters">
              <label>
                Severity
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="all">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </label>
              <label>
                Type
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                >
                  {types.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          </div>
          <div className="findings">
            {filteredFindings.map((finding) => (
              <article
                key={finding.id}
                className="finding"
                onClick={() => handleFindingClick(finding)}
              >
                <header>
                  <span className={`pill ${finding.severity}`}>
                    {finding.severity}
                  </span>
                  <h3>{finding.title}</h3>
                  {hasRuntimeProof(finding) && (
                    <span className="runtime-proof">Runtime proof</span>
                  )}
                </header>
                <p className="muted">{finding.description}</p>
                <p className="meta">
                  {finding.file_path}:{finding.line} • {finding.type} •{" "}
                  {finding.confidence}
                </p>
              </article>
            ))}
          </div>
        </div>
        <div className="card wide">
          <h2>Graph + Patches</h2>
          <MockGraph
            graph={graph}
            selectedNodeId={selectedNodeId}
            onNodeClick={handleNodeClick}
          />
          <PatchViewer
            patches={patches}
            selectedFindingId={selectedFinding?.id || null}
          />
        </div>
      </section>
      {selectedFinding && (
        <aside className="drawer">
          <div className="drawer-header">
            <div>
              <span className={`pill ${selectedFinding.severity}`}>
                {selectedFinding.severity}
              </span>
              <h3>{selectedFinding.title}</h3>
              {hasRuntimeProof(selectedFinding) && (
                <span className="runtime-proof">Runtime proof</span>
              )}
            </div>
            <button
              className="secondary"
              onClick={() => setSelectedFinding(null)}
            >
              Close
            </button>
          </div>
          <p className="muted">{selectedFinding.description}</p>
          <p className="meta">
            {selectedFinding.file_path}:{selectedFinding.line} •{" "}
            {selectedFinding.type}
          </p>
          <div className="evidence-panel">
            <h4>Evidence Panel</h4>
            <div className="evidence-block">
              <h5>Log snippet</h5>
              {selectedLogEvidence.length ? (
                selectedLogEvidence.map((ev) => (
                  <div key={ev.id} className="evidence-item">
                    <p className="muted">{ev.note || "Runtime log proof"}</p>
                    <pre>{ev.snippet}</pre>
                  </div>
                ))
              ) : (
                <p className="muted">No runtime log snippets attached.</p>
              )}
            </div>
            <div className="evidence-block">
              <h5>Screenshot preview</h5>
              {selectedScreenshotEvidence.length ? (
                selectedScreenshotEvidence.map((ev) => (
                  <figure key={ev.id} className="screenshot-preview">
                    {jobId ? (
                      <img
                        src={`${apiBase}/evidence/${encodeURIComponent(
                          String(jobId)
                        )}/${encodeURIComponent(ev.id)}`}
                        alt="Screenshot evidence"
                      />
                    ) : (
                      <p className="muted">Preview unavailable.</p>
                    )}
                    <figcaption className="muted">
                      {ev.note || ev.file_path}
                    </figcaption>
                    {ev.snippet && <pre>{ev.snippet}</pre>}
                  </figure>
                ))
              ) : (
                <p className="muted">No screenshot evidence attached.</p>
              )}
            </div>
          </div>
          <div className="evidence">
            {selectedOtherEvidence.length ? (
              selectedOtherEvidence.map((ev) => (
                <div key={ev.id} className="evidence-item">
                  <strong>{ev.kind}</strong>
                  <p className="muted">{ev.note}</p>
                  <pre>{ev.snippet}</pre>
                </div>
              ))
            ) : (
              <p className="muted">No additional evidence snippets available.</p>
            )}
          </div>
        </aside>
      )}
    </main>
  );
}
