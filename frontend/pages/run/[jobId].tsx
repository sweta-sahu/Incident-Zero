import { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
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
  source?: string[] | string;
  signals?: Record<string, unknown>;
};

type Patch = {
  id: string;
  finding_id: string;
  file_path: string;
  diff: string;
  summary: string;
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

type DiagramToolResult = {
  tool_name?: string;
  artifacts?: Record<string, unknown>;
  signals?: Record<string, unknown>;
  errors?: Array<Record<string, unknown>>;
};

type ManualFixRecommendation = {
  id: string;
  finding_id: string;
  vulnerability_type: string;
  reason: string;
  file_path: string;
  line: number;
  manual_fix_recommendation?: string[];
  source?: string[] | string;
  detail?: string;
};

type InputBundle = {
  job_id: string;
  repo_path?: string | null;
  log_path?: string | null;
  screenshot_path?: string | null;
  diagram_path?: string | null;
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const defaultGraph: Graph = { nodes: [], edges: [], top_paths: [] };
const AttackGraph = dynamic(() => import("../../components/MockGraph"), { ssr: false });

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

function findingDisplayTitle(finding: Finding): string {
  const given = String(finding.title || "").trim();
  if (given) return given;
  return titleFromType(finding.type);
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

function normalizeSourceList(source: string[] | string | undefined): string[] {
  if (!source) return [];
  if (typeof source === "string") {
    const cleaned = source.trim().toLowerCase();
    return cleaned ? [cleaned] : [];
  }
  return source
    .map((item) => String(item || "").trim().toLowerCase())
    .filter((item, idx, arr) => item && arr.indexOf(item) === idx);
}

function normalizeFilePath(value: string): string {
  return String(value || "").replace(/\\/g, "/").trim().toLowerCase();
}

function formatSignalKey(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatSignalValue(value: unknown): string {
  if (Array.isArray(value)) {
    const text = value.map((item) => String(item)).join(", ");
    return text.length > 180 ? `${text.slice(0, 180)}...` : text;
  }
  if (typeof value === "object" && value !== null) {
    const text = JSON.stringify(value);
    return text.length > 180 ? `${text.slice(0, 180)}...` : text;
  }
  return String(value);
}

function timelineStatusClass(value: string): "done" | "error" | "in_progress" {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "done") return "done";
  if (normalized === "error") return "error";
  return "in_progress";
}

function prettyTime(ts: string): string {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleString();
}

function safeJsonText(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch (_) {
    return String(value);
  }
}

export default function Run() {
  const { query } = useRouter();
  const jobId = Array.isArray(query.jobId) ? query.jobId[0] : query.jobId;
  const safeJobId = typeof jobId === "string" ? jobId : "";
  const apiBase = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

  const [jobStatus, setJobStatus] = useState("running");
  const [jobSummary, setJobSummary] = useState("");
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [patches, setPatches] = useState<Patch[]>([]);
  const [manualFixRecommendations, setManualFixRecommendations] = useState<
    ManualFixRecommendation[]
  >([]);
  const [graph, setGraph] = useState<Graph>(defaultGraph);
  const [diagramResult, setDiagramResult] = useState<DiagramToolResult | null>(null);

  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");

  const [uploadedInputs, setUploadedInputs] = useState<InputBundle | null>(null);
  const [uploadedLog, setUploadedLog] = useState("");
  const [logLoadState, setLogLoadState] = useState<"idle" | "loading" | "ready" | "error">(
    "idle"
  );
  const [screenshotPreviewError, setScreenshotPreviewError] = useState(false);
  const [diagramPreviewError, setDiagramPreviewError] = useState(false);
  const [findingScreenshotErrors, setFindingScreenshotErrors] = useState<Record<string, boolean>>(
    {}
  );

  useEffect(() => {
    if (!safeJobId) return;
    if (jobStatus === "done" || jobStatus === "error") return;

    const interval = setInterval(async () => {
      try {
        const statusResp = await fetch(`${apiBase}/status/${safeJobId}`);
        if (!statusResp.ok) return;
        const statusJson = await statusResp.json();
        setJobStatus(statusJson.status || "running");
        setTimeline(Array.isArray(statusJson.timeline) ? statusJson.timeline : []);
      } catch (_) {
        // Ignore transient polling errors.
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [apiBase, safeJobId, jobStatus]);

  useEffect(() => {
    if (!safeJobId) return;
    if (jobStatus !== "done" && jobStatus !== "error") return;

    const fetchResult = async () => {
      try {
        const resultResp = await fetch(`${apiBase}/result/${safeJobId}`);
        if (!resultResp.ok) return;
        const resultJson = await resultResp.json();
        setJobStatus(resultJson.status || "running");
        setJobSummary(resultJson.summary || "");
        setTimeline(Array.isArray(resultJson.timeline) ? resultJson.timeline : []);

        if (resultJson.status === "done") {
          const nextFindings = Array.isArray(resultJson.findings) ? resultJson.findings : [];
          setFindings(nextFindings);
          setPatches(Array.isArray(resultJson.patches) ? resultJson.patches : []);
          setManualFixRecommendations(
            Array.isArray(resultJson.manual_fix_recommendations)
              ? resultJson.manual_fix_recommendations
              : []
          );
          setGraph(resultJson.graph || defaultGraph);
          setDiagramResult(resultJson.diagram || null);

          if (nextFindings.length > 0) {
            setSelectedFindingId((prev) => prev || nextFindings[0].id);
          }
          return;
        }

        setFindings([]);
        setPatches([]);
        setManualFixRecommendations([]);
        setGraph(defaultGraph);
        setDiagramResult(null);
      } catch (_) {
        // Ignore result errors.
      }
    };

    fetchResult();
  }, [apiBase, safeJobId, jobStatus]);

  useEffect(() => {
    if (!safeJobId) return;

    const fetchInputs = async () => {
      try {
        const inputsResp = await fetch(`${apiBase}/inputs/${safeJobId}`);
        if (!inputsResp.ok) return;
        const inputsJson = await inputsResp.json();
        setUploadedInputs(inputsJson);
        setScreenshotPreviewError(false);
        setDiagramPreviewError(false);

        const hasLogPath = Boolean(String(inputsJson.log_path || "").trim());
        if (!hasLogPath) {
          setUploadedLog("");
          setLogLoadState("idle");
          return;
        }

        setLogLoadState("loading");
        const logResp = await fetch(
          `${apiBase}/input-file/${encodeURIComponent(safeJobId)}/log`
        );
        if (!logResp.ok) {
          setUploadedLog("");
          setLogLoadState("error");
          return;
        }
        const text = await logResp.text();
        setUploadedLog(text);
        setLogLoadState("ready");
      } catch (_) {
        setLogLoadState("error");
      }
    };

    fetchInputs();
  }, [apiBase, safeJobId]);

  useEffect(() => {
    if (!findings.length) {
      setSelectedFindingId(null);
      return;
    }
    const hasSelection =
      selectedFindingId && findings.some((finding) => finding.id === selectedFindingId);
    if (!hasSelection) {
      setSelectedFindingId(findings[0].id);
    }
  }, [findings, selectedFindingId]);

  useEffect(() => {
    setFindingScreenshotErrors({});
  }, [selectedFindingId]);

  const summary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((finding) => {
      const key = String(finding.severity || "").toLowerCase();
      if (key in counts) {
        counts[key as keyof typeof counts] += 1;
      }
    });
    return counts;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const base = [...findings].sort(
      (left, right) =>
        (SEVERITY_RANK[String(right.severity).toLowerCase()] || 0) -
        (SEVERITY_RANK[String(left.severity).toLowerCase()] || 0)
    );
    if (severityFilter === "all") return base;
    return base.filter((finding) => String(finding.severity).toLowerCase() === severityFilter);
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

  const selectedManualFixes = useMemo(() => {
    if (!selectedFinding) return [];

    const byFinding = manualFixRecommendations.filter(
      (item) => item.finding_id === selectedFinding.id
    );
    if (byFinding.length) {
      return byFinding;
    }

    const selectedFile = normalizeFilePath(
      selectedPatch?.file_path || selectedFinding.file_path || ""
    );
    if (!selectedFile) {
      return [];
    }

    return manualFixRecommendations.filter((item) => {
      const recFile = normalizeFilePath(item.file_path || "");
      if (!recFile) return false;
      return recFile === selectedFile || recFile.endsWith(selectedFile) || selectedFile.endsWith(recFile);
    });
  }, [manualFixRecommendations, selectedFinding, selectedPatch]);

  const selectedEvidence = useMemo(
    () => (selectedFinding ? selectedFinding.evidence || [] : []),
    [selectedFinding]
  );

  const codeEvidenceList = useMemo(
    () => selectedEvidence.filter((item) => item.kind === "code"),
    [selectedEvidence]
  );
  const logEvidenceList = useMemo(
    () => selectedEvidence.filter((item) => item.kind === "log" || item.kind === "runtime"),
    [selectedEvidence]
  );
  const screenshotEvidenceList = useMemo(
    () => selectedEvidence.filter((item) => item.kind === "screenshot"),
    [selectedEvidence]
  );
  const otherEvidenceList = useMemo(
    () =>
      selectedEvidence.filter(
        (item) => !["code", "log", "runtime", "screenshot"].includes(item.kind)
      ),
    [selectedEvidence]
  );

  const selectedSources = useMemo(
    () => normalizeSourceList(selectedFinding?.source),
    [selectedFinding]
  );
  const selectedSignals = useMemo(
    () => Object.entries(selectedFinding?.signals || {}),
    [selectedFinding]
  );
  const runtimeVerified = Boolean(selectedFinding && hasRuntimeProof(selectedFinding));

  const diagramArtifacts = (diagramResult?.artifacts || {}) as Record<string, unknown>;
  const diagramSignals = (diagramResult?.signals || {}) as Record<string, unknown>;
  const diagramErrors = Array.isArray(diagramResult?.errors) ? diagramResult?.errors || [] : [];
  const diagramComponents = Array.isArray(diagramArtifacts.components)
    ? (diagramArtifacts.components as Array<Record<string, unknown>>)
    : [];
  const diagramConnections = Array.isArray(diagramArtifacts.connections)
    ? (diagramArtifacts.connections as Array<Record<string, unknown>>)
    : [];
  const diagramTrustZones = Array.isArray(diagramArtifacts.trust_zones)
    ? (diagramArtifacts.trust_zones as Array<Record<string, unknown> | string>)
    : [];
  const diagramEntryPoints = Array.isArray(diagramArtifacts.entry_points)
    ? (diagramArtifacts.entry_points as Array<Record<string, unknown> | string>)
    : [];
  const diagramSecretsLocations = Array.isArray(diagramArtifacts.secrets_locations)
    ? (diagramArtifacts.secrets_locations as Array<Record<string, unknown> | string>)
    : [];
  const diagramExtractedText = Array.isArray(diagramArtifacts.extracted_text)
    ? (diagramArtifacts.extracted_text as string[])
    : [];

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

  const screenshotUrl = safeJobId
    ? `${apiBase}/input-file/${encodeURIComponent(safeJobId)}/screenshot`
    : "";
  const diagramUrl = safeJobId
    ? `${apiBase}/input-file/${encodeURIComponent(safeJobId)}/diagram`
    : "";

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

        <div className="summary-strip">
          <div className="summary-tile">
            <span className="muted">Total Findings</span>
            <strong>{findings.length}</strong>
          </div>
          <div className="summary-tile critical">
            <span className="muted">Critical</span>
            <strong>{summary.critical}</strong>
          </div>
          <div className="summary-tile high">
            <span className="muted">High</span>
            <strong>{summary.high}</strong>
          </div>
          <div className="summary-tile medium">
            <span className="muted">Medium</span>
            <strong>{summary.medium}</strong>
          </div>
          <div className="summary-tile low">
            <span className="muted">Low</span>
            <strong>{summary.low}</strong>
          </div>
        </div>

        <div className="analysis-columns no-progress">
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
                      <strong>{findingDisplayTitle(finding)}</strong>
                      <span className="muted">
                        {finding.file_path}:{finding.line}
                      </span>
                      <span className="finding-sources">
                        {normalizeSourceList(finding.source).join(" • ") || "code"}
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

          <article className="panel-block context-block">
            <h2>Finding Context</h2>
            {selectedFinding ? (
              <div className="context-content">
                <div className="context-metrics">
                  <div className="metric-card compact">
                    <span className="muted">Severity</span>
                    <strong className={selectedFinding.severity}>{selectedFinding.severity}</strong>
                  </div>
                  <div className="metric-card compact">
                    <span className="muted">Confidence</span>
                    <strong>{selectedFinding.confidence || "-"}</strong>
                  </div>
                  <div className="metric-card compact">
                    <span className="muted">Runtime Verified</span>
                    <strong className={runtimeVerified ? "high" : ""}>
                      {runtimeVerified ? "Yes" : "No"}
                    </strong>
                  </div>
                  <div className="metric-card compact">
                    <span className="muted">Location</span>
                    <strong>{selectedFinding.file_path}:{selectedFinding.line}</strong>
                  </div>
                </div>

                <div className="context-section">
                  <h3>Exploit Story</h3>
                  <p>{selectedFinding.description || "No narrative available yet."}</p>
                </div>

                <div className="context-section provenance-board">
                  <h3>Multimodal Provenance</h3>
                  <div className="source-chip-row">
                    {selectedSources.length ? (
                      selectedSources.map((source) => (
                        <span key={source} className="source-chip">
                          {source}
                        </span>
                      ))
                    ) : (
                      <span className="muted">No source metadata.</span>
                    )}
                  </div>
                  {selectedSignals.length ? (
                    <div className="signal-grid">
                      {selectedSignals.map(([key, value]) => (
                        <div key={key} className="signal-entry">
                          <strong>{formatSignalKey(key)}</strong>
                          <span>{formatSignalValue(value)}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">No multimodal signals attached to this finding.</p>
                  )}
                </div>

                <div className="context-section">
                  <h3>Code Evidence</h3>
                  {codeEvidenceList.length ? (
                    <div className="evidence-stack">
                      {codeEvidenceList.map((item, idx) => (
                        <div key={`${item.id || "code"}_${idx}`} className="evidence-item">
                          <p className="evidence-meta">
                            {item.file_path || "unknown path"}:{item.line || 0}
                          </p>
                          {item.note ? <p className="evidence-note">{item.note}</p> : null}
                          <pre>{item.snippet || "No snippet."}</pre>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">No code evidence attached.</p>
                  )}
                </div>

                <div className="context-section">
                  <h3>Runtime Evidence</h3>
                  {logEvidenceList.length ? (
                    <div className="evidence-stack">
                      {logEvidenceList.map((item, idx) => (
                        <div key={`${item.id || "log"}_${idx}`} className="evidence-item">
                          <p className="evidence-meta">
                            {item.file_path || "runtime logs"}:{item.line || 0}
                          </p>
                          {item.note ? <p className="evidence-note">{item.note}</p> : null}
                          <pre>{item.snippet || "No snippet."}</pre>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">No runtime log evidence attached.</p>
                  )}
                </div>

                <div className="context-section">
                  <h3>Screenshot Evidence</h3>
                  {screenshotEvidenceList.length ? (
                    <div className="evidence-stack">
                      {screenshotEvidenceList.map((item, idx) => {
                        const key = `${item.id || item.file_path || "screenshot"}_${idx}`;
                        const previewUrl =
                          safeJobId && item.id
                            ? `${apiBase}/evidence/${encodeURIComponent(
                                safeJobId
                              )}/${encodeURIComponent(item.id)}`
                            : "";
                        const blocked = findingScreenshotErrors[key];
                        return (
                          <div key={key} className="evidence-item screenshot-evidence-item">
                            <p className="evidence-meta">
                              {item.file_path || "screenshot"}:{item.line || 0}
                            </p>
                            {item.note ? <p className="evidence-note">{item.note}</p> : null}
                            {previewUrl && !blocked ? (
                              <img
                                className="upload-image-preview finding-screenshot-preview"
                                src={previewUrl}
                                alt="Screenshot evidence"
                                onError={() =>
                                  setFindingScreenshotErrors((prev) => ({ ...prev, [key]: true }))
                                }
                              />
                            ) : (
                              <p className="muted">Screenshot preview unavailable.</p>
                            )}
                            {item.snippet ? <pre>{item.snippet}</pre> : null}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="muted">No screenshot evidence attached.</p>
                  )}
                </div>

                <div className="context-section">
                  <h3>Additional Evidence</h3>
                  {otherEvidenceList.length ? (
                    <div className="evidence-stack">
                      {otherEvidenceList.map((item, idx) => (
                        <div key={`${item.id || "other"}_${idx}`} className="evidence-item">
                          <p className="evidence-meta">
                            {item.kind} | {item.file_path || "unknown path"}:{item.line || 0}
                          </p>
                          {item.note ? <p className="evidence-note">{item.note}</p> : null}
                          <pre>{item.snippet || "No snippet."}</pre>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">No additional evidence attached.</p>
                  )}
                </div>
              </div>
            ) : (
              <p className="muted">Select a finding to view severity, confidence, and evidence.</p>
            )}
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

            <div className="manual-fix-board">
              <h3>Manual Fix Recommendations</h3>
              {selectedManualFixes.length ? (
                <div className="manual-fix-list">
                  {selectedManualFixes.map((item) => (
                    <div key={item.id} className="manual-fix-item">
                      <p>
                        <strong>{item.file_path || "Unknown file"}</strong>
                        {item.line ? `:${item.line}` : ""} |{" "}
                        {String(item.reason || "manual_review").replace(/_/g, " ")}
                      </p>
                      <p className="muted">
                        Sources: {normalizeSourceList(item.source).join(", ") || "unknown"}
                      </p>
                      {item.detail ? <p className="error-note">{item.detail}</p> : null}
                      {Array.isArray(item.manual_fix_recommendation) &&
                      item.manual_fix_recommendation.length ? (
                        <ul>
                          {item.manual_fix_recommendation.map((step, idx) => (
                            <li key={`${item.id}_step_${idx}`}>{step}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="muted">No manual steps provided.</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted">No manual fix recommendations.</p>
              )}
            </div>
          </article>
        </div>
      </section>

      <section className="panel-shell investigation-shell">
        <header className="panel-header">
          <div className="panel-brand">
            <span className="brand-mark">IZ</span>
            <strong>Investigation Summary</strong>
            <span className="muted">{safeJobId || "pending job"}</span>
          </div>
          <span className="status-chip neutral">Report</span>
        </header>

        <div className="investigation-grid">
          <article className="panel-block investigation-summary-card">
            <h2>Narrative Summary</h2>
            <p>{jobSummary || "Summary will be available after correlation completes."}</p>
            <div className="summary-kv-grid">
              <div>
                <span className="muted">Findings</span>
                <strong>{findings.length}</strong>
              </div>
              <div>
                <span className="muted">Patches</span>
                <strong>{patches.length}</strong>
              </div>
              <div>
                <span className="muted">Manual Fixes</span>
                <strong>{manualFixRecommendations.length}</strong>
              </div>
              <div>
                <span className="muted">Timeline Events</span>
                <strong>{timeline.length}</strong>
              </div>
            </div>
            <h3>Timeline</h3>
            {timeline.length ? (
              <ul className="timeline-list-run">
                {timeline.map((event, idx) => (
                  <li key={`${event.ts}_${idx}`}>
                    <span className={`timeline-dot ${timelineStatusClass(event.status)}`} />
                    <div>
                      <p className="timeline-stage">
                        {event.stage} | {event.status}
                      </p>
                      <p className="timeline-message">{event.message}</p>
                      <p className="muted timeline-time">{prettyTime(event.ts)}</p>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No timeline events yet.</p>
            )}
          </article>

          <article className="panel-block graph-context-card">
            <h2>Attack Graph Context</h2>
            <p className="muted graph-intro">
              {selectedFinding
                ? `Focused path for: ${findingDisplayTitle(selectedFinding)} (${selectedFinding.file_path}:${selectedFinding.line})`
                : "Select a finding to view its attack path."}
            </p>
            <AttackGraph graph={graph} selectedFindingId={selectedFinding?.id || null} />
          </article>
        </div>
      </section>

      <section className="panel-shell uploads-shell">
        <header className="panel-header">
          <div className="panel-brand">
            <span className="brand-mark">IZ</span>
            <strong>Uploaded Artifacts</strong>
            <span className="muted">{safeJobId || "pending job"}</span>
          </div>
          <span className="status-chip neutral">Evidence</span>
        </header>

        <div className="uploads-grid">
          <article className="panel-block upload-evidence-panel">
            <h2>Uploaded Repository</h2>
            <p className="upload-path">{uploadedInputs?.repo_path || "No repository input attached."}</p>
          </article>

          <article className="panel-block upload-evidence-panel">
            <h2>Uploaded Screenshot</h2>
            <p className="upload-path">
              {uploadedInputs?.screenshot_path || "No screenshot input attached."}
            </p>
            {uploadedInputs?.screenshot_path && !screenshotPreviewError ? (
              <img
                className="upload-image-preview"
                src={screenshotUrl}
                alt="Uploaded screenshot"
                onError={() => setScreenshotPreviewError(true)}
              />
            ) : (
              <p className="muted">Screenshot preview unavailable.</p>
            )}
          </article>

          <article className="panel-block upload-evidence-panel">
            <h2>Uploaded Diagram + MCP Output</h2>
            <p className="upload-path">
              {uploadedInputs?.diagram_path || "No diagram input attached."}
            </p>
            {uploadedInputs?.diagram_path && !diagramPreviewError ? (
              <img
                className="upload-image-preview"
                src={diagramUrl}
                alt="Uploaded diagram"
                onError={() => setDiagramPreviewError(true)}
              />
            ) : (
              <p className="muted">Diagram preview unavailable.</p>
            )}

            <div className="diagram-meta-grid">
              <p>
                <strong>Tool:</strong> {diagramResult?.tool_name || "Diagram MCP not executed"}
              </p>
              <p>
                <strong>Confidence:</strong> {String(diagramArtifacts.confidence || "-")}
              </p>
              <p>
                <strong>Components:</strong> {diagramComponents.length}
              </p>
              <p>
                <strong>Connections:</strong> {diagramConnections.length}
              </p>
              <p>
                <strong>Trust Zones:</strong> {diagramTrustZones.length}
              </p>
              <p>
                <strong>Entry Points:</strong> {diagramEntryPoints.length}
              </p>
              <p>
                <strong>Secrets Locations:</strong> {diagramSecretsLocations.length}
              </p>
              <p>
                <strong>Errors:</strong> {diagramErrors.length}
              </p>
            </div>

            {diagramComponents.length > 0 && (
              <div className="diagram-list-block">
                <strong>Components</strong>
                <ul>
                  {diagramComponents.slice(0, 12).map((component, idx) => (
                    <li key={`component_${idx}`}>
                      {String(component.name || component.id || "component")} (
                      {String(component.type || "unknown")})
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {diagramConnections.length > 0 && (
              <div className="diagram-list-block">
                <strong>Connections</strong>
                <ul>
                  {diagramConnections.slice(0, 12).map((connection, idx) => (
                    <li key={`connection_${idx}`}>
                      {String(connection.from || "?")} {"->"} {String(connection.to || "?")}{" "}
                      {connection.protocol ? `(${String(connection.protocol)})` : ""}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {diagramTrustZones.length > 0 && (
              <div className="diagram-list-block">
                <strong>Trust Zones</strong>
                <pre>{safeJsonText(diagramTrustZones)}</pre>
              </div>
            )}

            {diagramEntryPoints.length > 0 && (
              <div className="diagram-list-block">
                <strong>Entry Points</strong>
                <pre>{safeJsonText(diagramEntryPoints)}</pre>
              </div>
            )}

            {diagramSecretsLocations.length > 0 && (
              <div className="diagram-list-block">
                <strong>Secrets Locations</strong>
                <pre>{safeJsonText(diagramSecretsLocations)}</pre>
              </div>
            )}

            {Object.keys(diagramSignals).length > 0 && (
              <div className="diagram-list-block">
                <strong>Diagram Signals</strong>
                <pre>{safeJsonText(diagramSignals)}</pre>
              </div>
            )}

            {diagramExtractedText.length > 0 && (
              <div className="diagram-list-block">
                <strong>Extracted Diagram Text</strong>
                <pre>{diagramExtractedText.join("\n")}</pre>
              </div>
            )}

            {diagramErrors.length > 0 && (
              <div className="diagram-list-block">
                <strong>Diagram MCP Errors</strong>
                <pre>{safeJsonText(diagramErrors)}</pre>
              </div>
            )}
          </article>

          <article className="panel-block upload-evidence-panel wide">
            <h2>Uploaded Logs</h2>
            <p className="upload-path">{uploadedInputs?.log_path || "No log input attached."}</p>
            {logLoadState === "loading" && <p className="muted">Loading log file...</p>}
            {logLoadState === "error" && (
              <p className="muted">Unable to read uploaded log file from current path.</p>
            )}
            {logLoadState !== "loading" && logLoadState !== "error" && (
              <pre className="upload-log-view">{uploadedLog || "No log content available."}</pre>
            )}
          </article>
        </div>
      </section>
    </main>
  );
}

