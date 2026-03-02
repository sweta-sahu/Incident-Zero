import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";

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

type Patch = {
  id: string;
  finding_id: string;
  file_path: string;
  diff: string;
  summary: string;
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
  const safeJobId = typeof jobId === "string" ? jobId : "";
  const apiBase = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

  const [jobStatus, setJobStatus] = useState("running");
  const [jobSummary, setJobSummary] = useState("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [patches, setPatches] = useState<Patch[]>([]);
  const [diagramTextBlocks, setDiagramTextBlocks] = useState<string[]>([]);

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

  useEffect(() => {
    if (!safeJobId) return;
    if (jobStatus === "done" || jobStatus === "error") return;

    const interval = setInterval(async () => {
      try {
        const statusResp = await fetch(`${apiBase}/status/${safeJobId}`);
        if (!statusResp.ok) return;
        const statusJson = await statusResp.json();
        setJobStatus(statusJson.status || "running");
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

        if (resultJson.status === "done") {
          const nextFindings = resultJson.findings || [];
          setFindings(nextFindings);
          setPatches(resultJson.patches || []);
          const extractedText = resultJson?.diagram?.artifacts?.extracted_text;
          setDiagramTextBlocks(Array.isArray(extractedText) ? extractedText : []);
          if (nextFindings.length > 0) {
            setSelectedFindingId((prev) => prev || nextFindings[0].id);
          }
          return;
        }

        setFindings([]);
        setPatches([]);
        setDiagramTextBlocks([]);
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

  const runtimeVerified = Boolean(selectedFinding && hasRuntimeProof(selectedFinding));

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

                <div className="context-section">
                  <h3>Code Evidence</h3>
                  <pre>{codeEvidence?.snippet || "No code evidence attached."}</pre>
                </div>

                <div className="context-section">
                  <h3>Runtime Evidence</h3>
                  <pre>{logEvidence?.snippet || "No runtime log evidence attached."}</pre>
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
            <h2>Uploaded Diagram</h2>
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

            {diagramTextBlocks.length > 0 && (
              <div className="diagram-text-block">
                <strong>Extracted Diagram Text</strong>
                <pre>{diagramTextBlocks.join("\n")}</pre>
              </div>
            )}
          </article>
        </div>
      </section>

      {jobStatus === "error" && (
        <section className="panel-shell">
          <div className="summary-card">
            <h2>Pipeline Error</h2>
            <p className="error-note">{jobSummary || "Unknown error while processing the job."}</p>
          </div>
        </section>
      )}
    </main>
  );
}
