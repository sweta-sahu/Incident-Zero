import { useEffect, useState } from "react";
import { useRouter } from "next/router";

const RECENT_RUNS_KEY = "incident-zero-recent-runs";

type InputMode = "path" | "upload";
type RepoMode = "path" | "github";

export default function Upload() {
  const router = useRouter();
  const apiBase = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

  const [repoPath, setRepoPath] = useState("");
  const [githubUrl, setGithubUrl] = useState("");
  const [repoMode, setRepoMode] = useState<RepoMode>("path");

  const [logMode, setLogMode] = useState<InputMode>("path");
  const [logPath, setLogPath] = useState("");
  const [logFile, setLogFile] = useState<File | null>(null);

  const [screenshotMode, setScreenshotMode] = useState<InputMode>("path");
  const [screenshotPath, setScreenshotPath] = useState("");
  const [screenshotFile, setScreenshotFile] = useState<File | null>(null);

  const [diagramMode, setDiagramMode] = useState<InputMode>("path");
  const [diagramPath, setDiagramPath] = useState("");
  const [diagramFile, setDiagramFile] = useState<File | null>(null);

  const [recentRuns, setRecentRuns] = useState<string[]>([]);
  const [status, setStatus] = useState<"idle" | "loading" | "error">("idle");

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      const raw = window.localStorage.getItem(RECENT_RUNS_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        setRecentRuns(parsed.filter((value) => typeof value === "string").slice(0, 5));
      }
    } catch (_) {
      // Ignore localStorage parse errors.
    }
  }, []);

  const persistRecentRun = (jobId: string) => {
    if (typeof window === "undefined") return;
    const next = [jobId, ...recentRuns.filter((value) => value !== jobId)].slice(0, 5);
    setRecentRuns(next);
    window.localStorage.setItem(RECENT_RUNS_KEY, JSON.stringify(next));
  };

  const handleSubmit = async () => {
    setStatus("loading");
    try {
      const payload = new FormData();
      const selectedRepo = repoMode === "path" ? repoPath.trim() : githubUrl.trim();
      payload.append("repo_path", selectedRepo);

      if (logMode === "path") {
        if (logPath.trim()) payload.append("log_path", logPath.trim());
      } else if (logFile) {
        payload.append("log_file", logFile);
      }

      if (screenshotMode === "path") {
        if (screenshotPath.trim()) payload.append("screenshot_path", screenshotPath.trim());
      } else if (screenshotFile) {
        payload.append("screenshot_file", screenshotFile);
      }

      if (diagramMode === "path") {
        if (diagramPath.trim()) payload.append("diagram_path", diagramPath.trim());
      } else if (diagramFile) {
        payload.append("diagram_file", diagramFile);
      }

      const resp = await fetch(`${apiBase}/analyze/upload`, {
        method: "POST",
        body: payload,
      });
      if (!resp.ok) {
        setStatus("error");
        return;
      }
      const data = await resp.json();
      if (data.job_id) {
        persistRecentRun(data.job_id);
        router.push(`/run/${data.job_id}`);
      } else {
        setStatus("error");
      }
    } catch (_) {
      setStatus("error");
    }
  };

  return (
    <main className="workbench-page">
      <section className="panel-shell intake-shell">
        <div className="panel-topbar">
          <div className="window-dots">
            <span />
            <span />
            <span />
          </div>
        </div>
        <div className="intake-content">
          <h1>Incident Zero</h1>
          <p className="subhead">Multimodal Security Investigation</p>

          <form
            className="intake-form"
            onSubmit={(event) => {
              event.preventDefault();
              handleSubmit();
            }}
          >
            <div className="upload-grid four">
              <label className="upload-card">
                <span className="upload-card-title">Upload Repository</span>
                <span className="upload-card-copy">
                  Choose local path or GitHub URL. Local path is required for active scanning.
                </span>
                <div className="mode-switch">
                  <button
                    type="button"
                    className={`mode-btn ${repoMode === "path" ? "active" : ""}`}
                    onClick={() => setRepoMode("path")}
                  >
                    Path
                  </button>
                  <button
                    type="button"
                    className={`mode-btn ${repoMode === "github" ? "active" : ""}`}
                    onClick={() => setRepoMode("github")}
                  >
                    GitHub
                  </button>
                </div>
                {repoMode === "path" ? (
                  <input
                    className="upload-input"
                    type="text"
                    placeholder="D:\\projects\\repo or /home/user/repo"
                    value={repoPath}
                    onChange={(event) => setRepoPath(event.target.value)}
                  />
                ) : (
                  <input
                    className="upload-input subtle"
                    type="text"
                    placeholder="https://github.com/org/repo"
                    value={githubUrl}
                    onChange={(event) => setGithubUrl(event.target.value)}
                  />
                )}
              </label>

              <label className="upload-card">
                <span className="upload-card-title">Upload Logs</span>
                <span className="upload-card-copy">
                  Provide path or upload a log file for runtime proof extraction.
                </span>
                <div className="mode-switch">
                  <button
                    type="button"
                    className={`mode-btn ${logMode === "path" ? "active" : ""}`}
                    onClick={() => setLogMode("path")}
                  >
                    Path
                  </button>
                  <button
                    type="button"
                    className={`mode-btn ${logMode === "upload" ? "active" : ""}`}
                    onClick={() => setLogMode("upload")}
                  >
                    Upload
                  </button>
                </div>
                {logMode === "path" ? (
                  <input
                    className="upload-input"
                    type="text"
                    placeholder="D:\\evidence\\runtime.log"
                    value={logPath}
                    onChange={(event) => setLogPath(event.target.value)}
                  />
                ) : (
                  <div className="file-pick">
                    <input
                      type="file"
                      accept=".log,.txt,.json"
                      onChange={(event) => setLogFile(event.target.files?.[0] || null)}
                    />
                    <span className="file-name">{logFile?.name || "No file selected"}</span>
                  </div>
                )}
              </label>

              <label className="upload-card">
                <span className="upload-card-title">Upload Screenshot</span>
                <span className="upload-card-copy">
                  Provide path or upload an image for OCR and secret exposure checks.
                </span>
                <div className="mode-switch">
                  <button
                    type="button"
                    className={`mode-btn ${screenshotMode === "path" ? "active" : ""}`}
                    onClick={() => setScreenshotMode("path")}
                  >
                    Path
                  </button>
                  <button
                    type="button"
                    className={`mode-btn ${screenshotMode === "upload" ? "active" : ""}`}
                    onClick={() => setScreenshotMode("upload")}
                  >
                    Upload
                  </button>
                </div>
                {screenshotMode === "path" ? (
                  <input
                    className="upload-input"
                    type="text"
                    placeholder="D:\\evidence\\error-screen.png"
                    value={screenshotPath}
                    onChange={(event) => setScreenshotPath(event.target.value)}
                  />
                ) : (
                  <div className="file-pick">
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(event) => setScreenshotFile(event.target.files?.[0] || null)}
                    />
                    <span className="file-name">
                      {screenshotFile?.name || "No file selected"}
                    </span>
                  </div>
                )}
              </label>

              <label className="upload-card">
                <span className="upload-card-title">Upload Diagram</span>
                <span className="upload-card-copy">
                  Provide path or upload architecture diagram for Diagram Extractor MCP.
                </span>
                <div className="mode-switch">
                  <button
                    type="button"
                    className={`mode-btn ${diagramMode === "path" ? "active" : ""}`}
                    onClick={() => setDiagramMode("path")}
                  >
                    Path
                  </button>
                  <button
                    type="button"
                    className={`mode-btn ${diagramMode === "upload" ? "active" : ""}`}
                    onClick={() => setDiagramMode("upload")}
                  >
                    Upload
                  </button>
                </div>
                {diagramMode === "path" ? (
                  <input
                    className="upload-input"
                    type="text"
                    placeholder="D:\\evidence\\architecture.png"
                    value={diagramPath}
                    onChange={(event) => setDiagramPath(event.target.value)}
                  />
                ) : (
                  <div className="file-pick">
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(event) => setDiagramFile(event.target.files?.[0] || null)}
                    />
                    <span className="file-name">{diagramFile?.name || "No file selected"}</span>
                  </div>
                )}
              </label>
            </div>

            <div className="action-row">
              <button type="submit" className="action-btn" disabled={status === "loading"}>
                {status === "loading" ? "Investigating..." : "Investigate System"}
              </button>
              {status === "error" && (
                <p className="muted">
                  Unable to start analysis. Confirm API is running and repository path is local.
                </p>
              )}
            </div>
          </form>

          <div className="recent-runs">
            <h2>Recent Runs</h2>
            <ul>
              {recentRuns.length ? (
                recentRuns.map((run) => (
                  <li key={run}>
                    <a href={`/run/${run}`}>{run}</a>
                  </li>
                ))
              ) : (
                <li className="muted">No runs yet.</li>
              )}
            </ul>
          </div>
        </div>
      </section>
    </main>
  );
}
