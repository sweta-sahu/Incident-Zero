import { useState } from "react";
import { useRouter } from "next/router";

export default function Upload() {
  const router = useRouter();
  const apiBase = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

  const [repoPath, setRepoPath] = useState("");
  const [githubUrl, setGithubUrl] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "error">("idle");

  const handleSubmit = async () => {
    setStatus("loading");
    try {
      const payload = {
        repo_path: repoPath || githubUrl,
      };
      const resp = await fetch(`${apiBase}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        setStatus("error");
        return;
      }
      const data = await resp.json();
      if (data.job_id) {
        router.push(`/run/${data.job_id}`);
      } else {
        setStatus("error");
      }
    } catch (_) {
      setStatus("error");
    }
  };

  return (
    <main className="page">
      <header className="hero compact">
        <p className="eyebrow">Upload</p>
        <h1>Start An Investigation</h1>
        <p className="subhead">
          Provide a repo path or GitHub URL. This will call /analyze.
        </p>
      </header>
      <section className="cards">
        <form
          className="card wide form"
          onSubmit={(event) => {
            event.preventDefault();
            handleSubmit();
          }}
        >
          <label className="field">
            <span>Repository path</span>
            <input
              type="text"
              placeholder="C:\\path\\to\\repo or /home/user/repo"
              value={repoPath}
              onChange={(event) => setRepoPath(event.target.value)}
            />
          </label>
          <label className="field">
            <span>GitHub URL</span>
            <input
              type="text"
              placeholder="https://github.com/org/repo"
              value={githubUrl}
              onChange={(event) => setGithubUrl(event.target.value)}
            />
          </label>
          <button type="submit" className="primary" disabled={status === "loading"}>
            {status === "loading" ? "Starting..." : "Start Analysis"}
          </button>
          {status === "error" && (
            <p className="muted">Unable to start analysis. Check API.</p>
          )}
        </form>
      </section>
    </main>
  );
}