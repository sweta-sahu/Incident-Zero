export default function Home() {
  return (
    <main className="page">
      <header className="hero">
        <p className="eyebrow">Incident Zero</p>
        <h1>Autonomous Security Investigation</h1>
        <p className="subhead">
          Upload a repo, watch the timeline, and receive a patch-ready report.
        </p>
        <div className="actions">
          <a className="primary" href="/upload">Upload Repo</a>
          <a className="secondary" href="/run/demo">Run Demo</a>
          <span className="ghost">/run/[jobId]</span>
        </div>
      </header>
      <section className="cards">
        <div className="card">
          <h2>Timeline</h2>
          <p>Live investigation stages with SSE fallback to polling.</p>
        </div>
        <div className="card">
          <h2>Findings</h2>
          <p>Correlated vulnerabilities with evidence and confidence.</p>
        </div>
        <div className="card">
          <h2>Graph</h2>
          <p>Attack paths with ranked impact nodes.</p>
        </div>
      </section>
    </main>
  );
}
