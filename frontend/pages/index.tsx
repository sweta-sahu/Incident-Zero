export default function Home() {
  return (
    <main className="workbench-page home-page">
      <section className="panel-shell home-shell">
        <header className="panel-header">
          <div className="panel-brand">
            <span className="brand-mark">IZ</span>
            <strong>Incident Zero</strong>
            <span className="muted">Autonomous Security Investigation Workbench</span>
          </div>
          <span className="status-chip neutral">Multimodal v4</span>
        </header>

        <div className="home-content">
          <section className="home-copy">
            <p className="home-kicker">AI-Powered Incident Triage</p>
            <h1 className="home-title">
              Correlate code, runtime logs, screenshots, and diagrams in one investigation.
            </h1>
            <p className="home-lead">
              Move from raw evidence to ranked findings and generated patch diffs with a single
              workflow built for real incident response.
            </p>

            <div className="home-cta-row">
              <a className="action-btn" href="/upload">
                Start New Investigation
              </a>
              <a className="action-btn alt" href="/run/demo">
                Open Demo Run
              </a>
            </div>

            <div className="home-chip-row">
              <span className="home-chip">Runtime Proof Signals</span>
              <span className="home-chip">Evidence-Linked Findings</span>
              <span className="home-chip">Patch Diff Generation</span>
            </div>
          </section>

          <aside className="home-visual">
            <div className="home-visual-glow" aria-hidden="true" />
            <div className="home-visual-card">
              <h2>Live Workflow</h2>
              <ol className="home-step-list">
                <li>
                  <span>1</span>
                  Ingest repository and multimodal evidence.
                </li>
                <li>
                  <span>2</span>
                  Correlate scanner + MCP outputs into unified findings.
                </li>
                <li>
                  <span>3</span>
                  Prioritize risks and generate mitigation patches.
                </li>
              </ol>
            </div>
          </aside>
        </div>

        <div className="home-feature-grid">
          <article className="home-feature-card">
            <h3>CodeScan MCP</h3>
            <p>Detects insecure patterns across repositories with structured findings output.</p>
          </article>
          <article className="home-feature-card">
            <h3>Log Parser MCP</h3>
            <p>Extracts runtime exceptions and stack traces to boost confidence and severity.</p>
          </article>
          <article className="home-feature-card">
            <h3>Screenshot Analyzer MCP</h3>
            <p>Reads visible error text and flags potential secret exposure in runtime screens.</p>
          </article>
          <article className="home-feature-card">
            <h3>Patch + Report Output</h3>
            <p>Creates actionable patch diffs with incident context and evidence traceability.</p>
          </article>
        </div>
      </section>
    </main>
  );
}
