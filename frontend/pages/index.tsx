export default function Home() {
  return (
    <main className="workbench-page">
      <section className="panel-shell home-shell">
        <header className="panel-header">
          <div className="panel-brand">
            <span className="brand-mark">IZ</span>
            <strong>Incident Zero</strong>
            <span className="muted">Autonomous Multimodal Security Investigation</span>
          </div>
        </header>
        <div className="home-actions">
          <a className="action-btn" href="/upload">
            Start New Investigation
          </a>
          <a className="action-btn alt" href="/run/demo">
            Open Demo Run
          </a>
        </div>
      </section>
    </main>
  );
}
