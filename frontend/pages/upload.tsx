export default function Upload() {
  return (
    <main className="page">
      <header className="hero compact">
        <p className="eyebrow">Upload</p>
        <h1>Start An Investigation</h1>
        <p className="subhead">
          Provide a repo path or GitHub URL. Backend wiring comes in Phase 2.
        </p>
      </header>
      <section className="cards">
        <form className="card wide form">
          <label className="field">
            <span>Repository path</span>
            <input
              type="text"
              placeholder="C:\\path\\to\\repo or /home/user/repo"
            />
          </label>
          <label className="field">
            <span>GitHub URL</span>
            <input type="text" placeholder="https://github.com/org/repo" />
          </label>
          <button type="button" className="primary">
            Start Analysis
          </button>
        </form>
      </section>
    </main>
  );
}
