import { useRouter } from "next/router";

export default function Run() {
  const { query } = useRouter();
  const jobId = Array.isArray(query.jobId) ? query.jobId[0] : query.jobId;

  return (
    <main className="page">
      <header className="hero compact">
        <p className="eyebrow">Investigation</p>
        <h1>Run Status</h1>
        <p className="subhead">Job ID: {jobId || "loading"}</p>
      </header>
      <section className="cards">
        <div className="card wide">
          <h2>Timeline Stream</h2>
          <p>Connect to /events/{"{jobId}"} for live updates.</p>
        </div>
        <div className="card">
          <h2>Findings</h2>
          <p>Awaiting results from /result/{"{jobId}"}.</p>
        </div>
        <div className="card">
          <h2>Graph + Patches</h2>
          <p>Render attack paths and diff viewer here.</p>
        </div>
      </section>
    </main>
  );
}