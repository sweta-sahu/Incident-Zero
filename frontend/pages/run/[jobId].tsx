import fs from "fs";
import path from "path";

import { useRouter } from "next/router";

import MockGraph from "../../components/MockGraph";

type TimelineEvent = {
  ts: string;
  stage: string;
  message: string;
  status: string;
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
  evidence: string[];
};

type RunProps = {
  timeline: TimelineEvent[];
  findings: Finding[];
  graph: {
    nodes: { id: string; label: string; type: string }[];
    edges: { from: string; to: string; label: string }[];
  };
};

export default function Run({ timeline, findings, graph }: RunProps) {
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
          <p className="muted">
            Connect to /events/{"{jobId}"} for live updates. Showing mock data
            for now.
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
          <h2>Findings</h2>
          <div className="findings">
            {findings.map((finding) => (
              <article key={finding.id} className="finding">
                <header>
                  <span className={`pill ${finding.severity}`}>
                    {finding.severity}
                  </span>
                  <h3>{finding.title}</h3>
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
          <MockGraph graph={graph} />
        </div>
      </section>
    </main>
  );
}

export async function getServerSideProps() {
  const root = process.cwd().replace(/frontend$/, "");
  const statusPath = path.join(root, "fixtures", "mockStatus.json");
  const resultPath = path.join(root, "fixtures", "mockResult.json");

  const statusRaw = fs.readFileSync(statusPath, "utf-8");
  const resultRaw = fs.readFileSync(resultPath, "utf-8");

  const statusJson = JSON.parse(statusRaw);
  const resultJson = JSON.parse(resultRaw);

  return {
    props: {
      timeline: statusJson.timeline || [],
      findings: resultJson.findings || [],
      graph: resultJson.graph || { nodes: [], edges: [] },
    },
  };
}
