type Patch = {
  id: string;
  finding_id: string;
  file_path: string;
  diff: string;
  summary: string;
};

type PatchViewerProps = {
  patches: Patch[];
  selectedFindingId?: string | null;
};

export default function PatchViewer({
  patches,
  selectedFindingId,
}: PatchViewerProps) {
  const visible =
    selectedFindingId && patches.length
      ? patches.filter((patch) => patch.finding_id === selectedFindingId)
      : patches;

  if (!visible.length) {
    return <p className="muted">No patches generated yet.</p>;
  }

  return (
    <div className="patches">
      {visible.map((patch) => (
        <div key={patch.id} className="patch-card">
          <div className="patch-header">
            <strong>{patch.file_path}</strong>
            <span className="muted">{patch.summary}</span>
          </div>
          <pre className="patch-diff">{patch.diff}</pre>
        </div>
      ))}
    </div>
  );
}
