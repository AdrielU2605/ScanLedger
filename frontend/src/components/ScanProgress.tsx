// UX-07: per-module progress and a live count of what the scan has touched.
//
// SSE is advisory: the status endpoint is authoritative, so the stream is used
// to refresh it promptly and polling keeps the page correct if SSE drops.

import { useEffect, useRef, useState } from "react";
import { type ScanDetail, api } from "../api/client";

interface Props {
  scanId: string;
  onFinished: () => void;
}

interface Footprint {
  hosts_probed: number;
  ports_touched: number;
}

const TERMINAL = new Set(["completed", "completed_with_warnings", "failed", "canceled"]);
const POLL_MS = 2000;

export function ScanProgress({ scanId, onFinished }: Props) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [footprint, setFootprint] = useState<Footprint>({ hosts_probed: 0, ports_touched: 0 });
  const [streaming, setStreaming] = useState(false);
  const [canceling, setCanceling] = useState(false);

  // Held in a ref so a changing callback identity cannot tear down and rebuild
  // the event stream on every render - that churned the SSE connection and
  // multiplied polling until one scan issued thousands of requests.
  const onFinishedRef = useRef(onFinished);
  useEffect(() => {
    onFinishedRef.current = onFinished;
  }, [onFinished]);

  useEffect(() => {
    let active = true;
    let finished = false;
    let timer: number | undefined;

    const source = new EventSource(`/api/scans/${encodeURIComponent(scanId)}/events`);

    function stopWatching() {
      if (timer !== undefined) window.clearInterval(timer);
      timer = undefined;
      source.close();
      setStreaming(false);
    }

    async function refresh() {
      try {
        const detail = await api.getScan(scanId);
        if (!active) return;
        setScan(detail);

        if (TERMINAL.has(detail.status) && !finished) {
          finished = true;
          // A finished scan has nothing left to report; stop polling and let
          // the stream go rather than holding both open forever.
          stopWatching();
          onFinishedRef.current();
        }
      } catch {
        // Transient failure: the next poll is the recovery path.
      }
    }

    void refresh();
    timer = window.setInterval(() => void refresh(), POLL_MS);

    source.onopen = () => setStreaming(true);
    source.onerror = () => setStreaming(false);
    source.addEventListener("footprint", (event) => {
      const payload = JSON.parse((event as MessageEvent<string>).data) as Footprint;
      setFootprint(payload);
    });
    source.addEventListener("module_status", () => void refresh());
    source.addEventListener("scan_status", () => void refresh());

    return () => {
      active = false;
      stopWatching();
    };
  }, [scanId]);

  async function handleCancel() {
    setCanceling(true);
    try {
      setScan(await api.cancelScan(scanId));
    } finally {
      setCanceling(false);
    }
  }

  if (scan === null) {
    return (
      <section className="panel">
        <h2>Scan progress</h2>
        <p className="empty">Loading scan…</p>
      </section>
    );
  }

  const running = !TERMINAL.has(scan.status);

  return (
    <section className="panel" aria-labelledby="progress-title">
      <h2 id="progress-title">Scan progress</h2>

      <p>
        <span className={`badge badge-${scan.status}`}>{scan.status.replace(/_/g, " ")}</span>{" "}
        <span className="mono">{scan.target_normalized}</span>
      </p>

      <p className="muted" aria-live="polite">
        {running ? "Footprint so far" : "Final footprint"}:{" "}
        <strong>{footprint.hosts_probed}</strong> host(s) probed,{" "}
        <strong>{footprint.ports_touched}</strong> port(s) touched.{" "}
        {!running
          ? "This scan has finished; the live stream is closed."
          : streaming
            ? "Live updates connected."
            : "Live updates unavailable — polling instead."}
      </p>

      <table className="module-table">
        <caption className="visually-hidden">Status of each selected module</caption>
        <thead>
          <tr>
            <th scope="col">Module</th>
            <th scope="col">Status</th>
            <th scope="col">Findings</th>
            <th scope="col">Detail</th>
          </tr>
        </thead>
        <tbody>
          {scan.module_runs.map((run) => (
            <tr key={run.module}>
              <th scope="row">{run.module}</th>
              <td>
                <span className={`badge badge-${run.status}`}>
                  {run.status.replace(/_/g, " ")}
                </span>
              </td>
              <td>{run.finding_count}</td>
              <td className="muted">{run.safe_error_message ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {running && (
        <button type="button" onClick={() => void handleCancel()} disabled={canceling}>
          {canceling ? "Cancelling…" : "Cancel scan"}
        </button>
      )}

      {scan.status === "completed_with_warnings" && (
        <p className="warning">
          At least one module did not complete. Its categories are incomplete, not empty —
          a module that did not run cannot be read as "nothing was there".
        </p>
      )}
    </section>
  );
}
