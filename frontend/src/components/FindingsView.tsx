// UX-08 and UX-13: findings grouped by category, with raw evidence rendered as
// inert text.
//
// Nothing here links to, loads from, or otherwise references a scanned host in
// a way the browser could act on. Host and port values are plain text inside
// <code>, never an href, image, or iframe: the backend does the scanning, and
// the browser must never contact a target on the dashboard's behalf.

import { useEffect, useState } from "react";
import { type Finding, type LedgerEntry, api } from "../api/client";

interface Props {
  scanId: string;
  reloadToken: number;
}

const CATEGORY_TITLES: Record<string, string> = {
  live_host: "Live hosts",
  port_service: "Ports and services",
  enumeration: "Enumeration",
  vulnerability: "Vulnerabilities",
};

const CATEGORY_ORDER = ["live_host", "port_service", "enumeration", "vulnerability"];

export function FindingsView({ scanId, reloadToken }: Props) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [ledger, setLedger] = useState<LedgerEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);

    async function load() {
      const [foundFindings, foundLedger] = await Promise.all([
        api.listFindings(scanId),
        api.listLedger(scanId),
      ]);
      if (!active) return;
      setFindings(foundFindings.items);
      setLedger(foundLedger);
      setLoading(false);
    }

    void load();
    return () => {
      active = false;
    };
  }, [scanId, reloadToken]);

  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const bucket = grouped.get(finding.category) ?? [];
    bucket.push(finding);
    grouped.set(finding.category, bucket);
  }

  const allowed = ledger.filter((entry) => entry.decision === "allowed").length;
  const denied = ledger.filter((entry) => entry.decision === "denied").length;

  return (
    <section className="panel" aria-labelledby="findings-title">
      <h2 id="findings-title">Findings</h2>

      {loading ? (
        <p className="empty">Loading evidence…</p>
      ) : (
        <>
          {CATEGORY_ORDER.map((category) => {
            const rows = grouped.get(category) ?? [];
            return (
              <div key={category} className="category">
                <h3>{CATEGORY_TITLES[category] ?? category}</h3>
                {rows.length === 0 ? (
                  <p className="empty">
                    Nothing recorded in this category for this scan. If a module did not
                    complete, that means unknown — not absent.
                  </p>
                ) : (
                  <ul className="finding-list">
                    {rows.map((finding) => (
                      <li key={finding.id}>
                        <p className="finding-title">{finding.title}</p>
                        <p className="muted">
                          {finding.summary}{" "}
                          <span className="mono">
                            [{finding.module} · {new Date(finding.observed_at).toLocaleString()}
                            {finding.confidence ? ` · ${finding.confidence} confidence` : ""}]
                          </span>
                        </p>
                        {finding.raw_evidence && (
                          <details>
                            <summary>Raw evidence</summary>
                            {/* Target-derived text, rendered inertly - never as markup. */}
                            <pre className="evidence">{finding.raw_evidence}</pre>
                          </details>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            );
          })}

          <div className="category">
            <h3>Audit ledger</h3>
            <p>
              <strong>{allowed}</strong> destination(s) probed,{" "}
              <strong>{denied}</strong> refused. Every one is recorded, so scope compliance
              is provable rather than asserted.
            </p>
            <details>
              <summary>Show ledger entries</summary>
              <table className="module-table">
                <thead>
                  <tr>
                    <th scope="col">Destination</th>
                    <th scope="col">Port</th>
                    <th scope="col">Decision</th>
                    <th scope="col">Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {ledger.slice(0, 200).map((entry, index) => (
                    <tr key={`${entry.destination}-${entry.port}-${index}`}>
                      {/* Inert text, never a link to a scanned host. */}
                      <td className="mono">{entry.destination}</td>
                      <td className="mono">{entry.port ?? "—"}</td>
                      <td>{entry.decision}</td>
                      <td className="muted">{entry.outcome}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {ledger.length > 200 && (
                <p className="muted">
                  Showing the first 200 of {ledger.length} entries; the exports carry the
                  complete record.
                </p>
              )}
            </details>
          </div>

          <div className="exports">
            <h3>Exports</h3>
            <p className="muted">
              Regenerated from stored evidence — downloading a report never sends a probe.
            </p>
            <a href={api.exportUrl(scanId, "md", "full")} download>
              Markdown report
            </a>
            <a href={api.exportUrl(scanId, "json", "full")} download>
              JSON export
            </a>
          </div>
        </>
      )}
    </section>
  );
}
