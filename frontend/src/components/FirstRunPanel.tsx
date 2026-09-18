// UX-01: the three-sentence explanation shown before the first scan.

interface Props {
  dismissed: boolean;
  onDismiss: () => void;
  onRestore: () => void;
}

export function FirstRunPanel({ dismissed, onDismiss, onRestore }: Props) {
  if (dismissed) {
    return (
      <button type="button" className="link-button" onClick={onRestore}>
        Show what ScanLedger does
      </button>
    );
  }

  return (
    <section className="panel first-run" aria-labelledby="first-run-title">
      <h2 id="first-run-title">Before your first scan</h2>
      <p>
        ScanLedger actively scans: it sends <strong>real network packets</strong> to the
        hosts you target, to learn which are alive, which ports are open, and what those
        services say about themselves.
      </p>
      <p>
        It will only ever contact a <strong>private address inside a lab scope profile you
        created and attested to</strong> — public addresses, cloud metadata, multicast and
        broadcast are refused before a single packet leaves, and every decision is written
        to an audit ledger.
      </p>
      <p>
        It never exploits anything it finds: vulnerabilities are correlated from version
        numbers and always labelled unconfirmed, because that is where Phase 2 stops.
      </p>
      <p className="muted">
        Valid input looks like a scope of <code>10.0.0.0/24</code>, a host like{" "}
        <code>10.0.0.5</code>, or the loopback self-test target <code>127.0.0.1</code>.
      </p>
      <button type="button" onClick={onDismiss}>
        Got it
      </button>
    </section>
  );
}
