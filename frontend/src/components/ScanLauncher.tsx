// UX-03 through UX-06: target input, module selection, intensity, and the
// authorization gate. Launch stays disabled until the attestation is checked.

import { useState } from "react";
import {
  ApiError,
  HARD_CEILING_TEXT,
  INTENSITY_PROFILES,
  type ScanDetail,
  type ScanModule,
  type ScopeProfile,
  api,
} from "../api/client";

interface Props {
  scope: ScopeProfile | null;
  modules: ScanModule[];
  onLaunched: (scan: ScanDetail) => void;
}

const ATTESTATION =
  "I own the systems in this scope profile, or I hold written authorization to actively " +
  "scan them, and I understand ScanLedger sends real network probes.";

export function ScanLauncher({ scope, modules, onLaunched }: Props) {
  const [target, setTarget] = useState("127.0.0.1");
  const [selected, setSelected] = useState<string[]>(["host_discovery", "port_scan"]);
  const [intensity, setIntensity] = useState<string>("polite");
  const [portSelection, setPortSelection] = useState("top-100");
  const [note, setNote] = useState("");
  const [attested, setAttested] = useState(false);
  const [refusal, setRefusal] = useState<ApiError | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const canLaunch =
    scope !== null && target.trim() !== "" && selected.length > 0 && attested && !busy;

  function toggleModule(name: string) {
    setSelected((current) =>
      current.includes(name) ? current.filter((item) => item !== name) : [...current, name],
    );
  }

  async function handleLaunch(event: React.FormEvent) {
    event.preventDefault();
    if (scope === null) return;

    setRefusal(null);
    setError(null);
    setBusy(true);
    try {
      const scan = await api.createScan({
        scope_id: scope.id,
        target: target.trim(),
        modules: selected,
        intensity_profile: intensity,
        note: note.trim() || null,
        attestation_accepted: attested,
        module_options: { port_selection: portSelection },
      });
      setAttested(false);
      onLaunched(scan);
    } catch (caught) {
      if (caught instanceof ApiError && caught.code === "target_out_of_scope") {
        setRefusal(caught);
      } else {
        setError(caught instanceof ApiError ? caught.message : String(caught));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="launch-title">
      <h2 id="launch-title">Launch a scan</h2>

      {scope === null ? (
        <p className="empty">
          Select or create a scope profile first — ScanLedger will not scan without one.
        </p>
      ) : (
        <p className="muted">
          Active scope: <strong>{scope.name}</strong>{" "}
          <span className="mono">({scope.entries.join(", ")})</span>
        </p>
      )}

      <form onSubmit={(event) => void handleLaunch(event)} className="stack">
        <label htmlFor="target">Target (host, IP, or CIDR)</label>
        <input
          id="target"
          className="mono"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
          aria-describedby="target-help"
          disabled={scope === null}
        />
        <p id="target-help" className="muted">
          Must be inside the active scope profile. A public address, or a hostname that
          resolves to one, is refused before any packet is sent.
        </p>

        {refusal && (
          <div className="refusal" role="alert">
            <h3>Target refused — nothing was sent</h3>
            <p>
              <span className="mono">{refusal.refusedDestination ?? target}</span> was
              refused: {refusal.refusalReason ?? refusal.message}
            </p>
            <p className="muted">
              The refusal is recorded in the audit ledger. Pick a target inside the active
              scope, or edit the scope profile if you are authorized to scan more.
            </p>
          </div>
        )}

        <fieldset disabled={scope === null}>
          <legend>Modules</legend>
          {modules.length === 0 ? (
            <p className="empty">No modules are registered.</p>
          ) : (
            modules.map((module) => (
              <label key={module.name} className="check-row">
                <input
                  type="checkbox"
                  checked={selected.includes(module.name)}
                  onChange={() => toggleModule(module.name)}
                />
                <span>
                  <strong>{module.display_name}</strong>{" "}
                  <span className={`badge badge-${module.readiness}`}>
                    {module.readiness.replace(/_/g, " ")}
                  </span>
                  <br />
                  <span className="muted">{module.description}</span>
                </span>
              </label>
            ))
          )}
        </fieldset>

        <label htmlFor="ports">Ports to scan</label>
        <select
          id="ports"
          value={portSelection}
          onChange={(event) => setPortSelection(event.target.value)}
          disabled={scope === null}
        >
          <option value="top-100">Top 100 common service ports</option>
          <option value="well-known">Well known (1–1024)</option>
          <option value="full">Full range (1–65535)</option>
        </select>

        <fieldset disabled={scope === null}>
          <legend>Intensity</legend>
          {INTENSITY_PROFILES.map((profile) => (
            <label key={profile.name} className="check-row">
              <input
                type="radio"
                name="intensity"
                value={profile.name}
                checked={intensity === profile.name}
                onChange={() => setIntensity(profile.name)}
              />
              <span>
                <strong>{profile.label}</strong>
                <br />
                <span className="muted mono">{profile.detail}</span>
              </span>
            </label>
          ))}
          <p className="muted">{HARD_CEILING_TEXT}</p>
        </fieldset>

        <label htmlFor="note">Engagement note (optional)</label>
        <input
          id="note"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          disabled={scope === null}
          placeholder="What is this scan for?"
        />

        <div className="attestation">
          <label className="check-row">
            <input
              type="checkbox"
              checked={attested}
              onChange={(event) => setAttested(event.target.checked)}
              disabled={scope === null}
            />
            <span>{ATTESTATION}</span>
          </label>
        </div>

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        <button type="submit" disabled={!canLaunch}>
          {busy ? "Queueing…" : "Launch scan"}
        </button>
        {!attested && scope !== null && (
          <p className="muted">Launch stays disabled until you confirm authorization.</p>
        )}
      </form>
    </section>
  );
}
