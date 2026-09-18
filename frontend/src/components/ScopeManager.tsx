// UX-02: create, pick, and remove lab scope profiles.
//
// Validation is the server's - the same ScopeProfile code the guard enforces -
// so the UI can never accept a profile the guard would not honour.

import { useState } from "react";
import { ApiError, type ScopeProfile, api } from "../api/client";

interface Props {
  scopes: ScopeProfile[];
  activeScopeId: string | null;
  onSelect: (id: string) => void;
  onChanged: () => Promise<void>;
}

export function ScopeManager({ scopes, activeScopeId, onSelect, onChanged }: Props) {
  const [name, setName] = useState("");
  const [entries, setEntries] = useState("127.0.0.0/24");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleCreate(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const parsed = entries
        .split(/[\n,]/)
        .map((entry) => entry.trim())
        .filter(Boolean);
      const created = await api.createScope({
        name: name.trim(),
        entries: parsed,
        allow_cgnat: false,
        allow_link_local: false,
      });
      setName("");
      await onChanged();
      onSelect(created.id);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(id: string) {
    setError(null);
    try {
      await api.deleteScope(id);
      await onChanged();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : String(caught));
    }
  }

  return (
    <section className="panel" aria-labelledby="scopes-title">
      <h2 id="scopes-title">Lab scope profiles</h2>
      <p className="muted">
        A scope profile is the set of private addresses you are authorized to scan. Every
        entry must sit inside RFC1918, IPv6 ULA, or loopback — anything else is refused
        when you save.
      </p>

      {scopes.length === 0 ? (
        <p className="empty">No scope profiles yet. Create one below to enable scanning.</p>
      ) : (
        <ul className="scope-list">
          {scopes.map((scope) => (
            <li key={scope.id} className={scope.id === activeScopeId ? "active" : ""}>
              <label>
                <input
                  type="radio"
                  name="active-scope"
                  checked={scope.id === activeScopeId}
                  onChange={() => onSelect(scope.id)}
                />
                <span className="scope-name">{scope.name}</span>
                <span className="mono">{scope.entries.join(", ")}</span>
              </label>
              <button
                type="button"
                className="link-button danger"
                onClick={() => void handleDelete(scope.id)}
              >
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}

      <form onSubmit={(event) => void handleCreate(event)} className="stack">
        <label htmlFor="scope-name">Profile name</label>
        <input
          id="scope-name"
          value={name}
          required
          onChange={(event) => setName(event.target.value)}
          placeholder="home lab"
        />

        <label htmlFor="scope-entries">
          Addresses and CIDRs <span className="muted">(one per line or comma separated)</span>
        </label>
        <textarea
          id="scope-entries"
          value={entries}
          rows={3}
          onChange={(event) => setEntries(event.target.value)}
          className="mono"
        />

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        <button type="submit" disabled={busy || !name.trim()}>
          {busy ? "Saving…" : "Save scope profile"}
        </button>
      </form>
    </section>
  );
}
