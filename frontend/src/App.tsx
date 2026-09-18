import { useCallback, useEffect, useState } from "react";
import { type ScanModule, type ScopeProfile, api } from "./api/client";
import { FindingsView } from "./components/FindingsView";
import { FirstRunPanel } from "./components/FirstRunPanel";
import { ScanLauncher } from "./components/ScanLauncher";
import { ScanProgress } from "./components/ScanProgress";
import { ScopeManager } from "./components/ScopeManager";

const FIRST_RUN_KEY = "scanledger.first-run-dismissed";

export function App() {
  const [scopes, setScopes] = useState<ScopeProfile[]>([]);
  const [modules, setModules] = useState<ScanModule[]>([]);
  const [activeScopeId, setActiveScopeId] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [dismissed, setDismissed] = useState(
    () => window.localStorage.getItem(FIRST_RUN_KEY) === "true",
  );
  const [loadError, setLoadError] = useState<string | null>(null);

  const refreshScopes = useCallback(async () => {
    const loaded = await api.listScopes();
    setScopes(loaded);
    setActiveScopeId((current) => {
      if (current && loaded.some((scope) => scope.id === current)) return current;
      return loaded[0]?.id ?? null;
    });
  }, []);

  useEffect(() => {
    async function load() {
      try {
        await refreshScopes();
        setModules(await api.listModules());
      } catch (caught) {
        setLoadError(
          `Could not reach the ScanLedger API. Is it running on 127.0.0.1:8000? (${String(caught)})`,
        );
      }
    }
    void load();
  }, [refreshScopes]);

  const handleScanFinished = useCallback(() => {
    setReloadToken((token) => token + 1);
  }, []);

  function dismissFirstRun() {
    window.localStorage.setItem(FIRST_RUN_KEY, "true");
    setDismissed(true);
  }

  const activeScope = scopes.find((scope) => scope.id === activeScopeId) ?? null;

  return (
    <div className="app">
      <header>
        <h1>ScanLedger</h1>
        <p className="muted">
          Lab-locked active scanning. Private, attested scope only — every probe and every
          refusal is recorded.
        </p>
      </header>

      {loadError && (
        <p className="error" role="alert">
          {loadError}
        </p>
      )}

      <FirstRunPanel
        dismissed={dismissed}
        onDismiss={dismissFirstRun}
        onRestore={() => setDismissed(false)}
      />

      <div className="columns">
        <div className="column">
          <ScopeManager
            scopes={scopes}
            activeScopeId={activeScopeId}
            onSelect={setActiveScopeId}
            onChanged={refreshScopes}
          />
          <ScanLauncher
            scope={activeScope}
            modules={modules}
            onLaunched={(scan) => setScanId(scan.id)}
          />
        </div>

        <div className="column">
          {scanId === null ? (
            <section className="panel">
              <h2>Scan progress</h2>
              <p className="empty">
                No scan yet. Pick a scope, enter an in-scope target, confirm authorization,
                and launch.
              </p>
            </section>
          ) : (
            <>
              <ScanProgress scanId={scanId} onFinished={handleScanFinished} />
              <FindingsView scanId={scanId} reloadToken={reloadToken} />
            </>
          )}
        </div>
      </div>

      <footer className="muted">
        ScanLedger never exploits what it finds, never attempts credentials, and refuses any
        public address. Phase 2 stops here.
      </footer>
    </div>
  );
}
