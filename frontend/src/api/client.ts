// Typed client for the ScanLedger API.
//
// Every request here targets ScanLedger's own origin. Nothing in the client
// may address a scanned host - that is the backend's job alone (PRD UX-13).

export interface ScopeProfile {
  id: string;
  name: string;
  entries: string[];
  allow_cgnat: boolean;
  allow_link_local: boolean;
  created_at: string;
  updated_at: string;
}

export interface ScanModule {
  name: string;
  display_name: string;
  description: string;
  category: string;
  supported_targets: string[];
  readiness: string;
  release: string;
  optional_dependency: string | null;
}

export interface ModuleRun {
  module: string;
  status: string;
  attempt_count: number;
  cache_hit: boolean;
  finding_count: number;
  safe_error_code: string | null;
  safe_error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface ScanDetail {
  id: string;
  scope_id: string;
  target_input: string;
  target_normalized: string;
  target_type: string;
  intensity_profile: string;
  status: string;
  note: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  resolved_addresses: string[];
  selected_modules: string[];
  attestation_text: string;
  attestation_version: string;
  attestation_at: string;
  cancel_requested: boolean;
  module_runs: ModuleRun[];
}

export interface Finding {
  id: string;
  host: string;
  port: number | null;
  category: string;
  kind: string;
  title: string;
  summary: string;
  normalized_value: Record<string, unknown>;
  raw_evidence: string | null;
  module: string;
  observed_at: string;
  confidence: string | null;
  sources: string[];
  fingerprint: string;
}

export interface LedgerEntry {
  destination: string;
  port: number | null;
  module: string;
  decision: string;
  reason: string;
  outcome: string;
  recorded_at: string;
  scan_id: string | null;
  scope_id: string | null;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export class ApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** The destination a scope refusal named, when this is one. */
  get refusedDestination(): string | null {
    const value = this.details?.["destination"];
    return typeof value === "string" ? value : null;
  }

  get refusalReason(): string | null {
    const value = this.details?.["reason"];
    return typeof value === "string" ? value : null;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  const body: unknown = text ? JSON.parse(text) : null;

  if (!response.ok) {
    const error = body as ApiErrorBody | null;
    throw new ApiError(
      error?.code ?? "unknown_error",
      error?.message ?? `Request failed with status ${response.status}`,
      error?.details,
    );
  }

  return body as T;
}

export interface CreateScanRequest {
  scope_id: string;
  target: string;
  modules: string[];
  intensity_profile: string;
  note: string | null;
  attestation_accepted: boolean;
  module_options: Record<string, unknown>;
}

export const api = {
  listScopes: () => request<ScopeProfile[]>("/api/scopes"),

  createScope: (payload: {
    name: string;
    entries: string[];
    allow_cgnat: boolean;
    allow_link_local: boolean;
  }) =>
    request<ScopeProfile>("/api/scopes", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  deleteScope: (id: string) =>
    request<void>(`/api/scopes/${encodeURIComponent(id)}`, { method: "DELETE" }),

  listModules: () => request<ScanModule[]>("/api/modules"),

  createScan: (payload: CreateScanRequest) =>
    request<ScanDetail>("/api/scans", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getScan: (id: string) => request<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`),

  cancelScan: (id: string) =>
    request<ScanDetail>(`/api/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" }),

  listFindings: (id: string) =>
    request<{ items: Finding[]; total: number }>(
      `/api/scans/${encodeURIComponent(id)}/findings?limit=500`,
    ),

  listLedger: (id: string) =>
    request<LedgerEntry[]>(`/api/scans/${encodeURIComponent(id)}/ledger`),

  listRefusals: () =>
    request<{ items: LedgerEntry[]; total: number }>("/api/ledger/refusals"),

  exportUrl: (id: string, format: "md" | "json", mode: "summary" | "full") =>
    `/api/scans/${encodeURIComponent(id)}/export?format=${format}&mode=${mode}`,
};

export const INTENSITY_PROFILES = [
  {
    name: "polite",
    label: "Polite",
    detail: "20 global / 4 per-host connections, 5 per second",
  },
  {
    name: "normal",
    label: "Normal",
    detail: "60 global / 10 per-host connections, 15 per second",
  },
  {
    name: "thorough",
    label: "Thorough",
    detail: "150 global / 16 per-host connections, 30 per second",
  },
] as const;

export const HARD_CEILING_TEXT =
  "These profiles sit under a hard ceiling of 200 global and 20 per-host connections at " +
  "50 per second. The ceiling is compiled in: no profile, setting, or request can raise it, " +
  "so ScanLedger cannot be turned into a flood against your own lab.";
