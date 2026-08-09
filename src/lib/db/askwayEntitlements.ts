import { createHash, randomBytes, randomUUID } from "node:crypto";
import { getDbInstance } from "./core";
import { invalidateApiKeyAuthCaches } from "./apiKeys";

export type AskwayEntitlementPolicy = Readonly<{
  tokenLimit: bigint;
  allowedModels: readonly string[];
  allowedCombos: readonly string[];
  allowedConnections: readonly string[];
  allowedEndpoints: readonly string[];
  requestsPerMinute?: number;
}>;

export type AskwayEntitlementInspection = Readonly<{
  externalKeyId: string;
  entitlementId: string;
  active: boolean;
  policy: AskwayEntitlementPolicy;
  policyVersion: number;
}>;

export type AskwayProvisionedCredential = Readonly<{
  externalKeyId: string;
  secret: string;
  displayPrefix: string;
  policyVersion: number;
}>;

type SqliteDatabase = ReturnType<typeof getDbInstance>;
type EntitlementRow = {
  id: string;
  external_entitlement_id: string;
  api_key_id: string;
  policy_json: string;
  policy_version: number;
  status: "active" | "revoked";
};

const HASH_ONLY_SENTINEL_PREFIX = "askway-hash-only:";

function stableStringList(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort();
}

function normalizePolicy(policy: AskwayEntitlementPolicy): AskwayEntitlementPolicy {
  if (policy.tokenLimit <= 0n || policy.tokenLimit > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("tokenLimit must be a positive safe integer");
  }
  if (policy.allowedModels.length === 0) throw new Error("At least one model must be allowed");
  if (policy.allowedEndpoints.length === 0)
    throw new Error("At least one endpoint category must be allowed");
  if (
    policy.requestsPerMinute !== undefined &&
    (!Number.isSafeInteger(policy.requestsPerMinute) || policy.requestsPerMinute <= 0)
  ) {
    throw new Error("requestsPerMinute must be a positive integer");
  }
  return {
    tokenLimit: policy.tokenLimit,
    allowedModels: stableStringList(policy.allowedModels),
    allowedCombos: stableStringList(policy.allowedCombos),
    allowedConnections: stableStringList(policy.allowedConnections),
    allowedEndpoints: stableStringList(policy.allowedEndpoints),
    ...(policy.requestsPerMinute === undefined
      ? {}
      : { requestsPerMinute: policy.requestsPerMinute }),
  };
}

function serializePolicy(policy: AskwayEntitlementPolicy): string {
  return JSON.stringify({ ...policy, tokenLimit: policy.tokenLimit.toString() });
}

function parsePolicy(value: string): AskwayEntitlementPolicy {
  const parsed = JSON.parse(value) as Omit<AskwayEntitlementPolicy, "tokenLimit"> & {
    tokenLimit: string;
  };
  return { ...parsed, tokenLimit: BigInt(parsed.tokenLimit) };
}

function inspectionFromRow(row: EntitlementRow): AskwayEntitlementInspection {
  return {
    externalKeyId: row.id,
    entitlementId: row.external_entitlement_id,
    active: row.status === "active",
    policy: parsePolicy(row.policy_json),
    policyVersion: row.policy_version,
  };
}

function credentialMaterial(): { secret: string; hash: string; prefix: string } {
  const secret = `ora_live_${randomBytes(32).toString("base64url")}`;
  return {
    secret,
    hash: createHash("sha256").update(secret).digest("hex"),
    prefix: `${secret.slice(0, 14)}…`,
  };
}

function commandExists(db: SqliteDatabase, idempotencyKey: string): boolean {
  return Boolean(
    db
      .prepare("SELECT 1 FROM askway_entitlement_commands WHERE idempotency_key = ?")
      .get(idempotencyKey)
  );
}

export function provisionAskwayEntitlementCredential(input: {
  externalEntitlementId: string;
  displayName: string;
  idempotencyKey: string;
  policy: AskwayEntitlementPolicy;
}): AskwayProvisionedCredential {
  const db = getDbInstance();
  const policy = normalizePolicy(input.policy);
  const material = credentialMaterial();
  const externalKeyId = randomUUID();
  const apiKeyId = randomUUID();
  const now = new Date().toISOString();

  const create = db.transaction(() => {
    if (commandExists(db, input.idempotencyKey)) throw new AskwayIdempotencyConflictError();
    const existing = db
      .prepare("SELECT id FROM askway_entitlement_keys WHERE external_entitlement_id = ?")
      .get(input.externalEntitlementId);
    if (existing) throw new AskwayEntitlementConflictError();

    db.prepare(
      `INSERT INTO api_keys (
         id, name, key, machine_id, allowed_models, allowed_combos, allowed_connections,
         allowed_endpoints, max_requests_per_minute, no_log, auto_resolve, is_active,
         created_at, key_prefix, key_hash, scopes
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 1, ?, ?, ?, ?)`
    ).run(
      apiKeyId,
      input.displayName,
      `${HASH_ONLY_SENTINEL_PREFIX}${apiKeyId}`,
      "askway-entitlement",
      JSON.stringify(policy.allowedModels),
      JSON.stringify(policy.allowedCombos),
      JSON.stringify(policy.allowedConnections),
      JSON.stringify(policy.allowedEndpoints),
      policy.requestsPerMinute ?? null,
      now,
      material.prefix,
      material.hash,
      JSON.stringify([])
    );
    db.prepare(
      `INSERT INTO askway_entitlement_keys (
         id, external_entitlement_id, api_key_id, display_name, policy_json,
         policy_version, lifetime_token_limit, observed_tokens, key_version,
         status, created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, 1, ?, 0, 1, 'active', ?, ?)`
    ).run(
      externalKeyId,
      input.externalEntitlementId,
      apiKeyId,
      input.displayName,
      serializePolicy(policy),
      policy.tokenLimit,
      now,
      now
    );
    db.prepare(
      `INSERT INTO askway_entitlement_commands
       (idempotency_key, command_type, entitlement_key_id, completed_at)
       VALUES (?, 'provision', ?, ?)`
    ).run(input.idempotencyKey, externalKeyId, now);
  });
  create();
  return {
    externalKeyId,
    secret: material.secret,
    displayPrefix: material.prefix,
    policyVersion: 1,
  };
}

export function inspectAskwayEntitlementByExternalId(
  externalEntitlementId: string
): AskwayEntitlementInspection | null {
  const row = getDbInstance()
    .prepare("SELECT * FROM askway_entitlement_keys WHERE external_entitlement_id = ?")
    .get(externalEntitlementId) as EntitlementRow | undefined;
  return row ? inspectionFromRow(row) : null;
}

export function inspectAskwayEntitlementById(id: string): AskwayEntitlementInspection | null {
  const row = getDbInstance()
    .prepare("SELECT * FROM askway_entitlement_keys WHERE id = ?")
    .get(id) as EntitlementRow | undefined;
  return row ? inspectionFromRow(row) : null;
}

export async function rotateAskwayEntitlementCredential(
  externalKeyId: string,
  idempotencyKey: string
): Promise<AskwayProvisionedCredential | null> {
  const db = getDbInstance();
  const material = credentialMaterial();
  const now = new Date().toISOString();
  let apiKeyId = "";
  let policyVersion = 0;
  const rotate = db.transaction(() => {
    if (commandExists(db, idempotencyKey)) throw new AskwayIdempotencyConflictError();
    const row = db
      .prepare("SELECT * FROM askway_entitlement_keys WHERE id = ?")
      .get(externalKeyId) as EntitlementRow | undefined;
    if (!row) return false;
    if (row.status !== "active") throw new AskwayRevokedCredentialError();
    apiKeyId = row.api_key_id;
    policyVersion = row.policy_version;
    db.prepare(
      `UPDATE api_keys
       SET key_hash = ?, key_prefix = ?, key = ?, last_used_at = NULL
       WHERE id = ?`
    ).run(material.hash, material.prefix, `${HASH_ONLY_SENTINEL_PREFIX}${apiKeyId}`, apiKeyId);
    db.prepare(
      `UPDATE askway_entitlement_keys
       SET key_version = key_version + 1, updated_at = ? WHERE id = ?`
    ).run(now, externalKeyId);
    db.prepare(
      `INSERT INTO askway_entitlement_commands
       (idempotency_key, command_type, entitlement_key_id, completed_at)
       VALUES (?, 'rotate', ?, ?)`
    ).run(idempotencyKey, externalKeyId, now);
    return true;
  });
  if (!rotate()) return null;
  await invalidateApiKeyAuthCaches(apiKeyId);
  return {
    externalKeyId,
    secret: material.secret,
    displayPrefix: material.prefix,
    policyVersion,
  };
}

export async function revokeAskwayEntitlementCredential(
  externalKeyId: string,
  idempotencyKey: string
): Promise<boolean> {
  const db = getDbInstance();
  const now = new Date().toISOString();
  let apiKeyId = "";
  const revoke = db.transaction(() => {
    if (commandExists(db, idempotencyKey)) throw new AskwayIdempotencyConflictError();
    const row = db
      .prepare("SELECT * FROM askway_entitlement_keys WHERE id = ?")
      .get(externalKeyId) as EntitlementRow | undefined;
    if (!row) return false;
    apiKeyId = row.api_key_id;
    db.prepare(
      `UPDATE askway_entitlement_keys
       SET status = 'revoked', revoked_at = COALESCE(revoked_at, ?), updated_at = ? WHERE id = ?`
    ).run(now, now, externalKeyId);
    db.prepare(
      `UPDATE api_keys
       SET revoked_at = COALESCE(revoked_at, ?), is_active = 0 WHERE id = ?`
    ).run(now, apiKeyId);
    db.prepare(
      `INSERT INTO askway_entitlement_commands
       (idempotency_key, command_type, entitlement_key_id, completed_at)
       VALUES (?, 'revoke', ?, ?)`
    ).run(idempotencyKey, externalKeyId, now);
    return true;
  });
  if (!revoke()) return false;
  await invalidateApiKeyAuthCaches(apiKeyId);
  return true;
}

export async function configureAskwayEntitlementCredential(
  externalKeyId: string,
  policyInput: AskwayEntitlementPolicy,
  expectedVersion: number
): Promise<AskwayEntitlementInspection | null> {
  const db = getDbInstance();
  const policy = normalizePolicy(policyInput);
  const now = new Date().toISOString();
  let apiKeyId = "";
  const configure = db.transaction(() => {
    const row = db
      .prepare("SELECT * FROM askway_entitlement_keys WHERE id = ?")
      .get(externalKeyId) as EntitlementRow | undefined;
    if (!row) return false;
    if (row.status !== "active") throw new AskwayRevokedCredentialError();
    if (row.policy_version !== expectedVersion) throw new AskwayPolicyVersionConflictError();
    apiKeyId = row.api_key_id;
    db.prepare(
      `UPDATE api_keys SET allowed_models = ?, allowed_combos = ?, allowed_connections = ?,
       allowed_endpoints = ?, max_requests_per_minute = ? WHERE id = ?`
    ).run(
      JSON.stringify(policy.allowedModels),
      JSON.stringify(policy.allowedCombos),
      JSON.stringify(policy.allowedConnections),
      JSON.stringify(policy.allowedEndpoints),
      policy.requestsPerMinute ?? null,
      apiKeyId
    );
    db.prepare(
      `UPDATE askway_entitlement_keys SET policy_json = ?, policy_version = policy_version + 1,
       lifetime_token_limit = ?, updated_at = ? WHERE id = ?`
    ).run(serializePolicy(policy), policy.tokenLimit, now, externalKeyId);
    return true;
  });
  if (!configure()) return null;
  await invalidateApiKeyAuthCaches(apiKeyId);
  return inspectAskwayEntitlementById(externalKeyId);
}

export function validateAskwayEntitlementRequest(
  apiKeyId: string,
  entitlementHeader: string | null
):
  | { allowed: true; externalKeyId: string }
  | { allowed: false; status: number; message: string }
  | null {
  const row = getDbInstance()
    .prepare(
      `SELECT id, external_entitlement_id, status, lifetime_token_limit, observed_tokens
       FROM askway_entitlement_keys WHERE api_key_id = ?`
    )
    .get(apiKeyId) as
    | {
        id: string;
        external_entitlement_id: string;
        status: string;
        lifetime_token_limit: number;
        observed_tokens: number;
      }
    | undefined;
  if (!row) return null;
  if (!entitlementHeader || entitlementHeader !== row.external_entitlement_id) {
    return { allowed: false, status: 403, message: "Entitlement header does not match key" };
  }
  if (row.status !== "active")
    return { allowed: false, status: 403, message: "Entitlement revoked" };
  if (row.observed_tokens >= row.lifetime_token_limit) {
    return { allowed: false, status: 429, message: "Entitlement token limit exhausted" };
  }
  return { allowed: true, externalKeyId: row.id };
}

export type AskwayUsageObservation = Readonly<{
  externalRequestId: string;
  externalKeyId: string;
  usage: Readonly<{
    inputTokens: number;
    outputTokens: number;
    cachedTokens: number;
    reasoningTokens: number;
    deliveredOutputTokens?: number;
    quality: "exact" | "providerReported" | "estimated" | "unknown";
    disposition: "final" | "partial" | "pendingReconciliation";
  }>;
  cost?: Readonly<{
    amountMicrounits: bigint;
    currency: string;
    quality: "providerReported" | "estimated" | "unknown";
    pricingVersion?: string;
  }>;
  diagnostics: Readonly<{
    actualProvider?: string;
    actualModel?: string;
    externalRequestId: string;
    latencyMilliseconds?: number;
    fallbackCount: number;
    routeTraceReference?: string;
  }>;
  observedAt: Date;
}>;

export function readAskwayUsageByRequest(requestId: string): AskwayUsageObservation | null {
  const row = getDbInstance()
    .prepare("SELECT * FROM askway_request_usage WHERE request_id = ?")
    .get(requestId) as Record<string, unknown> | undefined;
  if (!row) return null;
  const delivered = row.delivered_output_tokens;
  const costValue = row.cost_microunits;
  const routeReference = row.route_trace_reference;
  return {
    externalRequestId: String(row.request_id),
    externalKeyId: String(row.entitlement_key_id),
    usage: {
      inputTokens: Number(row.input_tokens),
      outputTokens: Number(row.output_tokens),
      cachedTokens: Number(row.cached_tokens),
      reasoningTokens: Number(row.reasoning_tokens),
      ...(delivered === null || delivered === undefined
        ? {}
        : { deliveredOutputTokens: Number(delivered) }),
      quality: String(row.usage_quality) as AskwayUsageObservation["usage"]["quality"],
      disposition: String(row.usage_disposition) as AskwayUsageObservation["usage"]["disposition"],
    },
    ...(typeof costValue === "string"
      ? {
          cost: {
            amountMicrounits: BigInt(costValue),
            currency: String(row.cost_currency),
            quality: String(row.cost_quality) as NonNullable<
              AskwayUsageObservation["cost"]
            >["quality"],
            ...(row.pricing_version ? { pricingVersion: String(row.pricing_version) } : {}),
          },
        }
      : {}),
    diagnostics: {
      ...(row.provider ? { actualProvider: String(row.provider) } : {}),
      ...(row.model ? { actualModel: String(row.model) } : {}),
      externalRequestId: String(row.request_id),
      ...(row.latency_ms === null || row.latency_ms === undefined
        ? {}
        : { latencyMilliseconds: Number(row.latency_ms) }),
      fallbackCount: Number(row.fallback_count),
      ...(typeof routeReference === "string" ? { routeTraceReference: routeReference } : {}),
    },
    observedAt: new Date(String(row.observed_at)),
  };
}

export function readAskwayRouteTrace(reference: string): unknown | null {
  const row = getDbInstance()
    .prepare(
      "SELECT request_id, attempts_json, created_at, updated_at FROM askway_route_traces WHERE reference = ?"
    )
    .get(reference) as
    | { request_id: string; attempts_json: string; created_at: string; updated_at: string }
    | undefined;
  if (!row) return null;
  return {
    reference,
    externalRequestId: row.request_id,
    attempts: JSON.parse(row.attempts_json),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function finiteToken(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
}

function nestedToken(record: Record<string, unknown>, group: string, field: string): number {
  const nested = record[group];
  return nested && typeof nested === "object" && !Array.isArray(nested)
    ? finiteToken((nested as Record<string, unknown>)[field])
    : 0;
}

export function recordAskwayRequestObservation(input: {
  requestId: string;
  apiKeyId?: string | null;
  usage: unknown;
  provider?: string | null;
  model?: string | null;
  latencyMilliseconds?: number | null;
  fallbackCount?: number;
  costUsd?: number | null;
  deliveredOutputTokens?: number;
}): void {
  if (!input.apiKeyId) return;
  const db = getDbInstance();
  const entitlement = db
    .prepare("SELECT id FROM askway_entitlement_keys WHERE api_key_id = ?")
    .get(input.apiKeyId) as { id: string } | undefined;
  if (!entitlement) return;

  const usageRecord =
    input.usage && typeof input.usage === "object" && !Array.isArray(input.usage)
      ? (input.usage as Record<string, unknown>)
      : null;
  const inputTokens = usageRecord
    ? finiteToken(usageRecord.prompt_tokens ?? usageRecord.input_tokens)
    : 0;
  const completionTotal = usageRecord
    ? finiteToken(usageRecord.completion_tokens ?? usageRecord.output_tokens)
    : 0;
  const reasoningTokens = usageRecord
    ? finiteToken(usageRecord.reasoning_tokens) ||
      nestedToken(usageRecord, "completion_tokens_details", "reasoning_tokens") ||
      nestedToken(usageRecord, "output_tokens_details", "reasoning_tokens")
    : 0;
  const outputTokens = Math.max(0, completionTotal - reasoningTokens);
  const cachedTokens = usageRecord
    ? Math.min(
        inputTokens,
        finiteToken(usageRecord.cached_tokens) ||
          nestedToken(usageRecord, "prompt_tokens_details", "cached_tokens") ||
          nestedToken(usageRecord, "input_tokens_details", "cached_tokens")
      )
    : 0;
  const hasUsage = Boolean(usageRecord) && inputTokens + completionTotal > 0;
  const disposition = hasUsage ? "final" : "pendingReconciliation";
  const quality = hasUsage ? "providerReported" : "unknown";
  const routeTraceReference = `askway-route-${input.requestId}`;
  const now = new Date().toISOString();
  const billableTokens = inputTokens + outputTokens + reasoningTokens;
  const costMicrounits =
    typeof input.costUsd === "number" && Number.isFinite(input.costUsd) && input.costUsd >= 0
      ? BigInt(Math.ceil(input.costUsd * 1_000_000)).toString()
      : null;

  const persist = db.transaction(() => {
    const existing = db
      .prepare("SELECT usage_disposition FROM askway_request_usage WHERE request_id = ?")
      .get(input.requestId) as { usage_disposition: string } | undefined;
    db.prepare(
      `INSERT INTO askway_request_usage (
         request_id, entitlement_key_id, api_key_id, input_tokens, output_tokens,
         cached_tokens, reasoning_tokens, delivered_output_tokens, usage_quality,
         usage_disposition, provider, model, latency_ms, fallback_count,
         route_trace_reference, cost_microunits, cost_currency, cost_quality,
         observed_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'USD', ?, ?, ?)
       ON CONFLICT(request_id) DO UPDATE SET
         input_tokens = excluded.input_tokens,
         output_tokens = excluded.output_tokens,
         cached_tokens = excluded.cached_tokens,
         reasoning_tokens = excluded.reasoning_tokens,
         delivered_output_tokens = excluded.delivered_output_tokens,
         usage_quality = excluded.usage_quality,
         usage_disposition = excluded.usage_disposition,
         provider = excluded.provider,
         model = excluded.model,
         latency_ms = excluded.latency_ms,
         fallback_count = excluded.fallback_count,
         route_trace_reference = excluded.route_trace_reference,
         cost_microunits = excluded.cost_microunits,
         cost_currency = excluded.cost_currency,
         cost_quality = excluded.cost_quality,
         updated_at = excluded.updated_at`
    ).run(
      input.requestId,
      entitlement.id,
      input.apiKeyId,
      inputTokens,
      outputTokens,
      cachedTokens,
      reasoningTokens,
      input.deliveredOutputTokens ?? null,
      quality,
      disposition,
      input.provider ?? null,
      input.model ?? null,
      input.latencyMilliseconds ?? null,
      input.fallbackCount ?? 0,
      routeTraceReference,
      costMicrounits,
      costMicrounits === null ? "unknown" : "estimated",
      now,
      now
    );
    db.prepare(
      `INSERT INTO askway_route_traces
       (reference, request_id, attempts_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(reference) DO UPDATE SET attempts_json = excluded.attempts_json,
       updated_at = excluded.updated_at`
    ).run(
      routeTraceReference,
      input.requestId,
      JSON.stringify([
        {
          sequence: 1,
          provider: input.provider ?? null,
          model: input.model ?? null,
          status: hasUsage ? "completed" : "usagePending",
          latencyMilliseconds: input.latencyMilliseconds ?? null,
        },
      ]),
      now,
      now
    );
    if (hasUsage && existing?.usage_disposition !== "final" && billableTokens > 0) {
      db.prepare(
        `UPDATE askway_entitlement_keys
         SET observed_tokens = observed_tokens + ?, updated_at = ? WHERE id = ?`
      ).run(billableTokens, now, entitlement.id);
    }
  });
  persist();
}

export class AskwayIdempotencyConflictError extends Error {}
export class AskwayEntitlementConflictError extends Error {}
export class AskwayPolicyVersionConflictError extends Error {}
export class AskwayRevokedCredentialError extends Error {}
