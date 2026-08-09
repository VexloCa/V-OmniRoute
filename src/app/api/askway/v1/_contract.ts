import { NextResponse } from "next/server";
import { z } from "zod";
import { requireManagementAuth } from "@/lib/api/requireManagementAuth";
import type {
  AskwayEntitlementInspection,
  AskwayEntitlementPolicy,
  AskwayUsageObservation,
} from "@/lib/db/askwayEntitlements";
import {
  AskwayEntitlementConflictError,
  AskwayIdempotencyConflictError,
  AskwayPolicyVersionConflictError,
  AskwayRevokedCredentialError,
} from "@/lib/db/askwayEntitlements";

const policySchema = z.object({
  tokenLimit: z.string().regex(/^[1-9]\d*$/),
  allowedModels: z.array(z.string().trim().min(1)).min(1),
  allowedCombos: z.array(z.string().trim().min(1)),
  allowedConnections: z.array(z.string().trim().min(1)).min(1),
  allowedEndpoints: z.array(z.string().trim().min(1)).min(1),
  requestsPerMinute: z.number().int().positive().optional(),
});

export const provisionSchema = z.object({
  externalEntitlementId: z.string().trim().min(1).max(200),
  displayName: z.string().trim().min(1).max(200),
  policy: policySchema,
});

export const policyUpdateSchema = z.object({
  policy: policySchema,
  expectedVersion: z.number().int().positive(),
});

export function parsePolicy(input: z.infer<typeof policySchema>): AskwayEntitlementPolicy {
  return { ...input, tokenLimit: BigInt(input.tokenLimit) };
}

export async function requireAskwayManagement(request: Request): Promise<Response | null> {
  return requireManagementAuth(request, { alwaysRequireAuth: true, invalidApiKeyStatus: 401 });
}

export function idempotencyKey(request: Request): string | null {
  const value = request.headers.get("idempotency-key")?.trim();
  return value || null;
}

export function inspectionJson(inspection: AskwayEntitlementInspection): unknown {
  return {
    ...inspection,
    policy: { ...inspection.policy, tokenLimit: inspection.policy.tokenLimit.toString() },
  };
}

export function usageJson(observation: AskwayUsageObservation): unknown {
  return {
    ...observation,
    ...(observation.cost
      ? {
          cost: {
            ...observation.cost,
            amountMicrounits: observation.cost.amountMicrounits.toString(),
          },
        }
      : {}),
    observedAt: observation.observedAt.toISOString(),
  };
}

export function contractError(error: unknown): NextResponse {
  if (error instanceof AskwayIdempotencyConflictError) {
    return NextResponse.json(
      { error: { code: "idempotency_conflict", message: "This command was already completed" } },
      { status: 409 }
    );
  }
  if (error instanceof AskwayEntitlementConflictError) {
    return NextResponse.json(
      { error: { code: "entitlement_conflict", message: "Entitlement key already exists" } },
      { status: 409 }
    );
  }
  if (error instanceof AskwayPolicyVersionConflictError) {
    return NextResponse.json(
      { error: { code: "policy_version_conflict", message: "Policy version is stale" } },
      { status: 409 }
    );
  }
  if (error instanceof AskwayRevokedCredentialError) {
    return NextResponse.json(
      { error: { code: "credential_revoked", message: "Credential is revoked" } },
      { status: 409 }
    );
  }
  if (error instanceof SyntaxError || error instanceof z.ZodError) {
    return NextResponse.json(
      { error: { code: "invalid_contract", message: "Request body is invalid" } },
      { status: 400 }
    );
  }
  return NextResponse.json(
    { error: { code: "management_operation_failed", message: "Management operation failed" } },
    { status: 500 }
  );
}
