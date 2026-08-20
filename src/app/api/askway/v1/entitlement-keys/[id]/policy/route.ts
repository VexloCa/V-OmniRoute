import { NextResponse } from "next/server";
import { configureAskwayEntitlementCredential } from "@/lib/db/askwayEntitlements";
import {
  contractError,
  inspectionJson,
  parsePolicy,
  policyUpdateSchema,
  requireAskwayManagement,
} from "../../../_contract";

export async function PUT(request: Request, context: { params: Promise<{ id: string }> }) {
  const authError = await requireAskwayManagement(request);
  if (authError) return authError;
  try {
    const { id } = await context.params;
    const parsed = policyUpdateSchema.safeParse(await request.json());
    if (!parsed.success) {
      return contractError(parsed.error);
    }
    const body = parsed.data;
    const inspection = await configureAskwayEntitlementCredential(
      id,
      parsePolicy(body.policy),
      body.expectedVersion
    );
    return inspection
      ? NextResponse.json(inspectionJson(inspection))
      : NextResponse.json(
          { error: { code: "not_found", message: "Entitlement key was not found" } },
          { status: 404 }
        );
  } catch (error) {
    return contractError(error);
  }
}
