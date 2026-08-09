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
    const body = policyUpdateSchema.parse(await request.json());
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
