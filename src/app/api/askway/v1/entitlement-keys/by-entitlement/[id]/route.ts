import { NextResponse } from "next/server";
import { inspectAskwayEntitlementByExternalId } from "@/lib/db/askwayEntitlements";
import { inspectionJson, requireAskwayManagement } from "../../../_contract";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const authError = await requireAskwayManagement(request);
  if (authError) return authError;
  const { id } = await context.params;
  const inspection = inspectAskwayEntitlementByExternalId(id);
  return inspection
    ? NextResponse.json(inspectionJson(inspection))
    : NextResponse.json(
        { error: { code: "not_found", message: "Entitlement key was not found" } },
        { status: 404 }
      );
}
