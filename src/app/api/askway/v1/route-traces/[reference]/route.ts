import { NextResponse } from "next/server";
import { readAskwayRouteTrace } from "@/lib/db/askwayEntitlements";
import { requireAskwayManagement } from "../../_contract";

export async function GET(request: Request, context: { params: Promise<{ reference: string }> }) {
  const authError = await requireAskwayManagement(request);
  if (authError) return authError;
  const { reference } = await context.params;
  const trace = readAskwayRouteTrace(reference);
  return trace
    ? NextResponse.json(trace)
    : NextResponse.json(
        { error: { code: "not_found", message: "Route trace was not found" } },
        { status: 404 }
      );
}
