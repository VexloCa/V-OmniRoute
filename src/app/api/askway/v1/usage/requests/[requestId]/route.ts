import { NextResponse } from "next/server";
import { readAskwayUsageByRequest } from "@/lib/db/askwayEntitlements";
import { requireAskwayManagement, usageJson } from "../../../_contract";

export async function GET(request: Request, context: { params: Promise<{ requestId: string }> }) {
  const authError = await requireAskwayManagement(request);
  if (authError) return authError;
  const { requestId } = await context.params;
  const observation = readAskwayUsageByRequest(requestId);
  return observation
    ? NextResponse.json(usageJson(observation))
    : NextResponse.json(
        { error: { code: "not_found", message: "Usage observation was not found" } },
        { status: 404 }
      );
}
