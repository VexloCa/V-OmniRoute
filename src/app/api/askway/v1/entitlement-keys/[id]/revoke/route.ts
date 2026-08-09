import { NextResponse } from "next/server";
import { revokeAskwayEntitlementCredential } from "@/lib/db/askwayEntitlements";
import { contractError, idempotencyKey, requireAskwayManagement } from "../../../_contract";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  const authError = await requireAskwayManagement(request);
  if (authError) return authError;
  const commandKey = idempotencyKey(request);
  if (!commandKey) {
    return NextResponse.json(
      { error: { code: "idempotency_key_required", message: "Idempotency-Key is required" } },
      { status: 400 }
    );
  }
  try {
    const { id } = await context.params;
    return (await revokeAskwayEntitlementCredential(id, commandKey))
      ? new Response(null, { status: 204 })
      : NextResponse.json(
          { error: { code: "not_found", message: "Entitlement key was not found" } },
          { status: 404 }
        );
  } catch (error) {
    return contractError(error);
  }
}
