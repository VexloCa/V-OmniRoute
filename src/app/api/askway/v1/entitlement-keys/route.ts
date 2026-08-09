import { NextResponse } from "next/server";
import { provisionAskwayEntitlementCredential } from "@/lib/db/askwayEntitlements";
import {
  contractError,
  idempotencyKey,
  parsePolicy,
  provisionSchema,
  requireAskwayManagement,
} from "../_contract";

export async function POST(request: Request) {
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
    const body = provisionSchema.parse(await request.json());
    return NextResponse.json(
      provisionAskwayEntitlementCredential({
        externalEntitlementId: body.externalEntitlementId,
        displayName: body.displayName,
        idempotencyKey: commandKey,
        policy: parsePolicy(body.policy),
      }),
      { status: 201 }
    );
  } catch (error) {
    return contractError(error);
  }
}
