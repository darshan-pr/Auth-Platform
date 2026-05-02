import { createAuthProxy } from "auth-platform-sdk/server";
import type { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const proxy = createAuthProxy();
type Ctx = { params: Promise<{ path?: string[] }> };

async function handler(req: NextRequest, ctx: Ctx): Promise<Response> {
  return proxy(req, ctx);
}

export const GET = handler;
export const POST = handler;
