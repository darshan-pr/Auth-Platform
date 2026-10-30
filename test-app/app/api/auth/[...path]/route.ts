import { createAuthHandlers } from "@authplatform/auth-nextjs";

const handlers = createAuthHandlers();

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PUT = handlers.PUT;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
