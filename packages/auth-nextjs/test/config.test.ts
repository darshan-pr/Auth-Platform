import test from "node:test";
import assert from "node:assert/strict";
import { cookieNames, resolveConfig } from "../src/config.ts";

test("server config requires the backend URL and publishable key", () => {
  assert.throws(() => resolveConfig({}), /AUTH_PLATFORM_BACKEND_URL is required/);
  assert.throws(() => resolveConfig({ backendUrl: "https://auth.internal" }), /AUTH_PLATFORM_PUBLISHABLE_KEY is required/);
  assert.equal(resolveConfig({ backendUrl: "https://auth.internal/", publishableKey: "pk_test" }).backendUrl, "https://auth.internal");
});

test("production auth cookies use the __Host- prefix", () => {
  assert.deepEqual(cookieNames(true), { access: "__Host-authplatform_sdk_access", refresh: "__Host-authplatform_sdk_refresh" });
  assert.deepEqual(cookieNames(false), { access: "authplatform_sdk_access", refresh: "authplatform_sdk_refresh" });
});
