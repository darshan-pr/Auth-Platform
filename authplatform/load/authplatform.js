import http from "k6/http";
import { check } from "k6";

export const options = {
  scenarios: {
    login: { executor: "constant-arrival-rate", rate: Number(__ENV.LOGIN_RATE || 1), timeUnit: "1s", duration: __ENV.DURATION || "30s", preAllocatedVUs: 5, maxVUs: 20 },
  },
  thresholds: { http_req_failed: ["rate<0.01"], http_req_duration: ["p(95)<500"] },
};

const base = __ENV.BASE_URL || "http://127.0.0.1:8080";
const appKey = __ENV.APP_KEY || "";
const email = __ENV.TEST_EMAIL || "";
const password = __ENV.TEST_PASSWORD || "";
const consoleAccessToken = __ENV.CONSOLE_ACCESS_TOKEN || "";

export default function () {
  const login = http.post(`${base}/api/v1/auth/login`, JSON.stringify({ email, password }), {
    headers: { "Content-Type": "application/json", "X-authplatform-Key": appKey },
    tags: { operation: "login" },
  });
  check(login, { "login returns an auth response": (response) => response.status === 200 || response.status === 202 });
  if (login.status !== 200) return;
  const accessToken = login.json("accessToken");
  const me = http.get(`${base}/api/v1/users/me`, {
    headers: { Authorization: `Bearer ${accessToken}`, "X-authplatform-Key": appKey },
    tags: { operation: "token-verification" },
  });
  check(me, { "token verification succeeds": (response) => response.status === 200 });
  if (consoleAccessToken) {
    const apps = http.get(`${base}/api/console/apps?page=0&size=20`, {
      headers: { Authorization: `Bearer ${consoleAccessToken}` },
      tags: { operation: "list-apps" },
    });
    check(apps, { "application list succeeds": (response) => response.status === 200 });
  }
}
