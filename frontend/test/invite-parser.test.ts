import test from "node:test";
import assert from "node:assert/strict";
import { chunk, isValidEmail, parseInvitees, stageInvitees } from "../lib/invite-parser.ts";

test("parses one address per line", () => {
  assert.deepEqual(parseInvitees("a@x.com\nb@y.org\n\n  c@z.io  "), [
    { email: "a@x.com", name: "" },
    { email: "b@y.org", name: "" },
    { email: "c@z.io", name: "" },
  ]);
});

test("parses comma, semicolon and space separated lists", () => {
  const rows = parseInvitees("a@x.com, b@y.org; c@z.io d@w.dev");
  assert.deepEqual(rows.map((row) => row.email), ["a@x.com", "b@y.org", "c@z.io", "d@w.dev"]);
});

test("parses Name <email> and name,email lines", () => {
  assert.deepEqual(parseInvitees('Ada Lovelace <ada@x.com>\n"Grace Hopper", grace@y.org\nlin@z.io,Lin Q'), [
    { email: "ada@x.com", name: "Ada Lovelace" },
    { email: "grace@y.org", name: "Grace Hopper" },
    { email: "lin@z.io", name: "Lin Q" },
  ]);
});

test("uses a CSV header row to find the columns", () => {
  const csv = "id,Full Name,Email\n1,Ada,ada@x.com\n2,Grace,grace@y.org\r\n";
  assert.deepEqual(parseInvitees(csv), [
    { email: "ada@x.com", name: "Ada" },
    { email: "grace@y.org", name: "Grace" },
  ]);
});

test("strips a byte order mark and keeps unreadable rows for review", () => {
  const rows = parseInvitees("\uFEFFemail\nnot an email\nok@x.com");
  assert.deepEqual(rows, [
    { email: "not an email", name: "" },
    { email: "ok@x.com", name: "" },
  ]);
});

test("flags invalid and duplicate addresses case-insensitively", () => {
  const staged = stageInvitees(parseInvitees("a@x.com\nA@X.com\nbroken\nb@y.org"));
  assert.deepEqual(staged.map((row) => row.error), [undefined, "duplicate", "invalid", undefined]);
  const next = stageInvitees(parseInvitees("b@y.org\nc@z.io"), staged);
  assert.deepEqual(next.map((row) => row.error), ["duplicate", undefined]);
});

test("rejects header injection and oversized addresses", () => {
  assert.equal(isValidEmail("a@x.com"), true);
  assert.equal(isValidEmail("a@x.com\r\nBcc: z@z.com"), false);
  assert.equal(isValidEmail("a b@x.com"), false);
  assert.equal(isValidEmail(`${"a".repeat(320)}@x.com`), false);
});

test("splits work into chunks", () => {
  assert.deepEqual(chunk([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
  assert.deepEqual(chunk([], 3), []);
});
