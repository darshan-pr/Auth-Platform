import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AuthProvider, SignIn, SignUp, VerifyEmail } from "../dist/esm/index.js";

test("sign-up renders labelled fields and no token-bearing client fields", () => {
  const html = renderToStaticMarkup(React.createElement(AuthProvider, null, React.createElement(SignUp)));
  assert.match(html, /<label for="[^"]+">Full name<\/label>/);
  assert.match(html, /<label for="[^"]+">Email address<\/label>/);
  assert.match(html, /<label for="[^"]+">Password<\/label>/);
  assert.match(html, /Create account/);
  assert.match(html, /class="auth-card/);
  assert.doesNotMatch(html, /auth-page|auth-page-footer/);
  assert.doesNotMatch(html, /accessToken|refreshToken|localStorage|sessionStorage/);
});

test("sign-in offers password recovery without exposing a session token", () => {
  const html = renderToStaticMarkup(React.createElement(AuthProvider, null, React.createElement(SignIn)));
  assert.match(html, /Sign in/);
  assert.match(html, /Forgot password\?/);
  assert.match(html, /auth-brand-mark/);
  assert.doesNotMatch(html, /auth-page|auth-page-footer/);
  assert.doesNotMatch(html, /accessToken|refreshToken|localStorage|sessionStorage/);
});

test("configured application branding replaces the platform brand on auth cards", () => {
  const html = renderToStaticMarkup(
    React.createElement(
      AuthProvider,
      { applicationName: "Example App", applicationIconUrl: "/example.svg" },
      React.createElement(SignIn)
    )
  );
  assert.match(html, /aria-label="Example App"/);
  assert.match(html, /class="auth-brand-icon" src="\/example\.svg" alt=""/);
  assert.match(html, /class="auth-switch auth-switch-end"/);
  assert.match(html, />Example App<\/span>/);
  assert.doesNotMatch(html, />auth<span class="auth-brand-accent">platform<\/span>/);
});

test("auth styles provide a block without imposing page positioning", () => {
  const styles = readFileSync(new URL("../dist/styles.css", import.meta.url), "utf8");
  assert.match(styles, /width: min\(430px, 100%\)/);
  assert.doesNotMatch(styles, /\.auth-page|min-height:\s*100vh/);
});

test("email verification renders as a standalone auth block", () => {
  const html = renderToStaticMarkup(
    React.createElement(AuthProvider, null, React.createElement(VerifyEmail, { token: "verification-token" }))
  );
  assert.match(html, /Verify your email/);
  assert.match(html, /class="auth-card/);
  assert.doesNotMatch(html, /auth-page|accessToken|refreshToken/);
});
