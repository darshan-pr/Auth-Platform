"use client";

import Link from "next/link";
import { useState } from "react";
import { useAuth, useUser } from "@authplatform/auth-react";

export default function PermissionsPage() {
  const { isLoaded, isSignedIn, user } = useUser();
  const { refresh } = useAuth();
  const [permissionKey, setPermissionKey] = useState("projects:read");
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState("");
  const [actionMessage, setActionMessage] = useState("");
  const permissions = user?.permissions ?? [];
  const checkedPermission = permissionKey.trim();
  const isAllowed = Boolean(checkedPermission && permissions.includes(checkedPermission));

  async function refreshPermissions() {
    setRefreshing(true);
    setRefreshError("");
    setActionMessage("");
    try {
      await refresh();
    } catch (error) {
      setRefreshError(error instanceof Error ? error.message : "Unable to refresh permissions.");
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <main className="test-shell">
      <h1>Permission checks</h1>
      <p>Inspect the permissions returned for the signed-in app user and test a permission-gated control.</p>
      <nav aria-label="Test app navigation">
        <Link href="/">Home</Link>
        <Link href="/protected">Protected page</Link>
        <Link href="/server-user">Server current user</Link>
      </nav>

      {!isLoaded ? (
        <p role="status">Loading session…</p>
      ) : !isSignedIn || !user ? (
        <section className="permission-card">
          <p>You must be signed in to inspect this user’s permissions.</p>
          <Link href="/sign-in">Sign in</Link>
        </section>
      ) : (
        <>
          <section aria-labelledby="granted-permissions-heading" className="permission-card">
            <div className="permission-card-heading">
              <div>
                <h2 id="granted-permissions-heading">Granted permissions</h2>
                <p>Server-computed permissions for {user.email}.</p>
              </div>
              <button disabled={refreshing} onClick={refreshPermissions} type="button">
                {refreshing ? "Refreshing…" : "Refresh permissions"}
              </button>
            </div>
            {refreshError && <p className="permission-error" role="alert">{refreshError}</p>}
            {permissions.length > 0 ? (
              <ul className="permission-list">
                {permissions.map((permission) => (
                  <li key={permission}>
                    <button
                      className="permission-chip"
                      onClick={() => {
                        setPermissionKey(permission);
                        setActionMessage("");
                      }}
                      type="button"
                    >
                      <code>{permission}</code>
                      <span>Check</span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="permission-empty">
                No permissions are currently granted. Create a permission, assign it to one of this
                user’s roles, then refresh here.
              </p>
            )}
          </section>

          <section aria-labelledby="permission-test-heading" className="permission-card">
            <h2 id="permission-test-heading">Test a permission</h2>
            <p>Enter the exact permission key configured for this app.</p>
            <label className="permission-field">
              <span>Permission key</span>
              <input
                autoComplete="off"
                onChange={(event) => {
                  setPermissionKey(event.target.value);
                  setActionMessage("");
                }}
                placeholder="e.g. projects:read"
                value={permissionKey}
              />
            </label>

            {!checkedPermission ? (
              <p className="permission-state" role="status">Enter a permission key to check it.</p>
            ) : isAllowed ? (
              <div className="permission-state permission-state-allowed" role="status">
                <strong>Granted:</strong> {checkedPermission}
              </div>
            ) : (
              <div className="permission-state permission-state-denied" role="status">
                <strong>Not granted:</strong> {checkedPermission}
              </div>
            )}

            {checkedPermission && isAllowed && (
              <button
                className="permission-action"
                onClick={() => setActionMessage(`Allowed by ${checkedPermission}.`)}
                type="button"
              >
                Run permission-gated demo action
              </button>
            )}
            {checkedPermission && !isAllowed && (
              <p className="permission-hidden" role="status">
                The demo action button is hidden because this user does not have that permission.
              </p>
            )}
            {actionMessage && <p className="permission-success" role="status">{actionMessage}</p>}
          </section>

          <p className="permission-note">
            This page demonstrates UI visibility only. Always enforce permissions on the backend
            for real protected actions.
          </p>
        </>
      )}
    </main>
  );
}
