import { SignIn } from "@phosphor-icons/react";
import { type FormEvent, useEffect, useState } from "react";
import { api, type Me, Unauthorized } from "./api";
import { BrandLockup } from "./brand";
import { Dashboard } from "./Dashboard";

function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.login(username, password);
      onLogin();
    } catch (err) {
      setError(
        err instanceof Unauthorized
          ? "That username and password did not match. Check both and try again."
          : "Sign-in could not be completed. The API may be unreachable.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="login">
      <form onSubmit={submit} className="login-card">
        <BrandLockup />
        <h1>Sign in</h1>
        <p>Passive OT threat detection - offline simulation.</p>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        {error && <p className="error">{error}</p>}
        <button type="submit" className="btn btn-accent" disabled={busy}>
          <SignIn size={16} weight="bold" />
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="login-note">
          Aegis observes only. It never probes the monitored network, decrypts payloads, or sends anything back.
        </p>
      </form>
    </main>
  );
}

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [checked, setChecked] = useState(false);

  const refresh = () =>
    api
      .me()
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setChecked(true));

  useEffect(() => {
    void refresh();
  }, []);

  if (!checked) return <p className="muted pad">Loading…</p>;
  if (!me) return <Login onLogin={() => void refresh()} />;
  return (
    <Dashboard
      me={me}
      onLogout={() => {
        void api.logout().finally(() => setMe(null));
      }}
    />
  );
}
