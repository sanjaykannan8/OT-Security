import { type FormEvent, useEffect, useState } from "react";
import { api, type Me, Unauthorized } from "./api";
import { Dashboard } from "./Dashboard";

function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    try {
      await api.login(username, password);
      onLogin();
    } catch (err) {
      setError(err instanceof Unauthorized ? "Invalid username or password." : "Login failed.");
    }
  };

  return (
    <main className="login">
      <form onSubmit={submit} className="card">
        <h1>SIH SOC</h1>
        <p className="muted">Passive OT threat detection (offline simulation)</p>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </label>
        {error && <p className="error">{error}</p>}
        <button type="submit">Sign in</button>
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
