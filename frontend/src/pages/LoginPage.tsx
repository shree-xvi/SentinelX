import { useEffect, useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { api, toApiError, type ApiError } from "../api/client";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [ssoUrl, setSsoUrl] = useState<string | null>(null);

  useEffect(() => {
    api
      .ssoConfig()
      .then((cfg) => {
        if (cfg.enabled && cfg.authorization_url) setSsoUrl(cfg.authorization_url);
      })
      .catch(() => {
        // SSO unavailable — password login still works.
      });
  }, []);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      navigate(from, { replace: true });
    } catch (err) {
      setError(toApiError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="brand">
          <img src="/shield.svg" alt="SentinelX" className="logo" />
          <span>SentinelX</span>
        </div>
        <h2>Sign in to your security console</h2>
        {error && <div className="form-error">{error.message}</div>}
        <form onSubmit={onSubmit} noValidate>
          <div className="field">
            <label htmlFor="email">Work email</label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <button className="btn primary" type="submit" disabled={submitting} style={{ width: "100%" }}>
            {submitting ? "Signing in…" : "Sign in"}
          </button>
          {ssoUrl && (
            <a className="btn" href={ssoUrl} style={{ width: "100%", marginTop: 8 }}>
              Continue with SSO
            </a>
          )}
        </form>
        <div className="alt-action">
          New organization? <Link to="/register">Create an account</Link>
        </div>
      </div>
    </div>
  );
}
