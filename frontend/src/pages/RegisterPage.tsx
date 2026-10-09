import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { toApiError, type ApiError } from "../api/client";

export function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [form, setForm] = useState({
    company_name: "",
    domain: "",
    full_name: "",
    email: "",
    password: "",
  });
  const [error, setError] = useState<ApiError | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const update = (key: keyof typeof form) => (e: { target: { value: string } }) =>
    setForm((prev) => ({ ...prev, [key]: e.target.value }));

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await register(form);
      navigate("/", { replace: true });
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
        <h2>Provision your organization</h2>
        {error && <div className="form-error">{error.message}</div>}
        <form onSubmit={onSubmit} noValidate>
          <div className="field">
            <label htmlFor="company_name">Company name</label>
            <input id="company_name" value={form.company_name} onChange={update("company_name")} required />
          </div>
          <div className="field">
            <label htmlFor="domain">Domain</label>
            <input id="domain" placeholder="acme.com" value={form.domain} onChange={update("domain")} required />
          </div>
          <div className="field">
            <label htmlFor="full_name">Your full name</label>
            <input id="full_name" value={form.full_name} onChange={update("full_name")} required />
          </div>
          <div className="field">
            <label htmlFor="email">Work email</label>
            <input id="email" type="email" value={form.email} onChange={update("email")} required />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="new-password"
              value={form.password}
              onChange={update("password")}
              required
            />
            <span className="muted" style={{ fontSize: 12 }}>Minimum 8 characters.</span>
          </div>
          <button className="btn primary" type="submit" disabled={submitting} style={{ width: "100%" }}>
            {submitting ? "Creating…" : "Create organization"}
          </button>
        </form>
        <div className="alt-action">
          Already registered? <Link to="/login">Sign in</Link>
        </div>
      </div>
    </div>
  );
}
