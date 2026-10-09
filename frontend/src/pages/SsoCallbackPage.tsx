import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { toApiError } from "../api/client";

export function SsoCallbackPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { loginWithSso } = useAuth();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = params.get("code");
    const state = params.get("state");
    const err = params.get("error");
    if (err) {
      setError(`Single sign-on failed: ${err}`);
      return;
    }
    if (!code || !state) {
      setError("Single sign-on callback is missing the authorization code.");
      return;
    }
    let cancelled = false;
    loginWithSso(code, state)
      .then(() => {
        if (!cancelled) navigate("/overview", { replace: true });
      })
      .catch((e) => {
        if (!cancelled) setError(toApiError(e).message);
      });
    return () => {
      cancelled = true;
    };
  }, [params, loginWithSso, navigate]);

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="brand">
          <img src="/shield.svg" alt="SentinelX" className="logo" />
          <span>SentinelX</span>
        </div>
        <h2>Completing sign-in…</h2>
        {error ? (
          <div className="form-error">{error}</div>
        ) : (
          <p className="muted">Verifying your identity with the SSO provider.</p>
        )}
      </div>
    </div>
  );
}
