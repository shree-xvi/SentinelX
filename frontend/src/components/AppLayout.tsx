import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

const NAV_ITEMS = [
  { to: "/overview", label: "Overview", end: true },
  { to: "/alerts", label: "Alerts" },
  { to: "/cases", label: "Cases" },
  { to: "/employees", label: "Employees" },
  { to: "/policies", label: "Policies" },
  { to: "/integrations", label: "Integrations" },
  { to: "/reports", label: "Reports" },
];

export function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img src="/shield.svg" alt="SentinelX" className="logo" />
          <span>SentinelX</span>
        </div>
        <nav>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="spacer" />
        <div className="muted" style={{ fontSize: 12, padding: "8px 12px" }}>
          {user?.email ?? "—"}
        </div>
        <button className="btn small" onClick={handleLogout}>
          Sign out
        </button>
      </aside>

      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
