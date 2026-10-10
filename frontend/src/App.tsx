import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { AppLayout } from "./components/AppLayout";
import { RequireAuth } from "./components/RequireAuth";
import { Loading } from "./components/ui";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { DashboardPage } from "./pages/DashboardPage";
import { AlertsPage } from "./pages/AlertsPage";
import { CasesPage } from "./pages/CasesPage";
import { EmployeesPage } from "./pages/EmployeesPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { IntegrationsPage } from "./pages/IntegrationsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { SsoCallbackPage } from "./pages/SsoCallbackPage";

function HomeRedirect() {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return <Loading label="Loading…" />;
  return <Navigate to={isAuthenticated ? "/overview" : "/login"} replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/auth/callback" element={<SsoCallbackPage />} />
          <Route
            element={
              <RequireAuth>
                <AppLayout />
              </RequireAuth>
            }
          >
            <Route path="/overview" element={<DashboardPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/employees" element={<EmployeesPage />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/integrations" element={<IntegrationsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
          </Route>
          <Route path="*" element={<HomeRedirect />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
