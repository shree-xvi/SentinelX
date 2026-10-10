import { useCallback, useEffect, useState } from "react";
import { api, toApiError } from "../api/client";
import type { Employee } from "../api/types";
import { isAdminRole, useAuth } from "../auth/AuthContext";
import { Badge, EmptyState, ErrorText, Loading, Stat } from "../components/ui";
import { timeAgo } from "../utils/format";

export function EmployeesPage() {
  const { role } = useAuth();
  const canManage = isAdminRole(role);

  const [employees, setEmployees] = useState<Employee[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [minRisk, setMinRisk] = useState("");
  const [baseline, setBaseline] = useState<Record<string, unknown> | null>(null);
  const [baselineName, setBaselineName] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);

  // Create form
  const [showCreate, setShowCreate] = useState(false);
  const [employeeId, setEmployeeId] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [department, setDepartment] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .listEmployees({
        search: search || undefined,
        min_risk: minRisk ? Number(minRisk) : undefined,
        limit: 200,
      })
      .then((data) => setEmployees(data))
      .catch((err) => setError(toApiError(err).message))
      .finally(() => setLoading(false));
  }, [search, minRisk]);

  useEffect(() => {
    const handle = setTimeout(load, search ? 300 : 0);
    return () => clearTimeout(handle);
  }, [load, search]);

  const viewBaseline = async (emp: Employee) => {
    setActionError(null);
    try {
      const data = await api.getEmployeeBaseline(emp.id);
      setBaseline(data.baseline);
      setBaselineName(data.name);
    } catch (err) {
      setActionError(toApiError(err).message);
      setBaseline(null);
    }
  };

  const createEmployee = async () => {
    setActionError(null);
    try {
      await api.createEmployee({
        employee_id: employeeId,
        name,
        email: email || undefined,
        department: department || undefined,
      });
      setShowCreate(false);
      setEmployeeId("");
      setName("");
      setEmail("");
      setDepartment("");
      load();
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const highRiskCount = employees.filter(
    (e) => e.risk_level === "CRITICAL" || e.risk_level === "HIGH"
  ).length;


  return (
    <>
      <div className="topbar">
        <div>
          <h1>Employees &amp; Risk</h1>
          <div className="subtitle">Monitor workforce behavioral risk profiles</div>
        </div>
        {canManage && (
          <button className="btn primary" onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? "Cancel" : "Add employee"}
          </button>
        )}
      </div>

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <Stat label="Monitored" value={employees.length} />
        <Stat label="High / Critical" value={highRiskCount} tone="critical" />
        <Stat
          label="Avg Score"
          value={
            employees.length
              ? (employees.reduce((s, e) => s + e.risk_score, 0) / employees.length).toFixed(1)
              : "0.0"
          }
        />
      </div>

      {showCreate && canManage && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h3>Add employee to roster</h3>
          <div className="grid cols-2">
            <div className="field">
              <label htmlFor="emp-id">Employee ID</label>
              <input id="emp-id" value={employeeId} onChange={(e) => setEmployeeId(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="emp-name">Name</label>
              <input id="emp-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="emp-email">Email</label>
              <input id="emp-email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="emp-dept">Department</label>
              <input id="emp-dept" value={department} onChange={(e) => setDepartment(e.target.value)} />
            </div>
          </div>
          {actionError && <ErrorText>{actionError}</ErrorText>}
          <button
            className="btn primary"
            onClick={createEmployee}
            disabled={!employeeId.trim() || !name.trim()}
          >
            Create employee
          </button>
        </div>
      )}

      <div className="toolbar">
        <input
          className="grow"
          placeholder="Search by name, ID, or email…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search employees"
        />
        <select
          value={minRisk}
          onChange={(e) => setMinRisk(e.target.value)}
          aria-label="Minimum risk"
          style={{ width: 160 }}
        >
          <option value="">Any risk</option>
          <option value="30">30+</option>
          <option value="60">60+</option>
          <option value="80">80+</option>
        </select>
      </div>

      {error && <ErrorText>{error}</ErrorText>}
      {actionError && !showCreate && <ErrorText>{actionError}</ErrorText>}

      <div className="grid cols-2">
        <div className="card">
          {loading ? (
            <Loading />
          ) : employees.length === 0 ? (
            <EmptyState message="No employees match the filters." />
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Employee</th>
                  <th>Department</th>
                  <th>Risk</th>
                  <th>Score</th>
                  <th>Last Active</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {employees.map((emp) => (
                  <tr key={emp.id}>
                    <td>
                      {emp.name}
                      <div className="muted" style={{ fontSize: 12 }}>
                        {emp.employee_id}
                      </div>
                    </td>
                    <td className="muted">{emp.department}</td>
                    <td>
                      <Badge value={emp.risk_level} />
                    </td>
                    <td>{emp.risk_score.toFixed(1)}</td>
                    <td className="muted">{timeAgo(emp.last_activity)}</td>
                    <td>
                      <button className="btn small" onClick={() => viewBaseline(emp)}>
                        Baseline
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <h3>{baseline ? `${baselineName} — behavioral baseline` : "Behavioral baseline"}</h3>
          {baseline ? (
            <pre className="evidence">{JSON.stringify(baseline, null, 2)}</pre>
          ) : (
            <EmptyState message="Select an employee and click Baseline to inspect their UEBA profile." />
          )}
        </div>
      </div>
    </>
  );
}
