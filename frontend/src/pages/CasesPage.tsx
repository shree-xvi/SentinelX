import { useCallback, useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { api, toApiError } from "../api/client";
import type { Case, CaseStatus, Priority } from "../api/types";
import { Badge, EmptyState, ErrorText, Loading } from "../components/ui";
import { formatDateTime } from "../utils/format";

const CASE_STATUSES: CaseStatus[] = ["New", "Investigating", "Escalated", "Resolved", "Closed"];
const PRIORITIES: Priority[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export function CasesPage() {
  const location = useLocation();
  const prefill = (location.state as { fromAlert?: string; title?: string } | null) ?? {};

  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Case | null>(null);
  const [noteText, setNoteText] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(Boolean(prefill.fromAlert));
  const [newTitle, setNewTitle] = useState(prefill.title ?? "");
  const [newDescription, setNewDescription] = useState("");
  const [newPriority, setNewPriority] = useState<Priority>("MEDIUM");

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .listCases({ limit: 100 })
      .then((data) => setCases(data))
      .catch((err) => setError(toApiError(err).message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const reloadCase = async (caseId: string) => {
    const fresh = await api.getCase(caseId);
    setSelected(fresh);
    setCases((prev) => prev.map((c) => (c.id === fresh.id ? fresh : c)));
  };

  const createCase = async () => {
    setActionError(null);
    try {
      const created = await api.createCase({
        title: newTitle,
        description: newDescription || undefined,
        priority: newPriority,
        alert_id: prefill.fromAlert ?? undefined,
      });
      setShowCreate(false);
      setNewTitle("");
      setNewDescription("");
      await reloadCase(created.id);
      load();
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const updateStatus = async (c: Case, status: CaseStatus) => {
    setActionError(null);
    try {
      await api.updateCase(c.id, { status });
      await reloadCase(c.id);
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  const addNote = async () => {
    if (!selected || !noteText.trim()) return;
    setActionError(null);
    try {
      await api.addCaseNote(selected.id, noteText.trim());
      setNoteText("");
      await reloadCase(selected.id);
    } catch (err) {
      setActionError(toApiError(err).message);
    }
  };

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Investigation Cases</h1>
          <div className="subtitle">Collaborate on escalated incidents</div>
        </div>
        <button className="btn primary" onClick={() => setShowCreate((v) => !v)}>
          {showCreate ? "Cancel" : "New case"}
        </button>
      </div>

      {showCreate && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h3>Open a new case</h3>
          <div className="field">
            <label htmlFor="case-title">Title</label>
            <input id="case-title" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="case-desc">Description</label>
            <input
              id="case-desc"
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="case-priority">Priority</label>
            <select
              id="case-priority"
              value={newPriority}
              onChange={(e) => setNewPriority(e.target.value as Priority)}
              style={{ width: 160 }}
            >
              {PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
          {actionError && <ErrorText>{actionError}</ErrorText>}
          <button className="btn primary" onClick={createCase} disabled={!newTitle.trim()}>
            Create case
          </button>
        </div>
      )}

      {error && <ErrorText>{error}</ErrorText>}
      {loading ? (
        <Loading />
      ) : cases.length === 0 ? (
        <EmptyState message="No investigation cases yet." />
      ) : (
        <div className="grid cols-2">
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Priority</th>
                  <th>Status</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <tr key={c.id} className="clickable" onClick={() => reloadCase(c.id)}>
                    <td>{c.title}</td>
                    <td>
                      <Badge value={c.priority} />
                    </td>
                    <td>
                      <Badge value={c.status} variant="status" />
                    </td>
                    <td className="muted">{formatDateTime(c.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <CaseDetail
            caseItem={selected}
            noteText={noteText}
            actionError={actionError}
            onNoteChange={setNoteText}
            onAddNote={addNote}
            onUpdateStatus={updateStatus}
          />
        </div>
      )}
    </>
  );

function CaseDetail({
  caseItem,
  noteText,
  actionError,
  onNoteChange,
  onAddNote,
  onUpdateStatus,
}: {
  caseItem: Case | null;
  noteText: string;
  actionError: string | null;
  onNoteChange: (value: string) => void;
  onAddNote: () => void;
  onUpdateStatus: (c: Case, status: CaseStatus) => void;
}) {
  if (!caseItem) {
    return (
      <div className="card">
        <EmptyState message="Select a case to view the audit trail." />
      </div>
    );
  }
  return (
    <div className="card">
      <div className="row-between" style={{ marginBottom: 8 }}>
        <h3 style={{ margin: 0 }}>{caseItem.title}</h3>
        <Badge value={caseItem.priority} />
      </div>
      {caseItem.description && <p className="muted">{caseItem.description}</p>}

      <div className="btn-row" style={{ margin: "10px 0 14px" }}>
        {CASE_STATUSES.map((s) => (
          <button
            key={s}
            className={`btn small${caseItem.status === s ? " primary" : ""}`}
            disabled={caseItem.status === s}
            onClick={() => onUpdateStatus(caseItem, s)}
          >
            {s}
          </button>
        ))}
      </div>

      {actionError && <ErrorText>{actionError}</ErrorText>}

      <h4 className="muted" style={{ margin: "0 0 8px" }}>
        Audit trail ({caseItem.notes.length})
      </h4>
      <div style={{ maxHeight: 260, overflow: "auto", marginBottom: 12 }}>
        {caseItem.notes.length === 0 ? (
          <EmptyState message="No notes yet." />
        ) : (
          caseItem.notes.map((n) => (
            <div key={n.id} style={{ borderBottom: "1px solid var(--border)", padding: "8px 0" }}>
              <div className="row-between">
                <span className="badge status">{n.action_type}</span>
                <span className="muted" style={{ fontSize: 12 }}>
                  {formatDateTime(n.created_at)}
                </span>
              </div>
              <div style={{ marginTop: 4 }}>{n.note}</div>
            </div>
          ))
        )}
      </div>

      <div className="field">
        <label htmlFor="new-note">Add a note</label>
        <textarea
          id="new-note"
          rows={3}
          value={noteText}
          onChange={(e) => onNoteChange(e.target.value)}
          placeholder="Record your findings…"
        />
      </div>
      <button className="btn primary" onClick={onAddNote} disabled={!noteText.trim()}>
        Add note
      </button>
    </div>
  );
}

}
