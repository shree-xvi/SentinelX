"use strict";

const API_ALERTS = "/api/alerts";
const API_STATUS = "/api/status";
const API_INVESTIGATION = "/api/investigation";

let allAlerts = [];
let selectedAlertId = null;

let severityChart = null;
let ruleChart = null;

let refreshInProgress = false;

const $ = (id) => document.getElementById(id);


function getSeverity(alert) {
    const value = String(
        alert.severity ??
        alert.level ??
        alert.priority ??
        "LOW"
    ).toUpperCase();

    if (
        value.includes("CRITICAL") ||
        value.includes("HIGH")
    ) {
        return "High";
    }

    if (
        value.includes("MEDIUM") ||
        value.includes("MODERATE")
    ) {
        return "Medium";
    }

    return "Low";
}


function getRule(alert) {
    return String(
        alert.rule_name ??
        alert.rule ??
        alert.detection_rule ??
        alert.type ??
        alert.alert_type ??
        alert.name ??
        "Unknown rule"
    );
}


function getTimestamp(alert) {
    return String(
        alert.detected_at ??
        alert.timestamp ??
        alert.time ??
        alert.created_at ??
        alert.datetime ??
        "Unknown time"
    );
}


function getSourceIp(alert) {
    return String(
        alert.source_ip ??
        alert.src_ip ??
        alert.ip_address ??
        alert.ip ??
        alert.src ??
        alert.remote_ip ??
        "Unknown IP"
    );
}


function getInvestigation(item) {
    return item.investigation ?? {
        status: "New",
        notes: "",
        updated_at: null,
        history: []
    };
}


function getRisk(item) {
    const risk = item.risk ?? {};

    let score = Number(risk.score);

    if (!Number.isFinite(score)) {
        score = 0;
    }

    score = Math.max(
        0,
        Math.min(
            100,
            Math.round(score)
        )
    );

    let level = String(
        risk.level ?? "LOW"
    ).toUpperCase();

    if (
        level !== "LOW" &&
        level !== "MEDIUM" &&
        level !== "HIGH" &&
        level !== "CRITICAL"
    ) {
        level = "LOW";
    }

    return {
        score,
        level
    };
}


function normaliseStatus(status) {
    const value = String(
        status ?? "New"
    ).toLowerCase();

    if (value === "resolved") {
        return "Resolved";
    }

    if (value === "investigating") {
        return "Investigating";
    }

    return "New";
}


function showMessage(
    element,
    message,
    type = ""
) {
    if (!element) {
        return;
    }

    element.textContent = message;

    element.className = type
        ? `message ${type}`
        : "message";
}


async function fetchJson(
    url,
    options = {}
) {
    const response = await fetch(
        url,
        {
            cache: "no-store",
            ...options
        }
    );

    if (!response.ok) {
        let detail = "";

        try {
            const body =
                await response.json();

            detail =
                body.error ??
                body.message ??
                "";
        } catch {
            // No JSON error body.
        }

        throw new Error(
            detail ||
            `Request failed (${response.status})`
        );
    }

    return response.json();
}


function formatDate(value) {
    if (
        !value ||
        value === "Unknown time"
    ) {
        return value || "Not available";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString();
}


function updateMonitorStatus(data) {
    const status = String(
        data.status ?? "UNKNOWN"
    ).toUpperCase();

    $("monitorStatus").textContent =
        status;

    $("monitorMessage").textContent =
        data.message ??
        "No monitoring status available.";

    for (const id of [
        "monitorCard",
        "monitorTag"
    ]) {
        const element = $(id);

        if (!element) {
            continue;
        }

        element.classList.remove(
            "running",
            "stopped",
            "unknown"
        );

        const style =
            status === "RUNNING"
                ? "running"
                : status === "STOPPED"
                    ? "stopped"
                    : "unknown";

        element.classList.add(style);
    }

    $("monitorTag").textContent =
        status === "RUNNING"
            ? "CHECKING"
            : status;

    if (data.updated_at) {
        $("monitorMessage").textContent +=
            ` Last update: ${formatDate(
                data.updated_at
            )}.`;
    }
}


function updateCharts(counts) {
    const severityCanvas =
        $("severityChart");

    const ruleCanvas =
        $("ruleChart");

    const severityFallback =
        $("severityChartFallback");

    const ruleFallback =
        $("ruleChartFallback");

    if (
        !severityCanvas ||
        !ruleCanvas ||
        !severityFallback ||
        !ruleFallback
    ) {
        return;
    }

    if (typeof Chart === "undefined") {
        severityCanvas.hidden = true;
        ruleCanvas.hidden = true;

        severityFallback.hidden = false;
        ruleFallback.hidden = false;

        severityFallback.textContent =
            `High: ${counts.High} · ` +
            `Medium: ${counts.Medium} · ` +
            `Low: ${counts.Low}`;

        ruleFallback.textContent =
            "Charts are unavailable. " +
            "Check your internet connection for Chart.js.";

        return;
    }

    severityCanvas.hidden = false;
    ruleCanvas.hidden = false;

    severityFallback.hidden = true;
    ruleFallback.hidden = true;

    const severityData = {
        labels: [
            "High",
            "Medium",
            "Low"
        ],

        datasets: [{
            data: [
                counts.High,
                counts.Medium,
                counts.Low
            ],

            backgroundColor: [
                "#fb7185",
                "#fbbf24",
                "#34d399"
            ],

            borderWidth: 0
        }]
    };

    if (!severityChart) {
        severityChart = new Chart(
            severityCanvas,
            {
                type: "doughnut",

                data: severityData,

                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: "68%",

                    plugins: {
                        legend: {
                            position: "bottom",

                            labels: {
                                color: "#cbd5e1",
                                padding: 18
                            }
                        }
                    }
                }
            }
        );
    } else {
        severityChart.data =
            severityData;

        severityChart.update();
    }

    const ruleCounts = {};

    for (const item of allAlerts) {
        const rule =
            getRule(item.data ?? {});

        ruleCounts[rule] =
            (ruleCounts[rule] ?? 0) + 1;
    }

    const sortedRules =
        Object.entries(ruleCounts)
            .sort(
                (a, b) => b[1] - a[1]
            )
            .slice(0, 8);

    const ruleData = {
        labels: sortedRules.map(
            ([name]) => name
        ),

        datasets: [{
            label: "Alerts",

            data: sortedRules.map(
                ([, count]) => count
            ),

            backgroundColor: "#818cf8",
            borderRadius: 5
        }]
    };

    if (!ruleChart) {
        ruleChart = new Chart(
            ruleCanvas,
            {
                type: "bar",

                data: ruleData,

                options: {
                    indexAxis: "y",

                    responsive: true,
                    maintainAspectRatio: false,

                    scales: {
                        x: {
                            beginAtZero: true,

                            ticks: {
                                color: "#94a3b8",
                                precision: 0
                            },

                            grid: {
                                color: "#263449"
                            }
                        },

                        y: {
                            ticks: {
                                color: "#cbd5e1"
                            },

                            grid: {
                                display: false
                            }
                        }
                    },

                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            }
        );
    } else {
        ruleChart.data =
            ruleData;

        ruleChart.update();
    }
}


function updateOverview() {
    const counts = {
        High: 0,
        Medium: 0,
        Low: 0
    };

    let open = 0;
    let resolved = 0;

    let criticalRisks = 0;
    let totalRiskScore = 0;

    for (const item of allAlerts) {
        const alert =
            item.data ?? {};

        const severity =
            getSeverity(alert);

        const status =
            normaliseStatus(
                getInvestigation(item).status
            );

        const risk =
            getRisk(item);

        counts[severity]++;

        totalRiskScore += risk.score;

        if (risk.level === "CRITICAL") {
            criticalRisks++;
        }

        if (status === "Resolved") {
            resolved++;
        } else {
            open++;
        }
    }

    const averageRisk =
        allAlerts.length > 0
            ? Math.round(
                totalRiskScore /
                allAlerts.length
            )
            : 0;

    $("totalCount").textContent =
        allAlerts.length;

    $("highCount").textContent =
        counts.High;

    $("mediumCount").textContent =
        counts.Medium;

    $("lowCount").textContent =
        counts.Low;

    $("openCount").textContent =
        open;

    $("resolvedCount").textContent =
        resolved;

    $("criticalCount").textContent =
        criticalRisks;

    $("averageRiskCount").textContent =
        `${averageRisk} / 100`;

    updateCharts(counts);
}


function makeCell(
    value,
    className = ""
) {
    const cell =
        document.createElement("td");

    cell.textContent =
        String(value ?? "");

    if (className) {
        cell.className =
            className;
    }

    return cell;
}


function ensureRiskTableHeaders() {
    const tbody = $("alertRows");

    if (!tbody) {
        return;
    }

    const table =
        tbody.closest("table");

    if (!table) {
        return;
    }

    const headerRow =
        table.querySelector("thead tr");

    if (!headerRow) {
        return;
    }

    headerRow.replaceChildren();

    const headers = [
        "Severity",
        "Risk Score",
        "Risk Level",
        "Detection Rule",
        "Source IP",
        "Timestamp",
        "Investigation"
    ];

    for (const header of headers) {
        const cell =
            document.createElement("th");

        cell.textContent = header;

        headerRow.appendChild(cell);
    }
}


function renderAlerts() {
    const tbody =
        $("alertRows");

    if (!tbody) {
        return;
    }

    ensureRiskTableHeaders();

    const query =
        $("searchInput")
            .value
            .trim()
            .toLowerCase();

    const severityFilter =
        $("severityFilter")
            .value
            .toLowerCase();

    const statusFilter =
        $("statusFilter")
            .value
            .toLowerCase();

    tbody.replaceChildren();

    const filtered =
        allAlerts.filter((item) => {
            const alert =
                item.data ?? {};

            const investigation =
                getInvestigation(item);

            const risk =
                getRisk(item);

            const severity =
                getSeverity(alert)
                    .toLowerCase();

            const status =
                normaliseStatus(
                    investigation.status
                ).toLowerCase();

            if (
                severityFilter !== "all" &&
                severity !== severityFilter
            ) {
                return false;
            }

            if (
                statusFilter !== "all" &&
                status !== statusFilter
            ) {
                return false;
            }

            if (query) {
                const searchable = [
                    JSON.stringify(alert),
                    JSON.stringify(risk),
                    investigation.notes ?? "",
                    investigation.status ?? ""
                ]
                    .join(" ")
                    .toLowerCase();

                if (
                    !searchable.includes(query)
                ) {
                    return false;
                }
            }

            return true;
        });

    $("resultCount").textContent =
        `${filtered.length} of ` +
        `${allAlerts.length} alerts`;

    if (filtered.length === 0) {
        const row =
            document.createElement("tr");

        const cell =
            document.createElement("td");

        cell.colSpan = 7;

        cell.className =
            "empty-state";

        cell.textContent =
            allAlerts.length
                ? "No alerts match the selected filters."
                : "No alerts recorded yet. " +
                  "Start monitoring to collect events.";

        row.appendChild(cell);
        tbody.appendChild(row);

        return;
    }

    for (const item of filtered) {
        const alert =
            item.data ?? {};

        const investigation =
            getInvestigation(item);

        const severity =
            getSeverity(alert);

        const risk =
            getRisk(item);

        const status =
            normaliseStatus(
                investigation.status
            );

        const row =
            document.createElement("tr");

        row.tabIndex = 0;

        row.setAttribute(
            "role",
            "button"
        );

        row.setAttribute(
            "aria-label",
            `Investigate ${getRule(alert)}`
        );

        // Severity
        const severityCell =
            makeCell("");

        const severityBadge =
            document.createElement("span");

        severityBadge.className =
            `severity-badge ${severity.toLowerCase()}`;

        severityBadge.textContent =
            severity;

        severityCell.appendChild(
            severityBadge
        );

        row.appendChild(
            severityCell
        );

        // Risk Score
        const riskScoreCell =
            makeCell("");

        const riskScoreBadge =
            document.createElement("span");

        riskScoreBadge.className =
            "risk-score-badge";

        riskScoreBadge.textContent =
            `${risk.score} / 100`;

        riskScoreCell.appendChild(
            riskScoreBadge
        );

        row.appendChild(
            riskScoreCell
        );

        // Risk Level
        const riskLevelCell =
            makeCell("");

        const riskLevelBadge =
            document.createElement("span");

        riskLevelBadge.className =
            `risk-badge ${risk.level.toLowerCase()}`;

        riskLevelBadge.textContent =
            risk.level;

        riskLevelCell.appendChild(
            riskLevelBadge
        );

        row.appendChild(
            riskLevelCell
        );

        // Detection Rule
        row.appendChild(
            makeCell(
                getRule(alert)
            )
        );

        // Source IP
        row.appendChild(
            makeCell(
                getSourceIp(alert)
            )
        );

        // Timestamp
        row.appendChild(
            makeCell(
                formatDate(
                    getTimestamp(alert)
                )
            )
        );

        // Investigation
        const statusCell =
            makeCell("");

        const statusBadge =
            document.createElement("span");

        statusBadge.className =
            `status-badge ${status.toLowerCase()}`;

        statusBadge.textContent =
            status;

        statusCell.appendChild(
            statusBadge
        );

        row.appendChild(
            statusCell
        );

        row.addEventListener(
            "click",
            () => openAlert(item)
        );

        row.addEventListener(
            "keydown",
            (event) => {
                if (
                    event.key === "Enter" ||
                    event.key === " "
                ) {
                    event.preventDefault();

                    openAlert(item);
                }
            }
        );

        tbody.appendChild(row);
    }
}


function addDetail(
    container,
    label,
    value
) {
    const wrapper =
        document.createElement("div");

    wrapper.className =
        "detail";

    const heading =
        document.createElement("div");

    heading.className =
        "detail-label";

    heading.textContent =
        label;

    const content =
        document.createElement("div");

    content.className =
        "detail-value";

    content.textContent =
        String(
            value ??
            "Not available"
        );

    wrapper.append(
        heading,
        content
    );

    container.appendChild(
        wrapper
    );
}


/*
 * Render the investigation history
 * returned by the Python backend.
 */
function renderInvestigationHistory(
    investigation
) {
    const container =
        $("investigationHistory");

    if (!container) {
        return;
    }

    container.replaceChildren();

    const history =
        Array.isArray(
            investigation.history
        )
            ? investigation.history
            : [];

    if (history.length === 0) {
        const empty =
            document.createElement("p");

        empty.className =
            "muted";

        empty.textContent =
            "No investigation history yet.";

        container.appendChild(
            empty
        );

        return;
    }

    /*
     * Display newest events first.
     */
    const orderedHistory =
        [...history].reverse();

    for (
        const event
        of orderedHistory
    ) {
        const entry =
            document.createElement("article");

        entry.className =
            "history-entry";

        const marker =
            document.createElement("div");

        marker.className =
            "history-marker";

        const content =
            document.createElement("div");

        content.className =
            "history-content";

        const header =
            document.createElement("div");

        header.className =
            "history-header";

        const action =
            document.createElement("strong");

        action.textContent =
            event.action ??
            "Investigation updated";

        const timestamp =
            document.createElement("time");

        timestamp.textContent =
            formatDate(
                event.timestamp
            );

        header.append(
            action,
            timestamp
        );

        const transition =
            document.createElement("div");

        transition.className =
            "history-transition";

        const previousStatus =
            event.previous_status ??
            "New";

        const newStatus =
            event.status ??
            "New";

        const previous =
            document.createElement("span");

        previous.className =
            `history-status ${String(
                previousStatus
            ).toLowerCase()}`;

        previous.textContent =
            previousStatus;

        const arrow =
            document.createElement("span");

        arrow.className =
            "history-arrow";

        arrow.textContent =
            "→";

        const current =
            document.createElement("span");

        current.className =
            `history-status ${String(
                newStatus
            ).toLowerCase()}`;

        current.textContent =
            newStatus;

        transition.append(
            previous,
            arrow,
            current
        );

        content.append(
            header,
            transition
        );

        if (
            typeof event.notes === "string" &&
            event.notes.trim()
        ) {
            const notes =
                document.createElement("p");

            notes.className =
                "history-notes";

            notes.textContent =
                event.notes;

            content.appendChild(
                notes
            );
        }

        entry.append(
            marker,
            content
        );

        container.appendChild(
            entry
        );
    }
}


function openAlert(item) {
    selectedAlertId =
        item.id;

    const alert =
        item.data ?? {};

    const risk =
        getRisk(item);

    const investigation =
        getInvestigation(item);

    $("modalTitle").textContent =
        getRule(alert);

    const summary =
        $("alertSummary");

    summary.replaceChildren();

    addDetail(
        summary,
        "Severity",
        getSeverity(alert)
    );

    addDetail(
        summary,
        "Risk Score",
        `${risk.score} / 100`
    );

    addDetail(
        summary,
        "Risk Level",
        risk.level
    );

    addDetail(
        summary,
        "Detection rule",
        getRule(alert)
    );

    addDetail(
        summary,
        "Source IP",
        getSourceIp(alert)
    );

    addDetail(
        summary,
        "Timestamp",
        formatDate(
            getTimestamp(alert)
        )
    );

    addDetail(
        summary,
        "Investigation status",
        normaliseStatus(
            investigation.status
        )
    );

    addDetail(
        summary,
        "Last investigation update",
        investigation.updated_at
            ? formatDate(
                investigation.updated_at
            )
            : "Not updated"
    );

    $("evidence").textContent =
        JSON.stringify(
            {
                alert,
                risk
            },
            null,
            2
        );

    renderInvestigationHistory(
        investigation
    );

    $("investigationStatus").value =
        normaliseStatus(
            investigation.status
        );

    $("investigationNotes").value =
        investigation.notes ?? "";

    updateNotesCount();

    showMessage(
        $("modalMessage"),
        ""
    );

    $("modalBackdrop").hidden =
        false;

    $("closeModal").focus();
}


function closeAlertModal() {
    $("modalBackdrop").hidden =
        true;

    selectedAlertId =
        null;
}


function updateNotesCount() {
    $("notesCount").textContent =
        `${$("investigationNotes").value.length} / 5000`;
}


async function refreshAlerts() {
    if (refreshInProgress) {
        return;
    }

    refreshInProgress = true;

    try {
        const payload =
            await fetchJson(
                API_ALERTS
            );

        allAlerts =
            Array.isArray(
                payload.alerts
            )
                ? payload.alerts
                : [];

        updateOverview();
        renderAlerts();

        if (
            selectedAlertId &&
            !$("modalBackdrop").hidden
        ) {
            const item =
                allAlerts.find(
                    (entry) =>
                        entry.id ===
                        selectedAlertId
                );

            if (item) {
                const notes =
                    $("investigationNotes")
                        .value;

                const status =
                    $("investigationStatus")
                        .value;

                openAlert(item);

                /*
                 * Keep unsaved edits intact
                 * during automatic refresh.
                 */
                $("investigationNotes")
                    .value = notes;

                $("investigationStatus")
                    .value = status;

                updateNotesCount();

            } else {
                closeAlertModal();
            }
        }

        showMessage(
            $("pageMessage"),
            ""
        );

    } catch (error) {
        showMessage(
            $("pageMessage"),
            `Could not load alerts: ${error.message}`,
            "error"
        );

    } finally {
        refreshInProgress =
            false;
    }
}


async function refreshStatus() {
    try {
        const data =
            await fetchJson(
                API_STATUS
            );

        updateMonitorStatus(
            data
        );

    } catch (error) {
        updateMonitorStatus({
            status: "UNKNOWN",
            message:
                `Could not load monitoring status: ${error.message}`
        });
    }
}


async function saveInvestigation() {
    if (!selectedAlertId) {
        showMessage(
            $("modalMessage"),
            "Select an alert first.",
            "error"
        );

        return;
    }

    const saveButton =
        $("saveInvestigation");

    saveButton.disabled =
        true;

    showMessage(
        $("modalMessage"),
        "Saving investigation..."
    );

    try {
        await fetchJson(
            API_INVESTIGATION,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    id:
                        selectedAlertId,

                    status:
                        $("investigationStatus")
                            .value,

                    notes:
                        $("investigationNotes")
                            .value
                })
            }
        );

        await refreshAlerts();

        showMessage(
            $("modalMessage"),
            "Investigation saved successfully.",
            "success"
        );

    } catch (error) {
        showMessage(
            $("modalMessage"),
            `Could not save investigation: ${error.message}`,
            "error"
        );

    } finally {
        saveButton.disabled =
            false;
    }
}


function resetFilters() {
    $("searchInput").value =
        "";

    $("severityFilter").value =
        "all";

    $("statusFilter").value =
        "all";

    renderAlerts();
}


function initialiseDashboard() {
    $("refreshButton")
        .addEventListener(
            "click",
            async () => {
                await Promise.all([
                    refreshAlerts(),
                    refreshStatus()
                ]);
            }
        );

    $("searchInput")
        .addEventListener(
            "input",
            renderAlerts
        );

    $("severityFilter")
        .addEventListener(
            "change",
            renderAlerts
        );

    $("statusFilter")
        .addEventListener(
            "change",
            renderAlerts
        );

    $("resetFilters")
        .addEventListener(
            "click",
            resetFilters
        );

    $("closeModal")
        .addEventListener(
            "click",
            closeAlertModal
        );

    $("saveInvestigation")
        .addEventListener(
            "click",
            saveInvestigation
        );

    $("markInvestigating")
        .addEventListener(
            "click",
            () => {
                $("investigationStatus")
                    .value =
                    "Investigating";

                $("investigationStatus")
                    .focus();
            }
        );

    $("markResolved")
        .addEventListener(
            "click",
            () => {
                $("investigationStatus")
                    .value =
                    "Resolved";

                $("investigationStatus")
                    .focus();
            }
        );

    $("investigationNotes")
        .addEventListener(
            "input",
            updateNotesCount
        );

    $("modalBackdrop")
        .addEventListener(
            "click",
            (event) => {
                if (
                    event.target ===
                    $("modalBackdrop")
                ) {
                    closeAlertModal();
                }
            }
        );

    document.addEventListener(
        "keydown",
        (event) => {
            if (
                event.key === "Escape" &&
                !$("modalBackdrop").hidden
            ) {
                closeAlertModal();
            }
        }
    );

    refreshAlerts();
    refreshStatus();

    window.setInterval(
        refreshAlerts,
        5000
    );

    window.setInterval(
        refreshStatus,
        3000
    );
}


document.addEventListener(
    "DOMContentLoaded",
    initialiseDashboard
);