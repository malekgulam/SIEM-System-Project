// ── Page Detection ─────────────────────────────────────
const onDashboard = typeof alertData !== "undefined";
const onMetrics   = typeof metricsData !== "undefined";
const onCoverage  = typeof tacticsData !== "undefined";

// ── Dashboard Charts ───────────────────────────────────
if (onDashboard) {

    const severityCounts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    alertData.forEach(a => {
        if (severityCounts[a.severity] !== undefined)
            severityCounts[a.severity]++;
    });

    new Chart(document.getElementById("severityChart"), {
        type: "doughnut",
        data: {
            labels: ["HIGH", "MEDIUM", "LOW"],
            datasets: [{
                data: [severityCounts.HIGH, severityCounts.MEDIUM, severityCounts.LOW],
                backgroundColor: ["#ff4444", "#ff8800", "#ffcc00"]
            }]
        },
        options: {
            plugins: {
                title: { display: true, text: "Alerts by Severity", color: "#fff" },
                legend: { labels: { color: "#fff" } }
            }
        }
    });

    const ipLabels = topIps.map(pair => pair[0]);
    const ipValues = topIps.map(pair => pair[1]);

    new Chart(document.getElementById("ipChart"), {
        type: "bar",
        data: {
            labels: ipLabels,
            datasets: [{
                label: "Alerts",
                data: ipValues,
                backgroundColor: "#7eb3ff"
            }]
        },
        options: {
            plugins: {
                title: { display: true, text: "Top Attacking IPs", color: "#fff" },
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: "#fff" } },
                y: { ticks: { color: "#fff" }, beginAtZero: true }
            }
        }
    });

    const tacticCounts = {};
    alertData.forEach(a => {
        if (a.tactic)
            tacticCounts[a.tactic] = (tacticCounts[a.tactic] || 0) + 1;
    });

    new Chart(document.getElementById("tacticChart"), {
        type: "bar",
        data: {
            labels: Object.keys(tacticCounts),
            datasets: [{
                label: "Alerts",
                data: Object.values(tacticCounts),
                backgroundColor: ["#7eb3ff", "#ff8800", "#ff4444", "#cc00ff"]
            }]
        },
        options: {
            plugins: {
                title: { display: true, text: "Alerts by Tactic", color: "#fff" },
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: "#fff" } },
                y: { ticks: { color: "#fff" }, beginAtZero: true }
            }
        }
    });

    // ── Dashboard Filters ──────────────────────────────
    const rows = document.querySelectorAll(".alert-row");

    function filterTable() {
        const query    = document.getElementById("searchIP").value.toLowerCase();
        const severity = document.getElementById("filterSeverity").value;
        const status   = document.getElementById("filterStatus").value;
        const tactic   = document.getElementById("filterTactic").value;

        rows.forEach(row => {
            const matchQuery = query === ""
                || row.dataset.ip.toLowerCase().includes(query)
                || row.dataset.rule.toLowerCase().includes(query)
                || row.dataset.technique.toLowerCase().includes(query);

            const matchSev    = severity === "" || row.dataset.severity === severity;
            const matchStatus = status   === "" || row.dataset.status   === status;
            const matchTactic = tactic   === "" || row.dataset.tactic   === tactic;

            row.style.display = (matchQuery && matchSev && matchStatus && matchTactic) ? "" : "none";
        });
    }

    document.getElementById("searchIP").addEventListener("input", filterTable);
    document.getElementById("filterSeverity").addEventListener("change", filterTable);
    document.getElementById("filterStatus").addEventListener("change", filterTable);
    document.getElementById("filterTactic").addEventListener("change", filterTable);
}

// ── Metrics Charts ─────────────────────────────────────
if (onMetrics) {

    const ruleLabels  = metricsData.map(r => r.rule_id);
    const ruleTotals  = metricsData.map(r => r.total);
    const ruleHigh    = metricsData.map(r => r.high_count);

    new Chart(document.getElementById("ruleChart"), {
        type: "bar",
        data: {
            labels: ruleLabels,
            datasets: [
                {
                    label: "Total Fired",
                    data: ruleTotals,
                    backgroundColor: "#7eb3ff"
                },
                {
                    label: "HIGH",
                    data: ruleHigh,
                    backgroundColor: "#ff4444"
                }
            ]
        },
        options: {
            plugins: {
                title: { display: true, text: "Alerts Fired per Rule", color: "#fff" },
                legend: { labels: { color: "#fff" } }
            },
            scales: {
                x: { ticks: { color: "#fff" } },
                y: { ticks: { color: "#fff" }, beginAtZero: true }
            }
        }
    });

    const newCounts    = metricsData.reduce((s, r) => s + r.new_count, 0);
    const closedCounts = metricsData.reduce((s, r) => s + r.closed_count, 0);
    const totalCounts  = metricsData.reduce((s, r) => s + r.total, 0);
    const otherCounts  = totalCounts - newCounts - closedCounts;

    new Chart(document.getElementById("statusChart"), {
        type: "doughnut",
        data: {
            labels: ["NEW", "CLOSED", "OTHER"],
            datasets: [{
                data: [newCounts, closedCounts, otherCounts],
                backgroundColor: ["#1a6ef5", "#555", "#ff8800"]
            }]
        },
        options: {
            plugins: {
                title: { display: true, text: "Alert Status Breakdown", color: "#fff" },
                legend: { labels: { color: "#fff" } }
            }
        }
    });
}

// ── Coverage Chart ─────────────────────────────────────
if (onCoverage) {

    const tacticLabels = Object.keys(tacticsData);
    const tacticTotals = tacticLabels.map(t =>
        tacticsData[t].reduce((s, r) => s + r.total, 0)
    );

    new Chart(document.getElementById("coverageChart"), {
        type: "bar",
        data: {
            labels: tacticLabels,
            datasets: [{
                label: "Alerts Fired",
                data: tacticTotals,
                backgroundColor: ["#7eb3ff", "#ff8800", "#ff4444", "#cc00ff"]
            }]
        },
        options: {
            plugins: {
                title: { display: true, text: "Alert Volume by Tactic", color: "#fff" },
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: "#fff" } },
                y: { ticks: { color: "#fff" }, beginAtZero: true }
            }
        }
    });
}