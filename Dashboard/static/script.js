// ── Page Detection ─────────────────────────────────────
const onDashboard = typeof alertData !== "undefined";
const onMetrics   = typeof metricsData !== "undefined";
const onCoverage  = typeof tacticsData !== "undefined";

// ── Chart Defaults ─────────────────────────────────────
const chartDefaults = {
    color: "#8b8d91",
    font: { family: "'JetBrains Mono', monospace", size: 11 },
    grid: { color: "#2c2f36", drawBorder: false },
    ticks: { color: "#8b8d91", font: { family: "'JetBrains Mono', monospace", size: 10 } }
};

function baseBarOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: true,
        indexAxis: "y",
        plugins: {
            legend: { display: false },
            title: {
                display: true,
                text: title,
                color: "#8b8d91",
                font: { family: "'Inter', sans-serif", size: 11, weight: "500" },
                padding: { bottom: 10 }
            }
        },
        scales: {
            x: {
                grid: chartDefaults.grid,
                ticks: chartDefaults.ticks,
                border: { color: "#2c2f36" }
            },
            y: {
                grid: { display: false },
                ticks: { ...chartDefaults.ticks, color: "#d8d9db" },
                border: { display: false }
            }
        }
    };
}

function baseDoughnutOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: true,
        cutout: "65%",
        plugins: {
            legend: {
                display: true,
                position: "bottom",
                labels: {
                    color: "#8b8d91",
                    font: { family: "'Inter', sans-serif", size: 10 },
                    padding: 10,
                    boxWidth: 10
                }
            },
            title: {
                display: true,
                text: title,
                color: "#8b8d91",
                font: { family: "'Inter', sans-serif", size: 11, weight: "500" },
                padding: { bottom: 10 }
            }
        }
    };
}

// ── Dashboard ──────────────────────────────────────────
if (onDashboard) {

    // Severity horizontal bar
    const severityCounts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    alertData.forEach(a => {
        if (severityCounts[a.severity] !== undefined)
            severityCounts[a.severity]++;
    });

    new Chart(document.getElementById("severityChart"), {
        type: "bar",
        data: {
            labels: ["HIGH", "MEDIUM", "LOW"],
            datasets: [{
                data: [severityCounts.HIGH, severityCounts.MEDIUM, severityCounts.LOW],
                backgroundColor: ["#c4162a", "#f5a623", "#3da562"],
                borderRadius: 1,
                barThickness: 14
            }]
        },
        options: baseBarOptions("Alerts by Severity")
    });

    // Top IPs horizontal bar
    const ipLabels = topIps.map(p => p[0]);
    const ipValues = topIps.map(p => p[1]);

    new Chart(document.getElementById("ipChart"), {
        type: "bar",
        data: {
            labels: ipLabels,
            datasets: [{
                data: ipValues,
                backgroundColor: "#e8742a",
                borderRadius: 1,
                barThickness: 14
            }]
        },
        options: baseBarOptions("Top Source IPs")
    });

    // Tactic horizontal bar
    const tacticLabels = Object.keys(tacticCounts);
    const tacticValues = Object.values(tacticCounts);

    new Chart(document.getElementById("tacticChart"), {
        type: "bar",
        data: {
            labels: tacticLabels,
            datasets: [{
                data: tacticValues,
                backgroundColor: "#5794f2",
                borderRadius: 1,
                barThickness: 14
            }]
        },
        options: baseBarOptions("Alerts by Tactic")
    });

    // ── Table Filters ──────────────────────────────────
    const rows = document.querySelectorAll(".alert-row");

    function filterTable() {
        const query    = document.getElementById("searchInput").value.toLowerCase();
        const severity = document.getElementById("filterSeverity").value;
        const status   = document.getElementById("filterStatus").value;
        const tactic   = document.getElementById("filterTactic").value;

        rows.forEach(row => {
            const matchQuery =
                query === "" ||
                (row.dataset.ip    && row.dataset.ip.toLowerCase().includes(query))    ||
                (row.dataset.rule  && row.dataset.rule.toLowerCase().includes(query))  ||
                (row.dataset.tech  && row.dataset.tech.toLowerCase().includes(query));

            const matchSev    = severity === "" || row.dataset.severity === severity;
            const matchStatus = status   === "" || row.dataset.status   === status;
            const matchTactic = tactic   === "" || row.dataset.tactic   === tactic;

            row.style.display = (matchQuery && matchSev && matchStatus && matchTactic)
                ? "" : "none";
        });
    }

    document.getElementById("searchInput").addEventListener("input", filterTable);
    document.getElementById("filterSeverity").addEventListener("change", filterTable);
    document.getElementById("filterStatus").addEventListener("change", filterTable);
    document.getElementById("filterTactic").addEventListener("change", filterTable);
}

// ── Metrics ────────────────────────────────────────────
if (onMetrics) {

    const ruleLabels = metricsData.map(r => r.rule_id);
    const totals     = metricsData.map(r => r.total);
    const tpCounts   = metricsData.map(r => r.tp_count);
    const fpCounts   = metricsData.map(r => r.fp_count);

    new Chart(document.getElementById("ruleFireChart"), {
        type: "bar",
        data: {
            labels: ruleLabels,
            datasets: [
                {
                    label: "Total",
                    data: totals,
                    backgroundColor: "#5794f2",
                    borderRadius: 1,
                    barThickness: 12
                },
                {
                    label: "True Positive",
                    data: tpCounts,
                    backgroundColor: "#3da562",
                    borderRadius: 1,
                    barThickness: 12
                },
                {
                    label: "False Positive",
                    data: fpCounts,
                    backgroundColor: "#c4162a",
                    borderRadius: 1,
                    barThickness: 12
                }
            ]
        },
        options: {
            ...baseBarOptions("Rule Performance"),
            indexAxis: "y",
            plugins: {
                ...baseBarOptions("Rule Performance").plugins,
                legend: {
                    display: true,
                    position: "bottom",
                    labels: {
                        color: "#8b8d91",
                        font: { family: "'Inter', sans-serif", size: 10 },
                        padding: 10,
                        boxWidth: 10
                    }
                }
            }
        }
    });

    const newCount    = metricsData.reduce((s, r) => s + r.new_count, 0);
    const closedCount = metricsData.reduce((s, r) => s + r.closed_count, 0);
    const total       = metricsData.reduce((s, r) => s + r.total, 0);
    const otherCount  = total - newCount - closedCount;

    new Chart(document.getElementById("statusChart"), {
        type: "doughnut",
        data: {
            labels: ["New", "Closed", "Other"],
            datasets: [{
                data: [newCount, closedCount, otherCount],
                backgroundColor: ["#5794f2", "#5c5f66", "#f5a623"],
                borderWidth: 0
            }]
        },
        options: baseDoughnutOptions("Alert Status")
    });
}

// ── Coverage ───────────────────────────────────────────
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
                data: tacticTotals,
                backgroundColor: "#e8742a",
                borderRadius: 1,
                barThickness: 16
            }]
        },
        options: baseBarOptions("Alert Volume by Tactic")
    });
}

// ── Risk Bar Helper ────────────────────────────────────
function getRiskClass(score) {
    if (score >= 80) return "critical";
    if (score >= 60) return "high";
    if (score >= 35) return "medium";
    return "";
}

document.querySelectorAll(".risk-bar-fill").forEach(el => {
    const score = parseInt(el.dataset.score || "0");
    el.style.width = score + "%";
    const cls = getRiskClass(score);
    if (cls) el.classList.add(cls);
});

// ── AI Assistant ───────────────────────────────────────
const aiBtn = document.getElementById("aiAssistBtn");
if (aiBtn) {
    aiBtn.addEventListener("click", () => {
        const alertId  = aiBtn.dataset.alertId;
        const output   = document.getElementById("aiOutput");
        const loading  = document.getElementById("aiLoading");
        const provider = document.getElementById("aiProvider").value;
        const model    = document.getElementById("aiModel").value.trim();
        const apiKey   = document.getElementById("aiApiKey").value.trim();

        if (!apiKey) {
            if (output) {
                output.style.display = "block";
                output.innerHTML = "Enter your API key above before analyzing.";
            }
            return;
        }

        if (!model) {
            if (output) {
                output.style.display = "block";
                output.innerHTML = "Enter a model name above before analyzing.";
            }
            return;
        }

        aiBtn.disabled = true;
        aiBtn.textContent = "Analyzing...";
        if (loading) loading.style.display = "block";
        if (output)  output.style.display  = "none";

        const formData = new FormData();
        formData.append("provider", provider);
        formData.append("api_key", apiKey);
        formData.append("model", model);

        fetch(`/alert/${alertId}/ai-assist`, {
            method: "POST",
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (loading) loading.style.display = "none";
            if (output) {
                output.style.display = "block";
                const raw = data.analysis || data.error || "No response.";
                const cleaned = raw
                    .replace(/###\s?(.*?)(\n|$)/g, "<strong style='font-size:12px;color:var(--text-data);display:block;margin-top:10px;margin-bottom:4px;'>$1</strong>")
                    .replace(/##\s?(.*?)(\n|$)/g,  "<strong style='font-size:12px;color:var(--text-data);display:block;margin-top:10px;margin-bottom:4px;'>$1</strong>")
                    .replace(/#\s?(.*?)(\n|$)/g,   "<strong style='font-size:12px;color:var(--text-data);display:block;margin-top:10px;margin-bottom:4px;'>$1</strong>")
                    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
                    .replace(/\*(.*?)\*/g, "<em>$1</em>")
                    .replace(/`(.*?)`/g, "<code style='background:var(--bg-elevated);padding:1px 5px;border-radius:2px;font-family:var(--font-mono);font-size:10px;color:var(--accent-blue);'>$1</code>")
                    .replace(/\n/g, "<br>");
                output.innerHTML = cleaned;
            }
            aiBtn.textContent = "Regenerate";
            aiBtn.disabled = false;
        })
        .catch(() => {
            if (loading) loading.style.display = "none";
            if (output) {
                output.style.display = "block";
                output.innerHTML = "Request failed. Check your internet connection.";
            }
            aiBtn.textContent = "Retry";
            aiBtn.disabled = false;
        });
    });
}