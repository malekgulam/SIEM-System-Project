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
    options: { plugins: { title: { display: true, text: "Alerts by Severity", color: "#fff" }}}
});



const ipCounts = {};
alertData.forEach(a => {
    ipCounts[a.source_ip] = (ipCounts[a.source_ip] || 0) + 1;
});

const top5 = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

const ipLabels = top5.map(pair => pair[0]);
const ipValues = top5.map(pair => pair[1]);

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
        plugins: { title: { display: true, text: "Top Attacking IPs", color: "#fff" }},
        scales: { x: { ticks: { color: "#fff" }}, y: { ticks: { color: "#fff" }}}
    }
});


const rows = document.querySelectorAll(".alert-row");

function filterTable() {
    const ip       = document.getElementById("searchIP").value.toLowerCase();
    const severity = document.getElementById("filterSeverity").value;
    const status   = document.getElementById("filterStatus").value;

    rows.forEach(row => {
        const matchIP  = row.dataset.ip.toLowerCase().includes(ip);
        const matchSev = severity === "" || row.dataset.severity === severity;
        const matchSta = status   === "" || row.dataset.status   === status;
        row.style.display = (matchIP && matchSev && matchSta) ? "" : "none";
    });
}

document.getElementById("searchIP").addEventListener("input", filterTable);
document.getElementById("filterSeverity").addEventListener("change", filterTable);
document.getElementById("filterStatus").addEventListener("change", filterTable);