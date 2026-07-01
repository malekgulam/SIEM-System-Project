import sys
from pathlib import Path
from flask import Flask, render_template, jsonify, request, redirect, url_for

sys.path.append(str(Path(__file__).parent.parent))

from Detection.engine import detection_engine
from Storage.store import update_alert, save_alert, load_alerts, load_alert_by_id, load_metrics, init_db

app = Flask(__name__)

init_db()

def run_pipeline():
    alerts = detection_engine()
    for alert in alerts:
        save_alert(alert)

@app.route("/")
def home():
    run_pipeline()
    alerts = load_alerts()
    total = len(alerts)
    high = sum(1 for a in alerts if a["severity"] == "HIGH")
    new = sum(1 for a in alerts if a["status"] == "NEW")
    escalated = sum(1 for a in alerts if a["status"] == "ESCALATED")

    ip_counts = {}
    for a in alerts:
        if a["source_ip"]:
            ip_counts[a["source_ip"]] = ip_counts.get(a["source_ip"], 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return render_template("index.html",
        alerts=alerts,
        total=total,
        high=high,
        new=new,
        escalated=escalated,
        top_ips=top_ips
    )

@app.route("/alert/<int:alert_id>")
def alert_details(alert_id):
    alert = load_alert_by_id(alert_id)
    if not alert:
        return render_template("404.html"), 404
    return render_template("alert_details.html", alert=alert)

@app.route("/alert/<int:alert_id>/update", methods=["POST"])
def update_alert_status(alert_id):
    new_status = request.form["status"]
    new_notes = request.form["notes"]
    update_alert(alert_id=alert_id, new_status=new_status, new_notes=new_notes)
    return redirect(url_for("alert_details", alert_id=alert_id))

@app.route("/metrics")
def metrics():
    data = load_metrics()
    return render_template("metrics.html", metrics=data)

@app.route("/coverage")
def coverage():
    data = load_metrics()
    tactics = {}
    for row in data:
        tactic = row["tactic"]
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append({
            "rule_id": row["rule_id"],
            "rule_name": row["rule_name"],
            "technique_id": row["technique_id"],
            "total": row["total"]
        })
    return render_template("coverage.html", tactics=tactics)

@app.route("/search")
def search():
    query = request.args.get("q", "").strip().lower()
    alerts = load_alerts()
    if query:
        alerts = [
            a for a in alerts
            if (a["source_ip"] and query in a["source_ip"].lower())
            or (a["rule_id"] and query in a["rule_id"].lower())
            or (a["rule_name"] and query in a["rule_name"].lower())
            or (a["technique_id"] and query in a["technique_id"].lower())
        ]
    return render_template("search.html", alerts=alerts, query=query)

@app.route("/debug")
def debug():
    alerts = load_alerts()
    return jsonify(alerts)

app.run(debug=True)