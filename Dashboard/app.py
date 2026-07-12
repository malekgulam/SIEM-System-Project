import sys
import os
import urllib.request
import urllib.error
import json
from pathlib import Path
from flask import Flask, render_template, jsonify, request, redirect, url_for, Response

sys.path.append(str(Path(__file__).parent.parent))

from Detection.engine import detection_engine, run_simulator
from Storage.store import (
    init_db, save_events, save_alert, save_alert_events,
    load_alerts, load_alert_by_id, load_events_by_alert_id,
    load_events, load_event_by_id,
    update_alert, update_verdict,
    open_case, load_cases, load_case_by_id, update_case,
    add_note, load_notes,
    load_metrics, reset_db
)

app = Flask(__name__)

init_db()

def run_pipeline():
    from Parsing.normalization import normalize_events
    events = normalize_events()
    save_events(events)
    results, db_events = detection_engine()
    for alert, triggered_events in results:
        alert_id = save_alert(alert)
        if alert_id:
            save_alert_events(alert_id, triggered_events)

@app.route("/")
def home():
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

    tactic_counts = {}
    for a in alerts:
        if a["tactic"]:
            tactic_counts[a["tactic"]] = tactic_counts.get(a["tactic"], 0) + 1

    avg_risk = 0
    if alerts:
        avg_risk = round(sum(a["risk_score"] or 0 for a in alerts) / len(alerts), 1)

    return render_template("index.html",
        alerts=alerts,
        total=total,
        high=high,
        new=new,
        escalated=escalated,
        top_ips=top_ips,
        tactic_counts=tactic_counts,
        avg_risk=avg_risk
    )

@app.route("/run", methods=["POST"])
def run():
    run_pipeline()
    return redirect(url_for("home"))

@app.route("/alert/<int:alert_id>")
def alert_details(alert_id):
    alert = load_alert_by_id(alert_id)
    if not alert:
        return render_template("404.html"), 404
    events = load_events_by_alert_id(alert_id)
    case = None
    cases = load_cases()
    for c in cases:
        if c["alert_id"] == alert_id:
            case = c
            break
    return render_template("alert_details.html", alert=alert, events=events, case=case)

@app.route("/alert/<int:alert_id>/update", methods=["POST"])
def update_alert_status(alert_id):
    new_status = request.form["status"]
    new_notes = request.form["notes"]
    update_alert(alert_id=alert_id, new_status=new_status, new_notes=new_notes)
    return redirect(url_for("alert_details", alert_id=alert_id))

@app.route("/alert/<int:alert_id>/verdict", methods=["POST"])
def set_verdict(alert_id):
    verdict = request.form["verdict"]
    update_verdict(alert_id, verdict)
    return redirect(url_for("alert_details", alert_id=alert_id))

@app.route("/alert/<int:alert_id>/open-case", methods=["POST"])
def create_case(alert_id):
    alert = load_alert_by_id(alert_id)
    if not alert:
        return render_template("404.html"), 404
    title = request.form.get("title", f"Investigation — {alert['rule_name']} from {alert['source_ip']}")
    case_id = open_case(alert_id, title)
    if case_id:
        return redirect(url_for("case_details", case_id=case_id))
    cases = load_cases()
    for c in cases:
        if c["alert_id"] == alert_id:
            return redirect(url_for("case_details", case_id=c["id"]))
    return redirect(url_for("alert_details", alert_id=alert_id))

@app.route("/events")
def events_browser():
    events = load_events()
    return render_template("events.html", events=events)

@app.route("/events/<int:event_id>")
def event_details(event_id):
    event = load_event_by_id(event_id)
    if not event:
        return render_template("404.html"), 404
    return render_template("event_details.html", event=event)

@app.route("/cases")
def cases_list():
    cases = load_cases()
    return render_template("cases.html", cases=cases)

@app.route("/cases/<int:case_id>")
def case_details(case_id):
    case = load_case_by_id(case_id)
    if not case:
        return render_template("404.html"), 404
    alert = load_alert_by_id(case["alert_id"])
    notes = load_notes(case_id)
    return render_template("case_details.html", case=case, alert=alert, notes=notes)

@app.route("/cases/<int:case_id>/update", methods=["POST"])
def update_case_status(case_id):
    status = request.form["status"]
    verdict = request.form["verdict"]
    update_case(case_id, status, verdict)
    return redirect(url_for("case_details", case_id=case_id))

@app.route("/cases/<int:case_id>/note", methods=["POST"])
def add_case_note(case_id):
    content = request.form["content"]
    if content.strip():
        add_note(case_id, content)
    return redirect(url_for("case_details", case_id=case_id))

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

@app.route("/coverage/export")
def navigator_export():
    data = load_metrics()
    techniques = []
    for row in data:
        if row["technique_id"]:
            score = 1
            if row["total"] > 10:
                score = 3
            elif row["total"] > 3:
                score = 2
            techniques.append({
                "techniqueID": row["technique_id"],
                "tactic": row["tactic"].lower().replace(" ", "-") if row["tactic"] else "",
                "score": score,
                "color": "",
                "comment": f"{row['rule_name']} — {row['total']} alerts fired",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
            })

    layer = {
        "name": "SIEM Detection Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Detection coverage from SIEM System Project",
        "filters": {"platforms": ["Linux", "Windows", "macOS"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#e8742a"],
            "minValue": 0,
            "maxValue": 3
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }

    return Response(
        json.dumps(layer, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=navigator_layer.json"}
    )

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

@app.route("/simulator", methods=["GET", "POST"])
def simulator():
    from Detection.engine import RULE_DISPATCHER
    import json as json_module
    rules = json_module.loads(Path(__file__).parent.parent.joinpath("Detection/rules.json").read_text())
    result = None
    selected_rule = None
    log_line = ""
    if request.method == "POST":
        selected_rule = request.form.get("rule_id")
        log_line = request.form.get("log_line", "")
        result = run_simulator(selected_rule, log_line)
    return render_template("simulator.html", rules=rules, result=result, selected_rule=selected_rule, log_line=log_line)

@app.route("/alert/<int:alert_id>/ai-assist", methods=["POST"])
def ai_assist(alert_id):
    alert = load_alert_by_id(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    provider = request.form.get("provider", "anthropic").lower().strip()
    api_key  = request.form.get("api_key", "").strip()
    model    = request.form.get("model", "").strip()

    if not api_key:
        return jsonify({"error": "No API key provided. Enter your API key in the AI assistant panel."}), 400

    if not model:
        return jsonify({"error": "No model specified. Enter a model name in the AI assistant panel."}), 400

    prompt = f"""You are a SOC analyst assistant. Analyze this security alert and provide a concise investigation summary.

Alert Details:
- Rule: {alert['rule_name']} ({alert['rule_id']})
- MITRE Technique: {alert['technique_id']} — {alert['tactic']}
- Source IP: {alert['source_ip']}
- User: {alert['user'] or 'Unknown'}
- Severity: {alert['severity']}
- Risk Score: {alert['risk_score']}/100
- Timestamp: {alert['timestamp']}
- Raw Event: {alert['raw_event']}

Respond using ONLY this exact format with no introduction, no preamble, no closing remarks:

**PROBABLE CAUSE**
Write 2-3 sentences here.

**MITRE CONTEXT**
Write 2-3 sentences here.

**NEXT STEPS**
Write 2-3 sentences here.

**RECOMMENDED ACTION**
Write 2-3 sentences here.

Use plain language an L1 SOC analyst would understand. Do not add any text before or after these four sections."""

    try:
        if provider == "anthropic":
            payload = json.dumps({
                "model": model,
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompt}]
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                    "x-api-key": api_key
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
                return jsonify({"analysis": data["content"][0]["text"]})

        elif provider == "openai":
            payload = json.dumps({
                "model": model,
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompt}]
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
                return jsonify({"analysis": data["choices"][0]["message"]["content"]})

        elif provider == "google":
            payload = json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": 1500}
            }).encode("utf-8")

            google_model = model.replace("models/", "")

            req = urllib.request.Request(
                f"https://generativelanguage.googleapis.com/v1beta/models/{google_model}:generateContent?key={api_key}",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
                return jsonify({"analysis": data["candidates"][0]["content"]["parts"][0]["text"]})

        else:
            return jsonify({"error": f"Unknown provider: {provider}. Choose anthropic, openai, or google."}), 400

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        try:
            error_data = json.loads(error_body)
            message = (
                error_data.get("error", {}).get("message")
                or error_data.get("message")
                or str(e)
            )
        except Exception:
            message = str(e)
        return jsonify({"error": f"API error ({provider}): {message}"}), 500

    except urllib.error.URLError as e:
        return jsonify({"error": f"Network error: {str(e.reason)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
        
@app.route("/reset", methods=["POST"])
def reset():
    reset_db()
    return redirect(url_for("home"))

@app.route("/debug")
def debug():
    alerts = load_alerts()
    return jsonify(alerts)

app.run(debug=True)