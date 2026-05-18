import sys
from pathlib import Path
from flask import Flask, render_template, jsonify, request, redirect, url_for

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from Detection.engine import detection_engine
from Storage.store import update_alert,save_alert,load_alerts,init_db

app = Flask(__name__)

init_db()

def get_alerts():
    alerts = detection_engine()
    for alert in alerts:
        save_alert(alert=alert)
    stored_alerts = load_alerts()
    return stored_alerts

@app.route("/alert")
def home():
    result = get_alerts()
    return render_template("index.html", alerts=result)

@app.route("/alert/<int:alert_id>")
def alert_details(alert_id):
    result = get_alerts()
    alert = next(a for a in result if a["id"] == alert_id)
    return render_template("alert_details.html", alert=alert)

@app.route("/alert/<int:alert_id>/update", methods=["POST"])
def update_alert_status(alert_id):
    new_status = request.form["status"]
    new_notes = request.form["notes"]
    update_alert(alert_id=alert_id,new_status=new_status,new_notes=new_notes)
    return redirect(url_for("alert_details", alert_id=alert_id))

@app.route("/debug")
def debug():
    result = get_alerts()
    return jsonify(result)

app.run(debug=True)