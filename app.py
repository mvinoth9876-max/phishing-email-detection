
from flask import Flask, render_template, request, send_file, abort
from email_analyzer import analyze_email
from datetime import datetime
from pathlib import Path
import json
import io

app = Flask(__name__)
HISTORY_FILE = Path("scan_history.json")


def load_history():
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def save_history(history):
    HISTORY_FILE.write_text(
        json.dumps(history, indent=4),
        encoding="utf-8"
    )


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    sender = ""
    subject = ""
    body = ""

    if request.method == "POST":
        sender = request.form.get("sender", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()

        if sender and subject and body:
            result = analyze_email(sender, subject, body)
            history = load_history()

            scan = {
                "id": int(datetime.now().timestamp() * 1000000),
                "sender": sender,
                "subject": subject,
                "risk_level": result["risk_level"],
                "risk_score": result["risk_score"],
                "findings": result["findings"],
                "urls_found": result["urls_found"],
                "url_results": result["url_results"],
                "date": datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")
            }

            history.insert(0, scan)
            save_history(history[:100])
        else:
            result = {
                "risk_level": "ERROR",
                "risk_score": 0,
                "findings": ["Please fill in all fields."],
                "urls_found": [],
                "url_results": []
            }

    history = load_history()

    stats = {
        "total": len(history),
        "high": sum(s["risk_level"] == "HIGH" for s in history),
        "medium": sum(s["risk_level"] == "MEDIUM" for s in history),
        "low": sum(s["risk_level"] == "LOW" for s in history)
    }

    return render_template(
        "index.html",
        result=result,
        sender=sender,
        subject=subject,
        body=body,
        history=history,
        stats=stats
    )


@app.route("/download/<int:scan_id>")
def download_report(scan_id):
    history = load_history()

    scan = next(
        (item for item in history if item["id"] == scan_id),
        None
    )

    if scan is None:
        abort(404)

    report = f"""
PHISHING EMAIL SECURITY REPORT
================================

Sender: {scan['sender']}
Subject: {scan['subject']}
Date: {scan['date']}

OVERALL SECURITY RESULT
-----------------------
Risk Level: {scan['risk_level']}
Risk Score: {scan['risk_score']}/100

SECURITY FINDINGS
-----------------
"""

    report += "\n".join(
        f"- {item}" for item in scan["findings"]
    ) or "No configured warning indicators detected."

    report += "\n\nURL SECURITY ANALYSIS\n---------------------\n"

    for item in scan.get("url_results", []):
        report += f"""
URL: {item['url']}
Risk Level: {item['risk_level']}
Risk Score: {item['risk_score']}/100
Warnings:
"""

        report += "\n".join(
            f"- {warning}" for warning in item["findings"]
        ) or "No configured URL warning indicators."

        report += "\n"

    if not scan.get("url_results"):
        report += "No URLs detected.\n"

    report += """
DISCLAIMER
----------
This tool uses heuristic security checks.
It cannot guarantee that an email or URL is safe.
Do not open suspicious links.
"""

    file_data = io.BytesIO(report.encode("utf-8"))

    return send_file(
        file_data,
        as_attachment=True,
        download_name=f"phishing_report_{scan_id}.txt",
        mimetype="text/plain"
    )


if __name__ == "__main__":
    app.run(debug=True)
