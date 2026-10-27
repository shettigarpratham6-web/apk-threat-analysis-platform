"""
Flask Web Dashboard for Android Malware Analysis Sandbox
Provides local GUI for emulator status, APK uploads, dynamic instrumentation,
and interactive forensic reporting.
Restricted strictly to localhost (127.0.0.1).
"""

import os
import sys
import glob
import json
import frida
from flask import Flask, render_template, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from sandbox.sandbox_manager import SandboxManager

app = Flask(__name__, template_folder="templates")
app.config["UPLOAD_FOLDER"] = os.path.abspath("datasets/uploads")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
sandbox = SandboxManager()


def get_all_reports():
    reports = []
    json_files = glob.glob("reports/report_session_*.json")
    for jf in sorted(json_files, reverse=True):
        try:
            with open(jf, "r", encoding="utf-8") as f:
                data = json.load(f)
                html_name = os.path.basename(jf).replace(".json", ".html")
                reports.append({
                    "session_id": data.get("session_id", os.path.basename(jf)),
                    "overall_risk_score": data.get("overall_risk_score", 0),
                    "overall_verdict": data.get("overall_verdict", "UNKNOWN"),
                    "generated_at": data.get("generated_at", ""),
                    "json_file": os.path.basename(jf),
                    "html_file": html_name
                })
        except Exception:
            pass
    return reports


@app.route("/")
def index():
    status = {
        "emulator": sandbox.avd_name,
        "is_online": sandbox.is_emulator_running(),
        "frida_version": frida.__version__,
        "proxy_port": sandbox.proxy_port
    }
    reports = get_all_reports()
    return render_template("index.html", status=status, reports=reports, reports_dir=os.path.abspath("reports"))


@app.route("/api/status")
def api_status():
    return jsonify({
        "emulator": sandbox.avd_name,
        "is_online": sandbox.is_emulator_running(),
        "frida_version": frida.__version__,
        "proxy_port": sandbox.proxy_port,
        "total_reports": len(get_all_reports())
    })


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "apk" not in request.files:
        return jsonify({"status": "error", "message": "No APK file uploaded"}), 400

    file = request.files["apk"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400

    if not file.filename.endswith(".apk"):
        return jsonify({"status": "error", "message": "Uploaded file must have .apk extension"}), 400

    filename = secure_filename(file.filename)
    saved_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(saved_path)

    duration = int(request.form.get("duration", 15))

    try:
        report = sandbox.analyse_apk(saved_path, duration_seconds=duration)
        return jsonify({
            "status": "success",
            "session_id": report["session_id"],
            "verdict": report["overall_verdict"],
            "score": report["overall_risk_score"],
            "html_report": f"/reports/report_{report['session_id']}.html",
            "json_report": f"/reports/json/report_{report['session_id']}.json"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/analyze_preset", methods=["POST"])
def api_analyze_preset():
    preset_type = request.args.get("type", "benign")
    if preset_type == "benign":
        target = "datasets/benign/BenignDemo.apk"
    elif preset_type == "malicious":
        target = "datasets/malicious/C2Simulator.apk"
    else:
        return jsonify({"status": "error", "message": "Invalid preset type"}), 400

    if not os.path.exists(target):
        return jsonify({"status": "error", "message": f"Preset APK not found: {target}"}), 404

    try:
        report = sandbox.analyse_apk(target, duration_seconds=15)
        return jsonify({
            "status": "success",
            "session_id": report["session_id"],
            "verdict": report["overall_verdict"],
            "score": report["overall_risk_score"]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/reports/<path:filename>")
def serve_html_report(filename):
    file_path = os.path.join("reports", filename)
    if not os.path.exists(file_path):
        abort(404)
    return send_file(file_path)


@app.route("/reports/json/<path:filename>")
def serve_json_report(filename):
    file_path = os.path.join("reports", filename)
    if not os.path.exists(file_path):
        abort(404)
    return send_file(file_path, mimetype="application/json")


if __name__ == "__main__":
    print("[*] Starting Local Sandbox Dashboard on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)
