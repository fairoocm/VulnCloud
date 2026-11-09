from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from flask import Flask, abort, render_template, request, send_file, url_for
from scanner.headers import analyze_headers
from scanner.history import (
    get_assessment,
    initialize_history,
    list_assessments,
    save_assessment,
)
from reports.pdf_report import create_pdf_report

app = Flask(__name__)
app.config["HISTORY_DB"] = str(Path(app.instance_path) / "vulncloud_history.db")
initialize_history(app.config["HISTORY_DB"])


@app.route("/", methods=["GET", "POST"])
def dashboard():
    scan_result = None
    target = ""
    authorized = False
    history_id = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        authorized = request.form.get("authorized") == "yes"
        scan_result = analyze_headers(target, authorized=authorized)
        history_id = save_assessment(app.config["HISTORY_DB"], scan_result)

    return render_template(
        "index.html",
        scan_result=scan_result,
        target=target,
        authorized=authorized,
        history_id=history_id,
    )


@app.route("/history")
def history():
    assessments = list_assessments(app.config["HISTORY_DB"])
    return render_template("history.html", assessments=assessments)


@app.route("/history/<int:assessment_id>")
def history_detail(assessment_id):
    assessment = get_assessment(app.config["HISTORY_DB"], assessment_id)
    if assessment is None:
        abort(404)
    return render_template("history_detail.html", assessment=assessment)


@app.route("/download-report", methods=["POST"])
def download_report():
    target = request.form.get("target", "").strip()
    authorized = request.form.get("authorized") == "yes"

    # Re-run the assessment at download time; do not trust client-submitted results.
    scan_result = analyze_headers(target, authorized=authorized)
    if not scan_result.get("success"):
        return (
            "Unable to generate the report because the assessment failed: "
            + scan_result.get("error", "Unknown error"),
            400,
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    pdf_buffer = BytesIO()
    create_pdf_report(scan_result, pdf_buffer)
    pdf_buffer.seek(0)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="VulnCloud_Assessment_Report.pdf",
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
