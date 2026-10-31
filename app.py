"""Flask web interface for the existing SOC Log Analyzer engine."""
import os
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

import log_analyzer as engine

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_LOG = BASE_DIR / "sample" / "auth.log"
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 5 * 1024 * 1024))
REPORT_ROOT = Path(tempfile.gettempdir()) / "soc-log-analyzer-reports"
REPORT_ROOT.mkdir(parents=True, exist_ok=True)

REPORT_TTL_SECONDS = int(os.environ.get("REPORT_TTL_SECONDS", 3600))
MAX_REPORTS = int(os.environ.get("MAX_REPORTS", 100))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.json.sort_keys = False

# Reports are intentionally kept in the server's temporary directory. They are
# deleted after REPORT_TTL_SECONDS, and only the newest MAX_REPORTS are kept.
# The registry lives in process memory, so run ONE gunicorn worker (threads ok).
_REPORTS = {}
_LOCK = threading.Lock()


def _cleanup_reports(now=None):
    """Delete expired/excess reports and stale leftover folders in REPORT_ROOT."""
    now = now if now is not None else time.time()
    with _LOCK:
        for rid in [r for r, v in _REPORTS.items()
                    if now - v["created"] > REPORT_TTL_SECONDS]:
            shutil.rmtree(_REPORTS.pop(rid)["dir"], ignore_errors=True)
        extra = len(_REPORTS) - MAX_REPORTS
        if extra > 0:
            for rid in sorted(_REPORTS, key=lambda r: _REPORTS[r]["created"])[:extra]:
                shutil.rmtree(_REPORTS.pop(rid)["dir"], ignore_errors=True)
        known = {v["dir"].name for v in _REPORTS.values()}
        for child in REPORT_ROOT.iterdir():          # leftovers from old runs
            try:
                if (child.is_dir() and child.name not in known
                        and now - child.stat().st_mtime > REPORT_TTL_SECONDS):
                    shutil.rmtree(child, ignore_errors=True)
            except OSError:
                pass


def _parse_year(value):
    """Return a valid year int, or raise ValueError."""
    if value in (None, ""):
        return datetime.now().year
    year = int(value)
    if year < 1970 or year > 2200:
        raise ValueError("year out of range")
    return year


def _analyze_path(path, year=None, source="uploaded"):
    _cleanup_reports()
    year = _parse_year(year)
    events = engine.parse_file(str(path), year)
    cfg = dict(engine.DEFAULT_CFG)
    findings, stats = engine.analyze(events, cfg)
    stats = dict(stats)
    stats["total_events"] = len(events)
    stats["severity_counts"] = {
        "High": sum(1 for f in findings if f.get("severity") == "High"),
        "Medium": sum(1 for f in findings if f.get("severity") == "Medium"),
        "Low": sum(1 for f in findings if f.get("severity") == "Low"),
    }
    stats["analysis_source"] = source
    stats["analyzed_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    category_counts = {}
    for finding in findings:
        category_counts[finding.get("type", "Other")] = category_counts.get(finding.get("type", "Other"), 0) + 1
    stats["category_counts"] = category_counts
    timeline = {}
    for event in events:
        bucket = event.ts.strftime("%Y-%m-%d %H:%M")
        if bucket not in timeline:
            timeline[bucket] = {"time": bucket, "failed": 0, "successful": 0}
        timeline[bucket]["failed" if event.kind == "failed" else "successful"] += 1
    stats["events_over_time"] = [timeline[key] for key in sorted(timeline)]
    report_id = uuid.uuid4().hex
    report_dir = REPORT_ROOT / report_id
    report_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    engine.write_json(str(report_dir / "report.json"), findings, stats)
    engine.write_csv(str(report_dir / "findings.csv"), findings)
    engine.write_html(str(report_dir / "report.html"), findings, stats)
    engine.write_blocklist(str(report_dir / "blocklist.txt"), findings)
    with _LOCK:
        _REPORTS[report_id] = {"dir": report_dir, "stats": stats,
                               "findings": findings, "created": time.time()}
    return {
        "report_id": report_id,
        "summary": stats,
        "findings": findings,
        "reports": {
            "json": f"/api/reports/{report_id}/json",
            "csv": f"/api/reports/{report_id}/csv",
            "html": f"/reports/{report_id}",
            "blocklist": f"/api/reports/{report_id}/blocklist",
        },
    }


def _get_report(report_id):
    _cleanup_reports()
    with _LOCK:
        report = _REPORTS.get(report_id)
    if not report:
        abort(404, description="Report not found or expired. Analyze the log again.")
    return report


@app.get("/")
def index():
    return render_template("index.html", max_upload_mb=round(MAX_UPLOAD_BYTES / (1024 * 1024), 1))


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "SOC Log Analyzer", "timestamp": datetime.now().astimezone().isoformat(timespec="seconds")})


@app.get("/api/sample")
def analyze_sample():
    if not SAMPLE_LOG.is_file():
        return jsonify({"error": "Bundled sample log is missing."}), 500
    try:
        year = _parse_year(request.args.get("year"))
    except (TypeError, ValueError):
        return jsonify({"error": "Year must be a number between 1970 and 2200."}), 400
    try:
        result = _analyze_path(SAMPLE_LOG, year, "sample")
        result["sample_data"] = True
        return jsonify(result)
    except (ValueError, OSError):
        app.logger.exception("Sample analysis failed")
        return jsonify({"error": "Could not analyze the bundled sample log."}), 500


@app.post("/api/analyze")
def analyze_upload():
    if "file" not in request.files:
        return jsonify({"error": "Choose a .log or .txt file to upload."}), 400
    upload = request.files["file"]
    if not upload or not upload.filename:
        return jsonify({"error": "No file was selected."}), 400
    safe_name = Path(upload.filename).name
    if Path(safe_name).suffix.lower() not in {".log", ".txt"}:
        return jsonify({"error": "Unsupported file type. Upload a .log or .txt file."}), 415
    raw = upload.stream.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        return jsonify({"error": f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."}), 413
    if not raw.strip():
        return jsonify({"error": "The uploaded file is empty."}), 400
    # Decode once to reject binary/invalid content; replacement is permitted for
    # legacy syslog text. Uploaded bytes are never executed.
    if b"\x00" in raw:
        return jsonify({"error": "The file does not look like a text log."}), 400
    try:
        year_int = _parse_year(request.form.get("year"))
    except (TypeError, ValueError):
        return jsonify({"error": "Year must be a number between 1970 and 2200."}), 400
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="soc-log-", suffix=".log", delete=False) as tmp:
            temp_path = Path(tmp.name)
            tmp.write(raw)
        result = _analyze_path(temp_path, year_int, "uploaded")
        result["sample_data"] = False
        return jsonify(result)
    except (ValueError, OSError):
        app.logger.exception("Uploaded log analysis failed")
        return jsonify({"error": "The log could not be analyzed. Check its encoding and format."}), 400
    finally:
        if temp_path:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                app.logger.warning("Could not remove temporary upload file")


@app.get("/api/reports/<report_id>/<kind>")
def download_report(report_id, kind):
    report = _get_report(report_id)
    files = {"json": "report.json", "csv": "findings.csv", "blocklist": "blocklist.txt"}
    if kind not in files:
        abort(404)
    path = report["dir"] / files[kind]
    return send_file(path, as_attachment=True, download_name=files[kind], conditional=True)


@app.get("/reports/<report_id>")
def view_report(report_id):
    report = _get_report(report_id)
    return send_file(report["dir"] / "report.html", mimetype="text/html")


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith("/reports/"):
        # Self-generated, fully escaped report page: no scripts at all.
        csp = ("default-src 'none'; style-src 'unsafe-inline'; "
               "frame-ancestors 'none'; base-uri 'none'")
    else:
        csp = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
               "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    response.headers.setdefault("Content-Security-Policy", csp)
    return response


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    return jsonify({"error": f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."}), 413


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/") or request.path.startswith("/reports/"):
        return jsonify({"error": getattr(error, "description", "Not found.")}), 404
    return "Not found", 404


if __name__ == "__main__":
    # Development only. Use the documented production WSGI command for hosting.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
