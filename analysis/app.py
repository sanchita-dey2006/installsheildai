import os
import uuid
import logging
from flask import Flask, render_template, request, jsonify, send_file
from markupsafe import escape
from werkzeug.utils import secure_filename

# Analysis & Database imports
from analysis.hashing import calculate_hashes, get_file_metadata
from analysis.strings import get_strings as extract_strings, analyze_strings
from analysis.entropy import calculate_entropy
from analysis.verify_signature import verify_signature
from analysis.publisher import is_trusted_publisher
from database.operations import get_all_scans, save_file, get_all_scans_dict, get_scan_by_id
from analysis.db import create_database
from ai.engine import AIEngine

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("backend")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FOLDER = BASE_DIR

IS_VERCEL = os.environ.get("VERCEL") == "1" or not os.access(BASE_DIR, os.W_OK)
if IS_VERCEL:
    UPLOAD_FOLDER = "/tmp/uploads"
else:
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

STATIC_FOLDER = os.path.join(BASE_DIR, "static")
app = Flask(__name__, template_folder=TEMPLATE_FOLDER, static_folder=STATIC_FOLDER, static_url_path="/static")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB Upload Limit

# Create uploads and database folders safely
try:
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except Exception as e:
    logger.warning("Could not create upload folder %s: %s", UPLOAD_FOLDER, e)

try:
    create_database()
except Exception as e:
    logger.warning("Database initialization deferred/failed: %s", e)

ALLOWED_EXTENSIONS = {"exe", "msi", "dll", "sys", "cab", "zip"}
VALID_MAGIC_HEADERS = (
    b"MZ",                   # Windows PE Executable (.exe, .dll, .sys)
    b"\xd0\xcf\x11\xe0",     # OLE Compound / Microsoft Installer (.msi)
    b"MSCF",                 # Microsoft Cabinet Archive (.cab)
    b"PK\x03\x04",           # ZIP / Package archive (.zip)
    b"7z\xbc\xaf\x27\x1c",   # 7-Zip archive
    b"Rar!\x1a\x07",         # RAR archive
)


def is_allowed_file(filename):
    """Check if file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_pe_executable(file_stream):
    """Verify Windows executable or installer package magic header bytes."""
    header = file_stream.read(8)
    file_stream.seek(0)
    return any(header.startswith(sig) for sig in VALID_MAGIC_HEADERS)


def calculate_risk_assessment(hashes, string_analysis, entropy, entropy_stats, sig_info, is_trusted):
    """Compute risk score (0-100) and threat verdict based on static analysis findings."""
    score = 15
    flags = []

    # Strings threat evaluation
    suspicious_apis = string_analysis.get("suspicious_apis", [])
    suspicious_keywords = string_analysis.get("suspicious_keywords", [])
    urls = string_analysis.get("urls", [])

    if suspicious_apis:
        score += min(len(suspicious_apis) * 10, 30)
        flags.append(f"Suspicious native APIs detected: {', '.join(suspicious_apis[:5])}")

    if suspicious_keywords:
        score += min(len(suspicious_keywords) * 8, 25)
        flags.append(f"Suspicious command utilities/keywords detected: {', '.join(suspicious_keywords[:5])}")

    if urls:
        score += min(len(urls) * 10, 20)
        flags.append(f"Embedded URLs/IP addresses found: {', '.join(urls[:3])}")

    # Digital signature evaluation
    sig_status = sig_info.get("status", "Unknown")
    publisher = sig_info.get("publisher", "Unknown")

    if sig_status == "Valid" and is_trusted:
        score -= 15
    elif sig_status == "Valid" and not is_trusted:
        score += 10
        flags.append(f"Signed by untrusted/unverified publisher: {publisher}")
    else:
        score += 20
        flags.append("Executable is unsigned or has invalid digital signature")

    # Entropy evaluation
    verdict = entropy_stats.get("verdict", "")
    if entropy > 7.5:
        score += 25
        flags.append(f"High Shannon entropy ({entropy:.2f}/8.0): binary may be packed or encrypted")
    elif entropy > 6.8:
        score += 10
        flags.append(f"Elevated entropy ({entropy:.2f}/8.0): suspicious compression")

    score = max(0, min(100, score))

    if score >= 65:
        threat_level = "Malicious"
    elif score >= 35:
        threat_level = "Suspicious"
    else:
        threat_level = "Clean"

    return {
        "risk_score": score,
        "threat_level": threat_level,
        "flags": flags
    }


@app.before_request
def log_request_info():
    """Request logging middleware."""
    logger.info("Incoming Request: %s %s from %s", request.method, request.path, request.remote_addr)


@app.after_request
def set_security_headers(response):
    """Middleware to set security headers on every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.errorhandler(413)
def request_entity_too_large(error):
    logger.warning("Upload rejected: File size exceeds limit (413).")
    return jsonify({"error": "File size exceeds maximum allowed limit of 32MB."}), 413


@app.errorhandler(415)
def unsupported_media_type(error):
    return jsonify({"error": "Unsupported media type. Only executable installer files are allowed."}), 415


@app.errorhandler(500)
def internal_server_error(error):
    import traceback
    logger.error("Internal Server Error: %s\n%s", error, traceback.format_exc())
    return jsonify({
        "status": "error",
        "message": "An internal server error occurred.",
        "details": str(error)
    }), 500


@app.route("/")
def home():
    try:
        return render_template("index.html")
    except Exception:
        index_path = os.path.join(BASE_DIR, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
        return "InstallShield AI Server Running", 200


@app.route("/api/scans", methods=["GET"])
def api_scans():
    """REST API endpoint to fetch list of scan history from local SQLite database."""
    try:
        scans = get_all_scans_dict()
    except Exception as e:
        logger.warning("Error fetching scans: %s", e)
        scans = []
    return jsonify({"status": "success", "scans": scans}), 200


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def api_scan_detail(scan_id):
    """REST API endpoint to fetch a single scan report by ID."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"status": "error", "message": "Scan record not found"}), 404
    return jsonify({"status": "success", "scan": scan}), 200


@app.route("/api/scans/<int:scan_id>/report", methods=["GET"])
def api_scan_pdf_report(scan_id):
    """Generate and download PDF security assessment report for a scan ID."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"status": "error", "message": "Scan record not found"}), 404

    save_path = scan.get("filepath", "")
    if not save_path or not os.path.exists(save_path):
        return jsonify({"status": "error", "message": "Scanned file no longer exists on disk"}), 404

    # Run AI evaluation on saved file
    hashes = calculate_hashes(save_path)
    string_analysis = analyze_strings(save_path)
    entropy_val, entropy_stats = calculate_entropy(save_path)
    sig_info = verify_signature(save_path)
    publisher_name = sig_info.get("publisher", scan.get("publisher", "Unknown"))
    trusted = is_trusted_publisher(publisher_name)
    metadata = hashes.get("metadata", {})

    ai_assessment = AIEngine.analyze(
        sig_info=sig_info,
        is_trusted_publisher=trusted,
        entropy=entropy_val,
        entropy_stats=entropy_stats,
        string_analysis=string_analysis,
        file_metadata=metadata,
        hashes=hashes,
        filename=scan.get("filename", "Unknown"),
        filepath=save_path,
        scan_id=scan_id
    )

    reports_dir = os.path.join(BASE_DIR, "reports")
    pdf_filename = f"InstallShield_AI_Report_{scan_id}.pdf"
    pdf_path = os.path.join(reports_dir, pdf_filename)

    AIEngine.generate_pdf_report(ai_assessment, pdf_path)

    return send_file(pdf_path, as_attachment=True, download_name=pdf_filename, mimetype="application/pdf")


@app.route("/api/scans/latest/report", methods=["GET"])
def api_latest_pdf_report():
    """Generate and download PDF security assessment report for the latest scan."""
    scans = get_all_scans_dict(limit=1)
    if not scans:
        return jsonify({"status": "error", "message": "No scan records found in database"}), 404
    latest_id = scans[0]["id"]
    return api_scan_pdf_report(latest_id)


from analysis.operations import (
    save_file,
    get_all_scans,
    get_all_scans_dict,
    get_scan_by_id,
    delete_all_scans,
    delete_scan_by_id,
)

@app.route("/history", methods=["GET"])
@app.route("/api/scans", methods=["GET"])
def history():
    scans = get_all_scans_dict()

    if request.headers.get("Accept") == "application/json" or request.args.get("json") or request.path.startswith("/api/"):
        return jsonify({"status": "success", "scans": scans}), 200

    html = """<!DOCTYPE html>
<html>
<head><title>Upload History</title></head>
<body>
    <h1>📁 Upload History</h1>
    <table border="1" cellpadding="10">
        <tr>
            <th>ID</th>
            <th>Filename</th>
            <th>Path</th>
            <th>Threat Level</th>
            <th>Upload Time</th>
        </tr>
    """

    for scan in scans:
        scan_id = escape(str(scan.get("id", "")))
        filename = escape(str(scan.get("filename", "")))
        filepath = escape(str(scan.get("filepath", "")))
        threat = escape(str(scan.get("threat_level", "Clean")))
        upload_time = escape(str(scan.get("upload_time", "")))
        html += f"""
        <tr>
            <td>{scan_id}</td>
            <td>{filename}</td>
            <td>{filepath}</td>
            <td>{threat}</td>
            <td>{upload_time}</td>
        </tr>
        """

    html += "</table><br><a href='/'>⬅ Home</a></body></html>"
    return html, 200


@app.route("/api/scans", methods=["DELETE"])
def clear_history():
    """Clear all scan records from database."""
    success = delete_all_scans()
    if success:
        return jsonify({"status": "success", "message": "All scan history cleared successfully"}), 200
    return jsonify({"status": "error", "message": "Failed to clear scan history"}), 500


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def delete_single_scan(scan_id):
    """Delete a single scan record from database by ID."""
    success = delete_scan_by_id(scan_id)
    if success:
        return jsonify({"status": "success", "message": f"Scan #{scan_id} deleted successfully"}), 200
    return jsonify({"status": "error", "message": f"Scan #{scan_id} not found or could not be deleted"}), 404


@app.route("/upload", methods=["POST"])
def upload():
    if "installer" not in request.files:
        logger.warning("Upload failed: No file part in request.")
        return jsonify({"error": "No file part in the request."}), 400

    file = request.files["installer"]

    if file.filename == "" or not file.filename:
        logger.warning("Upload failed: No file selected.")
        return jsonify({"error": "No file selected."}), 400

    original_filename = secure_filename(file.filename)
    if not original_filename:
        original_filename = "unnamed_installer.exe"

    # Save uploaded file with collision-safe unique name
    unique_prefix = uuid.uuid4().hex[:8]
    saved_filename = f"{unique_prefix}_{original_filename}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_filename)
    file.save(save_path)

    # 1. Hashing
    hashes = calculate_hashes(save_path)
    md5_val = hashes.get("md5", "N/A")
    sha1_val = hashes.get("sha1", "N/A")
    sha256_val = hashes.get("sha256", "N/A")

    # 2. Strings Extraction & Analysis
    strings = extract_strings(save_path)
    string_analysis = analyze_strings(save_path)

    # 3. Entropy Calculation
    entropy_val, entropy_stats = calculate_entropy(save_path)
    entropy_verdict = entropy_stats.get("verdict", "Normal")

    # 4. Signature Verification
    sig_info = verify_signature(save_path)
    sig_status = sig_info.get("status", "Unknown")
    publisher_name = sig_info.get("publisher", "Unknown")
    trusted = is_trusted_publisher(publisher_name)

    # 5. AI Engine Risk Assessment & Threat Intelligence
    file_metadata = hashes.get("metadata", {})
    ai_assessment = AIEngine.analyze(
        sig_info=sig_info,
        is_trusted_publisher=trusted,
        entropy=entropy_val,
        entropy_stats=entropy_stats,
        string_analysis=string_analysis,
        file_metadata=file_metadata,
        hashes=hashes,
        filename=original_filename,
        filepath=save_path
    )

    risk_score = ai_assessment["risk_score"]
    threat_level = ai_assessment["threat_level"]

    # 6. Persist complete scan report in SQLite database
    scan_id = save_file(
        filename=original_filename,
        filepath=save_path,
        md5=md5_val,
        sha1=sha1_val,
        sha256=sha256_val,
        entropy=round(entropy_val, 2),
        entropy_verdict=entropy_verdict,
        signature_status=sig_status,
        publisher=publisher_name,
        is_trusted=trusted,
        risk_score=risk_score,
        threat_level=threat_level,
    )

    ai_assessment["scan_id"] = scan_id

    logger.info("File saved & scanned successfully [Scan ID: %s] path: %s", scan_id, save_path)

    result_payload = {
        "status": "success",
        "scan_id": scan_id,
        "filename": original_filename,
        "savedTo": save_path,
        "hashes": {"md5": md5_val, "sha1": sha1_val, "sha256": sha256_val},
        "strings": strings[:100],
        "suspicious_apis": string_analysis.get("suspicious_apis", []),
        "suspicious_keywords": string_analysis.get("suspicious_keywords", []),
        "urls": string_analysis.get("urls", []),
        "entropy": round(entropy_val, 2),
        "entropy_verdict": entropy_verdict,
        "signature_status": sig_status,
        "publisher": publisher_name,
        "is_trusted": trusted,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "flags": ai_assessment["flags"],
        "threat_category": ai_assessment["threat_category"],
        "recommendations": ai_assessment["recommendations"],
        "explanation": ai_assessment["explanation"],
        "ai_assessment": ai_assessment,
    }

    # Return JSON if requested
    wants_json = (
        request.is_json
        or request.headers.get("Accept") == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.args.get("json") == "1"
    )

    if wants_json:
        return jsonify(result_payload), 200

    # HTML fallback for non-AJAX form submissions
    import json
    payload_json = json.dumps(result_payload)

    string_html = ""
    if not strings:
        string_html = "<li>No readable strings found.</li>"
    else:
        for s in strings[:50]:
            string_html += f"<li>{escape(s)}</li>"

    escaped_filename = escape(original_filename)
    escaped_save_path = escape(save_path)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Result</title>
        <script id="scan-payload" type="application/json">{payload_json}</script>
    </head>
    <body>
        <h1>🛡 Fake Software Installer Detector</h1>
        <hr>
        <h2>✅ File Uploaded & Analyzed Successfully!</h2>

        <h3>File Information</h3>
        <p><b>Filename:</b> {escaped_filename}</p>
        <p><b>Saved To:</b> {escaped_save_path}</p>
        <p><b>Threat Level:</b> {escape(threat_level)} (Risk Score: {risk_score}/100)</p>
        <p><b>Entropy:</b> {entropy_val:.2f} / 8.0 ({escape(entropy_verdict)})</p>
        <hr>

        <h2>🔑 Hash Values</h2>
        <p><b>MD5</b></p>
        <p>{escape(md5_val)}</p>

        <p><b>SHA-1</b></p>
        <p>{escape(sha1_val)}</p>

        <p><b>SHA-256</b></p>
        <p>{escape(sha256_val)}</p>
        <hr>

        <h2>🛡 Digital Signature & Publisher</h2>
        <p><b>Publisher:</b> {escape(publisher_name)}</p>
        <p><b>Status:</b> {escape(sig_status)}</p>
        <hr>

        <h2>📄 Readable Strings (First 50)</h2>
        <ul>
            {string_html}
        </ul>
        <hr>

        <a href="/">⬅ Upload Another File</a>
    </body>
    </html>
    """, 200


if __name__ == "__main__":
    app.run(debug=True)

