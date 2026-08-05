from flask import Flask, render_template, request
from analysis.hashing import calculate_hashes
from analysis.strings import calculate_hashes
from database.operations import save_file
from database.operations import save_file, get_all_scans
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/history")
def history():

    scans = get_all_scans()

    html = """
    <h1>📁 Upload History</h1>

    <table border="1" cellpadding="10">

        <tr>

            <th>ID</th>
            <th>Filename</th>
            <th>Path</th>
            <th>Upload Time</th>

        </tr>
    """

    for scan in scans:

        html += f"""

        <tr>

            <td>{scan[0]}</td>
            <td>{scan[1]}</td>
            <td>{scan[2]}</td>
            <td>{scan[3]}</td>

        </tr>

        """

    html += "</table><br><a href='/'>⬅ Home</a>"

    return html


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["installer"]

    if file.filename == "":
        return "No file selected."

    # Save uploaded file
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(save_path)
    save_file(file.filename, save_path)

    # Calculate hashes
    hashes = calculate_hashes(save_path)

    # Extract readable strings
    strings = extract_strings(save_path)

    # Show only first 50 strings
    string_html = ""

    if len(strings) == 0:
        string_html = "<li>No readable strings found.</li>"
    else:
        for s in strings[:50]:
            string_html += f"<li>{s}</li>"

    return f"""
    <!DOCTYPE html>
    <html>

    <head>

        <title>Scan Result</title>

    </head>

    <body>

        <h1>🛡 Fake Software Installer Detector</h1>

        <hr>

        <h2>✅ File Uploaded Successfully!</h2>

        <h3>File Information</h3>

        <p><b>Filename:</b> {file.filename}</p>

        <p><b>Saved To:</b> {save_path}</p>

        <hr>

        <h2>🔑 Hash Values</h2>

        <p><b>MD5</b></p>
        <p>{hashes['md5']}</p>

        <p><b>SHA-1</b></p>
        <p>{hashes['sha1']}</p>

        <p><b>SHA-256</b></p>
        <p>{hashes['sha256']}</p>

        <hr>

        <h2>📄 Readable Strings (First 50)</h2>

        <ul>
            {string_html}
        </ul>

        <hr>

        <a href="/">⬅ Upload Another File</a>

    </body>

    </html>
    """


if __name__ == "__main__":
    app.run(debug=True)