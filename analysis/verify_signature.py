import subprocess
import json

from signature import publisher


def verify_signature(file_path):

    command = (
        f"Get-AuthenticodeSignature '{file_path}' | "
        "Select-Object Status,@{Name='Publisher';Expression={$_.SignerCertificate.Subject}} | "
        "ConvertTo-Json"
    )

    result = subprocess.run(
    ["powershell", "-Command", command],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore"

    )

    if result.returncode != 0:
        return {
            "status": "Error",
            "publisher": "Unknown"
        }

    try:
        data = json.loads(result.stdout)
        status_codes = {
            0: "Valid",
            1: "NotSigned",
            2: "HashMismatch",
            3: "NotTrusted",
            4: "UnknownError"
        }

        status = status_codes.get(data["Status"], "Unknown")
        publisher = data.get("Publisher")

        if publisher:
            # Remove "CN=" and anything after the first comma
            if publisher.startswith("CN="):
                publisher = publisher[3:]
            publisher = publisher.split(",")[0]

        else:
            publisher = "Unknown"

        return {
            "status": status,
            "publisher": publisher
        }

    except Exception:
        return {
            "status": "Error",
            "publisher": "Unknown"
        }