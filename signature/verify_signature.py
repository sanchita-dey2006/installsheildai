import os
import sys
import re
import json
import shutil
import subprocess
import logging
from functools import lru_cache
from typing import Dict, Any

try:
    from signature.publisher import is_trusted_publisher
except ImportError:
    try:
        from publisher import is_trusted_publisher
    except ImportError:
        pass

logger = logging.getLogger(__name__)

STATUS_CODES: Dict[Any, str] = {
    0: "Valid",
    1: "NotSigned",
    2: "HashMismatch",
    3: "NotTrusted",
    4: "UnknownError",
    5: "NotSupported",
    "valid": "Valid",
    "notsigned": "NotSigned",
    "hashmismatch": "HashMismatch",
    "nottrusted": "NotTrusted",
    "unknownerror": "UnknownError",
    "notsupported": "NotSupported",
}


def _extract_publisher_name(raw_publisher: str) -> str:
    """
    Extracts the Common Name (CN) from an X.500 Subject Distinguished Name string.
    """
    if not raw_publisher or not isinstance(raw_publisher, str):
        return "Unknown"

    cn_match = re.search(r'CN=(?:"([^"]+)"|([^,]+))', raw_publisher, re.IGNORECASE)
    if cn_match:
        extracted = (cn_match.group(1) or cn_match.group(2)).strip()
        if extracted:
            return extracted

    publisher_str = raw_publisher.strip()
    if publisher_str.startswith("CN="):
        publisher_str = publisher_str[3:]
    publisher_str = publisher_str.split(",")[0].strip()

    return publisher_str if publisher_str else "Unknown"


@lru_cache(maxsize=128)
def _cached_verify_signature(powershell_bin: str, file_path: str, mtime: float, size: int) -> Dict[str, str]:
    """
    Internal cached execution of Authenticode signature verification.
    """
    ps_script = (
        "param([string]$Path); "
        "Get-AuthenticodeSignature -FilePath $Path | "
        "Select-Object Status,@{Name='Publisher';Expression={$_.SignerCertificate.Subject}} | "
        "ConvertTo-Json -Compress"
    )

    try:
        result = subprocess.run(
            [
                powershell_bin,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_script,
                "-Path",
                file_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=15,
        )

        if result.returncode != 0 or not result.stdout.strip():
            return {"status": "Error", "publisher": "Unknown"}

        data = json.loads(result.stdout)
        if isinstance(data, list) and len(data) > 0:
            data = data[0]

        if not isinstance(data, dict):
            return {"status": "Error", "publisher": "Unknown"}

        raw_status = data.get("Status")
        if isinstance(raw_status, str):
            status = STATUS_CODES.get(raw_status.lower(), raw_status)
        else:
            status = STATUS_CODES.get(raw_status, "Unknown")

        raw_publisher = data.get("Publisher")
        pub_name = _extract_publisher_name(raw_publisher) if raw_publisher else "Unknown"

        return {"status": status, "publisher": pub_name}

    except Exception as e:
        logger.error("Error verifying authenticode signature for %s: %s", file_path, e)
        return {"status": "Error", "publisher": "Unknown"}


def verify_signature(file_path: str) -> Dict[str, str]:
    """
    Verifies the digital signature of a Windows executable file.

    Args:
        file_path: Path to the executable file.

    Returns:
        dict: A dictionary containing 'status' and 'publisher'.
    """
    if not file_path or not isinstance(file_path, str):
        return {"status": "Error", "publisher": "Unknown"}

    abs_path = os.path.abspath(file_path)
    if not os.path.isfile(abs_path):
        return {"status": "Error", "publisher": "Unknown"}

    powershell_bin = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell_bin:
        logger.info("PowerShell not available on platform %s; skipping signature verification", sys.platform)
        return {"status": "NotSupported", "publisher": "Unknown"}

    try:
        stat_info = os.stat(abs_path)
        return _cached_verify_signature(powershell_bin, abs_path, stat_info.st_mtime, stat_info.st_size)
    except Exception:
        return _cached_verify_signature(powershell_bin, abs_path, 0.0, 0)
