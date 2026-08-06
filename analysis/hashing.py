import hashlib
import os
import time
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

BUFFER_SIZE = 65536  # 64KB chunk size for optimized I/O performance


def get_file_metadata(file_path: str) -> Dict[str, Any]:
    """Extract basic file metadata including magic bytes and file type indicators.

    :param file_path: Path to the target file.
    :return: Dictionary containing metadata attributes.
    """
    if not file_path or not os.path.exists(file_path):
        return {"error": "File not found"}

    if os.path.isdir(file_path):
        return {"error": "Path is a directory, not a file"}

    try:
        stat_info = os.stat(file_path)
        file_size = stat_info.st_size
        mod_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat_info.st_mtime))
        ext = os.path.splitext(file_path)[1].lower()

        magic_hex = ""
        file_type = "Unknown Binary / Data"

        with open(file_path, "rb") as f:
            header = f.read(16)
            magic_hex = header.hex().upper()

            if header.startswith(b"MZ"):
                file_type = "PE Executable (Windows EXE/DLL)"
            elif header.startswith(b"PK\x03\x04"):
                file_type = "ZIP Archive / Installer Package"
            elif header.startswith(b"\x7fELF"):
                file_type = "ELF Executable (Linux)"
            elif header.startswith(b"%PDF"):
                file_type = "PDF Document"
            elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
                file_type = "7-Zip Archive"
            elif header.startswith(b"Rar!\x1a\x07"):
                file_type = "RAR Archive"
            elif header.startswith(b"MSCF"):
                file_type = "Microsoft Cabinet (CAB) File"

        return {
            "file_name": os.path.basename(file_path),
            "file_size": file_size,
            "extension": ext if ext else "None",
            "modified_time": mod_time,
            "magic_bytes": magic_hex[:8],
            "file_type": file_type
        }
    except Exception as e:
        logger.error("Failed to retrieve metadata for %s: %s", file_path, e)
        return {"error": f"Failed to retrieve metadata: {str(e)}"}


def calculate_hashes(file_path: str) -> Dict[str, Any]:
    """Calculate MD5, SHA-1, and SHA-256 hashes of a file using 64KB chunk streaming.

    :param file_path: Path to the target file.
    :return: Dictionary containing md5, sha1, sha256, file_size, and metadata.
    """
    if not file_path or not os.path.exists(file_path):
        return {"error": "File not found"}

    if os.path.isdir(file_path):
        return {"error": "Path is a directory"}

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    total_bytes = 0

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(BUFFER_SIZE)
                if not data:
                    break
                total_bytes += len(data)
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
    except PermissionError:
        return {"error": "Permission denied reading file"}
    except Exception as e:
        logger.error("Error hashing file %s: %s", file_path, e)
        return {"error": str(e)}

    metadata = get_file_metadata(file_path)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "file_size": total_bytes,
        "metadata": metadata if "error" not in metadata else {}
    }


if __name__ == "__main__":
    file_path_input = input("Enter file path: ").strip()
    result = calculate_hashes(file_path_input)

    if "error" in result:
        print(f"Error: {result['error']}")
    else:
        print(f"\nFile Size: {result['file_size']} bytes")
        print(f"MD5:    {result['md5']}")
        print(f"SHA1:   {result['sha1']}")
        print(f"SHA256: {result['sha256']}")
        if result.get("metadata"):
            meta = result["metadata"]
            print(f"File Type: {meta.get('file_type')}")
            print(f"Magic:     {meta.get('magic_bytes')}")