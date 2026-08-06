import os
import re
import logging
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

# Pre-compiled regex pattern generators & matchers for high performance
_URL_REGEX = re.compile(
    r"https?://[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]+|\b(?:\d{1,3}\.){3}\d{1,3}\b",
    re.IGNORECASE
)

# Known suspicious Windows/Native APIs associated with security risks
SUSPICIOUS_APIS: Set[str] = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "OpenProcess",
    "RtlCreateUserThread", "NtUnmapViewOfSection", "SetWindowsHookExA", "SetWindowsHookExW",
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
    "InternetOpenUrlA", "InternetOpenUrlW", "HttpOpenRequestA", "HttpOpenRequestW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "AdjustTokenPrivileges", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
    "RegCreateKeyExW", "LoadLibraryA", "LoadLibraryW", "GetProcAddress"
}

# Suspicious keywords, path components, and command utilities
SUSPICIOUS_KEYWORDS: Set[str] = {
    "cmd.exe", "powershell", "powershell.exe", "wscript.exe", "cscript.exe",
    "appdata", "temp", "tmp", "runonce", "startup", "mimikatz", "bypass",
    "downloadstring", "downloadfile", "invoke-expression", "iex", "keylogger",
    "payload", "shellcode", "eval", "base64"
}

MAX_STRING_EXTRACT_SIZE = 50 * 1024 * 1024  # 50 MB limit for string extraction


def _compile_patterns(min_length: int):
    """Compile ASCII and UTF-16LE regex patterns for string extraction."""
    ascii_pat = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode("ascii") + rb",}")
    unicode_pat = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode("ascii") + rb",}")
    return ascii_pat, unicode_pat


def extract_strings(file_path: str, min_length: int = 4) -> List[str]:
    """Extract printable ASCII and UTF-16 wide strings from a binary file.

    :param file_path: Path to the target file.
    :param min_length: Minimum number of consecutive printable characters.
    :return: List of unique extracted string matches preserving order.
    """
    if not file_path or not os.path.exists(file_path):
        return []

    if os.path.isdir(file_path):
        return []

    try:
        file_size = os.path.getsize(file_path)
        read_size = min(file_size, MAX_STRING_EXTRACT_SIZE)

        with open(file_path, "rb") as f:
            data = f.read(read_size)

        if not data:
            return []

        ascii_pattern, unicode_pattern = _compile_patterns(min_length)

        # Extract ASCII strings
        ascii_matches = [
            match.decode("ascii", errors="ignore")
            for match in ascii_pattern.findall(data)
        ]

        # Extract UTF-16LE wide strings
        unicode_matches = [
            match.decode("utf-16le", errors="ignore")
            for match in unicode_pattern.findall(data)
        ]

        # Combine results and remove duplicates while preserving order
        seen: Set[str] = set()
        unique_strings: List[str] = []

        for s in ascii_matches + unicode_matches:
            s_clean = s.strip()
            if s_clean and s_clean not in seen:
                seen.add(s_clean)
                unique_strings.append(s_clean)

        return unique_strings

    except PermissionError:
        logger.error("Permission denied extracting strings from %s", file_path)
        return ["Error: Permission denied reading file."]
    except Exception as e:
        logger.error("Error extracting strings from %s: %s", file_path, e)
        return [f"Error extracting strings: {str(e)}"]


# Maintain backwards compatibility with callers importing get_strings
get_strings = extract_strings


def detect_suspicious_apis(strings_list: List[str]) -> List[str]:
    """Detect suspicious API names present in extracted strings list.

    :param strings_list: Extracted printable strings.
    :return: List of detected suspicious APIs.
    """
    detected = set()
    for s in strings_list:
        for api in SUSPICIOUS_APIS:
            if api in s:
                detected.add(api)
    return sorted(list(detected))


def detect_urls(strings_list: List[str]) -> List[str]:
    """Extract embedded URLs and IP addresses from strings list.

    :param strings_list: Extracted printable strings.
    :return: List of detected URLs.
    """
    urls = set()
    for s in strings_list:
        matches = _URL_REGEX.findall(s)
        for match in matches:
            if match and len(match) > 7:
                urls.add(match)
    return sorted(list(urls))


def detect_suspicious_keywords(strings_list: List[str]) -> List[str]:
    """Detect suspicious keywords or command utilities in strings list.

    :param strings_list: Extracted printable strings.
    :return: List of matched suspicious keywords.
    """
    detected = set()
    for s in strings_list:
        s_lower = s.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in s_lower:
                detected.add(kw)
    return sorted(list(detected))


def analyze_strings(file_path: str, min_length: int = 4) -> Dict[str, Any]:
    """Comprehensive string extraction and threat analysis.

    :param file_path: Path to target file.
    :param min_length: Minimum string length.
    :return: Structured dictionary containing extracted strings, APIs, URLs, and keywords.
    """
    all_strings = extract_strings(file_path, min_length=min_length)

    # Filter out error messages from extraction if any
    clean_strings = [s for s in all_strings if not s.startswith("Error:")]

    return {
        "total_count": len(clean_strings),
        "strings": clean_strings,
        "suspicious_apis": detect_suspicious_apis(clean_strings),
        "urls": detect_urls(clean_strings),
        "suspicious_keywords": detect_suspicious_keywords(clean_strings)
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        target = sys.argv[1]
        analysis = analyze_strings(target)
        print(f"Found {analysis['total_count']} strings.")
        print(f"Suspicious APIs: {analysis['suspicious_apis']}")
        print(f"URLs Found: {analysis['urls']}")
        print(f"Suspicious Keywords: {analysis['suspicious_keywords']}")
        print("\nFirst 10 strings:")
        for string in analysis["strings"][:10]:
            print(f"- {string}")
