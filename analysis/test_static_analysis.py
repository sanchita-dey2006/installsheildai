import os
import tempfile
import unittest

from analysis.hashing import calculate_hashes, get_file_metadata
from analysis.strings import (
    extract_strings, get_strings, detect_suspicious_apis,
    detect_urls, detect_suspicious_keywords, analyze_strings
)
from analysis.entropy import calculate_entropy


class TestStaticAnalysis(unittest.TestCase):

    def setUp(self):
        # Create temporary test binary file with known contents
        self.test_dir = tempfile.mkdtemp()
        self.test_file_path = os.path.join(self.test_dir, "test_installer.exe")
        
        # Binary data containing MZ header, ASCII strings, Unicode strings, URLs, APIs, and keywords
        self.sample_content = (
            b"MZ" + b"\x00" * 30 +
            b"Hello World! This is a test binary.\x00" +
            b"VirtualAlloc\x00" +
            b"WriteProcessMemory\x00" +
            b"http://example.com/payload.exe\x00" +
            b"cmd.exe /c powershell\x00" +
            b"H\x00e\x00l\x00l\x00o\x00 \x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00\x00\x00"
        )
        
        with open(self.test_file_path, "wb") as f:
            f.write(self.sample_content)

        # Empty test file
        self.empty_file_path = os.path.join(self.test_dir, "empty.bin")
        with open(self.empty_file_path, "wb") as f:
            pass

    def tearDown(self):
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)
        if os.path.exists(self.empty_file_path):
            os.remove(self.empty_file_path)
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)

    def test_hashing_and_metadata(self):
        res = calculate_hashes(self.test_file_path)
        self.assertIn("md5", res)
        self.assertIn("sha1", res)
        self.assertIn("sha256", res)
        self.assertEqual(res["file_size"], len(self.sample_content))
        self.assertIn("metadata", res)
        
        meta = res["metadata"]
        self.assertEqual(meta["file_type"], "PE Executable (Windows EXE/DLL)")
        self.assertTrue(meta["magic_bytes"].startswith("4D5A"))

    def test_hashing_error_handling(self):
        res = calculate_hashes("/path/to/nonexistent/file.exe")
        self.assertIn("error", res)
        self.assertEqual(res["error"], "File not found")

    def test_strings_extraction_and_alias(self):
        strings1 = extract_strings(self.test_file_path)
        strings2 = get_strings(self.test_file_path)
        self.assertEqual(strings1, strings2)
        self.assertIn("Hello World! This is a test binary.", strings1)
        self.assertIn("VirtualAlloc", strings1)

    def test_threat_detection(self):
        analysis = analyze_strings(self.test_file_path)
        self.assertIn("VirtualAlloc", analysis["suspicious_apis"])
        self.assertIn("WriteProcessMemory", analysis["suspicious_apis"])
        self.assertIn("http://example.com/payload.exe", analysis["urls"])
        self.assertIn("cmd.exe", analysis["suspicious_keywords"])
        self.assertIn("powershell", analysis["suspicious_keywords"])

    def test_entropy_calculation(self):
        entropy, stats = calculate_entropy(self.test_file_path)
        self.assertGreater(entropy, 0.0)
        self.assertLessEqual(entropy, 8.0)
        self.assertEqual(stats["status"], "OK")
        self.assertEqual(stats["file_size"], len(self.sample_content))
        self.assertIn("verdict", stats)

    def test_empty_file_entropy(self):
        entropy, stats = calculate_entropy(self.empty_file_path)
        self.assertEqual(entropy, 0.0)
        self.assertEqual(stats["status"], "Empty File")


if __name__ == "__main__":
    unittest.main()
