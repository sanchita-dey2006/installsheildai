import unittest
from unittest.mock import patch, MagicMock
import os
import json

from analysis.publisher import is_trusted_publisher, _load_trusted_publishers
from analysis.verify_signature import verify_signature, _extract_publisher_name


class TestPublisherVerification(unittest.TestCase):

    def test_trusted_publisher_exact_match(self):
        self.assertTrue(is_trusted_publisher("Google LLC"))
        self.assertTrue(is_trusted_publisher("google llc"))
        self.assertTrue(is_trusted_publisher("Microsoft Corporation"))

    def test_trusted_publisher_cn_string(self):
        self.assertTrue(is_trusted_publisher("CN=Google LLC, O=Google LLC, C=US"))
        self.assertTrue(is_trusted_publisher("CN=Microsoft Corporation"))

    def test_untrusted_and_invalid_publishers(self):
        self.assertFalse(is_trusted_publisher("Unknown"))
        self.assertFalse(is_trusted_publisher(""))
        self.assertFalse(is_trusted_publisher(None))
        self.assertFalse(is_trusted_publisher(12345))
        self.assertFalse(is_trusted_publisher("Malicious Software Inc"))

    def test_spoofing_prevention(self):
        # Word boundary prevents "Fake Google LLC" embedded in another word like "GoogleLLCFake"
        self.assertFalse(is_trusted_publisher("GoogleLLCMaliciousCorp"))

    def test_trusted_publishers_database_loading(self):
        trusted_list = _load_trusted_publishers()
        self.assertIsInstance(trusted_list, list)
        self.assertIn("Google LLC", trusted_list)
        self.assertIn("Microsoft Corporation", trusted_list)


class TestSignatureParsing(unittest.TestCase):

    def test_extract_publisher_name_standard(self):
        self.assertEqual(_extract_publisher_name("CN=Google LLC, O=Google LLC, C=US"), "Google LLC")
        self.assertEqual(_extract_publisher_name("CN=\"Microsoft Corporation\", O=Microsoft"), "Microsoft Corporation")
        self.assertEqual(_extract_publisher_name("OU=Dev, CN=Adobe Inc., C=US"), "Adobe Inc.")

    def test_extract_publisher_name_fallback(self):
        self.assertEqual(_extract_publisher_name("Google LLC"), "Google LLC")
        self.assertEqual(_extract_publisher_name(""), "Unknown")
        self.assertEqual(_extract_publisher_name(None), "Unknown")


class TestVerifySignatureFunction(unittest.TestCase):

    def test_verify_signature_nonexistent_file(self):
        res = verify_signature("non_existent_file_path_12345.exe")
        self.assertEqual(res, {"status": "Error", "publisher": "Unknown"})

    def test_verify_signature_invalid_input(self):
        self.assertEqual(verify_signature(None), {"status": "Error", "publisher": "Unknown"})
        self.assertEqual(verify_signature(""), {"status": "Error", "publisher": "Unknown"})

    @patch("analysis.verify_signature.shutil.which", return_value="powershell")
    @patch("analysis.verify_signature.os.path.isfile", return_value=True)
    @patch("analysis.verify_signature.os.stat")
    @patch("subprocess.run")
    def test_verify_signature_valid_powershell(self, mock_subproc, mock_stat, mock_isfile, mock_which):
        mock_stat_obj = MagicMock()
        mock_stat_obj.st_mtime = 1000.0
        mock_stat_obj.st_size = 5000
        mock_stat.return_value = mock_stat_obj

        mock_subproc.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Status": 0, "Publisher": "CN=Google LLC, O=Google LLC"})
        )

        res = verify_signature("/dummy/path/app.exe")
        self.assertEqual(res["status"], "Valid")
        self.assertEqual(res["publisher"], "Google LLC")

    @patch("analysis.verify_signature.shutil.which", return_value="powershell")
    @patch("analysis.verify_signature.os.path.isfile", return_value=True)
    @patch("analysis.verify_signature.os.stat")
    @patch("subprocess.run")
    def test_verify_signature_unsigned(self, mock_subproc, mock_stat, mock_isfile, mock_which):
        mock_stat_obj = MagicMock()
        mock_stat_obj.st_mtime = 2000.0
        mock_stat_obj.st_size = 6000
        mock_stat.return_value = mock_stat_obj

        mock_subproc.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Status": 1, "Publisher": None})
        )

        res = verify_signature("/dummy/path/unsigned.exe")
        self.assertEqual(res["status"], "NotSigned")
        self.assertEqual(res["publisher"], "Unknown")



if __name__ == "__main__":
    unittest.main()
