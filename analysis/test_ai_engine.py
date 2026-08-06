"""
InstallShield AI - AI Module Comprehensive Test Suite
Tests Risk Scoring, Threat Classification, Recommendations, Explainable AI, PDF Generation, and Facade.
"""

import os
import tempfile
import unittest

from ai.scoring import RiskScoringEngine
from ai.classification import ThreatClassifier
from ai.recommendation import RecommendationEngine
from ai.explanation import ExplainableAIGenerator
from ai.pdf_generator import PDFReportGenerator
from ai.engine import AIEngine


class TestRiskScoringEngine(unittest.TestCase):
    """Unit tests for Risk Scoring Engine."""

    def test_trusted_publisher_valid_sig(self):
        sig_info = {"status": "Valid", "publisher": "Google LLC"}
        entropy_stats = {"verdict": "Normal"}
        string_analysis = {"suspicious_apis": [], "suspicious_keywords": [], "urls": []}
        file_metadata = {"file_type": "PE Executable (Windows EXE/DLL)", "magic_bytes": "4D5A", "file_size": 1048576}

        res = RiskScoringEngine.calculate_score(
            sig_info=sig_info,
            is_trusted_publisher=True,
            entropy=5.2,
            entropy_stats=entropy_stats,
            string_analysis=string_analysis,
            file_metadata=file_metadata
        )

        self.assertLessEqual(res["risk_score"], 20)
        self.assertEqual(res["risk_tier"], "Trusted")
        self.assertEqual(len(res["flags"]), 0)

    def test_unsigned_high_entropy_suspicious_apis(self):
        sig_info = {"status": "NotSigned", "publisher": "Unknown"}
        entropy_stats = {"verdict": "Likely Packed/Compressed"}
        string_analysis = {
            "suspicious_apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "suspicious_keywords": ["cmd.exe", "powershell"],
            "urls": ["http://malicious-c2.com/payload.exe"]
        }
        file_metadata = {"file_type": "PE Executable (Windows EXE/DLL)", "magic_bytes": "4D5A", "file_size": 524288}

        res = RiskScoringEngine.calculate_score(
            sig_info=sig_info,
            is_trusted_publisher=False,
            entropy=7.6,
            entropy_stats=entropy_stats,
            string_analysis=string_analysis,
            file_metadata=file_metadata
        )

        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertIn(res["risk_tier"], ["High Risk", "Malicious"])
        self.assertGreater(len(res["flags"]), 2)
        self.assertTrue(any("VirtualAllocEx" in f or "code injection" in f for f in res["flags"]))

    def test_score_clamping(self):
        # Extreme malicious indicators that exceed 100 points raw
        sig_info = {"status": "HashMismatch", "publisher": "Fake Co"}
        entropy_stats = {"verdict": "Highly Encrypted/Packed"}
        string_analysis = {
            "suspicious_apis": ["VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"],
            "suspicious_keywords": ["cmd.exe", "powershell", "wscript.exe", "mimikatz", "downloadstring"],
            "urls": ["http://bad1.com", "http://bad2.com", "http://bad3.com"]
        }
        file_metadata = {"file_type": "PE Executable", "magic_bytes": "0000", "file_size": 2048}

        res = RiskScoringEngine.calculate_score(
            sig_info=sig_info,
            is_trusted_publisher=False,
            entropy=7.9,
            entropy_stats=entropy_stats,
            string_analysis=string_analysis,
            file_metadata=file_metadata
        )

        self.assertEqual(res["risk_score"], 100)
        self.assertEqual(res["risk_tier"], "Malicious")


class TestThreatClassifier(unittest.TestCase):
    """Unit tests for Threat Classification Engine."""

    def test_trusted_classification(self):
        res = ThreatClassifier.classify(
            risk_score=10,
            sig_info={"status": "Valid", "publisher": "Microsoft Corporation"},
            is_trusted_publisher=True,
            entropy=4.8,
            entropy_stats={"verdict": "Normal"},
            string_analysis={"suspicious_apis": [], "suspicious_keywords": [], "urls": []}
        )
        self.assertEqual(res["category"], "Trusted Software")
        self.assertEqual(res["confidence"], "High")

    def test_ransomware_classification(self):
        res = ThreatClassifier.classify(
            risk_score=85,
            sig_info={"status": "NotSigned", "publisher": "Unknown"},
            is_trusted_publisher=False,
            entropy=7.8,
            entropy_stats={"verdict": "Highly Encrypted/Packed"},
            string_analysis={"suspicious_apis": ["VirtualProtectEx", "WriteProcessMemory"], "suspicious_keywords": ["vssadmin", "shadow", "encrypt"]}
        )
        self.assertEqual(res["category"], "Ransomware")

    def test_backdoor_classification(self):
        res = ThreatClassifier.classify(
            risk_score=75,
            sig_info={"status": "NotSigned", "publisher": "Unknown"},
            is_trusted_publisher=False,
            entropy=6.9,
            entropy_stats={"verdict": "Normal"},
            string_analysis={"suspicious_apis": ["CreateRemoteThread"], "suspicious_keywords": ["powershell", "downloadstring"], "urls": ["http://c2.net"]}
        )
        self.assertEqual(res["category"], "Backdoor")

    def test_packed_executable_classification(self):
        res = ThreatClassifier.classify(
            risk_score=45,
            sig_info={"status": "NotSigned", "publisher": "Unknown"},
            is_trusted_publisher=False,
            entropy=7.5,
            entropy_stats={"verdict": "Likely Packed/Compressed"},
            string_analysis={"suspicious_apis": [], "suspicious_keywords": [], "urls": []}
        )
        self.assertEqual(res["category"], "Packed Executable")


class TestRecommendationEngine(unittest.TestCase):
    """Unit tests for Recommendation Engine."""

    def test_high_risk_recommendations(self):
        recs = RecommendationEngine.generate_recommendations(
            risk_score=85,
            risk_tier="Malicious",
            threat_category="Ransomware",
            sig_info={"status": "NotSigned", "publisher": "Unknown"},
            is_trusted_publisher=False,
            entropy=7.7,
            flags=["Unsigned executable", "Extreme entropy"]
        )
        actions = [r["action"] for r in recs]
        self.assertIn("Do Not Execute", actions)
        self.assertIn("Delete Immediately", actions)
        self.assertIn("Upload to VirusTotal", actions)

    def test_trusted_recommendations(self):
        recs = RecommendationEngine.generate_recommendations(
            risk_score=10,
            risk_tier="Trusted",
            threat_category="Trusted Software",
            sig_info={"status": "Valid", "publisher": "Google LLC"},
            is_trusted_publisher=True,
            entropy=5.0,
            flags=[]
        )
        actions = [r["action"] for r in recs]
        self.assertIn("Safe to Install", actions)


class TestExplainableAIGenerator(unittest.TestCase):
    """Unit tests for Explainable AI Engine."""

    def test_explanation_generation(self):
        breakdown = [
            {"factor": "Digital Signature", "weight": 25, "reason": "Binary is unsigned"},
            {"factor": "Entropy", "weight": 25, "reason": "High entropy detected"}
        ]
        res = ExplainableAIGenerator.generate_explanation(
            risk_score=65,
            risk_tier="High Risk",
            threat_category="Suspicious Installer",
            sig_info={"status": "NotSigned", "publisher": "Unknown"},
            is_trusted_publisher=False,
            entropy=7.4,
            string_analysis={"suspicious_apis": ["VirtualAlloc"], "suspicious_keywords": ["cmd.exe"], "urls": []},
            score_breakdown=breakdown,
            flags=["Unsigned executable"]
        )

        self.assertIn("summary_narrative", res)
        self.assertIn("risk_factors", res)
        self.assertIn("positive_indicators", res)
        self.assertTrue(len(res["summary_narrative"]) > 50)
        self.assertEqual(len(res["risk_factors"]), 2)


class TestPDFReportGenerator(unittest.TestCase):
    """Unit & Integration tests for PDF Security Report Generator."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.pdf_path = os.path.join(self.test_dir, "test_report.pdf")

    def tearDown(self):
        if os.path.exists(self.pdf_path):
            os.remove(self.pdf_path)
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)

    def test_pdf_generation(self):
        sample_analysis = {
            "scan_id": 101,
            "filename": "sample_setup.exe",
            "savedTo": "/tmp/sample_setup.exe",
            "risk_score": 65,
            "risk_tier": "High Risk",
            "threat_category": "Suspicious Installer",
            "signature_status": "NotSigned",
            "publisher": "Unknown",
            "is_trusted": False,
            "entropy": 7.4,
            "entropy_verdict": "Likely Packed/Compressed",
            "hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            "metadata": {"file_size": 1048576, "file_type": "PE Executable (Windows EXE/DLL)", "magic_bytes": "4D5A"},
            "suspicious_apis": ["VirtualAlloc", "WriteProcessMemory"],
            "suspicious_keywords": ["cmd.exe", "powershell"],
            "urls": ["http://example.com/check"],
            "score_breakdown": [{"factor": "Digital Signature", "weight": 25, "reason": "Unsigned"}],
            "flags": ["Unsigned binary", "High entropy"],
            "explanation": {
                "summary_narrative": "Detailed security breakdown narrative for test installer.",
                "positive_indicators": ["Normal header bytes"],
                "risk_factors": ["[Digital Signature (+25 pts)] Unsigned"]
            },
            "recommendations": [
                {"action": "Do Not Execute", "level": "CRITICAL", "description": "Do not run this file."},
                {"action": "Run Inside Sandbox", "level": "HIGH", "description": "Isolate file testing."}
            ]
        }

        pdf_result_path = PDFReportGenerator.generate_report(sample_analysis, self.pdf_path)
        self.assertTrue(os.path.exists(pdf_result_path))
        self.assertGreater(os.path.getsize(pdf_result_path), 500)


class TestAIEngineFacade(unittest.TestCase):
    """Integration test for unified AIEngine facade."""

    def test_full_analysis_pipeline(self):
        sig_info = {"status": "Valid", "publisher": "Google LLC"}
        entropy_stats = {"verdict": "Normal"}
        string_analysis = {"suspicious_apis": [], "suspicious_keywords": [], "urls": []}
        file_metadata = {"file_type": "PE Executable", "magic_bytes": "4D5A", "file_size": 500000}
        hashes = {"md5": "abc", "sha1": "def", "sha256": "ghi"}

        res = AIEngine.analyze(
            sig_info=sig_info,
            is_trusted_publisher=True,
            entropy=5.1,
            entropy_stats=entropy_stats,
            string_analysis=string_analysis,
            file_metadata=file_metadata,
            hashes=hashes,
            filename="chrome_installer.exe",
            filepath="/tmp/chrome_installer.exe"
        )

        self.assertIn("risk_score", res)
        self.assertIn("risk_tier", res)
        self.assertIn("threat_category", res)
        self.assertIn("recommendations", res)
        self.assertIn("explanation", res)
        self.assertEqual(res["threat_category"], "Trusted Software")


if __name__ == "__main__":
    unittest.main()
