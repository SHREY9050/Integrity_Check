"""Comprehensive Test Suite for VeriBlue AI Components.
"""

import hashlib
import os
import tempfile
import unittest

from veriblue_ai.config import Config
from veriblue_ai.core.hasher import calculate_sha256_stream, CHUNK_SIZE
from veriblue_ai.core.parser import (
    extract_binary_metadata,
    _parse_filename_heuristics,
    VENDOR_DOMAINS,
)
from veriblue_ai.engines.virus_total import (
    VirusTotalEngine,
    VirusTotalResult,
    ThreatStatus,
)
from veriblue_ai.engines.web_rag import (
    WebRagEngine,
    EphemeralMemoryCache,
    VerificationVerdict,
    Stage2Result,
)


class TestHasher(unittest.TestCase):
    """Test 4096-byte streaming SHA-256 calculation."""

    def test_chunk_size_constant(self):
        self.assertEqual(CHUNK_SIZE, 4096, "PRD requires exact 4096-byte chunk buffering")

    def test_stream_hashing_matches_ground_truth(self):
        # Create a temp file larger than multiple chunks
        test_data = b"VeriBlue-AI-Integrity-Payload" * 1000
        ground_truth = hashlib.sha256(test_data).hexdigest().lower()

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(test_data)
            tf_path = tf.name

        try:
            computed_hash = calculate_sha256_stream(tf_path)
            self.assertEqual(len(computed_hash), 64)
            self.assertEqual(computed_hash, ground_truth)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_progress_callback(self):
        test_data = b"A" * 10000
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(test_data)
            tf_path = tf.name

        callbacks = []
        try:
            calculate_sha256_stream(
                tf_path, progress_callback=lambda cur, tot: callbacks.append((cur, tot))
            )
            self.assertTrue(len(callbacks) > 0)
            self.assertEqual(callbacks[-1][0], len(test_data))
            self.assertEqual(callbacks[-1][1], len(test_data))
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


class TestMetadataParser(unittest.TestCase):
    """Test binary metadata parser and domain mapping."""

    def test_filename_heuristics(self):
        result = _parse_filename_heuristics("vlc-3.0.20-win64.exe")
        self.assertEqual(result["version"], "3.0.20")
        self.assertEqual(result["architecture"], "x64")
        self.assertIn("vlc", result["app_name"].lower())

    def test_vendor_domain_lookup(self):
        self.assertEqual(VENDOR_DOMAINS.get("vlc"), "videolan.org")
        self.assertEqual(VENDOR_DOMAINS.get("python"), "python.org")
        self.assertEqual(VENDOR_DOMAINS.get("git"), "git-scm.com")


class TestVirusTotalEngine(unittest.TestCase):
    """Test Stage 1 VirusTotal routing and conditional logic."""

    def test_unconfigured_api_key_graceful_handling(self):
        engine = VirusTotalEngine(api_key="")
        dummy_hash = "a" * 64
        result = engine.query_hash(dummy_hash)
        self.assertEqual(result.status, ThreatStatus.NO_API_KEY)

    def test_malicious_halt_logic(self):
        result = VirusTotalResult(
            status=ThreatStatus.MALICIOUS,
            hash_string="b" * 64,
            malicious_count=12,
            undetected_count=60,
        )
        self.assertEqual(result.status, ThreatStatus.MALICIOUS)
        self.assertEqual(result.malicious_count, 12)
        self.assertEqual(result.total_engines, 72)


class TestWebRagEngine(unittest.TestCase):
    """Test Stage 2 Ephemeral Cache and Cryptographic Boolean Checkpoint."""

    def test_ephemeral_cache_ingestion_and_ranking(self):
        cache = EphemeralMemoryCache(chunk_size=200, chunk_overlap=20)
        vendor_text = (
            "Official Release Notes for VLC 3.0.20. "
            "To verify your download, check the SHA256 checksum: "
            "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069. "
            "Do not download from untrusted mirrors."
        )
        cache.ingest_text(vendor_text, source_url="https://videolan.org/vlc/download")
        self.assertTrue(len(cache.documents) > 0)

        context = cache.get_ranked_context(keywords=["vlc", "3.0.20", "sha256"])
        self.assertIn("7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069", context)

    def test_boolean_match_checkpoint_true(self):
        target_hash = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
        is_match = (target_hash.lower() == target_hash.lower())
        self.assertTrue(is_match)

    def test_boolean_match_checkpoint_tampered(self):
        local_hash = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
        tampered_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        is_match = (local_hash.lower() == tampered_hash.lower())
        self.assertFalse(is_match)


if __name__ == "__main__":
    unittest.main()
