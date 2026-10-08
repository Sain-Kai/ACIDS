import unittest
from agents.patch_agent import validate_manifest

class PatchManifestSafetyTest(unittest.TestCase):
    def test_accepts_narrow_defensive_manifest(self):
        result = validate_manifest({"patches": [{"kind": "BLOCK_IP", "value": "203.0.113.10"}]})
        self.assertEqual(result["patches"][0]["kind"], "BLOCK_IP")

    def test_rejects_threshold_patch(self):
        with self.assertRaises(ValueError):
            validate_manifest({"patches": [{"kind": "RECLAIM_THRESHOLD", "value": "0.1"}]})

    def test_rejects_local_or_control_addresses(self):
        for ip in ["127.0.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0"]:
            with self.assertRaises(ValueError):
                validate_manifest({"patches": [{"kind": "BLOCK_IP", "value": ip}]})

    def test_rejects_extra_manifest_fields(self):
        with self.assertRaises(ValueError):
            validate_manifest({"patches": [{"kind": "BLOCK_IP", "value": "203.0.113.10", "command": "rm -rf /"}]})

if __name__ == "__main__":
    unittest.main()
