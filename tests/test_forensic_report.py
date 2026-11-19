"""Tests for CyberSentinel-LLM 19-Section Forensic Investigation Engine.
Validates report structure, evidence referencing (E-001, E-002, E-003),
timestamp preservation, simulated mitigation status, and printable HTML generation.
"""

import os
import sys
import unittest

os.environ["CYBERSENTINEL_OFFLINE_LLM"] = "1"
sys.path.insert(0, os.path.abspath("."))

from cybersentinel.forensic import ForensicReportGenerator, parse_evidence_records
from cybersentinel.agents import CyberSentinelCoordinator, SharedMemory


class TestForensicReportEngine(unittest.TestCase):

    def setUp(self):
        self.sample_logs = (
            "14:22:10 WARN auth.SecurityManager: Repeated authentication failures from user root on console session\n"
            "14:22:15 ALERT auth.SecurityManager: Unauthorized privilege escalation attempted by process PID_9921\n"
            "14:22:20 WARN dfs.FSNamesystem: Permission denied: user root is not authorized to export cryptographic keys"
        )
        self.generator = ForensicReportGenerator()

    def test_evidence_record_parsing(self):
        records = parse_evidence_records(self.sample_logs)
        self.assertEqual(len(records), 3)

        # Sequential IDs
        self.assertEqual(records[0].evidence_id, "E-001")
        self.assertEqual(records[1].evidence_id, "E-002")
        self.assertEqual(records[2].evidence_id, "E-003")

        # Preserved exact timestamps
        self.assertEqual(records[0].timestamp, "14:22:10")
        self.assertEqual(records[1].timestamp, "14:22:15")
        self.assertEqual(records[2].timestamp, "14:22:20")

        # Extracted fields
        self.assertEqual(records[0].user_account, "root")
        self.assertEqual(records[1].process_id, "PID_9921")
        self.assertIn("Cryptographic Key", records[2].target_resource)

        # Integrity SHA-256 hashes
        for r in records:
            self.assertEqual(len(r.sha256_hash), 64)

    def test_full_report_structure_and_depth(self):
        res = self.generator.generate_full_report(
            log_text=self.sample_logs,
            threat_class="Insider Threat",
            detection_score=0.94,
            classification_confidence=0.95,
            selected_action="User account suspension for insider threat (SIMULATED)",
            incident_id="INC-TEST-001"
        )

        md = res["markdown"]
        html = res["printable_html"]

        # Ensure no placeholder artifact remains
        self.assertNotIn("[BLK_SESSION_DATA]", md)
        self.assertNotIn("00:00:00 UTC", md)

        # Evidence references in narrative and analysis
        self.assertIn("E-001", md)
        self.assertIn("E-002", md)
        self.assertIn("E-003", md)

        # Verify key sections exist
        self.assertIn("## 1. Incident Identification and Metadata", md)
        self.assertIn("## 2. Executive Summary", md)
        self.assertIn("## 3. Detailed Incident Narrative", md)
        self.assertIn("## 4. Event-by-Event Technical Analysis", md)
        self.assertIn("## 5. Evidence Correlation and Attack Progression", md)
        self.assertIn("## 6. Indicators of Compromise", md)
        self.assertIn("## 7. MITRE ATT&CK", md)
        self.assertIn("## 8. Threat Classification and Severity Assessment", md)
        self.assertIn("## 9. Root-Cause Analysis and Competing Hypotheses", md)
        self.assertIn("## 10. Affected Assets and Potential Impact", md)
        self.assertIn("## 11. Timeline and Investigation Activity", md)
        self.assertIn("## 12. Multi-Agent Investigation Trace", md)
        self.assertIn("## 13. Response Decision and Technical Justification", md)
        self.assertIn("## 14. Investigation Gaps and Additional Evidence Required", md)
        self.assertIn("## 15. Remediation, Containment, and Recovery Plan", md)
        self.assertIn("## 16. Residual Risk and Confidence Limitations", md)
        self.assertIn("## 17. Evidence Integrity", md)
        self.assertIn("## 18. Final Assessment and Conclusion", md)
        self.assertIn("## 19. Technical Appendices", md)

        # Response must be explicitly marked as SIMULATED
        self.assertIn("SIMULATED", md)
        self.assertIn("SIMULATED", html)
        self.assertNotIn("AUTOMATED — COMPLETED", md)

        # Printable HTML verification
        self.assertIn("@media print", html)
        self.assertIn("window.print()", html)
        self.assertIn("E-001", html)

    def test_coordinator_integration(self):
        coordinator = CyberSentinelCoordinator()
        mem = coordinator.process_incident(self.sample_logs, incident_id="INC-UNIT-42")

        self.assertTrue(mem.is_anomaly)
        self.assertEqual(mem.threat_category, "Insider Threat")
        self.assertTrue(len(mem.forensic_report) > 500)
        self.assertTrue(len(mem.forensic_html) > 500)
        self.assertIn("INC-UNIT-42", mem.forensic_report)
        self.assertIn("E-001", mem.forensic_report)

    def test_app_dashboard_section_rendering(self):
        """Simulates all field accesses performed by app.py Tab 1."""
        coordinator = CyberSentinelCoordinator()
        mem = coordinator.process_incident(self.sample_logs)

        sec_data = mem.forensic_data.get("structured_sections", {})
        records = mem.forensic_data.get("records", [])

        # Correlations
        for c in sec_data.get("correlations", []):
            e1 = c.get("earlier_event", c.get("earlier", "N/A"))
            e2 = c.get("later_event", c.get("later", "N/A"))
            interp = c.get("possible_interpretation", c.get("interpretation", "N/A"))
            conf = c.get("confidence", "Moderate")
            rendered = f"- **`{e1}` → `{e2}`**: {interp} *(Confidence: {conf})*"
            self.assertTrue(len(rendered) > 5)

        # IoCs
        for i in sec_data.get("iocs", []):
            rendered = f"- `{i.get('value')}` ({i.get('type')}): {i.get('relevance')} [{i.get('status')}]"
            self.assertTrue(len(rendered) > 5)

        # MITRE
        for m in sec_data.get("mitre", []):
            rendered = f"- **{m.get('id')} - {m.get('name')}**: {m.get('relevance')} *(Status: {m.get('status')})*"
            self.assertTrue(len(rendered) > 5)

        # Hypotheses
        for h in sec_data.get("hypotheses", []):
            h_name = h.get("hypothesis", h.get("name", "Hypothesis"))
            h_status = h.get("status", "Candidate")
            h_desc = h.get("description", "")
            h_supp = h.get("supporting_evidence", h.get("supporting", "None"))
            h_contra = h.get("contradicting_evidence", h.get("contradicting", "None"))
            rendered = f"- **{h_name}** [{h_status}]: {h_desc} | Supp: {h_supp} | Contra: {h_contra}"
            self.assertTrue(len(rendered) > 5)

        # Assets
        assets_data = sec_data.get("assets", {})
        self.assertIsInstance(assets_data, dict)
        self.assertTrue("directly_observed" in assets_data)
        self.assertTrue("potentially_affected" in assets_data)
        self.assertTrue("requiring_investigation" in assets_data)

        # Response
        resp = sec_data.get("response", {})
        self.assertTrue("action" in resp)
        self.assertTrue("status" in resp)

        # Remediation
        for step in sec_data.get("remediation", []):
            rendered = f"- **[{step.get('priority')}] {step.get('phase')}:** {step.get('action')} *(Role: {step.get('role')})*"
            self.assertTrue(len(rendered) > 5)


if __name__ == "__main__":
    unittest.main()
