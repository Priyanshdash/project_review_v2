"""Comprehensive test suite for CyberSentinel-LLM.
Tests data preprocessing, Drain template extraction, sinusoidal temporal encoding,
ML classification, LLM response parsing, 4-agent coordination, PPO response orchestrator,
and SOC operational metrics.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath("."))

from cybersentinel.features import drain_extract_template, sinusoidal_temporal_encoding, LogFeatureExtractor
from cybersentinel.data import relabel_hdfs_anomalous_session, split_dataset, THREAT_CLASSES
from cybersentinel.ml_classifiers import MLThreatClassifier
from cybersentinel.llm_client import CyberSentinelLLMClient
from cybersentinel.agents import CyberSentinelCoordinator, SharedMemory, RESPONSE_ACTIONS
from cybersentinel.ppo_orchestrator import CyberIncidentEnv, PPOPolicyNetwork
from cybersentinel.metrics import compute_soc_operational_metrics


class TestCyberSentinel(unittest.TestCase):

    def test_drain_template_extraction(self):
        log_sample = "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating at 10.251.73.220:50010"
        tpl = drain_extract_template(log_sample)
        self.assertIn("<*BLK*>", tpl)
        self.assertIn("<*IP*>", tpl)

    def test_sinusoidal_temporal_encoding(self):
        timestamps = [100.0, 200.0, 300.0]
        enc = sinusoidal_temporal_encoding(timestamps, d_t=16)
        self.assertEqual(enc.shape, (3, 16))
        self.assertTrue(np.all(np.isfinite(enc)))

    def test_feature_extractor_dimension_consistency(self):
        extractor = LogFeatureExtractor(max_features=50, d_t=16)
        texts = [
            "Receiving block blk_1 src: 10.0.0.1 dest: 10.0.0.2",
            "PacketResponder 1 terminating with timeout"
        ]
        feats = extractor.fit_transform(texts, [1.0, 2.0])
        # Test transform without timestamps supplies identical feature dimension
        feats_no_ts = extractor.transform(texts)
        self.assertEqual(feats.shape[1], feats_no_ts.shape[1])
        self.assertTrue(feats.shape[1] > 16)

    def test_mitre_threat_relabelling(self):
        apt_log = "Lateral movement pattern confirmed (3 DataNode accesses in 7s) exfiltration via disguised HTTP"
        self.assertEqual(relabel_hdfs_anomalous_session(apt_log), "APT")

        ddos_log = "Connection flood: PacketResponder interrupted repeatedly with timeout and exception"
        self.assertEqual(relabel_hdfs_anomalous_session(ddos_log), "DDoS")

        insider_log = "Repeated authentication failure from user root and unauthorized privilege escalation"
        self.assertEqual(relabel_hdfs_anomalous_session(insider_log), "Insider Threat")

    def test_dataset_splitting_no_leakage(self):
        df = pd.DataFrame({
            "block_id": [f"blk_{i}" for i in range(100)],
            "text": [f"log {i}" for i in range(100)],
            "label": [0] * 80 + [1] * 20,
            "threat_class": ["Normal"] * 80 + ["Malware"] * 20,
            "threat_id": [0] * 80 + [1] * 20,
            "timestamp": list(range(100))
        })
        train, val, test = split_dataset(df, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, random_state=42)
        self.assertEqual(len(train), 80)
        self.assertEqual(len(val), 10)
        self.assertEqual(len(test), 10)
        # Check disjoint sets
        train_ids = set(train["block_id"])
        val_ids = set(val["block_id"])
        test_ids = set(test["block_id"])
        self.assertEqual(len(train_ids.intersection(val_ids)), 0)
        self.assertEqual(len(train_ids.intersection(test_ids)), 0)

    def test_llm_structured_reasoning(self):
        client = CyberSentinelLLMClient()
        log = "Lateral movement pattern confirmed with disguised HTTP exfiltration"
        res = client.analyze_log(log)
        self.assertTrue(res["is_anomaly"])
        self.assertEqual(res["threat_type"], "APT")
        self.assertIn("T1078", res.get("mitre_techniques", []))

    def test_forensic_report_generation(self):
        client = CyberSentinelLLMClient()
        log = "Receiving block blk_-123456 src: 10.0.0.1 dest: 10.0.0.2 with authentication failures"
        report = client.generate_forensic_report(
            log, "APT", {"confidence": 0.95, "mitre_techniques": ["T1078"], "severity": "CRITICAL"}, "Network isolation"
        )
        self.assertIn("CYBERSENTINEL-LLM INCIDENT FORENSIC REPORT", report)
        self.assertIn("Executive Summary", report)
        self.assertIn("Evidence and Indicators of Compromise", report)
        self.assertIn("Recommended Response Actions", report)

    def test_4agent_collaborative_workflow(self):
        coordinator = CyberSentinelCoordinator()
        log = "08:42:02 INFO dfs.DataNode: Lateral movement pattern confirmed (3 DataNode accesses in 7s)"
        mem = coordinator.process_incident(log, incident_id="TEST-INC-1")
        self.assertTrue(mem.is_anomaly)
        self.assertEqual(mem.threat_category, "APT")
        self.assertIn("Network isolation", mem.selected_action)
        self.assertTrue(len(mem.audit_trace) >= 4)
        self.assertTrue(len(mem.forensic_report) > 0)

    def test_ppo_incident_env_and_policy(self):
        env = CyberIncidentEnv()
        s0 = env.reset()
        self.assertEqual(s0.shape, (4,))
        next_s, reward, done, info = env.step(action=1)
        self.assertTrue(isinstance(reward, float))

        policy = PPOPolicyNetwork()
        act = policy.predict_action(s0)
        self.assertTrue(0 <= act < 7)

    def test_soc_operational_kpi_computation(self):
        dummy_incidents = [
            {
                "is_anomaly": True, "detected_anomaly": True,
                "detection_time_sec": 120.0, "response_time_sec": 5.0, "resolve_time_sec": 500.0,
                "action_taken": "Network isolation", "is_containment_successful": True,
                "is_disruptive_fp": False, "requires_human_escalation": False
            },
            {
                "is_anomaly": False, "detected_anomaly": False,
                "detection_time_sec": 30.0, "response_time_sec": 0.0, "resolve_time_sec": 0.0,
                "action_taken": "No action", "is_containment_successful": False,
                "is_disruptive_fp": False, "requires_human_escalation": False
            }
        ]
        kpis = compute_soc_operational_metrics(dummy_incidents)
        self.assertIn("MTTD (min)", kpis)
        self.assertIn("MTTR Response (min)", kpis)
        self.assertIn("Automation Rate (%)", kpis)
        self.assertEqual(kpis["Automation Rate (%)"], 100.0)
        self.assertEqual(kpis["FPR (%)"], 0.0)


if __name__ == "__main__":
    unittest.main()
