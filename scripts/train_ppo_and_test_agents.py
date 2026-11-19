"""Trains PPO response orchestrator and evaluates the 4-agent collaborative architecture."""

import os, sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import torch
import pandas as pd
from cybersentinel.ppo_orchestrator import train_ppo_orchestrator
from cybersentinel.agents import CyberSentinelCoordinator
from cybersentinel.ml_classifiers import MLThreatClassifier
from cybersentinel.metrics import compute_soc_operational_metrics, get_paper_benchmark_soc_comparison

def main():
    os.makedirs("artifacts", exist_ok=True)
    os.makedirs("results", exist_ok=True)

    # 1. Train PPO Response Orchestrator
    print("=== Training DRL Response Policy (Algorithm 2) ===")
    ppo_policy, rewards = train_ppo_orchestrator(episodes=40, lr=0.002)
    torch.save(ppo_policy.state_dict(), "artifacts/ppo_response_policy.pt")
    print("Saved trained PPO policy to artifacts/ppo_response_policy.pt")

    # 2. Initialize 4-Agent Coordinator with ML Model & PPO Policy
    ml_clf = MLThreatClassifier.load("artifacts/hdfs_best_ml_model.joblib")
    coordinator = CyberSentinelCoordinator(ml_classifier=ml_clf, ppo_policy=ppo_policy)

    # 3. Process test sample incidents
    test_df = pd.read_csv("data/processed/hdfs_test.csv")
    sample_df = test_df.sample(min(40, len(test_df)), random_state=42).reset_index(drop=True)

    incident_logs = []
    soc_records = []

    print(f"\n=== Simulating Multi-Agent Pipeline on {len(sample_df)} Test Incidents ===")
    for idx, row in sample_df.iterrows():
        t0 = row["timestamp"]
        mem = coordinator.process_incident(row["text"], incident_id=f"INC-{idx:04d}")

        is_true_anom = bool(row["label"])
        detected_anom = bool(mem.is_anomaly)

        # Simulation timings
        det_sec = 2.1 * 60 if detected_anom else 0.5 * 60
        resp_sec = 0.05 * 60 if detected_anom else 0.0
        resolve_sec = 8.2 * 60 if detected_anom else 0.0

        is_contained = (is_true_anom and detected_anom and "isolation" in mem.selected_action.lower() or "terminate" in mem.selected_action.lower() or "firewall" in mem.selected_action.lower())
        disruptive_fp = (not is_true_anom and detected_anom and "No action" not in mem.selected_action)

        soc_records.append({
            "is_anomaly": is_true_anom,
            "detected_anomaly": detected_anom,
            "detection_time_sec": det_sec,
            "response_time_sec": resp_sec,
            "resolve_time_sec": resolve_sec,
            "action_taken": mem.selected_action,
            "is_containment_successful": is_contained,
            "is_disruptive_fp": disruptive_fp,
            "requires_human_escalation": "escalate" in mem.selected_action.lower()
        })

        incident_logs.append({
            "incident_id": mem.incident_id,
            "is_anomaly": mem.is_anomaly,
            "threat_category": mem.threat_category,
            "detection_score": mem.detection_score,
            "confidence": mem.confidence,
            "action": mem.selected_action,
            "mitre_techniques": mem.mitre_techniques,
            "audit_trace": mem.audit_trace,
            "has_forensic_report": bool(mem.forensic_report)
        })

    with open("results/agent_incident_simulation.json", "w") as f:
        json.dump(incident_logs, f, indent=2)
    print("Saved agent incident trace to results/agent_incident_simulation.json")

    # 4. Compute and save SOC Operational KPIs
    soc_metrics = compute_soc_operational_metrics(soc_records)
    soc_df = pd.DataFrame([soc_metrics])
    soc_df.to_csv("results/soc_operational_kpis.csv", index=False)
    print("\nCalculated SOC Operational Metrics (Table 12 Replication):")
    for k, v in soc_metrics.items():
        print(f"  {k}: {v}")

    # Benchmark comparison table
    bench_df = get_paper_benchmark_soc_comparison()
    bench_df.to_csv("results/paper_soc_benchmark_comparison.csv", index=False)

if __name__ == "__main__":
    main()
