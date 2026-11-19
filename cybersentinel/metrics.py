"""Operational Security Operations Center (SOC) Key Performance Indicators (KPIs).
Implements the metrics defined in Section 5.12 and Table 12 of the research paper:
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR respond)
- Mean Time to Resolve (MTTR resolve)
- False Positive Rate (FPR)
- Actionable Alerts Ratio (Alert Fatigue)
- Automated Resolution Rate (Automation Rate)
- Containment Success Rate (CSR)
- False Mitigation Rate (FMR)
- Response Cost Score (RCS)
"""

from __future__ import annotations
import numpy as np
import pandas as pd


def compute_soc_operational_metrics(incidents: list[dict]) -> dict:
    """Computes Table 12 SOC operational metrics from a list of processed incident records.
    Each incident dict should contain:
    - is_anomaly (bool or int: ground truth)
    - detected_anomaly (bool or int: predicted)
    - detection_time_sec (float)
    - response_time_sec (float)
    - resolve_time_sec (float)
    - action_taken (str)
    - is_containment_successful (bool)
    - is_disruptive_fp (bool)
    - requires_human_escalation (bool)
    """
    total_incidents = len(incidents)
    if total_incidents == 0:
        return {}

    detection_times = [i["detection_time_sec"] for i in incidents]
    response_times = [i["response_time_sec"] for i in incidents]
    resolve_times = [i["resolve_time_sec"] for i in incidents]

    # MTTD, MTTR in minutes
    mttd_min = round(float(np.mean(detection_times)) / 60.0, 2)
    mttr_resp_min = round(float(np.mean(response_times)) / 60.0, 3)
    mttr_resolve_min = round(float(np.mean(resolve_times)) / 60.0, 2)

    # Classification breakdown
    benign_total = sum(1 for i in incidents if not i["is_anomaly"])
    fp_count = sum(1 for i in incidents if not i["is_anomaly"] and i["detected_anomaly"])
    fpr = round((fp_count / max(benign_total, 1)) * 100, 2)

    total_alerts = sum(1 for i in incidents if i["detected_anomaly"])
    actionable_alerts = sum(1 for i in incidents if i["detected_anomaly"] and i["is_anomaly"])
    alert_fatigue_ratio = round((actionable_alerts / max(total_alerts, 1)) * 100, 2)

    automated_count = sum(1 for i in incidents if not i.get("requires_human_escalation", False))
    automation_rate = round((automated_count / total_incidents) * 100, 2)

    anomalies_total = sum(1 for i in incidents if i["is_anomaly"])
    contained_count = sum(1 for i in incidents if i["is_anomaly"] and i.get("is_containment_successful", False))
    csr = round((contained_count / max(anomalies_total, 1)) * 100, 2)

    false_mitigations = sum(1 for i in incidents if i.get("is_disruptive_fp", False))
    fmr = round((false_mitigations / max(total_incidents, 1)) * 100, 2)

    # Response Cost Score: weighted sum of false mitigations and resolution latency
    rcs = round(float((false_mitigations * 1.5 + (mttr_resolve_min / 10.0)) / max(total_incidents, 1)), 2)

    return {
        "MTTD (min)": mttd_min,
        "MTTR Response (min)": mttr_resp_min,
        "MTTR Resolve (min)": mttr_resolve_min,
        "FPR (%)": fpr,
        "Alert Fatigue Ratio (%)": alert_fatigue_ratio,
        "Automation Rate (%)": automation_rate,
        "Containment Success Rate (%)": csr,
        "False Mitigation Rate (%)": fmr,
        "Response Cost Score": rcs
    }


def get_paper_benchmark_soc_comparison() -> pd.DataFrame:
    """Returns the paper's Table 12 benchmark comparison table."""
    data = [
        {"Metric": "MTTD", "Definition": "Mean Time to Detect", "CyberSentinel-LLM": "2.3 min", "Manual SOC": "18.7 min"},
        {"Metric": "MTTR (respond)", "Definition": "Mean Time to Respond", "CyberSentinel-LLM": "0.08 min", "Manual SOC": "12.4 min"},
        {"Metric": "MTTR (resolve)", "Definition": "Mean Time to Resolve", "CyberSentinel-LLM": "8.5 min", "Manual SOC": "47.3 min"},
        {"Metric": "FPR", "Definition": "False Positive Rate", "CyberSentinel-LLM": "1.2%", "Manual SOC": "3.8%"},
        {"Metric": "Alert Fatigue", "Definition": "Actionable Alerts Ratio", "CyberSentinel-LLM": "98.8%", "Manual SOC": "96.2%"},
        {"Metric": "Automation", "Definition": "Automated Resolution Rate", "CyberSentinel-LLM": "94.2%", "Manual SOC": "12.5%"},
        {"Metric": "CSR", "Definition": "Containment Success Rate", "CyberSentinel-LLM": "91.5%", "Manual SOC": "67.3%"},
        {"Metric": "FMR", "Definition": "False Mitigation Rate", "CyberSentinel-LLM": "3.2%", "Manual SOC": "N/A (manual)"},
        {"Metric": "RCS", "Definition": "Response Cost Score", "CyberSentinel-LLM": "0.23", "Manual SOC": "1.85"},
    ]
    return pd.DataFrame(data)
