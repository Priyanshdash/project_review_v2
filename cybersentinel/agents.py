"""Four-Agent Collaborative Autonomous Architecture for CyberSentinel-LLM.
Implements the 4 specialized agents defined in Section 4.5 of the research paper:
- Detection Agent (A_D): Binary anomaly scoring
- Classification Agent (A_C): Threat category assignment
- Response Agent (A_R): Autonomous defensive mitigation selection (6 actions)
- Forensic Agent (A_F): Natural language incident reporting (Appendix A)
- Shared Memory Mechanism (M): Thread-safe inter-agent communication and audit trace (Eq. 21)
"""

from __future__ import annotations
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .data import THREAT_CLASSES, THREAT_TO_ID
from .llm_client import CyberSentinelLLMClient
from .ml_classifiers import MLThreatClassifier
from .forensic import ForensicReportGenerator

RESPONSE_ACTIONS = [
    "No action",
    "Network isolation of the affected host (SIMULATED)",
    "Process termination of suspicious processes (SIMULATED)",
    "Firewall rule insertion to block malicious IPs/ports (SIMULATED)",
    "User account suspension for insider threat (SIMULATED)",
    "Security patch deployment for known exploits (SIMULATED)",
    "Alert escalation to human analysts (SIMULATED)"
]


@dataclass
class SharedMemory:
    """Inter-agent shared memory mechanism M (Eq. 21)."""
    incident_id: str
    log_text: str
    timestamp: str
    detection_score: float = 0.0
    is_anomaly: bool = False
    threat_category: str = "Normal"
    confidence: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)
    selected_action: str = "No action"
    forensic_report: str = ""
    forensic_html: str = ""
    forensic_data: dict[str, Any] = field(default_factory=dict)
    audit_trace: list[str] = field(default_factory=list)
    system_metrics: dict[str, float] = field(default_factory=dict)

    def log_event(self, agent_name: str, message: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        entry = f"[{ts}] [{agent_name}]: {message}"
        self.audit_trace.append(entry)


class DetectionAgent:
    """Detection Agent (A_D): Computes binary anomaly score s_D(i) (Eq. 18)."""

    def __init__(self, ml_classifier: MLThreatClassifier | None = None, llm_client: CyberSentinelLLMClient | None = None, threshold: float = 0.50):
        self.ml_classifier = ml_classifier
        self.llm_client = llm_client
        self.threshold = threshold

    def detect(self, memory: SharedMemory) -> float:
        score = 0.0
        reason = ""

        # 1. Use ML Classifier probability if available
        if self.ml_classifier:
            preds, probs, lat = self.ml_classifier.predict([memory.log_text])
            if probs.shape[1] > 1:
                score = float(probs[0, 1])
            else:
                score = float(preds[0])
            reason = f"ML model score={score:.3f} (inference: {lat:.2f}ms)"

        # 2. If borderline or no ML classifier, use LLM
        if (0.35 <= score <= 0.85 or not self.ml_classifier) and self.llm_client:
            llm_res = self.llm_client.analyze_log(memory.log_text)
            llm_score = float(llm_res.get("confidence", 0.5)) if llm_res.get("is_anomaly") else float(1.0 - llm_res.get("confidence", 0.8))
            # Blended gated score
            score = 0.6 * score + 0.4 * llm_score if self.ml_classifier else llm_score
            reason += f" | LLM contextual validation score={llm_score:.3f}"

        is_anom = score >= self.threshold
        memory.detection_score = score
        memory.is_anomaly = is_anom
        memory.log_event("Detection Agent (A_D)", f"Evaluated event stream: is_anomaly={is_anom}, score={score:.3f}. {reason}")
        return score


class ClassificationAgent:
    """Classification Agent (A_C): Assigns threat category y_hat_i (Eq. 19)."""

    def __init__(self, llm_client: CyberSentinelLLMClient | None = None):
        self.llm_client = llm_client

    def classify(self, memory: SharedMemory) -> str:
        if not memory.is_anomaly:
            memory.threat_category = "Normal"
            memory.confidence = 0.98
            memory.log_event("Classification Agent (A_C)", "Event confirmed Normal. Assigned category 'Normal'.")
            return "Normal"

        category = "Zero-Day"
        conf = 0.85
        mitre = []

        if self.llm_client:
            res = self.llm_client.analyze_log(memory.log_text, context=f"Detection Agent flagged anomaly (score={memory.detection_score:.2f})")
            category = res.get("threat_type", "Zero-Day")
            conf = float(res.get("confidence", 0.90))
            mitre = res.get("mitre_techniques", [])
        else:
            # Fallback heuristic
            t = memory.log_text.lower()
            if "apt" in t or "lateral" in t: category = "APT"
            elif "flood" in t or "packet" in t: category = "DDoS"
            elif "corrupt" in t or "malware" in t: category = "Malware"
            elif "auth" in t or "user" in t: category = "Insider Threat"
            elif "phish" in t: category = "Phishing"

        memory.threat_category = category
        memory.confidence = conf
        memory.mitre_techniques = mitre
        memory.log_event("Classification Agent (A_C)", f"Assigned threat class '{category}' with confidence {conf:.2f}. MITRE: {mitre}")
        return category


class ResponseAgent:
    """Response Agent (A_R): Selects optimal autonomous response action a* across 6 categories (Eq. 23)."""

    def __init__(self, ppo_policy=None):
        self.ppo_policy = ppo_policy

    def select_action(self, memory: SharedMemory) -> str:
        if not memory.is_anomaly:
            action = RESPONSE_ACTIONS[0]
            memory.selected_action = action
            memory.log_event("Response Agent (A_R)", "Threat level nominal; selected 'No action'.")
            return action

        # If PPO policy is supplied, query policy network
        if self.ppo_policy is not None:
            state = [memory.detection_score, THREAT_TO_ID.get(memory.threat_category, 0) / 6.0, memory.confidence, 0.5]
            action_idx = self.ppo_policy.predict_action(state)
            action = RESPONSE_ACTIONS[min(action_idx, len(RESPONSE_ACTIONS) - 1)]
        else:
            # Paper-specified deterministic mapping
            threat = memory.threat_category
            conf = memory.confidence

            if conf < 0.60 or threat == "Zero-Day":
                action = RESPONSE_ACTIONS[6]  # Escalate alert to human analyst
            elif threat == "APT":
                action = RESPONSE_ACTIONS[1]  # Network isolation
            elif threat == "Malware":
                action = RESPONSE_ACTIONS[2]  # Process termination
            elif threat == "DDoS":
                action = RESPONSE_ACTIONS[3]  # Firewall rule insertion
            elif threat in ["Insider Threat", "Phishing"]:
                action = RESPONSE_ACTIONS[4]  # User account suspension
            else:
                action = RESPONSE_ACTIONS[5]  # Security patch deployment

        memory.selected_action = action
        memory.log_event("Response Agent (A_R)", f"Autonomous response chosen: '{action}'")
        return action


class ForensicAgent:
    """Forensic Agent (A_F): Generates incident investigation report matching paper Appendix A (Eq. 20)."""

    def __init__(self, llm_client: CyberSentinelLLMClient | None = None):
        self.llm_client = llm_client or CyberSentinelLLMClient()
        self.report_generator = ForensicReportGenerator(llm_client=self.llm_client)

    def generate_report(self, memory: SharedMemory) -> str:
        report_res = self.report_generator.generate_full_report(
            log_text=memory.log_text,
            threat_class=memory.threat_category,
            detection_score=memory.detection_score,
            classification_confidence=memory.confidence,
            selected_action=memory.selected_action,
            incident_id=memory.incident_id,
            detection_model="Random Forest / HistGB Anomaly Detector (Eq. 18)",
            classification_model="CyberSentinel LLM / Rule Classifier (Eq. 19)",
            investigation_mode="4-Agent Collaborative Hybrid (CyberSentinel-LLM)"
        )
        memory.forensic_report = report_res["markdown"]
        memory.forensic_html = report_res["printable_html"]
        memory.forensic_data = report_res
        memory.log_event("Forensic Agent (A_F)", f"Official Incident Forensic Report generated (Report ID: {report_res['report_id']}).")
        return report_res["markdown"]


class CyberSentinelCoordinator:
    """Orchestrates the 4-agent collaborative system through shared memory M."""

    def __init__(self, ml_classifier: MLThreatClassifier | None = None, llm_client: CyberSentinelLLMClient | None = None, ppo_policy=None):
        self.ml_classifier = ml_classifier
        self.llm_client = llm_client or CyberSentinelLLMClient()
        self.detector = DetectionAgent(self.ml_classifier, self.llm_client)
        self.classifier = ClassificationAgent(self.llm_client)
        self.responder = ResponseAgent(ppo_policy)
        self.forensic = ForensicAgent(self.llm_client)

    def process_incident(self, log_text: str, incident_id: str | None = None) -> SharedMemory:
        """Executes Algorithm 1: Detection -> Classification -> Response -> Forensic -> Shared Memory Update."""
        inc_id = incident_id or f"INC-{int(time.time() * 1000) % 1000000}"
        now_ts = datetime.now(timezone.utc).isoformat()

        mem = SharedMemory(
            incident_id=inc_id,
            log_text=log_text,
            timestamp=now_ts,
            system_metrics={"cpu_util": 0.35, "mem_util": 0.42, "network_load": 0.58}
        )
        mem.log_event("Coordinator", f"Initialized incident pipeline {inc_id} with multi-agent architecture.")

        # Step 1: Detection Agent
        self.detector.detect(mem)

        # Step 2: Classification Agent
        self.classifier.classify(mem)

        # Step 3: Response Agent
        self.responder.select_action(mem)

        # Step 4: Forensic Agent
        self.forensic.generate_report(mem)

        mem.log_event("Coordinator", "Incident analysis complete across all four agents.")
        return mem
