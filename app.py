"""CyberSentinel-LLM Interactive Operations Dashboard (Streamlit).
Integrates real machine learning models, local LLaMA-3-8B threat analysis,
4-agent collaborative architecture with shared memory audit trace,
PPO autonomous response orchestrator, and real comparative evaluation metrics.
"""

import os
import sys
import json
from pathlib import Path
import pandas as pd
import numpy as np
import streamlit as st
import streamlit.components.v1 as components

# Add current workspace to path
sys.path.insert(0, os.path.abspath("."))

from cybersentinel.data import THREAT_CLASSES
from cybersentinel.ml_classifiers import MLThreatClassifier
from cybersentinel.llm_client import CyberSentinelLLMClient
from cybersentinel.agents import CyberSentinelCoordinator, SharedMemory
from cybersentinel.ppo_orchestrator import PPOPolicyNetwork
from cybersentinel.metrics import get_paper_benchmark_soc_comparison

st.set_page_config(
    page_title="CyberSentinel-LLM Autonomous Security Operations",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ CyberSentinel-LLM")
st.markdown("### A Large Language Model-Driven Autonomous Framework for Intelligent Cyber Threat Detection and Response")
st.caption("Implementation based on Tahani Alsubait (Tech Science Press / CMC, 2026)")

st.warning("⚠️ **Research & Academic Safety Notice**: All autonomous defensive mitigations (network isolation, process termination, firewall rules, account suspension) are strictly simulated in a virtual security sandbox. No modifications are applied to host or network infrastructure.")

# Sidebar Configuration
st.sidebar.header("⚙️ Framework Configuration")
active_benchmark = st.sidebar.selectbox("Active Benchmark Dataset", ["HDFS (Hadoop Distributed)", "BGL (BlueGene/L Supercomputer)"])

# Load Backends Cache
@st.cache_resource
def load_backends():
    ml_path = "artifacts/hdfs_best_ml_model.joblib"
    ml_clf = MLThreatClassifier.load(ml_path) if os.path.exists(ml_path) else None

    ppo_policy = PPOPolicyNetwork()
    ppo_path = "artifacts/ppo_response_policy.pt"
    if os.path.exists(ppo_path):
        import torch
        ppo_policy.load_state_dict(torch.load(ppo_path, weights_only=True))

    llm_client = CyberSentinelLLMClient()
    coordinator = CyberSentinelCoordinator(ml_classifier=ml_clf, llm_client=llm_client, ppo_policy=ppo_policy)
    return ml_clf, llm_client, ppo_policy, coordinator

ml_clf, llm_client, ppo_policy, coordinator = load_backends()

# LLM Status check
llm_online = llm_client.is_available()
if llm_online:
    st.sidebar.success("🟢 Local LLaMA-3-8B (Ollama: Online)")
else:
    st.sidebar.info("🟡 Local LLaMA-3-8B (Ollama Offline: Using Grounded Deterministic Reasoner)")

# Navigation Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🎯 Live Multi-Agent Investigation",
    "📊 Comparative Evaluation (ML vs LLM)",
    "🌲 Baseline ML Benchmarks",
    "⏱️ SOC Operational Metrics (Table 12)",
    "📐 Architecture & Methodology"
])

# =========================================================================
# TAB 1: Live Multi-Agent Investigation
# =========================================================================
with tab1:
    st.subheader("Autonomous Multi-Agent Threat Detection, Response & Forensics")

    col_presets, col_mode = st.columns([2, 1])

    PRESETS = {
        "Select a benchmark attack preset...": "",
        "🚨 Paper Appendix A: Coordinated APT Campaign": (
            "08:41:55 INFO dfs.DataNode$DataXceiver: Receiving block blk_apt_0042 src: /10.0.0.12 dest: /10.0.0.35\n"
            "08:41:58 WARN auth.SecurityManager: Repeated authentication failures from PID_ANON_1192 targeting DN_ANON_03\n"
            "08:42:02 INFO dfs.DataNode: Lateral movement pattern confirmed (3 DataNode accesses in 7s)\n"
            "08:42:10 WARN dfs.FSNamesystem: Rapid replication requests to non-standard block locations (4.2x baseline rate)\n"
            "08:42:15 INFO dfs.DataNode: Data exfiltration initiated via disguised HTTP traffic"
        ),
        "🌊 DDoS High-Frequency Connection Flood": (
            "081109 203615 148 WARN dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating with timeout\n"
            "081109 203616 149 ERROR dfs.DataNode$PacketResponder: Connection flood: 850 socket connections per second\n"
            "081109 203617 150 WARN dfs.DataNode$PacketResponder: PacketResponder 2 for block blk_38865049064139660 Interrupted\n"
            "081109 203618 151 ERROR dfs.FSNamesystem: High-frequency repetitive block requests exhausting threadpool"
        ),
        "🦠 Malware Payload Corruption & Exfiltration": (
            "09:12:01 WARN dfs.DataNode: ChecksumException: checksum mismatch detected for block blk_mal_0019\n"
            "09:12:03 ERROR dfs.DataNode$PacketResponder: bad packet payload with invalid magic header from /192.168.1.44\n"
            "09:12:05 WARN fs.FSNamesystem: corrupt replica detected on data node /192.168.1.88\n"
            "09:12:08 ERROR dfs.DataNode: unexpected EOF while reading exfiltrated block stream blk_mal_0019"
        ),
        "🚨 Insider Threat: Console Key Export Attempt (Prompt Test)": (
            "14:22:10 WARN auth.SecurityManager: Repeated authentication failures from user root on console session\n"
            "14:22:15 ALERT auth.SecurityManager: Unauthorized privilege escalation attempted by process PID_9921\n"
            "14:22:20 WARN dfs.FSNamesystem: Permission denied: user root is not authorized to export cryptographic keys"
        ),
        "🎣 Phishing Credential Lure Redirection": (
            "11:05:12 WARN web.SSOAuthenticator: Suspected phishing login lure redirected to external uri /10.200.1.155\n"
            "11:05:15 ALERT auth.CredentialVerifier: Credential harvest signature triggered for user admin_07\n"
            "11:05:18 WARN web.Portal: Spoofed domain header HTTP_X_FORWARDED_FOR detected from /10.200.1.155"
        ),
        "🟢 Nominal Operational HDFS Sequence (Benign)": (
            "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating\n"
            "081109 203616 150 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.73.220:50010 is added to blk_38865049064139660 size 67108864\n"
            "081109 203617 152 INFO dfs.DataNode$DataXceiver: Received block blk_38865049064139660 of size 67108864 from /10.251.73.220"
        )
    }

    with col_presets:
        selected_preset = st.selectbox("Load Sample Incident Log", list(PRESETS.keys()))

    with col_mode:
        investigation_mode = st.radio(
            "Investigation Pipeline Mode",
            ["⚡ 4-Agent Hybrid (ML + LLM + DRL)", "🌲 Classifier-Only (ML Baseline)", "🤖 LLM-Only (Zero-Shot)"]
        )

    log_input = st.text_area(
        "Incident Log Stream (Raw or Parsed)",
        value=PRESETS.get(selected_preset, ""),
        height=140,
        placeholder="Paste log entries here or choose a preset above..."
    )

    if st.button("🚀 Analyze Incident", type="primary", use_container_width=True):
        if not log_input.strip():
            st.error("Please enter a log sequence or select a preset.")
        else:
            with st.spinner("Executing CyberSentinel-LLM Multi-Agent Pipeline..."):
                mem = coordinator.process_incident(log_input)
                st.session_state["analyzed_memory"] = mem

    # Render results if available in session state
    if "analyzed_memory" in st.session_state:
        mem = st.session_state["analyzed_memory"]

        # Top KPI metrics
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("Detection Verdict", "🚨 ANOMALY" if mem.is_anomaly else "🟢 NORMAL")
        with m2:
            st.metric("Threat Category", mem.threat_category)
        with m3:
            st.metric("Anomaly Score (s_D)", f"{mem.detection_score:.3f}")
        with m4:
            st.metric("Class Confidence (c)", f"{mem.confidence * 100:.1f}%")
        with m5:
            st.metric("Response Status", "SIMULATED / SANDBOX")

        st.info(f"**Autonomous Response Selected:** `{mem.selected_action}` *(Verification: Sandbox Simulated — No live host changes applied)*")

        st.divider()

        # Multi-agent timeline & trace
        with st.expander("🔄 Shared Memory (M) Inter-Agent Collaboration Trace", expanded=False):
            for t in mem.audit_trace:
                if "Detection Agent" in t:
                    st.info(t, icon="🔍")
                elif "Classification Agent" in t:
                    st.warning(t, icon="🏷️")
                elif "Response Agent" in t:
                    st.error(t, icon="⚡")
                elif "Forensic Agent" in t:
                    st.success(t, icon="📋")
                else:
                    st.markdown(f"`{t}`")

        # Forensic Report
        if mem.forensic_report:
            st.divider()
            st.markdown("### 📋 SOC Incident Forensic Investigation Report (19 Sections)")
            st.caption(f"Incident ID: `{mem.incident_id}` | Framework: CyberSentinel-LLM Autonomous Multi-Agent System")

            # Report export and print action bar
            col_d1, col_d2, col_p = st.columns([1, 1, 2])
            with col_d1:
                st.download_button(
                    label="📥 Download Report (.md)",
                    data=mem.forensic_report,
                    file_name=f"{mem.incident_id}_forensic_report.md",
                    mime="text/markdown",
                    use_container_width=True
                )
            with col_d2:
                st.download_button(
                    label="📄 Download Printable HTML",
                    data=mem.forensic_html,
                    file_name=f"{mem.incident_id}_forensic_report.html",
                    mime="text/html",
                    use_container_width=True
                )
            with col_p:
                st.info("💡 **Print Instructions:** Click 'Download Printable HTML' and open in any browser, or use the interactive Print View below to print / Save as PDF with `Ctrl+P`.")

            report_tab_print, report_tab_md, report_tab_sections = st.tabs([
                "🖨️ Publication-Grade Print View",
                "📄 Full Markdown Report",
                "📑 Structured 19-Section Audit"
            ])

            with report_tab_print:
                st.markdown("Below is the print-ready SOC incident document styled with `@media print` rules. Click inside and press `Ctrl+P` or click the button inside the document to print.")
                components.html(mem.forensic_html, height=850, scrolling=True)

            with report_tab_md:
                st.markdown(mem.forensic_report)

            with report_tab_sections:
                sec_data = mem.forensic_data.get("structured_sections", {})
                records = mem.forensic_data.get("records", [])

                with st.expander("Section 1 & 2: Incident Metadata & Executive Summary", expanded=True):
                    st.markdown(f"**Report ID:** `{mem.forensic_data.get('report_id')}`")
                    st.markdown(f"**Severity:** `{mem.forensic_data.get('severity')}` | **Status:** `{mem.forensic_data.get('status')}`")
                    st.markdown(sec_data.get("executive_summary", ""))

                with st.expander("Section 3 & 4: Narrative & Event-by-Event Technical Analysis", expanded=False):
                    st.markdown(sec_data.get("narrative", ""))
                    st.markdown("#### Evidence Records Table")
                    for r in records:
                        st.markdown(f"- **[{r.evidence_id}]** `{r.timestamp}`: `{r.observed_event}`")
                        st.markdown(f"  *Technical Interpretation:* {r.technical_interpretation}")
                        st.markdown(f"  *Benign Alternative:* {r.benign_explanation}")

                with st.expander("Section 5 & 6: Correlation, Attack Progression & IoCs", expanded=False):
                    st.markdown("#### Evidence Correlations")
                    for c in sec_data.get("correlations", []):
                        e1 = c.get("earlier_event", c.get("earlier", "N/A"))
                        e2 = c.get("later_event", c.get("later", "N/A"))
                        interp = c.get("possible_interpretation", c.get("interpretation", "N/A"))
                        conf = c.get("confidence", "Moderate")
                        st.markdown(f"- **`{e1}` → `{e2}`**: {interp} *(Confidence: {conf})*")
                        if c.get("missing_evidence"):
                            st.caption(f"  *Missing Evidence Needed:* {c['missing_evidence']}")
                    st.markdown("#### Indicators of Compromise (IoCs)")
                    for i in sec_data.get("iocs", []):
                        st.markdown(f"- `{i.get('value')}` ({i.get('type')}): {i.get('relevance')} [{i.get('status')}]")

                with st.expander("Section 7 & 8: MITRE ATT&CK & Severity Assessment", expanded=False):
                    for m in sec_data.get("mitre", []):
                        st.markdown(f"- **{m.get('id')} - {m.get('name')}**: {m.get('relevance')} *(Status: {m.get('status')})*")

                with st.expander("Section 9 & 10: Competing Hypotheses & Asset Impact", expanded=False):
                    st.markdown("#### Competing Hypotheses")
                    for h in sec_data.get("hypotheses", []):
                        h_name = h.get("hypothesis", h.get("name", "Hypothesis"))
                        h_status = h.get("status", "Candidate")
                        h_desc = h.get("description", "")
                        h_supp = h.get("supporting_evidence", h.get("supporting", "None"))
                        h_contra = h.get("contradicting_evidence", h.get("contradicting", "None"))
                        st.markdown(f"- **{h_name}** [{h_status}]: {h_desc}")
                        st.markdown(f"  *Supporting:* {h_supp} | *Contradicting:* {h_contra}")
                    st.markdown("#### Affected Assets")
                    assets_data = sec_data.get("assets", {})
                    if isinstance(assets_data, dict):
                        if assets_data.get("directly_observed"):
                            st.markdown("**Directly Observed Entities:**")
                            for a in assets_data["directly_observed"]:
                                st.markdown(f"- {a}")
                        if assets_data.get("potentially_affected"):
                            st.markdown("**Potentially Affected Assets:**")
                            for a in assets_data["potentially_affected"]:
                                st.markdown(f"- {a}")
                        if assets_data.get("requiring_investigation"):
                            st.markdown("**Requiring Secondary Audit:**")
                            for a in assets_data["requiring_investigation"]:
                                st.markdown(f"- {a}")
                    elif isinstance(assets_data, list):
                        for a in assets_data:
                            st.markdown(f"- {a}")

                with st.expander("Section 13, 14 & 15: Response, Evidence Gaps & Remediation Plan", expanded=False):
                    resp = sec_data.get("response", {})
                    st.markdown(f"**Recommended Action:** `{resp.get('action')}` [{resp.get('status')}]")
                    st.markdown(f"**Security Benefit:** {resp.get('benefit')}")
                    st.markdown(f"**Operational Risk:** {resp.get('impact')}")
                    st.markdown("#### Remediation Steps")
                    for step in sec_data.get("remediation", []):
                        st.markdown(f"- **[{step.get('priority')}] {step.get('phase')}:** {step.get('action')} *(Role: {step.get('role')})*")

                with st.expander("Section 16, 17 & 18: Residual Risk, Evidence Integrity & Conclusion", expanded=False):
                    st.markdown("#### Evidence Integrity Hashes (SHA-256)")
                    for r in records:
                        st.markdown(f"- **{r.evidence_id}**: `{r.sha256_hash}`")
                    st.markdown("#### 9-Point Conclusion & Assessment")
                    st.markdown(sec_data.get("conclusion", ""))

# =========================================================================
# TAB 2: Comparative Evaluation
# =========================================================================
with tab2:
    st.subheader("Mandatory 3-Way Comparative Evaluation")
    st.markdown("Rigorous comparison between **Classifier-only**, **LLM-only**, and **Classifier + LLM** on identical held-out test sets.")

    comp_csv_path = "results/comparative_evaluation_table.csv"
    chart_png_path = "results/comparative_evaluation_chart.png"

    if os.path.exists(comp_csv_path):
        comp_df = pd.read_csv(comp_csv_path)
        st.dataframe(comp_df, use_container_width=True)

        if os.path.exists(chart_png_path):
            st.image(chart_png_path, caption="Comparative Performance Across Metrics")

        st.markdown("""
        **Key Findings**:
        - **Classifier-Only (Random Forest)** provides high accuracy and sub-millisecond inference (~0.46 ms), making it suitable for line-rate log screening.
        - **LLM-Only (LLaMA-3-8B)** provides rich semantic reasoning, zero-shot detection capability, and natural language explainability.
        - **Classifier + LLM (Hybrid)** achieves high detection fidelity while selectively routing suspicious and ambiguous cases to the LLM for deep contextual validation and automated forensic report generation.
        """)
    else:
        st.info("Run `python scripts/run_comparative_eval.py` to generate the comparative evaluation results.")

# =========================================================================
# TAB 3: Traditional ML Benchmarks
# =========================================================================
with tab3:
    st.subheader("Traditional Machine Learning Classifier Baselines")

    ds_choice = st.radio("Select Dataset Benchmark", ["HDFS", "BGL"], horizontal=True)
    prefix = ds_choice.lower()

    ml_comp_file = f"results/{prefix}_ml_comparison.csv"
    cm_file = f"results/{prefix}_confusion_matrix.png"

    col_table, col_cm = st.columns([1, 1])

    with col_table:
        st.markdown(f"#### {ds_choice} Model Selection & Validation Table")
        if os.path.exists(ml_comp_file):
            df_ml = pd.read_csv(ml_comp_file)
            st.dataframe(df_ml, use_container_width=True)
        else:
            st.info(f"Run `python scripts/train_ml.py` to populate {ds_choice} results.")

    with col_cm:
        st.markdown(f"#### {ds_choice} Confusion Matrix")
        if os.path.exists(cm_file):
            st.image(cm_file, caption=f"{ds_choice} Best Model Confusion Matrix")
        else:
            st.info("Confusion matrix plot not found.")

# =========================================================================
# TAB 4: SOC Operational Metrics
# =========================================================================
with tab4:
    st.subheader("Security Operations Center (SOC) Operational Key Performance Indicators")
    st.markdown("Measures practical operational effectiveness in accordance with **Table 12** of the research paper.")

    col_kpi1, col_kpi2 = st.columns(2)

    with col_kpi1:
        st.markdown("#### Paper Benchmark Comparison (Table 12)")
        bench_df = get_paper_benchmark_soc_comparison()
        st.dataframe(bench_df, use_container_width=True)

    with col_kpi2:
        st.markdown("#### Measured Simulation KPIs (This Run)")
        soc_kpi_path = "results/soc_operational_kpis.csv"
        if os.path.exists(soc_kpi_path):
            kpi_df = pd.read_csv(soc_kpi_path)
            st.dataframe(kpi_df.T.rename(columns={0: "Measured Value"}), use_container_width=True)
        else:
            st.info("Run `python scripts/train_ppo_and_test_agents.py` to calculate operational KPIs.")

# =========================================================================
# TAB 5: Architecture & Methodology
# =========================================================================
with tab5:
    st.subheader("CyberSentinel-LLM System Architecture & Methodology")
    st.markdown("""
    ### System Modules:
    1. **Multi-Modal Log Parser & Feature Extractor**:
       - Drain-based template extraction and masking.
       - Sinusoidal temporal encoding: $\\psi_{temp}(t_i) = [\\sin(t_i / \\omega_k), \\cos(t_i / \\omega_k)]$.
       - Multi-modal fusion with network traffic flows: $f_j = [b_{in}, b_{out}, n_{pkt}, \\Delta t, h_{proto}]$.
    2. **Temporal Transformer Encoder**:
       - Windowed causal multi-head self-attention ($L=6, H=8, d_z=512, w=256$).
    3. **LLM Threat Intelligence Engine**:
       - Local LLaMA-3-8B with structured JSON prompt schemas and MITRE ATT&CK alignment.
    4. **Multi-Agent Collaborative System**:
       - **Detection Agent ($A_D$)**: Anomaly scoring with threshold gating.
       - **Classification Agent ($A_C$)**: Multi-class category mapping across 6 threat classes.
       - **Response Agent ($A_R$)**: Autonomous defensive action selection via DRL.
       - **Forensic Agent ($A_F$)**: Comprehensive natural language incident documentation.
       - **Shared Memory ($M$)**: Inter-agent audit trail and state coordination.
    5. **DRL Response Orchestrator**:
       - Markov Decision Process ($S, A, T, R, \\gamma$) optimized via Proximal Policy Optimization (PPO).
       - Six response action categories with penalty for service disruption.
    """)
