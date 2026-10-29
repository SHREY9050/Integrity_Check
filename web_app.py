"""VeriBlue AI - Interactive Web UI (Streamlit Edition)

Companion Web UI providing direct browser-based access to the complete
VeriBlue AI multi-stage integrity pipeline.
"""

import os
import sys
import tempfile
import time
import streamlit as st

# Ensure veriblue_ai is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from veriblue_ai.config import Config
from veriblue_ai.core.hasher import calculate_sha256_stream
from veriblue_ai.core.parser import extract_binary_metadata
from veriblue_ai.engines.virus_total import VirusTotalEngine, ThreatStatus
from veriblue_ai.engines.web_rag import WebRagEngine, VerificationVerdict

st.set_page_config(
    page_title="VeriBlue AI - File Integrity Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling: ICE SILVER, DEEP AUBERGINE, MARIGOLD
st.markdown(
    """
    <style>
    /* Base background in Deep Aubergine */
    .stApp {
        background-color: #140921;
        color: #E2E8F0;
    }
    header[data-testid="stHeader"] {
        background-color: #140921;
    }
    [data-testid="stSidebar"] {
        background-color: #1C0D2E;
        border-right: 1px solid #482373;
    }
    [data-testid="stSidebar"] * {
        color: #E2E8F0;
    }
    h1, h2, h3, h4 {
        color: #FBBF24 !important; /* Marigold Gold */
        font-family: 'Segoe UI', sans-serif;
    }
    p, label, span {
        color: #E2E8F0; /* Ice Silver */
    }
    .metric-card {
        background-color: #26123D;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #482373;
    }
    .stTabs [data-baseweb="tab-list"] {
        background-color: #1C0D2E;
        border-radius: 8px;
        padding: 4px;
        border: 1px solid #482373;
    }
    .stTabs [data-baseweb="tab"] {
        color: #CBD5E1 !important;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background-color: #F59E0B !important; /* Marigold Accent */
        color: #140921 !important;
        border-radius: 6px;
    }
    .stButton>button {
        background-color: #F59E0B !important; /* Marigold Button */
        color: #140921 !important;
        font-weight: bold !important;
        border: none !important;
        border-radius: 6px !important;
    }
    .stButton>button:hover {
        background-color: #D97706 !important; /* Marigold Hover */
        color: #FFFFFF !important;
    }
    div[data-testid="stFileUploader"] {
        background-color: #26123D;
        border: 2px dashed #F59E0B;
        border-radius: 10px;
        padding: 10px;
    }
    code {
        color: #FDE68A !important;
        background-color: #0F0617 !important;
        border: 1px solid #482373 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ VeriBlue AI — File Integrity & Threat Shield")
st.caption("Deep Aubergine & Marigold Edition | Autonomous Multi-Stage RAG Verifier")

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Engine Configuration")
    vt_key = st.text_input("VirusTotal v3 API Key", value=Config.get_virustotal_key(), type="password")
    tavily_key = st.text_input("Tavily Search API Key", value=Config.get_tavily_key(), type="password")
    gemini_key = st.text_input("Google Gemini API Key (100% Free)", value=Config.get_gemini_key(), type="password")
    openai_key = st.text_input("OpenAI API Key (Optional)", value=Config.get_openai_key(), type="password")

    ai_prov = st.selectbox(
        "AI Engine Provider",
        ["Gemini (Free)", "OpenAI"],
        index=0 if Config.get_ai_provider() == "gemini" else 1,
    )
    model_choice = "gemini-2.5-flash" if "Gemini" in ai_prov else "gpt-4o-mini"

    if st.button("Save & Update Credentials", use_container_width=True):
        Config.save_keys(
            virustotal_key=vt_key,
            tavily_key=tavily_key,
            gemini_key=gemini_key,
            openai_key=openai_key,
            ai_provider="gemini" if "Gemini" in ai_prov else "openai",
            model_name=model_choice,
        )
        st.success("Credentials saved to .env!")

    st.markdown("---")
    st.subheader("Key Status")
    st.write(f"• **VirusTotal:** {'🟢 Active' if Config.is_virustotal_configured() else '🟡 Unconfigured'}")
    st.write(f"• **Tavily RAG:** {'🟢 Active' if Config.is_tavily_configured() else '🟡 Unconfigured'}")
    st.write(f"• **AI ({ai_prov}):** {'🟢 Active' if Config.is_ai_configured() else '🟡 Unconfigured'}")

tab_live, tab_generator, tab_p2p, tab_about = st.tabs([
    "🚀 Live AI Pipeline Shield",
    "📤 Generate Checksum",
    "🔒 P2P Offline Verify",
    "📖 Architecture & PRD",
])

# TAB 1: Live Pipeline
with tab_live:
    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.subheader("1. Target File Inspection")
        uploaded_file = st.file_uploader(
            "Drop or select installer binary (.exe, .msi, .zip, .pdf, .dll, etc.)",
            type=None,
            help="Streams binary data in 4096-byte chunk buffers without RAM exhaustion.",
        )

        if uploaded_file:
            st.info(f"📁 **File:** `{uploaded_file.name}` | **Size:** `{uploaded_file.size / 1024:.1f} KB`")

            # Save to temporary path for chunk streaming
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp:
                tmp.write(uploaded_file.getbuffer())
                temp_file_path = tmp.name

            try:
                meta = extract_binary_metadata(temp_file_path)
                with st.expander("🔍 Extracted Binary Structural Headers", expanded=True):
                    st.write(f"**Identified App:** `{meta.app_name}`")
                    st.write(f"**Release Version:** `{meta.version}`")
                    st.write(f"**Target Architecture:** `{meta.architecture}`")
                    if meta.suggested_domain:
                        st.write(f"**Trusted Domain:** `{meta.suggested_domain}`")
            except Exception as e:
                meta = None
                st.warning(f"Could not parse binary headers: {e}")

            start_btn = st.button("🚀 Start Verification Pipeline", type="primary", use_container_width=True)

    with col2:
        st.subheader("2. Pipeline Stages & Verdict")
        if uploaded_file and meta is not None and 'start_btn' in locals() and start_btn:
            log_container = st.empty()
            logs = []

            def append_ui_log(msg: str):
                logs.append(f"`{time.strftime('%H:%M:%S')}` {msg}")
                log_container.markdown("\n\n".join(logs))

            # Step 0
            with st.status("Executing Multi-Stage Verification Pipeline...", expanded=True) as status:
                append_ui_log("Step 0: Streaming file data with 4096-byte chunk buffering...")
                time.sleep(0.3)
                local_hash = calculate_sha256_stream(temp_file_path)
                append_ui_log(f"**Step 0 SHA-256:** `{local_hash}`")
                st.write(f"✅ **Step 0 Complete:** Local SHA-256 = `{local_hash[:16]}...`")

                # Step 1
                append_ui_log("Step 1: Contacting VirusTotal v3 Threat Registry...")
                vt_engine = VirusTotalEngine()
                vt_res = vt_engine.query_hash(local_hash)

                if vt_res.status == ThreatStatus.MALICIOUS:
                    st.error(f"⛔ **MALWARE DETECTED:** {vt_res.malicious_count} engines flagged this binary as malicious!")
                    st.warning(vt_res.ai_explanation or "Execution halted immediately.")
                    status.update(label="Malware Detected! Execution Halted.", state="error")
                    st.stop()
                elif vt_res.status == ThreatStatus.CLEAN:
                    append_ui_log(
                        f"VirusTotal: No malicious detections reported "
                        f"({vt_res.malicious_count}/{vt_res.total_engines})."
                    )
                    st.write(
                        "✅ **Step 1:** VirusTotal reports no malicious detections. "
                        "This alone does not prove the file is safe."
                    )
                elif vt_res.status == ThreatStatus.NOT_FOUND_404:
                    append_ui_log("VirusTotal 404 Not Found (not in threat registry). Cascading to Stage 2...")
                    st.warning("⚠️ **Step 1 Notice:** VirusTotal has no record for this file. This is not a clean verdict.")
                else:
                    error_text = vt_res.error_message or vt_res.status.value
                    append_ui_log(f"VirusTotal could not complete the check: {error_text}")
                    st.warning(
                        f"⚠️ **Step 1 Inconclusive:** {error_text}. "
                        "Continuing to Stage 2, but this is not a malware-free result."
                    )

                # Step 2
                append_ui_log("Step 2: Crawling vendor documentation via Tavily Web RAG...")
                rag_engine = WebRagEngine(log_callback=lambda stage, m: append_ui_log(f"[{stage}] {m}"))
                stage2_res = rag_engine.run_pipeline(local_hash, meta)

                # Step 3 Checkpoint
                if stage2_res.verdict == VerificationVerdict.GENUINE:
                    status.update(label="Integrity Confirmed!", state="complete")
                    st.success("### ✅ INTEGRITY MATCHED TO VENDOR CHECKSUM")
                    st.markdown(
                        f"""
                        - **Local Calculated SHA-256:** `{stage2_res.local_hash}`
                        - **Official Published SHA-256:** `{stage2_res.fetched_hash}`
                        - **Vendor Source:** `{stage2_res.vendor_domain or 'Official Vendor'}`

                        **Verdict:** The local file matches the checksum retrieved from the vendor source. This confirms integrity against that source; it does not independently prove the file is malware-free.
                        """
                    )
                elif stage2_res.verdict == VerificationVerdict.TAMPERED:
                    status.update(label="Integrity Compromised!", state="error")
                    st.error("### 🚨 INTEGRITY BROKEN: FILE ALTERED OR TAMPERED")
                    st.markdown(
                        f"""
                        - **Local Calculated SHA-256:** `{stage2_res.local_hash}`
                        - **Vendor Expected SHA-256:** `{stage2_res.fetched_hash}`

                        **CRITICAL ALERT:** The file does not match the vendor's authentic checksum. It may be trojanized, repackaged, or corrupted.
                        """
                    )
                elif stage2_res.verdict == VerificationVerdict.NOT_FOUND:
                    status.update(label="Checksum Not Published Online", state="complete")
                    st.warning("### ⚠️ Official Checksum Not Located on Vendor Page")
                    st.write(stage2_res.summary_message)
                    st.info("Tip: Use the **P2P Offline Secure Mode** tab to test against a manually supplied checksum.")
                else:
                    status.update(label="Notice", state="complete")
                    st.info(stage2_res.summary_message)

            # Cleanup temp file
            try:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
            except Exception:
                pass
        elif uploaded_file and meta is None:
            st.error("Metadata inspection failed. Verification cannot safely continue without a usable file identity.")
        else:
            st.info("Drop or select a file on the left and click 'Start Verification' to run the pipeline.")

# TAB 2: Checksum Generator (Dedicated Section for Senders)
with tab_generator:
    st.subheader("📤 Checksum Generator & Share")
    st.caption("Calculate the authentic 64-character SHA-256 fingerprint for any file or PDF before sharing it with a peer.")

    send_file = st.file_uploader("Select file to generate its cryptographic checksum", key="tab_gen_file")
    if send_file:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(send_file.getbuffer())
            tmp_p = tmp.name
        try:
            gen_hash = calculate_sha256_stream(tmp_p)
            st.success("✅ **SHA-256 Checksum Generated!** Copy this string and send it to your peer:")
            st.code(gen_hash, language="text")
            st.info("💡 **What to do:** Message this 64-character hash to your peer. When they receive the file, they can verify it in the **P2P Offline Verify** tab to guarantee it was not modified or corrupted.")
        finally:
            if os.path.exists(tmp_p):
                os.remove(tmp_p)

# TAB 3: P2P Offline Verify (Dedicated Section for Receivers)
with tab_p2p:
    st.subheader("🔒 P2P Offline Secure Verification Mode")
    st.caption("Verify a received file against an expected checksum provided by your peer (100% offline).")

    p2p_file = st.file_uploader("Select received file", key="p2p_file")
    expected_hash = st.text_input("Expected SHA-256 Hash (from sender/peer):", placeholder="Paste 64-character hash e.g. 7f83b165...").strip().lower()

    if p2p_file and expected_hash:
        if st.button("Run Offline Cryptographic Match", type="primary"):
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(p2p_file.getbuffer())
                p2p_path = tmp.name

            try:
                computed_hash = calculate_sha256_stream(p2p_path)
                if computed_hash == expected_hash:
                    st.success("### ✅ AUTHENTIC P2P INTEGRITY VERIFIED (100% MATCH)")
                    st.code(f"Calculated: {computed_hash}\nExpected:   {expected_hash}")
                    st.write("Result: The file matches the sender's fingerprint exactly with zero deviation.")
                else:
                    st.error("### 🚨 P2P CHECKSUM MISMATCH (TAMPERED OR CORRUPTED)")
                    st.code(f"Calculated: {computed_hash}\nExpected:   {expected_hash}")
                    st.write("Result: The calculated hash deviates from what the sender transmitted. Do not trust this file.")
            finally:
                if os.path.exists(p2p_path):
                    os.remove(p2p_path)

# TAB 3: About
with tab_about:
    st.markdown(
        """
        ### VeriBlue AI Architecture
        - **Local Deterministic Layer:** 4096-byte chunk buffered streaming SHA-256 + PE header parser.
        - **Stage 1 (Malware Shield):** VirusTotal v3 files endpoint (halts on malicious, cascades on 404).
        - **Stage 2 (Integrity Shield):** Tavily web crawler + Ephemeral vector memory cache + LangChain `gpt-4o-mini` at `temperature=0.0`.
        - **Cryptographic Checkpoint:** Traditional boolean equality test (`Local == Fetched`).
        """
    )
