"""VeriBlue AI - Stage 1 Malware Shield (VirusTotal Integration)

Queries the VirusTotal v3 API using only the 64-character SHA-256 fingerprint.
Handles conditional routing:
- Malicious > 0: Halts execution, routes diagnostics to AI explainer.
- 404 Not Found: Smoothly traps exception, cascades execution to Stage 2.
- 200 Clean: Reports clean global threat reputation, ready for integrity validation.
"""

from enum import Enum
from typing import Dict, Any, Optional
import requests
try:
    from ..config import Config
except (ImportError, ValueError):
    from config import Config

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


class ThreatStatus(str, Enum):
    MALICIOUS = "MALICIOUS"
    CLEAN = "CLEAN"
    NOT_FOUND_404 = "NOT_FOUND_404"
    API_ERROR = "API_ERROR"
    NO_API_KEY = "NO_API_KEY"


class VirusTotalResult:
    """Structured response container for Stage 1 threat scanning."""

    def __init__(
        self,
        status: ThreatStatus,
        hash_string: str,
        malicious_count: int = 0,
        suspicious_count: int = 0,
        harmless_count: int = 0,
        undetected_count: int = 0,
        raw_json: Optional[Dict[str, Any]] = None,
        ai_explanation: Optional[str] = None,
        error_message: Optional[str] = None,
    ):
        self.status = status
        self.hash_string = hash_string
        self.malicious_count = malicious_count
        self.suspicious_count = suspicious_count
        self.harmless_count = harmless_count
        self.undetected_count = undetected_count
        self.raw_json = raw_json or {}
        self.ai_explanation = ai_explanation
        self.error_message = error_message

    @property
    def total_engines(self) -> int:
        return (
            self.malicious_count
            + self.suspicious_count
            + self.harmless_count
            + self.undetected_count
        )


class VirusTotalEngine:
    """Stage 1 VirusTotal Threat Registry Gateway."""

    VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else Config.get_virustotal_key()

    def query_hash(self, sha256_hash: str) -> VirusTotalResult:
        """Lookup SHA-256 fingerprint in VirusTotal v3 files endpoint.

        Args:
            sha256_hash: 64-character local calculated hash string.

        Returns:
            VirusTotalResult with threat diagnosis and routing state.
        """
        api_key = self.api_key if self.api_key is not None else Config.get_virustotal_key()
        if not api_key:
            return VirusTotalResult(
                status=ThreatStatus.NO_API_KEY,
                hash_string=sha256_hash,
                error_message="VirusTotal API key not configured in settings.",
            )

        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "VeriBlue-AI/1.0",
        }

        url = f"{self.VT_BASE_URL}{sha256_hash.strip().lower()}"

        try:
            response = requests.get(url, headers=headers, timeout=Config.get_http_timeout())

            # Stage 1 Trap: 404 Not Found -> cascade smoothly into Stage 2
            if response.status_code == 404:
                return VirusTotalResult(
                    status=ThreatStatus.NOT_FOUND_404,
                    hash_string=sha256_hash,
                    error_message="File signature unknown in threat database (404 Not Found). Cascading to Stage 2.",
                )

            if response.status_code == 401 or response.status_code == 403:
                return VirusTotalResult(
                    status=ThreatStatus.API_ERROR,
                    hash_string=sha256_hash,
                    error_message=f"VirusTotal authentication failed (HTTP {response.status_code}). Check API key.",
                )

            if response.status_code != 200:
                return VirusTotalResult(
                    status=ThreatStatus.API_ERROR,
                    hash_string=sha256_hash,
                    error_message=f"VirusTotal API returned HTTP {response.status_code}: {response.text[:200]}",
                )

            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            # If Malicious > 0: execution halts immediately. Route JSON to AI Explainer.
            if malicious > 0:
                ai_explanation = self._explain_malware_with_llm(
                    sha256_hash, attributes, stats
                )
                return VirusTotalResult(
                    status=ThreatStatus.MALICIOUS,
                    hash_string=sha256_hash,
                    malicious_count=malicious,
                    suspicious_count=suspicious,
                    harmless_count=harmless,
                    undetected_count=undetected,
                    raw_json=payload,
                    ai_explanation=ai_explanation,
                )

            # Known clean in registry
            return VirusTotalResult(
                status=ThreatStatus.CLEAN,
                hash_string=sha256_hash,
                malicious_count=malicious,
                suspicious_count=suspicious,
                harmless_count=harmless,
                undetected_count=undetected,
                raw_json=payload,
            )

        except requests.RequestException as e:
            return VirusTotalResult(
                status=ThreatStatus.API_ERROR,
                hash_string=sha256_hash,
                error_message=f"Network error contacting VirusTotal: {str(e)}",
            )

    def _explain_malware_with_llm(
        self, hash_str: str, attributes: Dict[str, Any], stats: Dict[str, Any]
    ) -> str:
        """Route threat diagnostics to an LLM context wrapper to build plain-English explanation."""
        # Gather flagged engines and their results
        analysis_results = attributes.get("last_analysis_results", {})
        flagged_engines = []
        for engine, detail in analysis_results.items():
            category = detail.get("category", "")
            if category in ["malicious", "suspicious"]:
                flagged_engines.append(
                    f"{engine}: {detail.get('result', 'threat')} ({category})"
                )

        flagged_summary = ", ".join(flagged_engines[:15])
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        threat_names = attributes.get("popular_threat_classification", {})

        # Check AI provider (Gemini or OpenAI)
        prompt = (
            f"You are VeriBlue AI's Senior Cybersecurity Threat Explainer.\n"
            f"A downloaded file with SHA-256 {hash_str} was flagged as MALICIOUS by "
            f"{malicious} out of {total} security engines on VirusTotal.\n"
            f"Threat indicators: {flagged_summary}\n"
            f"Threat classification data: {threat_names}\n\n"
            f"Write a concise, plain-English security warning for the user:\n"
            f"1. What kind of threat this represents (Trojan, Ransomware, PUP, Backdoor, etc.).\n"
            f"2. Potential risk to their operating system and personal data.\n"
            f"3. Direct action advice (DO NOT RUN / quarantine immediately).\n"
            f"Keep it under 3 paragraphs, authoritative, and direct."
        )
        sys_msg = "You are a professional security analyst explaining malware detections clearly."

        # 1. Try Gemini if configured
        if Config.is_gemini_configured() and (Config.get_ai_provider() == "gemini" or not Config.is_openai_configured()):
            try:
                g_key = Config.get_gemini_key()
                g_model = Config.get_gemini_model()
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{g_model}:generateContent?key={g_key}"
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "systemInstruction": {"parts": [{"text": sys_msg}]},
                    "generationConfig": {"temperature": 0.1, "maxOutputTokens": 350},
                }
                resp = requests.post(url, json=payload, timeout=Config.get_http_timeout())
                if resp.status_code == 200:
                    candidates = resp.json().get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if text.strip():
                            return text.strip()
            except Exception:
                pass

        # 2. Try OpenAI if configured
        openai_key = Config.get_openai_key()
        if HAS_OPENAI and openai_key and Config.is_openai_configured():
            try:
                client = OpenAI(api_key=openai_key)
                response = client.chat.completions.create(
                    model=Config.get_openai_model(),
                    temperature=0.1,
                    messages=[
                        {"role": "system", "content": sys_msg},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=300,
                )
                content = response.choices[0].message.content
                if content:
                    return content.strip()
            except Exception:
                pass

        # Robust local synthesizer fallback
        return (
            f"HIGH-RISK SECURITY ALERT: {malicious} of {total} antivirus engines on VirusTotal "
            f"flagged this file as MALICIOUS.\n\n"
            f"Key detections reported: {flagged_summary if flagged_summary else 'Heuristic malware detection'}.\n\n"
            f"Verdict: Execution halted by VeriBlue AI. Running this binary poses a critical risk "
            f"of system compromise, credential theft, or unauthorized persistence. Delete or quarantine the file immediately."
        )
