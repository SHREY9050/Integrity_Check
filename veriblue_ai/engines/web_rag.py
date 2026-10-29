
"""
VeriBlue AI - Stage 2 Integrity Shield (Web-Search RAG Loop)

Orchestrates Tavily Search API, an ephemeral in-memory context cache,
and an optimized streaming API parser running at temperature=0.0 with a rigid system prompt
to isolate official vendor-published SHA-256 hashes and run cryptographic match validation.
"""

import os
import re
import time
from urllib.parse import urlsplit
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field

try:
    from ..config import Config
    from ..core.parser import BinaryMetadata
except (ImportError, ValueError):
    from config import Config
    from core.parser import BinaryMetadata

try:
    from tavily import TavilyClient
    HAS_TAVILY = True
except ImportError:
    HAS_TAVILY = False

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False


class VerificationVerdict(str, Enum):
    GENUINE = "GENUINE"
    TAMPERED = "TAMPERED"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class Stage2Result:
    verdict: VerificationVerdict
    local_hash: str
    fetched_hash: Optional[str] = None
    vendor_url: Optional[str] = None
    vendor_domain: Optional[str] = None
    search_query: str = ""
    summary_message: str = ""
    retrieved_chunks_count: int = 0
    raw_response: Optional[str] = None


class EphemeralMemoryCache:
    """In-memory ephemeral cache for crawled vendor text chunks with regex text filtering."""

    def __init__(
        self,
        chunk_size: int = 800,
        chunk_overlap: int = 150,
    ):
        if chunk_size <= 0:
            raise ValueError("chunk_size must be greater than zero.")
        if chunk_overlap < 0 or chunk_overlap >= chunk_size:
            raise ValueError("chunk_overlap must be between zero and chunk_size - 1.")
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.documents: List[Dict[str, Any]] = []

    def clear(self) -> None:
        self.documents.clear()

    def ingest_text(
        self,
        text: str,
        source_url: str = "",
    ) -> None:
        """Split raw scraped text into clean fragments and store in memory."""

        clean_text = re.sub(r"\s+", " ", text).strip()

        if not clean_text:
            return

        start = 0
        text_len = len(clean_text)

        while start < text_len:
            end = min(start + self.chunk_size, text_len)
            chunk = clean_text[start:end]

            self.documents.append(
                {
                    "text": chunk,
                    "source": source_url,
                    "has_hex": bool(
                        re.search(r"\b[0-9a-fA-F]{64}\b", chunk)
                    ),
                }
            )

            if end == text_len:
                break

            start += self.chunk_size - self.chunk_overlap

    def get_ranked_context(
        self,
        keywords: List[str],
        max_chunks: int = 6,
    ) -> str:
        """Rank chunks by relevance to keywords, prioritizing 64-char hex strings."""

        def score_chunk(doc: Dict[str, Any]) -> int:
            score = 0
            text_lower = doc["text"].lower()

            if doc["has_hex"]:
                score += 50

            if "sha256" in text_lower or "sha-256" in text_lower:
                score += 20

            if (
                "checksum" in text_lower
                or "hash" in text_lower
                or "digest" in text_lower
            ):
                score += 10

            for kw in keywords:
                if kw and kw.lower() in text_lower:
                    score += 5

            return score

        scored = sorted(
            self.documents,
            key=score_chunk,
            reverse=True,
        )

        top_chunks = scored[:max_chunks]

        return "\n\n---\n\n".join(
            f"[Source: {chunk['source']}]\n{chunk['text']}"
            for chunk in top_chunks
        )


class WebRagEngine:
    """Stage 2 Automated Web-Search RAG & Integrity Verification Pipeline."""

    RIGID_SYSTEM_PROMPT = (
        "You are a strict cryptographic verification engine for VeriBlue AI.\n"
        "Your sole task is to isolate and return the authentic 64-character "
        "hexadecimal SHA-256 verification hash published by the official "
        "software vendor in the provided text.\n\n"
        "STRICT EXECUTION RULES:\n"
        "1. Return ONLY the exact 64-character lowercase hexadecimal SHA-256 "
        "hash (characters 0-9, a-f).\n"
        "2. Do NOT output markdown ticks, quotes, labels, file paths, or "
        "conversational text.\n"
        "3. If the authentic 64-character SHA-256 hash for the specified "
        "application and version cannot be positively identified in the "
        "text, you MUST output exactly: NOT_FOUND\n"
        "4. Never guess, shorten, or hallucinate a hash string under any "
        "circumstance."
    )

    def __init__(
        self,
        openai_key: Optional[str] = None,
        tavily_key: Optional[str] = None,
        log_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self.openai_key = openai_key or Config.get_openai_key()
        self.tavily_key = tavily_key or Config.get_tavily_key()
        self.log_callback = log_callback or (
            lambda stage, msg: None
        )
        self.memory_cache = EphemeralMemoryCache()

    def _log(
        self,
        stage: str,
        message: str,
    ) -> None:
        """Route internal status updates through the registered log UI callback thread."""

        if self.log_callback:
            self.log_callback(stage, message)

    def build_domain_restricted_query(
        self,
        metadata: BinaryMetadata,
    ) -> str:
        """Formulate strict domain-restricted, version-locked search query."""

        app_name = metadata.app_name
        version = (
            metadata.version
            if metadata.version != "Unknown"
            else ""
        )
        domain = metadata.suggested_domain

        if domain:
            query = (
                f'site:{domain} "{app_name}" "{version}" '
                "SHA256 checksum"
            ).strip()
        else:
            query = (
                f'"{app_name}" "{version}" official release '
                "SHA256 checksum verification"
            ).strip()

        query = re.sub(r"\s+", " ", query)
        return query

    def run_pipeline(
        self,
        local_hash: str,
        metadata: BinaryMetadata,
    ) -> Stage2Result:
        """Execute the end-to-end Stage 2 RAG verification workflow."""

        self._log(
            "STAGE_2_START",
            "Initiating Stage 2 Integrity Shield (Web-Search RAG Loop)...",
        )

        tavily_api_key = (
            self.tavily_key or Config.get_tavily_key()
        )
        provider = Config.get_ai_provider()
        ai_configured = (
            Config.is_gemini_configured()
            if provider == "gemini"
            else (
                Config.is_openai_configured()
                or bool(
                    self.openai_key
                    and len(self.openai_key) > 10
                    and not self.openai_key.startswith("your_")
                )
            )
        )

        if not tavily_api_key or len(tavily_api_key) <= 5 or tavily_api_key.startswith("your_"):
            msg = (
                "Tavily API key is missing. Configure key in Settings "
                "to enable Stage 2 web search."
            )

            self._log("STAGE_2_ERROR", msg)

            return Stage2Result(
                verdict=VerificationVerdict.ERROR,
                local_hash=local_hash,
                summary_message=msg,
            )

        if not ai_configured:
            msg = (
                "AI API key is missing. Configure Google Gemini (Free) "
                "or OpenAI key in Settings."
            )

            self._log("STAGE_2_ERROR", msg)

            return Stage2Result(
                verdict=VerificationVerdict.ERROR,
                local_hash=local_hash,
                summary_message=msg,
            )

        # Never verify against arbitrary search results when the parser
        # cannot map the application to a known vendor domain.
        trusted_domain = (metadata.suggested_domain or "").strip().lower().rstrip(".")
        if not trusted_domain:
            msg = (
                "No trusted vendor domain could be identified for this file. "
                "Automatic online verification is disabled to avoid trusting mirrors."
            )
            self._log("STAGE_2_WARNING", msg)
            return Stage2Result(
                verdict=VerificationVerdict.NOT_FOUND,
                local_hash=local_hash,
                summary_message=msg,
            )

        if not re.fullmatch(r"[0-9a-fA-F]{64}", local_hash):
            return Stage2Result(
                verdict=VerificationVerdict.ERROR,
                local_hash=local_hash,
                summary_message="Invalid local SHA-256 value; expected exactly 64 hexadecimal characters.",
            )

        if not HAS_TAVILY:
            msg = "The tavily-python package is missing. Install project requirements before using Stage 2."
            self._log("STAGE_2_ERROR", msg)
            return Stage2Result(
                verdict=VerificationVerdict.ERROR,
                local_hash=local_hash,
                summary_message=msg,
            )

        # 1. Domain-restricted query formulation
        query = self.build_domain_restricted_query(metadata)

        self._log(
            "QUERY_FORMULATION",
            f"Formulated Search Query: {query}",
        )

        # 2. Scraping and context retrieval via Tavily
        self._log(
            "TAVILY_SEARCH",
            "Crawling authenticated vendor endpoints via Tavily API...",
        )

        try:
            tavily_client = TavilyClient(
                api_key=tavily_api_key
            )

            search_response = tavily_client.search(
                query=query,
                search_depth="advanced",
                max_results=5,
                include_raw_content=True,
            )

        except Exception as e:
            err_msg = f"Tavily search request failed: {str(e)}"

            self._log("STAGE_2_ERROR", err_msg)

            return Stage2Result(
                verdict=VerificationVerdict.ERROR,
                local_hash=local_hash,
                search_query=query,
                summary_message=err_msg,
            )

        results = search_response.get("results", [])

        if not results:
            self._log(
                "STAGE_2_WARNING",
                "No search results returned for target application query.",
            )

            return Stage2Result(
                verdict=VerificationVerdict.NOT_FOUND,
                local_hash=local_hash,
                search_query=query,
                summary_message=(
                    "No official vendor documentation or checksum "
                    "pages found for this release."
                ),
            )

        # 3. Dynamic trust constraints and cache ingestion
        self.memory_cache.clear()

        primary_url = ""

        for item in results:
            url = str(item.get("url", "") or "")
            parsed_url = urlsplit(url)
            hostname = (parsed_url.hostname or "").lower().rstrip(".")
            is_trusted_url = (
                parsed_url.scheme == "https"
                and bool(hostname)
                and (hostname == trusted_domain or hostname.endswith("." + trusted_domain))
                and parsed_url.username is None
                and parsed_url.password is None
            )

            if not is_trusted_url:
                self._log(
                    "DYNAMIC_TRUST",
                    f"Ignoring untrusted mirror: {url}",
                )
                continue

            if not primary_url:
                primary_url = url

            content = (
                item.get("raw_content")
                or item.get("content", "")
            )

            if content:
                self.memory_cache.ingest_text(
                    content,
                    source_url=url,
                )

        total_chunks = len(self.memory_cache.documents)

        self._log(
            "EPHEMERAL_CACHE",
            f"Cached {total_chunks} text chunks into in-memory "
            "ephemeral context buffer.",
        )

        if total_chunks == 0:
            return Stage2Result(
                verdict=VerificationVerdict.NOT_FOUND,
                local_hash=local_hash,
                vendor_domain=trusted_domain,
                search_query=query,
                summary_message=(
                    "No usable content was found on HTTPS pages belonging "
                    "to the mapped vendor domain. Untrusted results were ignored."
                ),
                retrieved_chunks_count=0,
            )

        context_block = self.memory_cache.get_ranked_context(
            keywords=[
                metadata.app_name,
                metadata.version,
                "sha256",
                "checksum",
            ],
            max_chunks=6,
        )

        if not context_block.strip():
            return Stage2Result(
                verdict=VerificationVerdict.NOT_FOUND,
                local_hash=local_hash,
                vendor_url=primary_url,
                search_query=query,
                summary_message=(
                    "Vendor context crawled but no usable textual "
                    "content was obtained."
                ),
            )

        # Automated regex pre-check guard
        has_hash_pattern = bool(
            re.search(
                r"\b([a-fA-F0-9]{64})\b",
                context_block,
            )
        )

        if not has_hash_pattern:
            self._log(
                "STAGE_2_WARNING",
                "Pre-check guard: Crawled context contains no "
                "64-char hex structures. Skipping extraction loop "
                "to prevent timeouts.",
            )

            return Stage2Result(
                verdict=VerificationVerdict.NOT_FOUND,
                local_hash=local_hash,
                fetched_hash=None,
                vendor_url=primary_url,
                vendor_domain=metadata.suggested_domain,
                search_query=query,
                summary_message=(
                    "Official vendor hash layout pattern not present "
                    "in public context documents."
                ),
                retrieved_chunks_count=total_chunks,
            )

        # 4. LLM context layer extraction
        provider = Config.get_ai_provider()
        active_model = Config.get_active_model_name()

        self._log(
            "AI_EXTRACTION",
            f"Invoking {provider.upper()} ({active_model} at "
            "temperature=0.0) for strict hash isolation...",
        )

        fetched_hash = "NOT_FOUND"

        user_prompt = (
            f"Application Name: {metadata.app_name}\n"
            f"Version: {metadata.version}\n"
            f"Architecture: {metadata.architecture}\n"
            f"Suggested Domain: "
            f"{metadata.suggested_domain or 'Vendor Official'}\n\n"
            f"--- VENDOR CONTEXT EXTRACT ---\n"
            f"{context_block}\n"
            f"--- END VENDOR CONTEXT ---\n\n"
            "Isolate the clean 64-character SHA-256 hash "
            "or return 'NOT_FOUND':"
        )

        try:
            clean_res = "NOT_FOUND"

            if provider == "gemini":
                import requests

                g_key = Config.get_gemini_key()
                g_model = Config.get_gemini_model()
                if not g_key:
                    raise RuntimeError("Gemini API key is not configured.")

                api_url = (
                    "https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{g_model}:generateContent"
                )
                payload = {
                    "contents": [{"parts": [{"text": user_prompt}]}],
                    "systemInstruction": {
                        "parts": [{"text": self.RIGID_SYSTEM_PROMPT}]
                    },
                    "generationConfig": {
                        "temperature": 0.0,
                        "maxOutputTokens": 100,
                    },
                }
                with requests.post(
                    api_url,
                    headers={"x-goog-api-key": g_key},
                    json=payload,
                    timeout=Config.get_http_timeout(),
                ) as response:
                    response.raise_for_status()
                    response_json = response.json()

                candidates = response_json.get("candidates", [])
                parts = (
                    candidates[0].get("content", {}).get("parts", [])
                    if candidates else []
                )
                clean_res = "".join(
                    part.get("text", "")
                    for part in parts
                    if isinstance(part, dict)
                )
            else:
                if not HAS_LANGCHAIN:
                    raise RuntimeError(
                        "OpenAI provider requires langchain-openai and langchain-core."
                    )
                openai_api_key = self.openai_key or Config.get_openai_key()
                if not openai_api_key:
                    raise RuntimeError("OpenAI API key is not configured.")

                llm = ChatOpenAI(
                    model=Config.get_openai_model(),
                    temperature=0.0,
                    api_key=openai_api_key,
                    max_tokens=100,
                    request_timeout=Config.get_http_timeout(),
                )
                response = llm.invoke(
                    [
                        SystemMessage(content=self.RIGID_SYSTEM_PROMPT),
                        HumanMessage(content=user_prompt),
                    ]
                )
                clean_res = str(
                    response.content if hasattr(response, "content") else response
                )

            clean_res = clean_res.strip()
            if re.fullmatch(r"[a-fA-F0-9]{64}", clean_res):
                fetched_hash = clean_res.lower()
            elif clean_res.upper() == "NOT_FOUND":
                fetched_hash = "NOT_FOUND"
            else:
                fetched_hash = "NOT_FOUND"

            # The extracted digest must actually appear in the retrieved vendor
            # context. This prevents the model from inventing a plausible digest.
            if fetched_hash != "NOT_FOUND":
                context_hashes = {
                    match.lower()
                    for match in re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", context_block)
                }
                if fetched_hash not in context_hashes:
                    self._log(
                        "STAGE_2_WARNING",
                        "Model output was not present in retrieved vendor text; rejecting it.",
                    )
                    fetched_hash = "NOT_FOUND"

        except Exception as e:
            err_msg = f"LLM extraction error: {e}"
            self._log(
                "STAGE_2_WARNING",
                f"{err_msg}. Refusing to guess a vendor checksum.",
            )
            # A failed model/API call cannot establish which hash belongs to
            # this exact product release and architecture. Fail closed.
            fetched_hash = "NOT_FOUND"

        # 5. Cryptographic match engine
        self._log(
            "MATCH_CHECKPOINT",
            "Executing boolean checkpoint: "
            "Local Hash == Fetched Hash...",
        )

        if (
            fetched_hash == "NOT_FOUND"
            or len(fetched_hash) != 64
        ):
            self._log(
                "MATCH_RESULT",
                "Official published hash could not be identified "
                "with certainty in vendor documentation.",
            )

            return Stage2Result(
                verdict=VerificationVerdict.NOT_FOUND,
                local_hash=local_hash,
                fetched_hash=None,
                vendor_url=primary_url,
                vendor_domain=metadata.suggested_domain,
                search_query=query,
                summary_message=(
                    "Official vendor hash not found in public "
                    "release documentation. Use Offline P2P Mode."
                ),
                retrieved_chunks_count=total_chunks,
            )

        is_exact_match = (
            local_hash.lower() == fetched_hash.lower()
        )

        if is_exact_match:
            self._log(
                "MATCH_RESULT",
                "VERIFIED: Local calculated hash mathematically "
                "matches official vendor published hash!",
            )

            return Stage2Result(
                verdict=VerificationVerdict.GENUINE,
                local_hash=local_hash,
                fetched_hash=fetched_hash,
                vendor_url=primary_url,
                vendor_domain=metadata.suggested_domain,
                search_query=query,
                summary_message=(
                    "Genuine, clean deployment verified against "
                    "official vendor release."
                ),
                retrieved_chunks_count=total_chunks,
            )

        else:
            self._log(
                "MATCH_RESULT",
                "CRITICAL INTEGRITY FAILURE: Local hash differs "
                "from official vendor published hash!",
            )

            return Stage2Result(
                verdict=VerificationVerdict.TAMPERED,
                local_hash=local_hash,
                fetched_hash=fetched_hash,
                vendor_url=primary_url,
                vendor_domain=metadata.suggested_domain,
                search_query=query,
                summary_message=(
                    "Integrity Broken: File has been altered, "
                    "tampered with, or corrupted."
                ),
                retrieved_chunks_count=total_chunks,
            )
