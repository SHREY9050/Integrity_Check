"""VeriBlue AI - Configuration & API Key Management

Loads and persists API keys (VirusTotal, Tavily, Gemini, OpenAI) from environment
variables and local .env file.
"""

import os
from pathlib import Path
from typing import Dict, Optional
from dotenv import load_dotenv

# Base directory for the VeriBlue AI application
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent

ENV_PATH = BASE_DIR / ".env"
ROOT_ENV_PATH = ROOT_DIR / ".env"

# Load existing environment file if present (checks root first, then veriblue_ai dir)
if ROOT_ENV_PATH.exists():
    load_dotenv(dotenv_path=ROOT_ENV_PATH, override=True)
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH, override=True)


class Config:
    """Application configuration holder with dynamic reload capabilities."""

    @classmethod
    def get_virustotal_key(cls) -> str:
        return os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    @classmethod
    def get_tavily_key(cls) -> str:
        return os.getenv("TAVILY_API_KEY", "").strip()

    @classmethod
    def get_gemini_key(cls) -> str:
        return os.getenv("GEMINI_API_KEY", "").strip()

    @classmethod
    def get_openai_key(cls) -> str:
        return os.getenv("OPENAI_API_KEY", "").strip()

    @classmethod
    def get_ai_provider(cls) -> str:
        """Return 'gemini' or 'openai'. Auto-detects if not set."""
        prov = os.getenv("AI_PROVIDER", "").strip().lower()
        if prov in ["gemini", "openai"]:
            return prov
        if cls.is_gemini_configured():
            return "gemini"
        if cls.is_openai_configured():
            return "openai"
        return "gemini"  # Default to free Gemini

    @classmethod
    def get_gemini_model(cls) -> str:
        return os.getenv("GEMINI_MODEL", "gemini-flash-latest").strip()

    @classmethod
    def get_openai_model(cls) -> str:
        return os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()

    @classmethod
    def get_http_timeout(cls) -> int:
        """HTTP client timeout in seconds (default 90s, minimum 60s)."""
        try:
            return max(60, int(os.getenv("HTTP_TIMEOUT", "90")))
        except ValueError:
            return 90

    @classmethod
    def get_temperature(cls) -> float:
        try:
            return float(os.getenv("AI_TEMPERATURE", "0.0"))
        except ValueError:
            return 0.0

    @classmethod
    def is_virustotal_configured(cls) -> bool:
        key = cls.get_virustotal_key()
        return bool(key and len(key) > 10 and not key.startswith("your_"))

    @classmethod
    def is_tavily_configured(cls) -> bool:
        key = cls.get_tavily_key()
        return bool(key and len(key) > 5 and not key.startswith("your_"))

    @classmethod
    def is_gemini_configured(cls) -> bool:
        key = cls.get_gemini_key()
        return bool(key and len(key) > 10 and not key.startswith("your_"))

    @classmethod
    def is_openai_configured(cls) -> bool:
        key = cls.get_openai_key()
        return bool(key and len(key) > 10 and not key.startswith("your_"))

    @classmethod
    def is_ai_configured(cls) -> bool:
        prov = cls.get_ai_provider()
        if prov == "gemini":
            return cls.is_gemini_configured()
        return cls.is_openai_configured()

    @classmethod
    def get_active_model_name(cls) -> str:
        prov = cls.get_ai_provider()
        if prov == "gemini":
            return cls.get_gemini_model()
        return cls.get_openai_model()

    @classmethod
    def save_keys(
        cls,
        virustotal_key: Optional[str] = None,
        tavily_key: Optional[str] = None,
        gemini_key: Optional[str] = None,
        openai_key: Optional[str] = None,
        ai_provider: Optional[str] = None,
        model_name: Optional[str] = None,
    ) -> None:
        """Persist updated API keys to .env file and active environment."""
        current: Dict[str, str] = {}
        target_path = ENV_PATH

        if target_path.exists():
            with open(target_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        current[k.strip()] = v.strip().strip("'\"")

        if virustotal_key is not None:
            current["VIRUSTOTAL_API_KEY"] = virustotal_key.strip()
            os.environ["VIRUSTOTAL_API_KEY"] = virustotal_key.strip()
        if tavily_key is not None:
            current["TAVILY_API_KEY"] = tavily_key.strip()
            os.environ["TAVILY_API_KEY"] = tavily_key.strip()
        if gemini_key is not None:
            current["GEMINI_API_KEY"] = gemini_key.strip()
            os.environ["GEMINI_API_KEY"] = gemini_key.strip()
        if openai_key is not None:
            current["OPENAI_API_KEY"] = openai_key.strip()
            os.environ["OPENAI_API_KEY"] = openai_key.strip()
        if ai_provider is not None:
            current["AI_PROVIDER"] = ai_provider.strip().lower()
            os.environ["AI_PROVIDER"] = ai_provider.strip().lower()
        if model_name is not None:
            prov = current.get("AI_PROVIDER", "gemini")
            if prov == "gemini":
                current["GEMINI_MODEL"] = model_name.strip()
                os.environ["GEMINI_MODEL"] = model_name.strip()
            else:
                current["OPENAI_MODEL"] = model_name.strip()
                os.environ["OPENAI_MODEL"] = model_name.strip()

        with open(target_path, "w", encoding="utf-8") as f:
            f.write("# VeriBlue AI Configuration File\n")
            f.write(f"VIRUSTOTAL_API_KEY={current.get('VIRUSTOTAL_API_KEY', '')}\n")
            f.write(f"TAVILY_API_KEY={current.get('TAVILY_API_KEY', '')}\n")
            f.write(f"GEMINI_API_KEY={current.get('GEMINI_API_KEY', '')}\n")
            f.write(f"OPENAI_API_KEY={current.get('OPENAI_API_KEY', '')}\n")
            f.write(f"AI_PROVIDER={current.get('AI_PROVIDER', 'gemini')}\n")
            f.write(f"GEMINI_MODEL={current.get('GEMINI_MODEL', 'gemini-flash-latest')}\n")
            f.write(f"OPENAI_MODEL={current.get('OPENAI_MODEL', 'gpt-4o-mini')}\n")
            f.write(f"HTTP_TIMEOUT={current.get('HTTP_TIMEOUT', '90')}\n")
            f.write("AI_TEMPERATURE=0.0\n")
