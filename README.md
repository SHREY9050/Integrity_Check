# VeriBlue AI — Multi-Stage AI-Powered File Integrity Verifier

> **Autonomous Defense-in-Depth Desktop Security Utility for Software Installers, Application Binaries, and Deployment Archives.**

---

## 1. Project Overview & Vision

Typical antivirus solutions focus on flagging cataloged malware signatures. **VeriBlue AI** prioritizes **data integrity**, safeguarding developers and end-users against supply chain attacks, corrupted binaries, trojanized mirrors, and unauthorized third-party repackaging.

VeriBlue AI utilizes a **deterministic hybrid architecture**: mathematical cryptographic calculations are strictly isolated from language-model operations, guaranteeing that AI hallucinations can never alter or corrupt a cryptographic checksum string.

---

## 2. Multi-Stage Pipeline Architecture

```
                 [ User Drops Installer File ]
                                |
                                v
     +------------------------------------------------------+
     | 0. LOCAL DETERMINISTIC ENGINE (Python Native)        |
     | • 4096-byte chunk buffering streaming SHA-256       |
     | • PE structural header parsing (Name, Ver, Arch)     |
     +--------------------------+---------------------------+
                                |
                                v
     +------------------------------------------------------+
     | STAGE 1: THE VIRUSTOTAL SHIELD                       |
     | Sends ONLY 64-char fingerprint to VT v3 API          |
     | • Malicious > 0: Halts execution -> AI Explainer     |
     | • 404 Not Found: Trap smoothly -> Cascades to Stage 2|
     +--------------------------+---------------------------+
                                | (404 / Clean)
                                v
     +------------------------------------------------------+
     | STAGE 2: THE WEB-SEARCH RAG ENGINE                   |
     | • Formulates domain-restricted query (e.g. site:...) |
     | • Tavily crawls & strips layout clutter              |
     | • Ephemeral in-memory vector cache & trust filter    |
     | • LangChain + gpt-4o-mini (temp=0.0) rigid extract   |
     +--------------------------+---------------------------+
                                |
                                v
     +------------------------------------------------------+
     | 3. CRYPTOGRAPHIC MATCH ENGINE                        |
     | Strict Boolean Logic: Local Hash == Fetched Hash     |
     | • Match (TRUE): GREEN (Genuine, Clean Deployment)    |
     | • Mismatch (FALSE): RED (Integrity Broken / Tampered)|
     +------------------------------------------------------+
```

---

## 3. Key Features

- **Responsive Drag-and-Drop Graphical Dashboard:** Built with CustomTkinter, featuring an active landing container box, file browser fallback, and native OS drag-and-drop support.
- **Asynchronous Execution Pipeline:** Hashing and network RAG calls execute on background worker threads with thread-safe UI updates, ensuring large multi-gigabyte files never freeze or lock the interface.
- **4096-Byte Chunk Stream Hashing:** Streams binary data block-by-block using native `hashlib.sha256()`, preventing RAM exhaustion on large installer packages.
- **Structural Header Metadata Harvester:** Isolates internal application names, semantic versions, target architectures (x86, x64, ARM64), and company signatures using `pefile` with filename heuristic fallbacks.
- **Automated Fallback Routing:** Catches HTTP 404 responses from threat registries smoothly, cascading to live vendor documentation without user intervention.
- **Dynamic Trust Constraints:** Rejects untrusted mirrors and scrapes only official vendor domains (e.g., `videolan.org`, `python.org`, `git-scm.com`).
- **Rigid Zero-Hallucination Extraction:** Enforces a rigid system prompt ensuring the LLM returns only the authentic 64-character hexadecimal SHA-256 string or `NOT_FOUND`.
- **P2P Offline Secure Mode:** Dedicated input canvas that completely bypasses all web and network APIs for comparing sensitive internal builds and private peer-to-peer files.
- **Interactive Visual Pipeline Stepper & Live Log:** Displays live progress badges and streaming diagnostic operations in real time.

---

## 4. Project Target Structure

```
d:/AI PROJECT/
│
├── veriblue_ai/
│   ├── __init__.py
│   ├── __main__.py          # Entry point for python -m veriblue_ai
│   ├── main.py              # CustomTkinter UI loop & Async threading
│   ├── config.py            # API credentials & configuration management
│   ├── .env.example         # Template for environment credentials
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── hasher.py        # 4096-byte chunk buffered stream hashing (Step 0)
│   │   └── parser.py        # Structural binary header metadata extractor (Step 0)
│   │
│   └── engines/
│       ├── __init__.py
│       ├── virus_total.py   # Stage 1 VirusTotal v3 connector & AI threat explainer
│       └── web_rag.py       # Stage 2 Tavily RAG, ephemeral cache & LLM extraction
│
├── tests/
│   └── test_veriblue.py     # Unit test suite for hashing, parsing, and RAG logic
│
├── run_app.py               # Root application launcher
└── requirements.txt         # Project dependencies
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.11+
- Windows 10/11 (or macOS / Linux)

### Installation
1. Clone or navigate to the repository directory:
   ```bash
   cd "d:/AI PROJECT"
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Configure API credentials in `.env`:
   ```bash
   copy veriblue_ai\.env.example veriblue_ai\.env
   ```
   *Note: You can also configure credentials directly inside the desktop application via the **Engine Credentials** tab.*

---

## 6. Running VeriBlue AI

Launch the desktop interface using either:

```bash
python run_app.py
```
*or*
```bash
python -m veriblue_ai
```

---

## 7. Configuration Details

| Environment Variable | Description | Default |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key for Stage 1 threat scanning | *Optional / User provided* |
| `TAVILY_API_KEY` | Tavily Search API key for Stage 2 vendor documentation RAG | *Optional / User provided* |
| `OPENAI_API_KEY` | OpenAI API key for strict hash extraction & threat explanation | *Optional / User provided* |
| `OPENAI_MODEL` | LLM model for extraction (`gpt-4o-mini`, `gpt-4o`) | `gpt-4o-mini` |
| `OPENAI_TEMPERATURE`| Strict deterministic sampling temperature | `0.0` |

---

## 8. Running the Unit Tests

Execute the automated test suite:

```bash
python -m unittest tests/test_veriblue.py
```

All 10 tests validate:
- 4096-byte chunk stream hashing matches Python ground truth digests
- Progress callback execution during multi-chunk streaming
- Filename and PE structural metadata extraction
- VirusTotal 404 trap and malicious payload halting
- Ephemeral vector context cache ingestion, chunking, and keyword relevance scoring
- Traditional cryptographic boolean match verification
