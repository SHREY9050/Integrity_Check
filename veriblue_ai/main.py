"""VeriBlue AI - Multi-Stage AI-Powered File Integrity Verifier

Main desktop graphical application built with CustomTkinter.
Features:
- Native Drag-and-Drop landing container with fallback file browser
- Asynchronous pipeline execution engine (never freezes UI)
- Stage 1: VirusTotal global threat registry lookup
- Stage 2: Web-Search RAG with Tavily, ephemeral vector cache, and LLM hash extraction
- Cryptographic Match Engine (Deterministic Local vs Fetched comparison)
- P2P Offline Secure Mode (Zero web API transmission)
- Real-time animated pipeline progress tracker and visual log
"""

import os
import sys
import threading
import time
from typing import Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox

# Optional TkinterDnD2 integration for OS drag-and-drop
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
except ImportError:
    HAS_DND = False

try:
    from .config import Config
    from .core.hasher import calculate_sha256_stream
    from .core.parser import extract_binary_metadata, BinaryMetadata
    from .engines.virus_total import VirusTotalEngine, VirusTotalResult, ThreatStatus
    from .engines.web_rag import WebRagEngine, Stage2Result, VerificationVerdict
except (ImportError, ValueError):
    from config import Config
    from core.hasher import calculate_sha256_stream
    from core.parser import extract_binary_metadata, BinaryMetadata
    from engines.virus_total import VirusTotalEngine, VirusTotalResult, ThreatStatus
    from engines.web_rag import WebRagEngine, Stage2Result, VerificationVerdict


# Subclass CustomTkinter root with TkinterDnD if available
if HAS_DND:
    class BaseRootWindow(ctk.CTk, TkinterDnD.DnDWrapper):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.TkdndVersion = TkinterDnD._require(self)
else:
    class BaseRootWindow(ctk.CTk):
        pass


# ==============================================================================
# VeriBlue AI — Cyberpunk Theme: BLACK / ELECTRIC-BLUE / NEON-RED  (Approved)
# Colours extracted 1-to-1 from theme_preview_cyberpunk.html
# ==============================================================================

# ── Backgrounds ────────────────────────────────────────────────────────────────
C_BG_BODY        = "#050608"   # deepest black  — window root
C_BG_SHELL       = "#090A0F"   # app shell
C_BG_HEADER      = "#0B0D14"   # header bar
C_BG_TITLEBAR    = "#0D0F17"   # title bar
C_BG_PANEL       = "#0C0E17"   # left/right content panes
C_BG_STEPPER     = "#0C0E15"   # pipeline stepper card
C_BG_CARD        = "#07090F"   # inner cards / hash frame
C_BG_DROPZONE    = "#0F111A"   # drag-and-drop zone
C_BG_TERMINAL    = "#05060A"   # live log terminal
C_BG_HASH        = "#06080D"   # hash comparison row
C_BG_BROWSE_BTN  = "#121622"   # Browse File button
C_BG_INPUT       = "#030407"   # text entry background

# ── Borders ────────────────────────────────────────────────────────────────────
C_BORDER_SUBTLE  = "#1E293B"   # default subtle border
C_BORDER_INNER   = "#192033"   # inner card border
C_BORDER_STEPPER = "#181D2A"   # stepper card border

# ── Primary Accents ─────────────────────────────────────────────────────────────
C_BLUE           = "#0084FF"   # electric blue  — active tab, borders, pills
C_BLUE_BRIGHT    = "#00A3FF"   # bright electric blue — titles, log timestamps
C_BLUE_SKY       = "#38BDF8"   # sky / cyan — pill text, vendor hash waiting
C_BLUE_HOVER     = "#1A2030"   # browse button hover

C_RED            = "#FF073A"   # neon red — drop-zone border, logo, start btn
C_RED_DARK       = "#D90429"   # neon red gradient end
C_RED_PILL_BG    = "#260008"   # AI status pill background
C_RED_PILL_TEXT  = "#FF4D6D"   # AI status pill text
C_RED_PILL_BORD  = "#800018"   # AI status pill border

C_BLUE_PILL_BG   = "#001833"   # VT / Tavily pill background
C_BLUE_PILL_BORD = "#004080"   # VT / Tavily pill border

# ── Text ──────────────────────────────────────────────────────────────────────
C_TEXT_PRIMARY   = "#F1F5F9"   # bright white text — headings
C_TEXT_BODY      = "#E2E8F0"   # body / data text
C_TEXT_MUTED     = "#CBD5E1"   # muted — subtitles
C_TEXT_DIM       = "#94A3B8"   # dim — inactive tabs, hints
C_TEXT_FAINT     = "#64748B"   # very dim — meta info, timestamps

# ── Status colours (keep as-is in verdict logic) ──────────────────────────────
C_GREEN          = "#22C55E"   # verified / clean
C_AMBER          = "#F59E0B"   # warning / not-found
C_ERR_RED        = "#EF4444"   # error / tampered

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Backward-compatibility aliases — every old widget reference works unchanged
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COLOR_AUBERGINE_BG      = C_BG_BODY
COLOR_AUBERGINE_PANEL   = C_BG_PANEL
COLOR_AUBERGINE_CARD    = C_BG_CARD
COLOR_AUBERGINE_SURFACE = C_BG_BROWSE_BTN
COLOR_AUBERGINE_BORDER  = C_BORDER_SUBTLE
COLOR_MARIGOLD_BRIGHT   = C_RED
COLOR_MARIGOLD_PRIMARY  = C_BLUE
COLOR_MARIGOLD_HOVER    = C_RED_DARK
COLOR_ICE_SILVER_LIGHT  = C_TEXT_PRIMARY
COLOR_ICE_SILVER_BODY   = C_TEXT_BODY
COLOR_ICE_SILVER_MUTED  = C_TEXT_MUTED
COLOR_ICE_SILVER_DIM    = C_TEXT_DIM




class VeriBlueApp(BaseRootWindow):
    """Main application window for VeriBlue AI."""

    def __init__(self):
        super().__init__()

        # Window Appearance & Configuration
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=C_BG_BODY)

        self.title("VeriBlue AI - Multi-Stage File Integrity Verifier")
        self.geometry("1060x820")
        self.minsize(980, 720)

        # Application State
        self.selected_file_path: Optional[str] = None
        self.selected_file_metadata: Optional[BinaryMetadata] = None
        self.local_hash: Optional[str] = None
        self.is_scanning: bool = False
        self.cancel_requested: bool = False

        # Engines
        self.vt_engine = VirusTotalEngine()
        self.web_rag_engine = WebRagEngine(log_callback=self._on_rag_log)

        # Build UI layout
        self._build_header()
        self._build_navigation_tabs()

        # Update API status pills
        self.refresh_api_status_pills()

    # ---------------------------------------------------------
    # UI Layout Builders
    # ---------------------------------------------------------
    def _build_header(self):
        """Top branding header with status pills and quick settings."""
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=C_BG_HEADER, height=70)
        self.header_frame.pack(fill="x", side="top")

        # Brand Title & Icon
        title_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_box.pack(side="left", padx=24, pady=12)

        logo_label = ctk.CTkLabel(
            title_box,
            text="🛡️ VeriBlue AI",
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
            text_color=COLOR_MARIGOLD_BRIGHT,
        )
        logo_label.pack(side="top", anchor="w")

        subtitle_label = ctk.CTkLabel(
            title_box,
            text="Autonomous Defense-in-Depth File Integrity & Threat Shield",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=C_TEXT_MUTED,
        )
        subtitle_label.pack(side="top", anchor="w")

        # Status Pills (VT, Tavily, AI)
        self.pills_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.pills_frame.pack(side="right", padx=24, pady=12)

        self.vt_pill = ctk.CTkLabel(
            self.pills_frame,
            text="VirusTotal: ...",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=C_BLUE_PILL_BG,
            text_color=C_BLUE_SKY,
            corner_radius=6,
            padx=10,
            pady=4,
        )
        self.vt_pill.pack(side="left", padx=4)

        self.tavily_pill = ctk.CTkLabel(
            self.pills_frame,
            text="Tavily: ...",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=C_BLUE_PILL_BG,
            text_color=C_BLUE_SKY,
            corner_radius=6,
            padx=10,
            pady=4,
        )
        self.tavily_pill.pack(side="left", padx=4)

        self.openai_pill = ctk.CTkLabel(
            self.pills_frame,
            text="AI: ...",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=C_RED_PILL_BG,
            text_color=C_RED_PILL_TEXT,
            corner_radius=6,
            padx=10,
            pady=4,
        )
        self.openai_pill.pack(side="left", padx=4)

    def _build_navigation_tabs(self):
        """Build main segmented tab view."""
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=C_BG_BODY,
            segmented_button_fg_color=C_BG_STEPPER,
            segmented_button_selected_color=C_BLUE,
            segmented_button_selected_hover_color=C_BLUE_BRIGHT,
            text_color=C_TEXT_DIM,
        )
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(10, 16))

        # Navigation tabs
        self.tab_pipeline = self.tabview.add("  Live AI Pipeline Shield  ")
        self.tab_generator = self.tabview.add("  Generate Checksum  ")
        self.tab_p2p = self.tabview.add("  P2P Offline Verify  ")
        self.tab_settings = self.tabview.add("  Engine Credentials  ")

        self._build_pipeline_tab()
        self._build_generator_tab()
        self._build_p2p_tab()
        self._build_settings_tab()

    # ---------------------------------------------------------
    # TAB 1: Live AI Pipeline Shield
    # ---------------------------------------------------------
    def _build_pipeline_tab(self):
        tab = self.tab_pipeline

        # Two-column layout in Black, Electric‑Blue, Neon‑Red theme
        main_panes = ctk.CTkFrame(tab, fg_color="transparent")
        main_panes.pack(fill="both", expand=True, padx=6, pady=6)

        left_pane = ctk.CTkFrame(
            main_panes,
            fg_color=C_BG_PANEL,
            border_color=C_BORDER_SUBTLE,
            border_width=1,
            corner_radius=10,
            width=440,
        )
        left_pane.pack(side="left", fill="both", expand=False, padx=(0, 8), pady=0)
        left_pane.pack_propagate(False)

        right_pane = ctk.CTkFrame(
            main_panes,
            fg_color=C_BG_PANEL,
            border_color=C_BORDER_SUBTLE,
            border_width=1,
            corner_radius=10,
        )
        right_pane.pack(side="right", fill="both", expand=True, padx=(8, 0), pady=0)

        # --- LEFT PANE: DRAG & DROP BOX & CONTROLS ---
        drop_header = ctk.CTkLabel(
            left_pane,
            text="1. Target File Inspection",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        )
        drop_header.pack(anchor="w", padx=16, pady=(16, 8))

        # Drag & Drop Container Landing Card
        self.drop_card = ctk.CTkFrame(
            left_pane,
            fg_color=C_BG_DROPZONE,
            border_color=C_RED,
            border_width=2,
            corner_radius=10,
            height=140,
        )
        self.drop_card.pack(fill="x", padx=16, pady=4)
        self.drop_card.pack_propagate(False)

        self.drop_icon = ctk.CTkLabel(
            self.drop_card,
            text="📥",
            font=ctk.CTkFont(size=28),
        )
        self.drop_icon.pack(pady=(12, 2))

        self.drop_text = ctk.CTkLabel(
            self.drop_card,
            text="DRAG & DROP INSTALLER HERE\n-- or click to select binary --",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C_RED,
            justify="center",
        )
        self.drop_text.pack(pady=(0, 10))

        # Enable click on card
        self.drop_card.bind("<Button-1>", lambda e: self._choose_file_dialog())
        self.drop_icon.bind("<Button-1>", lambda e: self._choose_file_dialog())
        self.drop_text.bind("<Button-1>", lambda e: self._choose_file_dialog())

        # Enable native Drag and Drop if TkinterDnD is available
        if HAS_DND:
            try:
                self.drop_card.drop_target_register(DND_FILES)
                self.drop_card.dnd_bind("<<Drop>>", self._on_file_dropped)
            except Exception:
                pass

        # File Details Summary Card
        self.file_info_frame = ctk.CTkFrame(left_pane, fg_color=C_BG_CARD, corner_radius=8)
        self.file_info_frame.pack(fill="x", padx=16, pady=10)

        self.info_file_name = ctk.CTkLabel(
            self.file_info_frame,
            text="No file selected",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
            anchor="w",
        )
        self.info_file_name.pack(fill="x", padx=12, pady=(10, 4))

        self.info_meta = ctk.CTkLabel(
            self.file_info_frame,
            text="Size: -- | Architecture: -- | Version: --",
            font=ctk.CTkFont(size=11),
            text_color=C_TEXT_MUTED,
            anchor="w",
        )
        self.info_meta.pack(fill="x", padx=12, pady=(0, 10))

        # Button Row
        btn_frame = ctk.CTkFrame(left_pane, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=6)

        self.btn_browse = ctk.CTkButton(
            btn_frame,
            text="Browse File",
            command=self._choose_file_dialog,
            fg_color=C_BG_BROWSE_BTN,
            hover_color=C_BLUE_HOVER,
            text_color=C_TEXT_MUTED,
            width=110,
        )
        self.btn_browse.pack(side="left", padx=(0, 6))

        self.btn_start = ctk.CTkButton(
            btn_frame,
            text="Start Verification",
            command=self._start_pipeline_thread,
            fg_color=C_RED,
            hover_color=C_RED_DARK,
            text_color="#FFFFFF",
            font=ctk.CTkFont(weight="bold"),
        )
        self.btn_start.pack(side="left", fill="x", expand=True)

        # Pipeline Visual Stepper (Interactive 4-Step Tracker)
        stepper_title = ctk.CTkLabel(
            left_pane,
            text="2. Pipeline Stages",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        )
        stepper_title.pack(anchor="w", padx=16, pady=(14, 6))

        self.stepper_frame = ctk.CTkFrame(left_pane, fg_color=C_BG_STEPPER, corner_radius=8, border_color=C_BORDER_STEPPER, border_width=1)
        self.stepper_frame.pack(fill="x", padx=16, pady=4)

        self.step_widgets = []
        steps_info = [
            ("Step 0", "Local Deterministic Hashing & PE Headers"),
            ("Step 1", "Stage 1: VirusTotal Threat Shield"),
            ("Step 2", "Stage 2: Web-Search RAG Engine"),
            ("Step 3", "Cryptographic Boolean Match Engine"),
        ]

        for code, label_text in steps_info:
            row = ctk.CTkFrame(self.stepper_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=5)

            indicator = ctk.CTkLabel(
                row,
                text="⚪",
                font=ctk.CTkFont(size=14),
                width=24,
            )
            indicator.pack(side="left")

            label = ctk.CTkLabel(
                row,
                text=f"{code}: {label_text}",
                font=ctk.CTkFont(size=11),
                text_color=C_TEXT_DIM,
                anchor="w",
            )
            label.pack(side="left", fill="x", expand=True, padx=6)
            self.step_widgets.append((indicator, label))

        # Animated Progress Bar
        self.progress_bar = ctk.CTkProgressBar(left_pane, fg_color=C_BG_STEPPER, progress_color=C_BLUE)
        self.progress_bar.pack(fill="x", padx=16, pady=(14, 6))
        self.progress_bar.set(0.0)

        self.progress_status_label = ctk.CTkLabel(
            left_pane,
            text="Ready. Select or drop a file to verify.",
            font=ctk.CTkFont(size=11),
            text_color=C_TEXT_DIM,
            anchor="w",
        )
        self.progress_status_label.pack(fill="x", padx=16, pady=(0, 10))

        # --- RIGHT PANE: VERDICT CANVAS & LIVE LOGS ---
        right_header = ctk.CTkLabel(
            right_pane,
            text="Verification Verdict & Threat Diagnostics",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        )
        right_header.pack(anchor="w", padx=16, pady=(16, 8))

        # Main Dynamic Verdict Canvas Card (Aubergine base with Marigold / Green / Red borders)
        self.verdict_canvas = ctk.CTkFrame(
            right_pane,
            fg_color=C_BG_PANEL,
            border_color=C_BLUE,
            border_width=2,
            corner_radius=10,
        )
        self.verdict_canvas.pack(fill="x", padx=16, pady=4)

        self.verdict_title = ctk.CTkLabel(
            self.verdict_canvas,
            text="Awaiting File Analysis",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=C_BLUE_BRIGHT,
        )
        self.verdict_title.pack(anchor="w", padx=16, pady=(12, 4))

        self.verdict_body = ctk.CTkLabel(
            self.verdict_canvas,
            text="Drop an installer or binary on the left panel to execute the multi-stage integrity pipeline.",
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_MUTED,
            justify="left",
            wraplength=520,
            anchor="w",
        )
        self.verdict_body.pack(fill="x", padx=16, pady=(0, 8))

        # Hash Comparison Sub-Frame
        self.hash_comp_frame = ctk.CTkFrame(self.verdict_canvas, fg_color=C_BG_HASH, corner_radius=6, border_color=C_BORDER_INNER, border_width=1)
        self.hash_comp_frame.pack(fill="x", padx=16, pady=(4, 12))

        self.lbl_local_hash = ctk.CTkLabel(
            self.hash_comp_frame,
            text="Local SHA-256:  --",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=C_BLUE_BRIGHT,
            anchor="w",
        )
        self.lbl_local_hash.pack(fill="x", padx=10, pady=(6, 2))

        self.lbl_fetched_hash = ctk.CTkLabel(
            self.hash_comp_frame,
            text="Vendor SHA-256: --",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=C_RED,
            anchor="w",
        )
        self.lbl_fetched_hash.pack(fill="x", padx=10, pady=(2, 6))

        # Live Terminal Visual Log
        log_header = ctk.CTkLabel(
            right_pane,
            text="Live Internal Operations Log",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        )
        log_header.pack(anchor="w", padx=16, pady=(12, 4))

        self.log_textbox = ctk.CTkTextbox(
            right_pane,
            fg_color="#050608",
            text_color="#00EAFF",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=8,
            border_color=C_BORDER_INNER,
            border_width=1,
        )
        self.log_textbox.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.log_textbox.insert("end", "[VeriBlue AI Engine initialized - Cyber Black/Electric-Blue/Neon-Red theme]\n")
        self.log_textbox.configure(state="disabled")

    # ---------------------------------------------------------
    # TAB 2: Checksum Generator & Share (Dedicated Section)
    # ---------------------------------------------------------
    def _build_generator_tab(self):
        tab = self.tab_generator

        container = ctk.CTkFrame(tab, fg_color=C_BG_PANEL, corner_radius=10, border_color=C_BORDER_SUBTLE, border_width=1)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        title = ctk.CTkLabel(
            container,
            text="📤 Checksum Generator & Share",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=C_RED,
        )
        title.pack(anchor="w", padx=24, pady=(20, 4))

        desc = ctk.CTkLabel(
            container,
            text=(
                "Generate the authentic SHA-256 cryptographic fingerprint for any file, PDF, or archive "
                "before sending it. Copy the 64-character hash and send it to your peer over WhatsApp, "
                "Signal, or email so they can verify the file hasn't been modified or corrupted."
            ),
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_MUTED,
            justify="left",
            wraplength=850,
        )
        desc.pack(anchor="w", padx=24, pady=(0, 16))

        # File Select Section
        file_sec = ctk.CTkFrame(container, fg_color=C_BG_CARD, corner_radius=8, border_color=C_BORDER_INNER, border_width=1)
        file_sec.pack(fill="x", padx=24, pady=8)

        ctk.CTkLabel(
            file_sec,
            text="Select File to Share:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        ).pack(side="left", padx=16, pady=16)

        self.gen_file_label = ctk.CTkLabel(
            file_sec,
            text="No file selected",
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_MUTED,
            anchor="w",
        )
        self.gen_file_label.pack(side="left", fill="x", expand=True, padx=8)

        btn_browse = ctk.CTkButton(
            file_sec,
            text="Browse File",
            command=self._choose_gen_file,
            fg_color=C_BG_BROWSE_BTN,
            hover_color=C_BLUE_HOVER,
            text_color=C_TEXT_MUTED,
            width=110,
        )
        btn_browse.pack(side="right", padx=16, pady=16)

        # Action Button
        self.btn_calc_hash = ctk.CTkButton(
            container,
            text="⚡ Calculate Cryptographic SHA-256 Checksum",
            command=self._calculate_and_display_hashes,
            fg_color=C_RED,
            hover_color=C_RED_DARK,
            text_color="#FFFFFF",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
        )
        self.btn_calc_hash.pack(fill="x", padx=24, pady=14)

        # Result display
        self.gen_results_box = ctk.CTkFrame(container, fg_color=C_BG_CARD, corner_radius=8, border_color=C_BORDER_INNER, border_width=1)
        self.gen_results_box.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        ctk.CTkLabel(
            self.gen_results_box,
            text="Generated 64-Character SHA-256 Checksum:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLOR_MARIGOLD_BRIGHT,
        ).pack(anchor="w", padx=16, pady=(16, 6))

        sha_row = ctk.CTkFrame(self.gen_results_box, fg_color="transparent")
        sha_row.pack(fill="x", padx=16, pady=(0, 10))

        self.entry_gen_sha256 = ctk.CTkEntry(
            sha_row,
            placeholder_text="Calculated SHA-256 checksum will appear here...",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C_BG_INPUT,
            border_color=C_BORDER_INNER,
            text_color=C_BLUE_SKY,
            height=38,
        )
        self.entry_gen_sha256.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.btn_copy_sha256 = ctk.CTkButton(
            sha_row,
            text="📋 Copy Checksum",
            command=self._copy_gen_sha256,
            fg_color=C_BG_BROWSE_BTN,
            hover_color="#0060CC",
            text_color=C_TEXT_PRIMARY,
            font=ctk.CTkFont(weight="bold"),
            width=150,
            height=38,
        )
        self.btn_copy_sha256.pack(side="right")

        self.lbl_gen_status = ctk.CTkLabel(
            self.gen_results_box,
            text="Pick any document or installer above and click Calculate.",
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_DIM,
            anchor="w",
        )
        self.lbl_gen_status.pack(fill="x", padx=16, pady=(4, 16))

    # ---------------------------------------------------------
    # TAB 3: P2P Offline Secure Verification Mode
    # ---------------------------------------------------------
    def _build_p2p_tab(self):
        tab = self.tab_p2p

        p2p_container = ctk.CTkFrame(tab, fg_color=C_BG_PANEL, corner_radius=10, border_color=C_BORDER_SUBTLE, border_width=1)
        p2p_container.pack(fill="both", expand=True, padx=20, pady=20)

        title = ctk.CTkLabel(
            p2p_container,
            text="🔒 P2P Offline Secure Verification Mode",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=C_RED,
        )
        title.pack(anchor="w", padx=24, pady=(20, 4))

        desc = ctk.CTkLabel(
            p2p_container,
            text=(
                "Bypasses all internet and web API layers. Designed for sensitive corporate documents, "
                "internal builds, and direct peer-to-peer file transfers. Compares local cryptographic "
                "hash against an out-of-band checksum string provided by your trusted peer."
            ),
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_MUTED,
            justify="left",
            wraplength=850,
        )
        desc.pack(anchor="w", padx=24, pady=(0, 20))

        # File Select Section
        file_sec = ctk.CTkFrame(p2p_container, fg_color=C_BG_CARD, corner_radius=8, border_color=C_BORDER_INNER, border_width=1)
        file_sec.pack(fill="x", padx=24, pady=8)

        ctk.CTkLabel(
            file_sec,
            text="Received File:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        ).pack(side="left", padx=16, pady=16)

        self.p2p_file_label = ctk.CTkLabel(
            file_sec,
            text="No file selected",
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_MUTED,
            anchor="w",
        )
        self.p2p_file_label.pack(side="left", fill="x", expand=True, padx=8)

        btn_p2p_browse = ctk.CTkButton(
            file_sec,
            text="Select File",
            command=self._choose_p2p_file,
            fg_color=C_BG_BROWSE_BTN,
            hover_color="#0060CC",
            text_color=C_TEXT_PRIMARY,
            width=110,
        )
        btn_p2p_browse.pack(side="right", padx=16, pady=16)

        # Expected Hash Input Section
        hash_sec = ctk.CTkFrame(p2p_container, fg_color=C_BG_CARD, corner_radius=8, border_color=C_BORDER_INNER, border_width=1)
        hash_sec.pack(fill="x", padx=24, pady=8)

        ctk.CTkLabel(
            hash_sec,
            text="Expected SHA-256 Hash (from peer):",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(14, 6))

        self.p2p_hash_entry = ctk.CTkEntry(
            hash_sec,
            placeholder_text="Paste 64-character hex hash provided by your sender...",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C_BG_INPUT,
            border_color=C_BORDER_INNER,
            text_color=C_BLUE_SKY,
            height=36,
        )
        self.p2p_hash_entry.pack(fill="x", padx=16, pady=(0, 14))

        # Action Button
        self.btn_p2p_verify = ctk.CTkButton(
            p2p_container,
            text="Run Offline Cryptographic Match",
            command=self._run_p2p_verification,
            fg_color=C_RED,
            hover_color=C_RED_DARK,
            text_color="#FFFFFF",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
        )
        self.btn_p2p_verify.pack(fill="x", padx=24, pady=16)

        # Result Display Box
        self.p2p_result_box = ctk.CTkFrame(p2p_container, fg_color=C_BG_CARD, corner_radius=8, border_color=C_BORDER_INNER, border_width=1)
        self.p2p_result_box.pack(fill="both", expand=True, padx=24, pady=(0, 24))

        self.p2p_result_title = ctk.CTkLabel(
            self.p2p_result_box,
            text="Awaiting comparison",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=C_TEXT_DIM,
        )
        self.p2p_result_title.pack(anchor="w", padx=16, pady=(16, 6))

        self.p2p_result_detail = ctk.CTkLabel(
            self.p2p_result_box,
            text="Select a file and enter the sender's hash to run zero-knowledge deterministic comparison.",
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_MUTED,
            justify="left",
        )
        self.p2p_result_detail.pack(anchor="w", padx=16, pady=(0, 16))

    # ---------------------------------------------------------
    # TAB 4: Credentials & Settings
    # ---------------------------------------------------------
    def _build_settings_tab(self):
        tab = self.tab_settings

        settings_container = ctk.CTkFrame(tab, fg_color=C_BG_PANEL, corner_radius=10, border_color=C_BORDER_SUBTLE, border_width=1)
        settings_container.pack(fill="both", expand=True, padx=20, pady=20)

        title = ctk.CTkLabel(
            settings_container,
            text="⚙️ Engine Credentials & Model Selection",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=C_RED,
        )
        title.pack(anchor="w", padx=24, pady=(20, 6))

        desc = ctk.CTkLabel(
            settings_container,
            text="Configure your API keys to enable automated VirusTotal screening and Stage 2 RAG web retrieval.",
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_MUTED,
        )
        desc.pack(anchor="w", padx=24, pady=(0, 20))

        # Form entries
        form_frame = ctk.CTkFrame(settings_container, fg_color=C_BG_CARD, corner_radius=8, border_color=C_BORDER_INNER, border_width=1)
        form_frame.pack(fill="x", padx=24, pady=8)

        # 1. VirusTotal API Key
        ctk.CTkLabel(
            form_frame,
            text="VirusTotal v3 API Key:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(16, 4))

        self.entry_vt_key = ctk.CTkEntry(
            form_frame,
            placeholder_text="Enter VirusTotal API key (Free tier supported)",
            fg_color=C_BG_INPUT,
            border_color=C_BORDER_INNER,
            text_color=C_BLUE_SKY,
            show="*",
            height=34,
        )
        self.entry_vt_key.pack(fill="x", padx=16, pady=(0, 10))
        self.entry_vt_key.insert(0, Config.get_virustotal_key())

        # 2. Tavily Search API Key
        ctk.CTkLabel(
            form_frame,
            text="Tavily Search API Key (Stage 2 Web Retriever):",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(6, 4))

        self.entry_tavily_key = ctk.CTkEntry(
            form_frame,
            placeholder_text="Enter Tavily API key (e.g. tvly-...)",
            fg_color=C_BG_INPUT,
            border_color=C_BORDER_INNER,
            text_color=C_BLUE_SKY,
            show="*",
            height=34,
        )
        self.entry_tavily_key.pack(fill="x", padx=16, pady=(0, 10))
        self.entry_tavily_key.insert(0, Config.get_tavily_key())

        # 3. Google Gemini API Key (FREE)
        ctk.CTkLabel(
            form_frame,
            text="Google Gemini API Key (Recommended - 100% Free):",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_RED,
        ).pack(anchor="w", padx=16, pady=(6, 4))

        self.entry_gemini_key = ctk.CTkEntry(
            form_frame,
            placeholder_text="Enter free Gemini API key from Google AI Studio (e.g. AIzaSy...)",
            fg_color=C_BG_INPUT,
            border_color=C_BORDER_INNER,
            text_color=C_BLUE_SKY,
            show="*",
            height=34,
        )
        self.entry_gemini_key.pack(fill="x", padx=16, pady=(0, 10))
        self.entry_gemini_key.insert(0, Config.get_gemini_key())

        # 4. OpenAI API Key (Optional)
        ctk.CTkLabel(
            form_frame,
            text="OpenAI API Key (Optional Alternative):",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(6, 4))

        self.entry_openai_key = ctk.CTkEntry(
            form_frame,
            placeholder_text="Enter OpenAI API key (e.g. sk-proj-...)",
            fg_color=C_BG_INPUT,
            border_color=C_BORDER_INNER,
            text_color=C_BLUE_SKY,
            show="*",
            height=34,
        )
        self.entry_openai_key.pack(fill="x", padx=16, pady=(0, 10))
        self.entry_openai_key.insert(0, Config.get_openai_key())

        # 5. Provider & Model Selection
        model_row = ctk.CTkFrame(form_frame, fg_color="transparent")
        model_row.pack(fill="x", padx=16, pady=(6, 16))

        ctk.CTkLabel(
            model_row,
            text="AI Provider:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        ).pack(side="left", padx=(0, 10))

        self.provider_combo = ctk.CTkComboBox(
            model_row,
            values=["Gemini (Free)", "OpenAI"],
            width=160,
            command=self._on_provider_changed,
        )
        self.provider_combo.pack(side="left", padx=(0, 20))
        self.provider_combo.set("Gemini (Free)" if Config.get_ai_provider() == "gemini" else "OpenAI")

        ctk.CTkLabel(
            model_row,
            text="Model:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_TEXT_PRIMARY,
        ).pack(side="left", padx=(0, 10))

        self.model_combo = ctk.CTkComboBox(
            model_row,
            values=["gemini-flash-latest", "gemini-1.5-flash"] if Config.get_ai_provider() == "gemini" else ["gpt-4o-mini", "gpt-4o"],
            width=170,
        )
        self.model_combo.pack(side="left")
        self.model_combo.set(Config.get_active_model_name())

        # Save Button
        btn_save = ctk.CTkButton(
            settings_container,
            text="Save & Apply Credentials",
            command=self._save_settings,
            fg_color=C_RED,
            hover_color=C_RED_DARK,
            text_color="#FFFFFF",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
        )
        btn_save.pack(anchor="w", padx=24, pady=16)
        btn_save.pack(anchor="w", padx=24, pady=16)

    # ---------------------------------------------------------
    # Event Handlers & File Selection
    # ---------------------------------------------------------
    def _choose_file_dialog(self):
        """Standard file open dialog."""
        if self.is_scanning:
            return
        path = filedialog.askopenfilename(
            title="Select Installer or Application Binary",
            filetypes=[
                ("Executables & Archives", "*.exe;*.msi;*.dll;*.zip;*.tar.gz;*.iso;*.bin"),
                ("All Files", "*.*"),
            ],
        )
        if path:
            self._handle_file_selected(path)

    def _on_file_dropped(self, event):
        """Native TkinterDnD drop event."""
        if self.is_scanning:
            return
        data = event.data.strip()
        # On Windows, path with spaces may be enclosed in braces like {C:\path with spaces\file.exe}
        if data.startswith("{") and data.endswith("}"):
            data = data[1:-1]
        if os.path.exists(data):
            self._handle_file_selected(data)

    def _handle_file_selected(self, file_path: str):
        """Parse structural headers and update UI display."""
        self.selected_file_path = file_path
        file_size = os.path.getsize(file_path)

        # Format readable size
        if file_size > 1024 * 1024 * 1024:
            size_str = f"{file_size / (1024**3):.2f} GB"
        elif file_size > 1024 * 1024:
            size_str = f"{file_size / (1024**2):.2f} MB"
        else:
            size_str = f"{file_size / 1024:.1f} KB"

        # Harvest metadata using core/parser.py
        try:
            meta = extract_binary_metadata(file_path)
            self.selected_file_metadata = meta
            self.info_file_name.configure(text=f"📄 {meta.raw_filename}")
            self.info_meta.configure(
                text=f"App: {meta.app_name} | Ver: {meta.version} | Arch: {meta.architecture} | Size: {size_str}"
            )
        except Exception as e:
            self.info_file_name.configure(text=f"📄 {os.path.basename(file_path)}")
            self.info_meta.configure(text=f"Size: {size_str} (Metadata parse error: {str(e)})")

        self.drop_text.configure(text=f"READY TO VERIFY:\n{os.path.basename(file_path)}")
        self._reset_verdict_card()
        self._reset_stepper()
        self.progress_status_label.configure(text="File loaded. Click 'Start Verification' to begin.")
        self._append_log(f"Loaded file: {file_path} ({size_str})")

    def _reset_verdict_card(self):
        self.verdict_canvas.configure(border_color=C_BLUE)
        self.verdict_title.configure(text="Awaiting Pipeline Execution", text_color=C_BLUE_BRIGHT)
        self.verdict_body.configure(
            text="Press 'Start Verification' to execute Step 0 (Local Hash) -> Step 1 (VirusTotal) -> Step 2 (Web RAG).",
            text_color=C_TEXT_MUTED,
        )
        self.lbl_local_hash.configure(text="Local SHA-256:  --", text_color=C_BLUE_BRIGHT)
        self.lbl_fetched_hash.configure(text="Vendor SHA-256: --", text_color=C_RED)

    def _reset_stepper(self):
        for ind, lbl in self.step_widgets:
            ind.configure(text="⚪", text_color=C_TEXT_DIM)
            lbl.configure(text_color=C_TEXT_DIM)

    def _update_step_status(self, step_index: int, status: str):
        """Update visual stepper row: status in ['running', 'success', 'warning', 'error']."""
        if 0 <= step_index < len(self.step_widgets):
            ind, lbl = self.step_widgets[step_index]
            if status == "running":
                ind.configure(text="⏳", text_color=C_BLUE_BRIGHT)
                lbl.configure(text_color=C_BLUE_BRIGHT)
            elif status == "success":
                ind.configure(text="✅", text_color="#22C55E")
                lbl.configure(text_color="#22C55E")
            elif status == "warning":
                ind.configure(text="⚠️", text_color=C_AMBER)
                lbl.configure(text_color=C_AMBER)
            elif status == "error":
                ind.configure(text="❌", text_color="#EF4444")
                lbl.configure(text_color="#EF4444")

    # ---------------------------------------------------------
    # Pipeline Execution Thread (Asynchronous)
    # ---------------------------------------------------------
    def _start_pipeline_thread(self):
        if self.is_scanning:
            return
        if not self.selected_file_path or not os.path.exists(self.selected_file_path):
            messagebox.showwarning("No File", "Please select or drop an installer binary first.")
            return

        self.is_scanning = True
        self.btn_start.configure(state="disabled", text="Verifying...")
        self.btn_browse.configure(state="disabled")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

        threading.Thread(target=self._run_pipeline_worker, daemon=True).start()

    def _run_pipeline_worker(self):
        file_path = self.selected_file_path
        meta = self.selected_file_metadata or extract_binary_metadata(file_path)

        try:
            # ---------------------------------------------------------
            # STEP 0: Local Deterministic Layer (Python Native)
            # ---------------------------------------------------------
            self.after(0, self._update_step_status, 0, "running")
            self.after(0, self.progress_status_label.configure, {"text": "Step 0: Streaming file (4096-byte buffers)..."})
            self._append_log("--- [STEP 0: LOCAL DETERMINISTIC STREAM HASHING] ---")
            self._append_log(f"Streaming {os.path.basename(file_path)} with 4096-byte chunk buffering...")

            start_time = time.time()
            local_hash = calculate_sha256_stream(file_path)
            self.local_hash = local_hash
            elapsed = time.time() - start_time

            self._append_log(f"Local Calculated SHA-256: {local_hash} (completed in {elapsed:.2f}s)")
            self.after(0, self._update_step_status, 0, "success")
            self.after(0, self.lbl_local_hash.configure, {"text": f"Local SHA-256:  {local_hash}"})

            # ---------------------------------------------------------
            # STEP 1: Stage 1 Malware Shield (VirusTotal Integration)
            # ---------------------------------------------------------
            self.after(0, self._update_step_status, 1, "running")
            self.after(0, self.progress_status_label.configure, {"text": "Step 1: Checking VirusTotal global threat registry..."})
            self._append_log("--- [STEP 1: VIRUSTOTAL THREAT REGISTRY LOOKUP] ---")
            self._append_log(f"Querying VirusTotal v3 endpoint for fingerprint {local_hash[:16]}...")

            vt_result = self.vt_engine.query_hash(local_hash)

            # Route 1: MALICIOUS > 0 -> Halt immediately!
            if vt_result.status == ThreatStatus.MALICIOUS:
                self.after(0, self._update_step_status, 1, "error")
                self._append_log(
                    f"CRITICAL MALWARE ALERT: {vt_result.malicious_count}/{vt_result.total_engines} "
                    f"engines flagged this binary as MALICIOUS! Execution halted immediately."
                )
                self.after(0, self._show_malware_alert_verdict, vt_result)
                return

            # Route 2: 404 NOT FOUND -> Trap smoothly and cascade to Stage 2
            elif vt_result.status == ThreatStatus.NOT_FOUND_404:
                self.after(0, self._update_step_status, 1, "warning")
                self._append_log("VirusTotal returned 404 (Not Found in threat registry).")
                self._append_log("File is uncataloged / new release. Cascading execution into Stage 2 Integrity Shield...")

            # Route 3: CLEAN in VT -> Cataloged safe, continue to Integrity Shield
            elif vt_result.status == ThreatStatus.CLEAN:
                self.after(0, self._update_step_status, 1, "success")
                self._append_log(
                    f"VirusTotal Status: Clean (0/{vt_result.total_engines} detections). "
                    f"Proceeding to Stage 2 vendor integrity validation..."
                )

            # Route 4: Missing or invalid API key
            else:
                self.after(0, self._update_step_status, 1, "warning")
                self._append_log(f"VirusTotal Note: {vt_result.error_message}. Cascading to Stage 2...")

            # ---------------------------------------------------------
            # STEP 2 & 3: Stage 2 Integrity Shield & Cryptographic Match
            # ---------------------------------------------------------
            self.after(0, self._update_step_status, 2, "running")
            self.after(0, self.progress_status_label.configure, {"text": "Step 2: Crawling vendor domain via Tavily & AI extraction..."})
            self._append_log("--- [STEP 2: WEB-SEARCH RAG & LLM EXTRACTION] ---")

            stage2_result = self.web_rag_engine.run_pipeline(local_hash, meta)

            if stage2_result.verdict == VerificationVerdict.GENUINE:
                self.after(0, self._update_step_status, 2, "success")
                self.after(0, self._update_step_status, 3, "success")
                self.after(0, self._show_genuine_verdict, stage2_result)
            elif stage2_result.verdict == VerificationVerdict.TAMPERED:
                self.after(0, self._update_step_status, 2, "success")
                self.after(0, self._update_step_status, 3, "error")
                self.after(0, self._show_tampered_verdict, stage2_result)
            elif stage2_result.verdict == VerificationVerdict.NOT_FOUND:
                self.after(0, self._update_step_status, 2, "warning")
                self.after(0, self._update_step_status, 3, "warning")
                self.after(0, self._show_not_found_verdict, stage2_result)
            else:
                self.after(0, self._update_step_status, 2, "error")
                self.after(0, self._show_error_verdict, stage2_result)

        except Exception as e:
            self._append_log(f"Pipeline Execution Error: {str(e)}")
            self.after(0, self.progress_status_label.configure, {"text": f"Error: {str(e)}"})
        finally:
            self.after(0, self._finalize_scan_state)

    def _finalize_scan_state(self):
        self.is_scanning = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1.0)
        self.btn_start.configure(state="normal", text="Start Verification")
        self.btn_browse.configure(state="normal")
        self.progress_status_label.configure(text="Verification pipeline completed.")

    # ---------------------------------------------------------
    # Visual Verdict Displays
    # ---------------------------------------------------------
    def _show_genuine_verdict(self, res: Stage2Result):
        """Displays green confirmation dashboard."""
        self.verdict_canvas.configure(border_color="#22C55E")
        self.verdict_title.configure(
            text="✅ GENUINE, CLEAN DEPLOYMENT VERIFIED",
            text_color="#22C55E",
        )
        body = (
            f"Cryptographic Match Confirmed!\n"
            f"The local binary hash matches the official hash published by the vendor ({res.vendor_domain or 'Vendor Source'}).\n"
            f"The binary has not been modified, corrupted, or altered by any third party."
        )
        self.verdict_body.configure(text=body)
        self.lbl_local_hash.configure(text=f"Local SHA-256:  {res.local_hash}", text_color="#22C55E")
        self.lbl_fetched_hash.configure(text=f"Vendor SHA-256: {res.fetched_hash}", text_color="#22C55E")

    def _show_tampered_verdict(self, res: Stage2Result):
        """Displays high-visibility red warning canvas."""
        self.verdict_canvas.configure(border_color="#EF4444")
        self.verdict_title.configure(
            text="🚨 INTEGRITY BROKEN: FILE ALTERED OR TAMPERED",
            text_color="#EF4444",
        )
        body = (
            f"CRITICAL WARNING: The local calculated hash does NOT match the official published hash!\n"
            f"This indicates the installer has been modified, tampered with by a malicious third party, "
            f"or damaged in transit. DO NOT EXECUTE THIS INSTALLER."
        )
        self.verdict_body.configure(text=body)
        self.lbl_local_hash.configure(text=f"Local SHA-256:  {res.local_hash}", text_color="#EF4444")
        self.lbl_fetched_hash.configure(text=f"Vendor SHA-256: {res.fetched_hash}", text_color="#38BDF8")

    def _show_malware_alert_verdict(self, vt: VirusTotalResult):
        """Displays active warning canvas for malicious file halted at Stage 1."""
        self.verdict_canvas.configure(border_color="#DC2626")
        self.verdict_title.configure(
            text=f"⛔ MALWARE SHIELD TRIGGERED ({vt.malicious_count}/{vt.total_engines} Engines Flagged)",
            text_color="#DC2626",
        )
        explanation = vt.ai_explanation or "Threat detected in global threat registry. File flagged as malicious."
        self.verdict_body.configure(text=explanation)
        self.lbl_local_hash.configure(text=f"Local SHA-256:  {vt.hash_string}", text_color="#DC2626")
        self.lbl_fetched_hash.configure(text="Vendor Hash:    [HALTED: Malicious Payload]", text_color="#EF4444")

    def _show_not_found_verdict(self, res: Stage2Result):
        """Displays neutral amber warning if vendor hash was absent in crawled pages."""
        self.verdict_canvas.configure(border_color="#0084FF")
        self.verdict_title.configure(
            text="⚠️ OFFICIAL HASH NOT LOCATED IN VENDOR RELEASE TEXT",
            text_color="#0084FF",
        )
        body = (
            f"Stage 1 Malware Shield passed without malicious detections.\n"
            f"However, the official 64-character SHA-256 checksum was not explicitly found on the crawled vendor page.\n"
            f"Recommendation: Switch to 'P2P Offline Secure Mode' tab to enter the checksum manually."
        )
        self.verdict_body.configure(text=body)
        self.lbl_local_hash.configure(text=f"Local SHA-256:  {res.local_hash}", text_color="#38BDF8")
        self.lbl_fetched_hash.configure(text="Vendor SHA-256: NOT_FOUND (Check manual source)", text_color="#0084FF")

    def _show_error_verdict(self, res: Stage2Result):
        self.verdict_canvas.configure(border_color="#0084FF")
        self.verdict_title.configure(text="⚠️ Pipeline Notice", text_color="#0084FF")
        self.verdict_body.configure(text=res.summary_message)

    # ---------------------------------------------------------
    # Checksum Generator Actions (Dedicated Section)
    # ---------------------------------------------------------
    def _choose_gen_file(self):
        path = filedialog.askopenfilename(title="Select File to Calculate Checksum")
        if path:
            self.gen_file_label.configure(text=path)
            self.lbl_gen_status.configure(
                text="File ready. Click 'Calculate Cryptographic SHA-256 Checksum'.",
                text_color="#38BDF8",
            )

    def _calculate_and_display_hashes(self):
        file_path = self.gen_file_label.cget("text")
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Generator", "Please select a file first.")
            return

        try:
            sha256_hash = calculate_sha256_stream(file_path)
            self.entry_gen_sha256.delete(0, "end")
            self.entry_gen_sha256.insert(0, sha256_hash)
            self.lbl_gen_status.configure(
                text="✅ Checksum calculated! Click 'Copy Checksum' to copy it to clipboard.",
                text_color="#22C55E",
            )
            self._append_log(f"Generator: SHA-256 calculated for {os.path.basename(file_path)}: {sha256_hash}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to calculate hash: {e}")

    def _copy_gen_sha256(self):
        h = self.entry_gen_sha256.get().strip()
        if not h:
            messagebox.showwarning("Copy", "No checksum to copy. Calculate checksum first.")
            return
        self.clipboard_clear()
        self.clipboard_append(h)
        self.lbl_gen_status.configure(
            text="✅ Copied to clipboard! Ready to send to peer.",
            text_color="#22C55E",
        )
        messagebox.showinfo("Copied!", f"SHA-256 Checksum copied to clipboard:\n\n{h}")

    # ---------------------------------------------------------
    # P2P Offline Mode Action
    # ---------------------------------------------------------
    def _choose_p2p_file(self):
        path = filedialog.askopenfilename(title="Select File for P2P Verification")
        if path:
            self.p2p_file_label.configure(text=path)
            self._append_log(f"P2P Mode: Target file loaded -> {path}")

    def _run_p2p_verification(self):
        file_path = self.p2p_file_label.cget("text")
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("P2P Mode", "Please choose a valid local file first.")
            return

        expected_hash = self.p2p_hash_entry.get().strip().lower()
        if not expected_hash:
            messagebox.showwarning("P2P Mode", "Please paste the expected 64-character SHA-256 hash.")
            return

        # Calculate local hash block by block
        try:
            local_hash = calculate_sha256_stream(file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to compute file hash: {str(e)}")
            return

        # Pure boolean logic comparison
        is_match = (local_hash == expected_hash)

        if is_match:
            self.p2p_result_box.configure(border_color="#22C55E", border_width=2)
            self.p2p_result_title.configure(
                text="✅ AUTHENTIC P2P INTEGRITY VERIFIED (100% MATCH)",
                text_color="#22C55E",
            )
            detail = (
                f"Local SHA-256:    {local_hash}\n"
                f"Expected SHA-256: {expected_hash}\n\n"
                f"Result: The file matches the sender's fingerprint exactly with zero deviation."
            )
            self.p2p_result_detail.configure(text=detail)
            self._append_log("P2P Verification: MATCH CONFIRMED (100% cryptographic equality).")
        else:
            self.p2p_result_box.configure(border_color="#EF4444", border_width=2)
            self.p2p_result_title.configure(
                text="🚨 P2P CHECKSUM MISMATCH (TAMPERED OR WRONG FILE)",
                text_color="#EF4444",
            )
            detail = (
                f"Local Calculated: {local_hash}\n"
                f"Expected Checksum: {expected_hash}\n\n"
                f"Result: The calculated hash deviates from the peer's expected checksum. Do not trust this file."
            )
            self.p2p_result_detail.configure(text=detail)
            self._append_log("P2P Verification: MISMATCH DETECTED!")

    # ---------------------------------------------------------
    # Settings & Credentials Persistence
    # ---------------------------------------------------------
    def _on_provider_changed(self, choice: str):
        if "Gemini" in choice:
            self.model_combo.configure(values=["gemini-flash-latest", "gemini-1.5-flash"])
            self.model_combo.set("gemini-flash-latest")
        else:
            self.model_combo.configure(values=["gpt-4o-mini", "gpt-4o"])
            self.model_combo.set("gpt-4o-mini")

    def _save_settings(self):
        vt_key = self.entry_vt_key.get().strip()
        tavily_key = self.entry_tavily_key.get().strip()
        gemini_key = self.entry_gemini_key.get().strip()
        openai_key = self.entry_openai_key.get().strip()
        prov_choice = self.provider_combo.get().strip()
        ai_provider = "gemini" if "Gemini" in prov_choice else "openai"
        model = self.model_combo.get().strip()

        Config.save_keys(
            virustotal_key=vt_key,
            tavily_key=tavily_key,
            gemini_key=gemini_key,
            openai_key=openai_key,
            ai_provider=ai_provider,
            model_name=model,
        )

        self.refresh_api_status_pills()
        messagebox.showinfo(
            "VeriBlue AI",
            "Configuration saved successfully to local environment (.env)!",
        )
        self._append_log("Credentials updated and reloaded into active memory.")

    def refresh_api_status_pills(self):
        """Update top header badge pills based on active credentials."""
        # VT
        if Config.is_virustotal_configured():
            self.vt_pill.configure(text="VirusTotal: Active", text_color="#22C55E")
        else:
            self.vt_pill.configure(text="VirusTotal: Unset", text_color="#0084FF")

        # Tavily
        if Config.is_tavily_configured():
            self.tavily_pill.configure(text="Tavily: Active", text_color="#22C55E")
        else:
            self.tavily_pill.configure(text="Tavily: Unset", text_color="#0084FF")

        # AI (Gemini or OpenAI)
        provider = Config.get_ai_provider()
        if Config.is_ai_configured():
            active_model = Config.get_active_model_name()
            pill_label = f"AI: {provider.capitalize()} ({active_model})"
            self.openai_pill.configure(text=pill_label, text_color="#22C55E")
        else:
            self.openai_pill.configure(text="AI: Unset", text_color="#0084FF")

    # ---------------------------------------------------------
    # Logging Utilities
    # ---------------------------------------------------------
    def _on_rag_log(self, stage: str, message: str):
        """Callback from WebRagEngine."""
        self._append_log(f"[{stage}] {message}")

    def _append_log(self, text: str):
        """Thread-safe UI log appending."""
        def _write():
            timestamp = time.strftime("%H:%M:%S")
            self.log_textbox.configure(state="normal")
            self.log_textbox.insert("end", f"[{timestamp}] {text}\n")
            self.log_textbox.see("end")
            self.log_textbox.configure(state="disabled")

        if threading.current_thread() is threading.main_thread():
            _write()
        else:
            self.after(0, _write)


def main():
    app = VeriBlueApp()
    app.mainloop()


if __name__ == "__main__":
    main()
