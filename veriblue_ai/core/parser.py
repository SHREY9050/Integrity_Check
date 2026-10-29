"""VeriBlue AI - Binary Header Metadata Extractor (Step 0)

Extracts application name, major/minor release version, and target architecture
from binary structural headers (e.g. Windows Portable Executable headers via pefile)
with heuristic fallbacks for common installer packaging formats (.msi, .zip, .tar.gz, etc.).
"""

import os
import re
from dataclasses import dataclass
from typing import Optional, Dict, Any

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


@dataclass
class BinaryMetadata:
    app_name: str
    version: str
    architecture: str
    company_name: Optional[str] = None
    file_description: Optional[str] = None
    raw_filename: str = ""
    file_size_bytes: int = 0
    file_type: str = "Unknown"
    suggested_domain: Optional[str] = None

    def get_search_tokens(self) -> str:
        """Format tokenized name and version query string for search RAG."""
        parts = []
        if self.app_name and self.app_name != "Unknown":
            parts.append(self.app_name)
        if self.version and self.version != "Unknown":
            parts.append(self.version)
        if self.architecture and self.architecture != "Unknown":
            parts.append(self.architecture)
        return " ".join(parts).strip()


# Common well-known vendor domain map for dynamic trust constraints
VENDOR_DOMAINS: Dict[str, str] = {
    "vlc": "videolan.org",
    "videolan": "videolan.org",
    "python": "python.org",
    "git": "git-scm.com",
    "node": "nodejs.org",
    "nodejs": "nodejs.org",
    "visual studio code": "code.visualstudio.com",
    "vscode": "code.visualstudio.com",
    "brave": "brave.com",
    "firefox": "mozilla.org",
    "mozilla": "mozilla.org",
    "chrome": "google.com",
    "7-zip": "7-zip.org",
    "7zip": "7-zip.org",
    "putty": "chiark.greenend.org.uk",
    "wireshark": "wireshark.org",
    "virtualbox": "virtualbox.org",
    "notepad++": "notepad-plus-plus.org",
    "sublime": "sublimetext.com",
    "rust": "rust-lang.org",
    "golang": "go.dev",
    "docker": "docker.com",
    "postman": "postman.com",
    "audacity": "audacityteam.org",
    "blender": "blender.org",
    "obs": "obsproject.com",
    "filezilla": "filezilla-project.org",
    "keepass": "keepass.info",
}


def _clean_string(val: Optional[Any]) -> str:
    if val is None:
        return ""
    if isinstance(val, bytes):
        val = val.decode("utf-8", errors="ignore")
    return str(val).strip("\x00 \t\r\n")


def _detect_pe_architecture(pe: "pefile.PE") -> str:
    """Detect binary machine architecture from PE header."""
    machine = getattr(pe.FILE_HEADER, "Machine", 0)
    # Common machine constants
    # 0x014c: IMAGE_FILE_MACHINE_I386 (x86 32-bit)
    # 0x8664: IMAGE_FILE_MACHINE_AMD64 (x64 64-bit)
    # 0xaa64: IMAGE_FILE_MACHINE_ARM64
    # 0x01c0: IMAGE_FILE_MACHINE_ARM
    if machine == 0x8664:
        return "x64"
    elif machine == 0x014C:
        return "x86"
    elif machine == 0xAA64:
        return "ARM64"
    elif machine == 0x01C0:
        return "ARM"
    return "Unknown"


def _extract_pe_version_info(pe: "pefile.PE") -> Dict[str, str]:
    """Parse StringFileInfo from PE resources."""
    info: Dict[str, str] = {}
    if not hasattr(pe, "FileInfo"):
        return info

    for file_info_list in pe.FileInfo:
        for file_info in file_info_list:
            if hasattr(file_info, "StringTable"):
                for st in file_info.StringTable:
                    for key, val in st.entries.items():
                        k_str = _clean_string(key)
                        v_str = _clean_string(val)
                        if k_str:
                            info[k_str] = v_str
    return info


def _parse_filename_heuristics(filename: str) -> Dict[str, str]:
    """Fallback parser extracting product, version, and architecture from filename."""
    base = os.path.basename(filename)
    name_no_ext, _ = os.path.splitext(base)
    # Also handle compound extensions like .tar.gz
    if name_no_ext.endswith(".tar"):
        name_no_ext = name_no_ext[:-4]

    # Detect architecture tokens in filename
    arch = "Unknown"
    if re.search(r"(?:win64|x64|x86_64|amd64|64-bit|64bit)", name_no_ext, re.IGNORECASE):
        arch = "x64"
    elif re.search(r"(?:win32|x86|i386|32-bit|32bit)", name_no_ext, re.IGNORECASE):
        arch = "x86"
    elif re.search(r"(?:arm64|aarch64)", name_no_ext, re.IGNORECASE):
        arch = "ARM64"
    elif re.search(r"(?:armv7|arm)", name_no_ext, re.IGNORECASE):
        arch = "ARM"

    # Extract version: e.g. 3.0.20 or 1.2.3-beta or 2024.1 (avoiding consuming architecture tags)
    version = "Unknown"
    ver_match = re.search(r"(\d+(?:\.\d+)+(?:-(?:beta|rc|alpha|preview)\d*)?)", name_no_ext, re.IGNORECASE)
    if ver_match:
        version = ver_match.group(1).rstrip(".-_")
        # App name is usually before the version token
        prefix = name_no_ext[: ver_match.start()].strip("-_ .")
        app_name = prefix if prefix else name_no_ext
    else:
        app_name = name_no_ext

    # Clean app name
    app_name = re.sub(r"[-_](?:setup|installer|install|portable|win|windows|mac|linux|x64|x86)", "", app_name, flags=re.IGNORECASE).strip("-_ .")
    if not app_name:
        app_name = name_no_ext

    return {
        "app_name": app_name,
        "version": version,
        "architecture": arch,
    }


def _guess_vendor_domain(app_name: str, company: Optional[str] = None) -> Optional[str]:
    """Match application name or company against trusted vendor domain directory."""
    check_terms = [app_name.lower()]
    if company:
        check_terms.append(company.lower())

    for term in check_terms:
        normalized_term = re.sub(r"\s+", " ", term).strip()
        for key, domain in VENDOR_DOMAINS.items():
            # Match whole product/company phrases, not arbitrary substrings
            # (e.g. avoid mapping "notpython" to the Python vendor).
            pattern = r"(?<![\w])" + re.escape(key.lower()) + r"(?![\w])"
            if re.search(pattern, normalized_term):
                return domain
    return None


def extract_binary_metadata(file_path: str) -> BinaryMetadata:
    """Inspect and isolate structural metadata from the target binary.

    Args:
        file_path: Path to target installer or binary file.

    Returns:
        BinaryMetadata instance with extracted fields.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Binary file not found: {file_path}")

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    _, ext = os.path.splitext(filename.lower())

    heuristics = _parse_filename_heuristics(filename)
    app_name = heuristics["app_name"]
    version = heuristics["version"]
    architecture = heuristics["architecture"]
    company_name = None
    file_description = None
    file_type = ext if ext else "Binary"

    # If it is a Windows PE executable (.exe, .dll, .sys) and pefile is available
    if HAS_PEFILE and ext in [".exe", ".dll", ".sys", ".bin", ""]:
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
                ]
            )

            # Extract architecture from PE header
            pe_arch = _detect_pe_architecture(pe)
            if pe_arch != "Unknown":
                architecture = pe_arch

            # Extract StringFileInfo metadata
            version_info = _extract_pe_version_info(pe)
            if version_info:
                if "ProductName" in version_info and version_info["ProductName"]:
                    app_name = version_info["ProductName"]
                elif "FileDescription" in version_info and version_info["FileDescription"]:
                    app_name = version_info["FileDescription"]

                if "ProductVersion" in version_info and version_info["ProductVersion"]:
                    version = version_info["ProductVersion"]
                elif "FileVersion" in version_info and version_info["FileVersion"]:
                    version = version_info["FileVersion"]

                company_name = version_info.get("CompanyName")
                file_description = version_info.get("FileDescription")

            pe.close()
            file_type = "Windows Portable Executable (PE)"
        except Exception:
            # Fall back to heuristic parse if PE reading encounters malformed headers or non-PE
            pass

    # Wrapper / repackager cleanup (e.g., Softonic downloader stubs wrapping authentic binaries)
    is_wrapper = any(w in (company_name or "").lower() or w in app_name.lower() for w in ["softonic", "cnet", "download.com", "installcore"])
    if is_wrapper and heuristics["app_name"] != app_name and heuristics["app_name"] != filename:
        app_name = heuristics["app_name"]
        version = heuristics["version"]

    # Guess trusted official vendor domain
    suggested_domain = _guess_vendor_domain(app_name, company_name)

    return BinaryMetadata(
        app_name=app_name,
        version=version,
        architecture=architecture,
        company_name=company_name,
        file_description=file_description,
        raw_filename=filename,
        file_size_bytes=file_size,
        file_type=file_type,
        suggested_domain=suggested_domain,
    )
