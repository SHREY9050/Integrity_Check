"""VeriBlue AI - Deterministic Stream Hashing Engine (Step 0)

Streams binary data block-by-block using native hashlib in 4096-byte buffer slices.
Generates an exact 64-character SHA-256 hex digest without loading the whole
file into RAM, preventing memory exhaustion on large installers and system archives.
"""

import hashlib
import os
from typing import Callable, Optional

# Strict 4096-byte buffer size as specified in the PRD
CHUNK_SIZE: int = 4096


def calculate_sha256_stream(
    file_path: str,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> str:
    """Calculate 64-character SHA-256 hex digest of a file using 4096-byte chunks.

    Args:
        file_path: Path to the target binary/file.
        progress_callback: Optional callback(bytes_processed, total_bytes).
        cancel_check: Optional callback returning True if calculation should abort.

    Returns:
        64-character lowercase SHA-256 hexadecimal string.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        PermissionError: If the file cannot be accessed.
        InterruptedError: If cancel_check returns True during processing.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    total_bytes = os.path.getsize(file_path)
    bytes_processed = 0

    sha256_hasher = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            if cancel_check and cancel_check():
                raise InterruptedError("Hashing operation cancelled by user.")

            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            sha256_hasher.update(chunk)
            bytes_processed += len(chunk)

            if progress_callback and total_bytes > 0:
                progress_callback(bytes_processed, total_bytes)

    # Return exactly 64-character lowercase hex string
    digest = sha256_hasher.hexdigest().lower()
    assert len(digest) == 64, f"Digest length expected 64, got {len(digest)}"
    return digest
