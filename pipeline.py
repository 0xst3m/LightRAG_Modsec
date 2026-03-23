import asyncio
import hashlib
import json
import logging
from pathlib import Path

from config_loader import BATCH_SIZE, DATABASE_DIR, KNOWLEDGE_DIR, WORKSPACE_NAME
from ingest.parser import ingest_all_files, SUPPORTED_EXTENSIONS
from rag.indexer import get_rag_instance

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

INDEX_MANIFEST = Path(DATABASE_DIR) / WORKSPACE_NAME / "ingest_manifest.json"
PROGRESS_FILE = Path(DATABASE_DIR) / WORKSPACE_NAME / "ingest_progress.json"


def _compute_chunks_hash(chunks: list[str]) -> str:
    """Deterministic hash of all chunk contents to detect changes."""
    h = hashlib.sha256()
    for chunk in chunks:
        h.update(chunk.encode("utf-8"))
    return h.hexdigest()


def _should_skip_indexing(chunks: list[str]) -> bool:
    """
    Check if the knowledge graph already contains these exact chunks.
    Compares a SHA-256 hash of all chunk contents against a saved manifest.
    Returns True if chunks haven't changed since last successful indexing.
    """
    if not INDEX_MANIFEST.exists():
        return False

    try:
        manifest = json.loads(INDEX_MANIFEST.read_text())
        saved_hash = manifest.get("chunks_hash", "")
        saved_count = manifest.get("chunks_count", 0)
    except (json.JSONDecodeError, OSError):
        return False

    current_hash = _compute_chunks_hash(chunks)
    if current_hash == saved_hash and len(chunks) == saved_count:
        return True
    return False


def _save_index_manifest(chunks: list[str]) -> None:
    """Save a manifest after successful indexing so future runs can skip."""
    INDEX_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "chunks_hash": _compute_chunks_hash(chunks),
        "chunks_count": len(chunks),
    }
    INDEX_MANIFEST.write_text(json.dumps(manifest, indent=2))


def _load_progress() -> int:
    """Return the number of chunks already indexed (0 if no progress file)."""
    if not PROGRESS_FILE.exists():
        return 0
    try:
        data = json.loads(PROGRESS_FILE.read_text())
        return data.get("chunks_completed", 0)
    except (json.JSONDecodeError, OSError):
        return 0


def _save_progress(chunks_completed: int, total: int) -> None:
    """Save checkpoint after each batch so we can resume on restart."""
    PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PROGRESS_FILE.write_text(json.dumps({
        "chunks_completed": chunks_completed,
        "chunks_total": total,
    }, indent=2))


async def run_crs_forge():
    """
    Orchestrator connecting all phases of CRS-Forge.
    Phases:
      1. Ingest — parse CRS .conf and .mediawiki files into chunks
      2. Build Knowledge Graph — batch insert chunks into LightRAG
    """
    # ── Phase 1: Ingest ──────────────────────────────────────────────
    logger.info("=== Phase 1: Ingest ===")

    data_dir = Path(KNOWLEDGE_DIR)
    all_files = [
        str(p) for p in data_dir.rglob("*")
        if p.is_file()
        and p.suffix.lower() in SUPPORTED_EXTENSIONS
        and "example" not in p.name
    ]

    if not all_files:
        logger.warning(
            "No supported files found to ingest. "
            f"Place {', '.join(SUPPORTED_EXTENSIONS)} files in the {KNOWLEDGE_DIR}/ directory."
        )
    else:
        logger.info(f"Found {len(all_files)} files to ingest:")
        for f in all_files:
            logger.info(f"  - {f}")

    parsed_chunks = ingest_all_files(all_files) if all_files else []
    logger.info(f"Total chunks extracted: {len(parsed_chunks)}")

    # ── Phase 2: Build Knowledge Graph ───────────────────────────────
    logger.info("=== Phase 2: Build Knowledge Graph ===")

    rag = get_rag_instance(WORKSPACE_NAME)
    await rag.initialize_storages()

    if parsed_chunks:
        # Skip-if-indexed: avoid re-processing when chunks haven't changed
        if _should_skip_indexing(parsed_chunks):
            logger.info(
                "Knowledge graph is up to date — skipping indexing. "
                "Delete %s to force re-index.", INDEX_MANIFEST
            )
        else:
            already_done = _load_progress()
            total = len(parsed_chunks)

            if already_done > 0:
                logger.info(
                    f"Resuming from chunk {already_done}/{total} "
                    f"({total - already_done} remaining)"
                )

            try:
                for i in range(already_done, total, BATCH_SIZE):
                    batch = parsed_chunks[i : i + BATCH_SIZE]
                    batch_end = min(i + BATCH_SIZE, total)
                    logger.info(
                        f"Inserting batch [{i+1}-{batch_end}] / {total} "
                        f"({len(batch)} chunks)..."
                    )
                    await rag.ainsert(batch)
                    _save_progress(batch_end, total)
                    logger.info(f"Checkpoint saved at {batch_end}/{total}")

                # All batches done — save final manifest and clean up progress
                _save_index_manifest(parsed_chunks)
                if PROGRESS_FILE.exists():
                    PROGRESS_FILE.unlink()
                logger.info(f"Phase 2 complete: {total} chunks inserted.")

            except Exception as e:
                logger.error(f"Batch insertion failed at chunk ~{i}: {e}")
                logger.info(
                    "Progress saved. Re-run pipeline to resume from last checkpoint."
                )
    else:
        logger.info("No new chunks to insert (skipping).")

    # ── Finalize ─────────────────────────────────────────────────────
    await rag.finalize_storages()
    logger.info("Storages finalized. Pipeline complete.")


if __name__ == "__main__":
    asyncio.run(run_crs_forge())
