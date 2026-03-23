import re
import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


# ── Filename category extraction ─────────────────────────────

def _extract_conf_category(filename: str) -> str:
    """
    Extracts a human-readable category from a CRS .conf filename.

    Examples:
        REQUEST-932-APPLICATION-ATTACK-RCE.conf  → "APPLICATION ATTACK RCE"
        RESPONSE-951-DATA-LEAKAGES-SQL.conf      → "DATA LEAKAGES SQL"
        REQUEST-901-INITIALIZATION.conf          → "INITIALIZATION"
        REQUEST-920-PROTOCOL-ENFORCEMENT.conf    → "PROTOCOL ENFORCEMENT"
    """
    stem = Path(filename).stem  # e.g. REQUEST-932-APPLICATION-ATTACK-RCE
    match = re.match(r'^(?:REQUEST|RESPONSE)-\d+-(.+)$', stem)
    if match:
        return match.group(1).replace('-', ' ')
    return stem


def _extract_mediawiki_topic(filename: str) -> str:
    """
    Extracts a human-readable topic from a MediaWiki documentation filename.

    Examples:
        Reference-Manual-Variables.mediawiki                    → "Variables"
        Reference-Manual-Actions.mediawiki                      → "Actions"
        Reference-Manual-Transformation-Functions.mediawiki      → "Transformation Functions"
        Reference-Manual-Configuration-Directives.mediawiki      → "Configuration Directives"
        Reference-Manual.mediawiki                              → "ModSecurity Reference Manual"
        ModSecurity-Frequently-Asked-Questions-(FAQ).mediawiki   → "Frequently Asked Questions (FAQ)"
    """
    stem = Path(filename).stem  # e.g. Reference-Manual-Variables

    # Reference-Manual-<Topic> pattern
    match = re.match(r'^Reference-Manual-(.+)$', stem)
    if match:
        return match.group(1).replace('-', ' ')

    # Standalone Reference-Manual (the main file)
    if stem == 'Reference-Manual':
        return "ModSecurity Reference Manual"

    # ModSecurity-Frequently-Asked-Questions-(FAQ) pattern
    match = re.match(r'^ModSecurity-(.+)$', stem)
    if match:
        topic = match.group(1).replace('-', ' ')
        # Restore parenthesized abbreviations: "( FAQ)" → "(FAQ)"
        topic = re.sub(r'\(\s*', '(', topic)
        topic = re.sub(r'\s*\)', ')', topic)
        return topic

    # Fallback: use stem with dashes replaced
    return stem.replace('-', ' ')


# ── CRS .conf parsing ────────────────────────────────────────

def parse_crs_file(filepath: str) -> List[str]:
    """
    Reads a ModSecurity CRS '.conf' file, handles line continuations,
    splits at SecRule and SecAction boundaries, and groups chained rules
    together into single chunks.

    Each chunk is prefixed with source filename and category metadata
    so the RAG system can route queries to the right rules.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(filepath, 'r', encoding='latin-1') as f:
            content = f.read()

    # Resolve \ line continuations (both LF and CRLF)
    content = re.sub(r'\\\r?\n\s*', ' ', content)

    # Split at SecRule / SecAction boundaries (including indented ones)
    raw_chunks = re.split(
        r'(?=^[ \t]*SecRule\s|^[ \t]*SecAction\s)',
        content,
        flags=re.MULTILINE,
    )

    # Keep only chunks that start with SecRule or SecAction (after stripping)
    valid_chunks = []
    for chunk in raw_chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk.startswith('SecRule') or chunk.startswith('SecAction'):
            valid_chunks.append(chunk)

    # Group chained rules together
    rules = []
    current_chain = []

    filename = Path(filepath).name
    category = _extract_conf_category(filename)

    for chunk in valid_chunks:
        current_chain.append(chunk)

        # Check if this rule has a 'chain' action.
        # The chain keyword appears in the actions string like:
        #   ...,chain,... or ...,chain" or "chain" or standalone chain
        if re.search(r'(?:^|[,"])\s*chain\s*(?:[,"]|$)', chunk, flags=re.IGNORECASE):
            continue  # Part of a chain, wait for the terminal rule

        # Chain ends or rule is standalone — flush
        combined_rule = "\n".join(current_chain)
        prefix = f"[Source: {filename} | Category: {category}]"
        rules.append(f"{prefix}\n{combined_rule}")
        current_chain = []

    # If file ends while still in a chain (malformed conf), flush remaining
    if current_chain:
        combined_rule = "\n".join(current_chain)
        prefix = f"[Source: {filename} | Category: {category}]"
        rules.append(f"{prefix}\n{combined_rule}")

    return rules


# ── MediaWiki documentation parsing ──────────────────────────

def _extract_section_name(heading: str) -> str:
    """
    Strips mediawiki heading markers and whitespace.
    '== ARGS =='   → 'ARGS'
    '== allow == '  → 'allow'
    '=== Commercial Help ===' → 'Commercial Help'
    """
    # Strip outer whitespace first, then remove = markers
    heading = heading.strip()
    return re.sub(r'^=+\s*|\s*=+$', '', heading).strip()


def parse_mediawiki_file(filepath: str) -> List[str]:
    """
    Reads a MediaWiki documentation file and splits it into per-section
    chunks. Each section (delimited by == headings) becomes its own chunk
    with full metadata (source filename, topic, and section name).

    This ensures every chunk the RAG indexes carries metadata, even after
    LightRAG's internal sub-chunking.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
    except UnicodeDecodeError:
        with open(filepath, 'r', encoding='latin-1') as f:
            content = f.read().strip()

    if not content:
        return []

    filename = Path(filepath).name
    topic = _extract_mediawiki_topic(filename)

    # Split at level-2 headings (== Section ==).
    # Level 1 (= Title =) is typically the document title / broad category,
    # level 2 (== ... ==) is where individual concepts live (ARGS, ENV, deny, etc.)
    # We use lookahead so the heading stays with its content.
    section_splits = re.split(r'(?=^==\s[^=])', content, flags=re.MULTILINE)

    # If no level-2 headings found, return the whole file as one chunk
    if len(section_splits) <= 1:
        return [f"[Source: {filename} | Topic: {topic}]\n{content}"]

    chunks = []

    # The first split is everything before the first == heading (preamble:
    # title, copyright, intro text). Keep it as one chunk if non-trivial.
    preamble = section_splits[0].strip()
    if preamble and len(preamble) > 50:
        chunks.append(f"[Source: {filename} | Topic: {topic}]\n{preamble}")

    # Each remaining split starts with a == heading
    for section in section_splits[1:]:
        section = section.strip()
        if not section:
            continue

        # Extract the section name from the first line (the heading)
        first_line = section.split('\n', 1)[0]
        section_name = _extract_section_name(first_line)

        if not section_name:
            section_name = "General"

        prefix = f"[Source: {filename} | Topic: {topic} | Section: {section_name}]"
        chunks.append(f"{prefix}\n{section}")

    return chunks


# ── Unified ingestion ────────────────────────────────────────

SUPPORTED_EXTENSIONS = {'.conf', '.mediawiki'}


def ingest_all_files(file_paths: List[str]) -> List[str]:
    """
    Ingests multiple .conf and .mediawiki files.
    Detects file type by extension and uses the appropriate parser.
    Ensures crs-setup.conf is processed first if present.
    """
    if not file_paths:
        return []

    # Ensure crs-setup.conf is at the start if present
    setup_file = next((f for f in file_paths if 'crs-setup.conf' in f), None)
    ordered_files = []
    if setup_file:
        ordered_files.append(setup_file)
        ordered_files.extend(f for f in file_paths if f != setup_file)
    else:
        ordered_files = list(file_paths)

    all_chunks = []
    for filepath in ordered_files:
        ext = Path(filepath).suffix.lower()
        try:
            if ext == '.conf':
                chunks = parse_crs_file(filepath)
                logger.info(f"Parsed {filepath}: {len(chunks)} combined rules/actions")
            elif ext == '.mediawiki':
                chunks = parse_mediawiki_file(filepath)
                logger.info(f"Parsed {filepath}: {len(chunks)} text chunk(s)")
            else:
                logger.warning(f"Skipping unsupported file type: {filepath}")
                continue
            all_chunks.extend(chunks)
        except Exception as e:
            logger.error(f"Failed to parse {filepath}: {e}")

    return all_chunks
