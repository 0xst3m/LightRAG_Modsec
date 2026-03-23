import logging
from pathlib import Path

from lightrag import LightRAG
from lightrag.base import QueryParam

from config_loader import RAG_CHUNK_TOP_K, RAG_DEFAULT_MODE, RAG_RESPONSE_TYPE, RAG_TOP_K

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT_PATH = Path(__file__).parent / "system_prompt.txt"
_SYSTEM_PROMPT = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


async def query_rag(
    rag: LightRAG,
    query_text: str,
    mode: str = RAG_DEFAULT_MODE,
    only_context: bool = False,
    top_k: int = RAG_TOP_K,
    chunk_top_k: int = RAG_CHUNK_TOP_K,
) -> str:
    """
    Queries the knowledge graph + vector store via LightRAG.

    The system prompt from rag/system_prompt.txt is prepended to every
    user query so the LLM has full ModSecurity reference context.

    Modes:
        naive   — vector chunks only (semantic similarity)
        local   — KG entities → related chunks
        global  — KG relationships → connected entities
        hybrid  — local + global merged (KG only, no vector chunks)
        mix     — KG + vector chunks (recommended, uses everything)
    """
    # Prepend system prompt to user query
    full_query = f"{_SYSTEM_PROMPT}\n\n---USER QUERY---\n{query_text}"

    param = QueryParam(
        mode=mode,
        only_need_context=only_context,
        top_k=top_k,
        chunk_top_k=chunk_top_k,
        response_type=RAG_RESPONSE_TYPE,
    )

    try:
        result = await rag.aquery(full_query, param=param)
    except Exception as e:
        logger.error(f"Query failed: {e}")
        return f"Error: {e}"
    return result or "No response generated."
