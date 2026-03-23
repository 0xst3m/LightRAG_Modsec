import logging
import os
import re

import ollama
import openai
from lightrag import LightRAG
from lightrag.llm.ollama import ollama_embed
from lightrag.llm.ollama import ollama_model_complete as _ollama_model_complete
from lightrag.utils import EmbeddingFunc

from config_loader import (
    DEFAULT_MODEL,
    EMBEDDING_DIM,
    EMBEDDING_MAX_TOKENS,
    EMBEDDING_MODEL,
    NVIDIA_API_KEY,
    NVIDIA_BASE_URL,
    NVIDIA_MAX_TOKENS_KW,
    NVIDIA_MAX_TOKENS_LLM,
    NVIDIA_TEMPERATURE,
    NVIDIA_TOP_P,
    OLLAMA_HOST,
    OLLAMA_KW_OPTIONS,
    OLLAMA_LLM_OPTIONS,
    RAG_CHUNK_TOKEN_SIZE,
    RAG_ENTITY_GLEANING,
    RAG_ENTITY_TYPES,
    RAG_LLM_TIMEOUT,
    RAG_MAX_ASYNC,
)

logger = logging.getLogger(__name__)

_THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)

DEBUG_MODE = False

# ── Model configuration ─────────────────────────────────────────
# Provider is auto-detected from model name:
#   "nvidia:moonshotai/kimi-k2.5"  → NVIDIA API
#   anything else                   → Ollama (local or :cloud)

MODEL_NAME = DEFAULT_MODEL


def set_model(name: str):
    global MODEL_NAME
    MODEL_NAME = name
    logger.info(f"Model switched to: {MODEL_NAME}")


def _is_nvidia_model(name: str) -> bool:
    return name.startswith("nvidia:")


def _nvidia_model_id(name: str) -> str:
    """Strip 'nvidia:' prefix to get the NVIDIA model ID."""
    return name[len("nvidia:"):]


def enable_debug():
    global DEBUG_MODE
    DEBUG_MODE = True
    logging.getLogger("lightrag").setLevel(logging.DEBUG)


# ── NVIDIA API call ─────────────────────────────────────────────


async def _nvidia_chat(
    prompt: str,
    system_prompt: str = "",
    max_tokens: int = NVIDIA_MAX_TOKENS_LLM,
    temperature: float = NVIDIA_TEMPERATURE,
    top_p: float = NVIDIA_TOP_P,
) -> str:
    """Call NVIDIA API (OpenAI-compatible) and return the response text."""
    client = openai.AsyncOpenAI(
        api_key=NVIDIA_API_KEY,
        base_url=NVIDIA_BASE_URL,
    )
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    model_id = _nvidia_model_id(MODEL_NAME)

    if DEBUG_MODE:
        logger.info("=" * 80)
        logger.info(
            f"[NVIDIA] model={model_id} temp={temperature} max_tokens={max_tokens}"
        )
        logger.info(f"[NVIDIA] system_prompt length: {len(system_prompt)}")
        logger.info(f"[NVIDIA] prompt length: {len(prompt)}")
        logger.info("=" * 80)

    resp = await client.chat.completions.create(
        model=model_id,
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        stream=True,
    )

    # Collect streamed chunks (thinking models put reasoning in separate field)
    result_parts = []
    thinking_parts = []
    async for chunk in resp:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        if delta:
            if delta.content:
                result_parts.append(delta.content)
            # Thinking models may use 'reasoning' or 'reasoning_content'
            reasoning = getattr(delta, "reasoning", None) or getattr(delta, "reasoning_content", None)
            if reasoning:
                thinking_parts.append(reasoning)

    result = "".join(result_parts)
    if thinking_parts:
        logger.info(f"[NVIDIA] Thinking: {len(''.join(thinking_parts))} chars")

    # If no content but thinking was captured, the model used all tokens on reasoning
    if not result and thinking_parts:
        logger.warning("[NVIDIA] No content generated — all tokens used for reasoning. Increase max_tokens.")

    if DEBUG_MODE:
        logger.info("=" * 80)
        logger.info(f"[NVIDIA] Response length: {len(result)} chars")
        if result:
            logger.info(f"[NVIDIA] Response (first 2000):\n{result[:2000]}")
        logger.info("=" * 80)

    # Strip any <think> blocks if present
    result = _THINK_RE.sub("", result)
    return result


# ── LLM wrapper for LightRAG ────────────────────────────────────


async def ollama_model_complete(*args, **kwargs):
    kw = kwargs.pop("keyword_extraction", None)

    if _is_nvidia_model(MODEL_NAME):
        # Route all calls through NVIDIA API
        prompt = args[0] if args else kwargs.get("prompt", "")
        sys_prompt = kwargs.get("system_prompt", "") or ""
        kwargs.pop("hashing_kv", None)
        kwargs.pop("options", None)
        kwargs.pop("system_prompt", None)
        kwargs.pop("history_messages", None)
        kwargs.pop("stream", None)
        kwargs.pop("enable_cot", None)

        max_tokens = NVIDIA_MAX_TOKENS_KW if kw else NVIDIA_MAX_TOKENS_LLM
        logger.info(
            f"[NVIDIA] {'keyword extraction' if kw else 'LLM call'} via {MODEL_NAME}"
        )
        return await _nvidia_chat(
            prompt=prompt,
            system_prompt=sys_prompt,
            max_tokens=max_tokens,
        )

    # ── Ollama path ──────────────────────────────────────────────
    if kw:
        prompt = args[0] if args else kwargs.get("prompt", "")

        if DEBUG_MODE:
            logger.info("=" * 80)
            logger.info("[KW_EXTRACT] === KEYWORD EXTRACTION CALL ===")
            logger.info(f"[KW_EXTRACT] Prompt length: {len(prompt)} chars")
            logger.info(f"[KW_EXTRACT] Full prompt:\n{prompt}")
            logger.info(f"[KW_EXTRACT] Options: {OLLAMA_KW_OPTIONS}")
            logger.info("=" * 80)
        else:
            logger.info("[KW_EXTRACT] extracting keywords")

        client = ollama.AsyncClient(host=OLLAMA_HOST)
        try:
            resp = await client.chat(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
                options=OLLAMA_KW_OPTIONS,
            )
            msg = resp["message"]
            result = msg.content or ""
            thinking_len = (
                len(msg.thinking) if hasattr(msg, "thinking") and msg.thinking else 0
            )

            if DEBUG_MODE:
                thinking = (
                    msg.thinking if hasattr(msg, "thinking") and msg.thinking else ""
                )
                logger.info("=" * 80)
                logger.info("[KW_EXTRACT] === KEYWORD EXTRACTION RESPONSE ===")
                logger.info(f"[KW_EXTRACT] eval_count: {resp.get('eval_count')}")
                logger.info(f"[KW_EXTRACT] done_reason: {resp.get('done_reason')}")
                logger.info(f"[KW_EXTRACT] Thinking: {thinking_len} chars")
                logger.info(f"[KW_EXTRACT] Content:\n{result}")
                logger.info("=" * 80)
            else:
                logger.info(
                    f"[KW_EXTRACT] done: len={len(result)}, thinking={thinking_len}, "
                    f"eval={resp.get('eval_count')}, done={resp.get('done_reason')}"
                )
            return result
        finally:
            await client._client.aclose()

    # Normal Ollama LLM calls
    if DEBUG_MODE:
        prompt = args[0] if args else kwargs.get("prompt", "")
        kw_keys = sorted(k for k in kwargs.keys() if k != "hashing_kv")
        opts = kwargs.get("options", {})
        sys_prompt = kwargs.get("system_prompt", "")
        history = kwargs.get("history_messages", [])
        logger.info("=" * 80)
        logger.info("[LLM_CALL] === NORMAL LLM CALL ===")
        logger.info(f"[LLM_CALL] kwargs keys: {kw_keys}")
        logger.info(f"[LLM_CALL] options: {opts}")
        logger.info(
            f"[LLM_CALL] system_prompt length: {len(sys_prompt) if sys_prompt else 0}"
        )
        if sys_prompt:
            logger.info(f"[LLM_CALL] system_prompt (first 500):\n{sys_prompt[:500]}")
        logger.info(f"[LLM_CALL] history_messages count: {len(history)}")
        logger.info(f"[LLM_CALL] Prompt length: {len(prompt)} chars")
        logger.info(f"[LLM_CALL] Prompt (first 2000 chars):\n{prompt[:2000]}")
        if len(prompt) > 2000:
            logger.info(f"[LLM_CALL] ... (truncated, {len(prompt) - 2000} more chars)")
        logger.info("=" * 80)

    result = await _ollama_model_complete(*args, **kwargs)

    if DEBUG_MODE:
        logger.info("=" * 80)
        logger.info("[LLM_CALL] === NORMAL LLM RESPONSE ===")
        logger.info(f"[LLM_CALL] Response length: {len(result) if result else 0} chars")
        if result:
            logger.info(f"[LLM_CALL] Response (first 2000 chars):\n{result[:2000]}")
            if len(result) > 2000:
                logger.info(
                    f"[LLM_CALL] ... (truncated, {len(result) - 2000} more chars)"
                )
        else:
            logger.info("[LLM_CALL] Response is EMPTY")
        logger.info("=" * 80)

    return result


# ── RAG instance ────────────────────────────────────────────────


def get_rag_instance(workspace_name: str, working_dir: str = None) -> LightRAG:
    """
    Initializes LightRAG for a given workspace.
    Uses configured embedding model for embeddings and MODEL_NAME for LLM.
    Storage: NanoVectorDB (local files) + NetworkX graph.
    """
    from config_loader import DATABASE_DIR
    if working_dir is None:
        working_dir = DATABASE_DIR

    full_workspace_path = os.path.join(working_dir, workspace_name)
    os.makedirs(full_workspace_path, exist_ok=True)

    async def embedding_func(texts: list[str]) -> list[list[float]]:
        return await ollama_embed.func(
            texts, embed_model=EMBEDDING_MODEL, host=OLLAMA_HOST
        )

    rag = LightRAG(
        working_dir=full_workspace_path,
        embedding_func=EmbeddingFunc(
            embedding_dim=EMBEDDING_DIM,
            max_token_size=EMBEDDING_MAX_TOKENS,
            func=embedding_func,
        ),
        llm_model_func=ollama_model_complete,
        llm_model_name=MODEL_NAME,
        llm_model_kwargs={
            "options": OLLAMA_LLM_OPTIONS,
            "host": OLLAMA_HOST,
        },
        chunk_token_size=RAG_CHUNK_TOKEN_SIZE,
        default_llm_timeout=RAG_LLM_TIMEOUT,
        llm_model_max_async=RAG_MAX_ASYNC,
        entity_extract_max_gleaning=RAG_ENTITY_GLEANING,
        vector_storage="NanoVectorDBStorage",
        graph_storage="NetworkXStorage",
        addon_params={"entity_types": RAG_ENTITY_TYPES},
    )
    return rag
