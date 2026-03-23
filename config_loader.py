"""
Centralized configuration loader.
Reads config.yaml and .env, exposes typed settings for all modules.
"""

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv

# Load .env file (if present) into os.environ
_PROJECT_ROOT = Path(__file__).parent
load_dotenv(_PROJECT_ROOT / ".env", override=True)

# Load config.yaml
_CONFIG_PATH = _PROJECT_ROOT / "config.yaml"
with open(_CONFIG_PATH, encoding="utf-8") as f:
    _cfg = yaml.safe_load(f)


# ── Workspace ────────────────────────────────────────────────
WORKSPACE_NAME: str = _cfg["workspace"]["name"]
DATABASE_DIR: str = _cfg["workspace"]["database_dir"]
KNOWLEDGE_DIR: str = _cfg["workspace"]["knowledge_dir"]
BATCH_SIZE: int = _cfg["workspace"]["batch_size"]

# ── Embedding ────────────────────────────────────────────────
EMBEDDING_MODEL: str = _cfg["embedding"]["model"]
EMBEDDING_DIM: int = _cfg["embedding"]["dimensions"]
EMBEDDING_MAX_TOKENS: int = _cfg["embedding"]["max_token_size"]

# ── LLM ──────────────────────────────────────────────────────
DEFAULT_MODEL: str = _cfg["llm"]["default_model"]
AVAILABLE_MODELS: list[str] = _cfg["llm"]["available_models"]

# ── Ollama ───────────────────────────────────────────────────
OLLAMA_HOST: str = _cfg["ollama"]["host"]

OLLAMA_KW_OPTIONS: dict = _cfg["ollama"]["keyword_extraction"]
OLLAMA_LLM_OPTIONS: dict = _cfg["ollama"]["llm"]

# ── NVIDIA ───────────────────────────────────────────────────
NVIDIA_API_KEY: str = os.environ.get("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL: str = _cfg["nvidia"]["base_url"]
NVIDIA_TEMPERATURE: float = _cfg["nvidia"]["temperature"]
NVIDIA_TOP_P: float = _cfg["nvidia"]["top_p"]
NVIDIA_MAX_TOKENS_KW: int = _cfg["nvidia"]["max_tokens_keyword"]
NVIDIA_MAX_TOKENS_LLM: int = _cfg["nvidia"]["max_tokens_llm"]

# ── RAG ──────────────────────────────────────────────────────
RAG_CHUNK_TOKEN_SIZE: int = _cfg["rag"]["chunk_token_size"]
RAG_LLM_TIMEOUT: int = _cfg["rag"]["llm_timeout"]
RAG_MAX_ASYNC: int = _cfg["rag"]["max_async_workers"]
RAG_ENTITY_GLEANING: int = _cfg["rag"]["entity_extract_max_gleaning"]
RAG_TOP_K: int = _cfg["rag"]["top_k"]
RAG_CHUNK_TOP_K: int = _cfg["rag"]["chunk_top_k"]
RAG_DEFAULT_MODE: str = _cfg["rag"]["default_mode"]
RAG_RESPONSE_TYPE: str = _cfg["rag"]["response_type"]
RAG_ENTITY_TYPES: list[str] = _cfg["rag"]["entity_types"]

# ── UI ───────────────────────────────────────────────────────
UI_HOST: str = _cfg["ui"]["host"]
UI_PORT: int = _cfg["ui"]["port"]
UI_TITLE: str = _cfg["ui"]["title"]
