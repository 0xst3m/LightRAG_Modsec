import asyncio
import argparse
import logging

from config_loader import WORKSPACE_NAME
from rag.indexer import get_rag_instance, enable_debug
from rag.query import query_rag

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


async def run_query(question: str, mode: str, only_context: bool):
    rag = get_rag_instance(WORKSPACE_NAME)
    await rag.initialize_storages()

    logger.info(f"Querying ({mode} mode): {question}")
    result = await query_rag(rag, question, mode=mode, only_context=only_context)

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    print(result)
    print("=" * 70)

    await rag.finalize_storages()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query the CRS-Forge knowledge base")
    parser.add_argument("question", help="Natural language query")
    parser.add_argument(
        "--mode",
        default="mix",
        choices=["naive", "local", "global", "hybrid", "mix"],
        help="Retrieval mode (default: mix)",
    )
    parser.add_argument(
        "--context-only",
        action="store_true",
        help="Return raw retrieved context without LLM generation",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable full debug logging: prompts, responses, thinking, options, etc.",
    )
    args = parser.parse_args()

    if args.debug:
        enable_debug()
        logging.getLogger().setLevel(logging.DEBUG)

    asyncio.run(run_query(args.question, args.mode, args.context_only))
