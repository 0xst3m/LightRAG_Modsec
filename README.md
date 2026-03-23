# LightRAG_Modsec

AI-powered ModSecurity rule generation using a **knowledge graph + vector search** RAG pipeline.

Turns plain English into battle-ready ModSecurity rules, grounded in the complete OWASP CRS ruleset and ModSecurity reference documentation.

## How It Works

```
Your query ──→ System Prompt (387-line ModSec reference)
                    │
                    ▼
         ┌──────────┴──────────┐
         ▼                     ▼
   Vector Search        Knowledge Graph
   (NanoVectorDB)        (NetworkX)
   1,321 chunks          2,182 nodes
   Semantic match        2,579 edges
         │                     │
         └──────────┬──────────┘
                    ▼
            Merged Context
                    ▼
           LLM Generates Rule
```

**Vector search** finds semantically similar rule chunks. **Knowledge graph** traverses entity relationships across rule files (e.g., tracing how anomaly scoring chains from detection → evaluation → blocking across 3 different config files). Both fire simultaneously and results are merged.

## Quick Start

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/download) installed and running

### 1. Clone and setup

```bash
git clone https://github.com/<your-username>/modsec-agent.git
cd modsec-agent
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

### 2. Pull the embedding model

```bash
ollama pull qwen3-embedding:8b
```

This is **required** regardless of which LLM you use — it powers the vector search retrieval.

### 3. Pull an LLM (for local inference)

```bash
ollama pull qwen3.5:9b          # lightweight, fast
# or
ollama pull qwen3:32b           # better quality, needs more VRAM
```

Or skip this if you'll use NVIDIA API or Ollama cloud models.

### 4. Configure

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

```
NVIDIA_API_KEY=your-nvidia-api-key-here
```

Edit `config.yaml` to set your default model, available models, and other settings.

### 5. Add your knowledge base

Place your files in the `knowledge/` directory:

```
knowledge/
├── Documentation/        # .mediawiki reference docs
│   ├── Reference-Manual.mediawiki
│   └── ...
└── rules/                # .conf CRS rule files
    ├── REQUEST-930-APPLICATION-ATTACK-LFI.conf
    └── ...
```

Supported formats: `.conf` (CRS rules), `.mediawiki` (documentation)

### 6. Build the knowledge graph

```bash
python pipeline.py
```

This parses all files, extracts entities/relationships, and builds the vector + graph database. Progress is checkpointed — if interrupted, re-run to resume.

### 7. Run

**Web UI (recommended):**

```bash
python app.py
```

Open http://127.0.0.1:7860

**CLI:**

```bash
python query.py "Write a rule to detect SQL injection in POST parameters"
python query.py "How does anomaly scoring work across paranoia levels?" --mode hybrid
python query.py "Show me all rules related to LFI detection" --context-only
```

## Configuration

All settings are in `config.yaml`:

| Section | What it controls |
|---------|-----------------|
| `workspace` | Database path, knowledge directory, batch size |
| `embedding` | Embedding model, dimensions, token size |
| `llm` | Default model, available models list |
| `ollama` | Host, temperature, top_p, context window |
| `nvidia` | API base URL, token limits, temperature |
| `rag` | Chunk size, timeout, top_k, entity types |
| `ui` | Host, port, title |

### LLM Providers

The system auto-detects the provider from the model name:

| Model name pattern | Provider | Example |
|-------------------|----------|---------|
| `nvidia:<model>` | NVIDIA API | `nvidia:moonshotai/kimi-k2.5` |
| `<model>:cloud` | Ollama Cloud | `kimi-k2.5:cloud` |
| `<model>` | Ollama Local | `qwen3.5:9b` |

Switch models from the UI dropdown or change `default_model` in `config.yaml`.

## Retrieval Modes

| Mode | What it searches | Best for |
|------|-----------------|----------|
| `naive` | Vector chunks only | Simple lookups |
| `local` | Graph entity neighbors (1-hop) | "What connects to this variable?" |
| `global` | Graph relationship paths (multi-hop) | "How does scoring lead to blocking?" |
| `hybrid` | Local + Global (graph only) | Relationship-heavy questions |
| **`mix`** | **Graph + vectors (everything)** | **Rule generation (default)** |

## Project Structure

```
modsec-agent/
├── config.yaml            # All configuration
├── config_loader.py       # Centralized config reader
├── .env                   # API keys (gitignored)
├── .env.example           # Template for .env
├── requirements.txt       # Python dependencies
│
├── app.py                 # Gradio web UI
├── query.py               # CLI query interface
├── pipeline.py            # Ingest + index orchestrator
│
├── rag/
│   ├── indexer.py         # LLM routing (Ollama / NVIDIA)
│   ├── query.py           # RAG query with system prompt
│   └── system_prompt.txt  # 387-line ModSecurity reference
│
├── ingest/
│   └── parser.py          # .conf and .mediawiki parser
│
├── knowledge/             # Source files (your rules + docs)
│   ├── Documentation/     # .mediawiki files
│   └── rules/             # .conf files
│
└── database/              # Generated (gitignored, rebuild with pipeline.py)
    └── knowledge_v1/      # Vector DB + knowledge graph
```

## Key Numbers

| Metric | Value |
|--------|-------|
| Source files | 27 CRS rules + 8 MediaWiki docs |
| Text chunks | 1,321 |
| Knowledge graph nodes | 2,182 |
| Knowledge graph edges | 2,579 |
| Embedding dimensions | 4,096 |
| System prompt | 387 lines |
| Database size | ~199 MB |

## Adding New Rules

Drop new `.conf` or `.mediawiki` files into `knowledge/` and re-run `python pipeline.py`. The pipeline is incremental — existing chunks are skipped, only new content is processed.

## Portability

To move to another machine:
1. Copy the entire project (including `database/` if you want to skip re-indexing)
2. Install Ollama + pull `qwen3-embedding:8b`
3. `pip install -r requirements.txt`
4. Set up `.env` with your API keys
5. Run `python app.py`

**Note:** Changing the embedding model requires a full re-index. Changing the LLM does not.

## Tech Stack

- [LightRAG](https://github.com/HKUDS/LightRAG) — RAG framework with knowledge graph support
- [NetworkX](https://networkx.org/) — Knowledge graph storage
- [NanoVectorDB](https://github.com/gusye1234/nano-vectordb) — Local vector database
- [Ollama](https://ollama.com/) — Local LLM inference
- [Gradio](https://gradio.app/) — Web UI
- [NVIDIA NIM](https://build.nvidia.com/) — Cloud LLM API (optional)

## License

MIT
