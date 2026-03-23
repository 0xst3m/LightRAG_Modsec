import logging
import time

import gradio as gr

from config_loader import AVAILABLE_MODELS, UI_HOST, UI_PORT, UI_TITLE, WORKSPACE_NAME
from rag.indexer import MODEL_NAME, get_rag_instance, set_model
from rag.query import query_rag

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

CSS = """
.main-header {
    text-align: center;
    padding: 1.5rem 0 0.5rem 0;
}
.main-header h1 {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
}
.main-header p {
    color: #6b7280;
    font-size: 0.95rem;
    margin: 0;
}
.status-bar {
    font-size: 0.8rem;
    color: #6b7280;
    padding: 0.25rem 0;
}
.sidebar {
    border-left: 1px solid #e5e7eb;
    padding-left: 1rem;
}
.dark .sidebar {
    border-color: #374151;
}
footer {
    display: none !important;
}
"""

rag = None
current_model = MODEL_NAME


async def ensure_rag():
    global rag
    if rag is None:
        rag = get_rag_instance(WORKSPACE_NAME)
        await rag.initialize_storages()
    return rag


async def switch_model(model_name: str):
    global rag, current_model
    if not model_name or model_name == current_model:
        return current_model
    set_model(model_name)
    if rag:
        await rag.finalize_storages()
    rag = None
    current_model = model_name
    await ensure_rag()
    return current_model


async def run_query(question: str, mode: str, context_only: bool, history: list):
    if not question.strip():
        return history, ""

    r = await ensure_rag()
    logger.info(f"[{current_model}] ({mode}) {question}")

    t0 = time.perf_counter()
    result = await query_rag(r, question, mode=mode, only_context=context_only)
    elapsed = time.perf_counter() - t0

    status = f"{current_model} | {mode} mode | {elapsed:.1f}s"
    history = history + [
        {"role": "user", "content": question},
        {"role": "assistant", "content": result},
    ]
    return history, status


def clear_chat():
    return [], ""


with gr.Blocks(title=UI_TITLE) as app:
    gr.HTML(f"""
    <div class="main-header">
        <h1>{UI_TITLE}</h1>
        <p>AI-powered ModSecurity rule generation backed by OWASP CRS knowledge graph</p>
    </div>
    """)

    with gr.Row():
        with gr.Column(scale=4):
            chatbot = gr.Chatbot(
                label="Conversation",
                height=520,
                render_markdown=True,
                placeholder="Ask about ModSecurity rules, CRS configuration, or request custom rule generation...",
            )

            with gr.Row():
                question = gr.Textbox(
                    placeholder="e.g. Write a rule to detect SQL injection in POST parameters",
                    show_label=False,
                    scale=6,
                    container=False,
                    lines=1,
                    max_lines=4,
                )
                submit_btn = gr.Button("Send", variant="primary", scale=1, min_width=80)

            status_bar = gr.Textbox(
                value="Ready",
                show_label=False,
                interactive=False,
                container=False,
                elem_classes=["status-bar"],
            )

        with gr.Column(scale=1, elem_classes=["sidebar"]):
            gr.Markdown("### Settings")

            model = gr.Dropdown(
                choices=AVAILABLE_MODELS,
                value=AVAILABLE_MODELS[0],
                label="Model",
                allow_custom_value=True,
                info="Select or type any Ollama model name",
            )

            mode = gr.Dropdown(
                choices=["mix", "naive", "local", "global", "hybrid"],
                value="mix",
                label="Retrieval Mode",
                info="mix = KG + vector chunks (best quality)",
            )

            context_only = gr.Checkbox(
                label="Context only",
                value=False,
                info="Return raw context without LLM generation",
            )

            gr.Markdown("---")

            clear_btn = gr.Button("Clear Chat", variant="secondary")

            gr.Markdown("---")

            gr.Markdown(
                "### Retrieval Modes\n"
                "- **mix** — KG + vector (recommended)\n"
                "- **naive** — vector similarity only\n"
                "- **local** — KG entity neighbors\n"
                "- **global** — KG relationship traversal\n"
                "- **hybrid** — local + global combined",
                elem_classes=["status-bar"],
            )

    model.change(fn=switch_model, inputs=[model], outputs=[status_bar])

    submit_btn.click(
        fn=run_query,
        inputs=[question, mode, context_only, chatbot],
        outputs=[chatbot, status_bar],
    ).then(fn=lambda: "", outputs=[question])

    question.submit(
        fn=run_query,
        inputs=[question, mode, context_only, chatbot],
        outputs=[chatbot, status_bar],
    ).then(fn=lambda: "", outputs=[question])

    clear_btn.click(fn=clear_chat, outputs=[chatbot, status_bar])

if __name__ == "__main__":
    app.launch(
        server_name=UI_HOST,
        server_port=UI_PORT,
        theme=gr.themes.Soft(),
        css=CSS,
    )
