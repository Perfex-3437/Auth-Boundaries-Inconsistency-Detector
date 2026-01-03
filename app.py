# app.py
import gradio as gr
from engine import run_analysis

def analyze(api_spec, api_key):
    if not api_spec.strip():
        return "Please provide an API specification."
    if not api_key.strip():
        return "Please provide your OpenAI API key."
    
    try:
        return run_analysis(api_spec, api_key)
    except Exception as e:
        return f"Error: {str(e)}"


with gr.Blocks(title="Auth Boundary Inconsistency Detector") as app:
    gr.Markdown("## 🔒 Auth Boundary Inconsistency Detector (v1)")
    gr.Markdown(
        "Paste an OpenAPI specification to identify **authorization and trust boundary inconsistencies**.\n"
        "This tool performs **structural reasoning only** and does **not** simulate attacks."
    )

    api_spec_input = gr.Textbox(
        label="OpenAPI Specification",
        lines=20,
        placeholder="Paste OpenAPI / Swagger JSON here"
    )

    api_key_input = gr.Textbox(
        label="OpenAI API Key",
        type="password",
        placeholder="sk-..."
    )

    analyze_btn = gr.Button("Analyze Auth Boundaries")
    output = gr.Textbox(label="Findings", lines=20)

    analyze_btn.click(analyze, inputs=[api_spec_input, api_key_input], outputs=output)

app.launch()