from fastapi import FastAPI
from pydantic import BaseModel
import subprocess
import os

app = FastAPI(title="LLMForge Gateway")


class Prompt(BaseModel):
    prompt: str


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/generate")
async def generate(p: Prompt):
    """
    Minimal gateway endpoint that forwards prompts to the `ollama` CLI.
    This is a simple example; in production you may prefer an SDK or HTTP
    integration depending on how `ollama` is exposed in your environment.
    """
    try:
        # Example: `ollama run <model> --json "<prompt>"`
        # Model can be provided via the OLLAMA_MODEL env var (recommended for containers).
        model = os.getenv("OLLAMA_MODEL", "<model>")
        proc = subprocess.run(
            ["ollama", "run", model, "--json", p.prompt],
            capture_output=True,
            text=True,
            check=True,
        )
        return {"output": proc.stdout}
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr}
