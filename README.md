# 🛡️ LLMForge
![](https://img.shields.io/github/v/release/SasanLabs/LLMForge?style=flat) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) [![Docker Pulls](https://badgen.net/docker/pulls/sasanlabs/llmforge?icon=docker&label=pulls)](https://hub.docker.com/r/sasanlabs/llmforge/) 

AI Security Gateway for Dynamic Vulnerability Labs
LLMForge is a security-first LLM control plane built to power AI-driven vulnerability simulations.
It serves as the AI execution layer for SasanLabs and integrates directly with the VulnerableApp ecosystem, enabling dynamic exploit labs driven by language models.

It also includes a simple local retrieval setup backed by Ollama embeddings and a FAISS index so you can store and query small text collections without adding another external service.

🎯 Purpose

LLMForge enables two powerful security modes:

1️⃣ LLM as Target

Simulate real-world AI vulnerabilities such as:
Prompt injection
System prompt extraction
Data exfiltration
Guardrail bypass
Tool misuse
Designed for structured AI red-team experimentation.

2️⃣ LLM as Vulnerable System

Turn a language model into:

A vulnerable machine
A misconfigured API
A flawed authentication system
Each session can generate unique exploit paths, enabling infinite security training scenarios.

🧠 What LLMForge Does

LLMForge acts as:

A policy enforcement layer
A session and memory controller
A deterministic challenge engine
A logging and evaluation gateway
The model is not trusted.
The gateway controls behavior.

🔌 Model Agnostic

LLMForge supports:
Local models (via Ollama or compatible runtimes)
OpenAI-compatible APIs
Cloud-based LLM providers
Models can be swapped without changing lab logic.

🧩 Integration

LLMForge integrates with the existing VulnerableApp architecture and works alongside VulnerableApp to introduce AI-native security labs into the platform.
It is designed to evolve into the AI security backbone of the ecosystem.

⚠️ Disclaimer

This project is intended strictly for educational and defensive research purposes.
Do not use it for unauthorized or malicious activity.

🔥 Vision
Static vulnerable applications are limited.
LLMForge enables dynamic, adaptive, AI-driven security training — built for the next generation of cybersecurity challenges.


**Quick Start (Docker-first - recommended)**

- **docker compose (recommended for development)**

```bash
docker compose up --build -d
```

Notes:
- The LLM runtime (`ollama`) and the `llmforge` gateway run in separate containers. Running the app image alone is not supported unless you provide a compatible `ollama` CLI and runtime accessible to the container.
- Use `docker compose` (above) to start both services together.


**Health check**

```bash
curl http://localhost:8000/health
```

**Generate example**

```bash
curl -X POST http://localhost:8000/generate \
	-H "Content-Type: application/json" \
	-d '{"prompt":"Say hello"}'
```

Notes:
- The gateway currently forwards prompts to the `ollama` CLI via subprocess. The recommended way to run both the runtime and gateway together is via `docker compose` so the CLI/runtime are available.
- `OLLAMA_MODEL` controls which pulled model the gateway will target.
- `OLLAMA_EMBED_MODEL` controls which embedding model is pulled for vector search. The default is `nomic-embed-text`.

**Choose model runtime**

Set `MODEL_PROFILE` before startup. `ollama-init` will wait for a healthy Ollama, pull that model, and `llmforge` starts only after init completes.

PowerShell:

```bash
$env:MODEL_PROFILE="llama3.1:8b"
docker compose up --build
```

Bash:

```bash
export MODEL_PROFILE=mistral:7b-instruct-q4_0
docker compose up --build

```

If `MODEL_PROFILE` is not set, default is `phi3:mini`.

**Simple vector DB setup**

The app now ships with:

- Ollama running in Docker
- automatic model pull for both generation and embeddings
- a local FAISS index persisted under `data/`
- minimal APIs for indexing and semantic search

Defaults:

- `OLLAMA_MODEL=phi3:mini`
- `OLLAMA_EMBED_MODEL=nomic-embed-text`

PowerShell:

```bash
$env:MODEL_PROFILE="llama3.1:8b"
$env:OLLAMA_EMBED_MODEL="nomic-embed-text"
docker compose up --build
```

Index documents:

```bash
curl -X POST http://localhost:8000/api/v1/vector/documents \
	-H "Content-Type: application/json" \
	-d '{"documents":[{"id":"doc-1","text":"FAISS is a vector index library."},{"id":"doc-2","text":"Ollama can generate embeddings with nomic-embed-text."}]}'
```

Search documents:

```bash
curl -X POST http://localhost:8000/api/v1/vector/search \
	-H "Content-Type: application/json" \
	-d '{"query":"Which model creates embeddings?","top_k":2}'
```

Inspect index status:

```bash
curl http://localhost:8000/api/v1/vector/status
```
