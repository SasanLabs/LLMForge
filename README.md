🛡️ LLMForge

AI Security Gateway for Dynamic Vulnerability Labs
LLMForge is a security-first LLM control plane built to power AI-driven vulnerability simulations.
It serves as the AI execution layer for SasanLabs and integrates directly with the VulnerableApp ecosystem, enabling dynamic exploit labs driven by language models.

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
- Use `docker compose` (above) to start both services together. The compose file also contains profile-based helper services to pull models.


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
- `OLLAMA_MODEL` controls which pulled model the gateway will target. Use the compose profiles (below) to pull models into the `ollama` runtime.

**Docker Compose Profiles (select model sets)**

You can selectively pull models using Docker Compose profiles. Examples:

- Start the app + Ollama and pull `llama3`:

```bash
docker compose --profile llama up --build -d
```

- Start the app + Ollama and pull `mistral`:

```bash
docker compose --profile mistral up --build -d
```

Profiles create small helper services (`ollama-init-<name>`) that run `ollama pull` after the runtime starts, keeping the compose file clean and flexible.
