# 🛡️ LLMForge
![](https://img.shields.io/github/v/release/SasanLabs/LLMForge?style=flat) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) [![Docker Pulls](https://badgen.net/docker/pulls/sasanlabs/llmforge?icon=docker&label=pulls)](https://hub.docker.com/r/sasanlabs/llmforge/) 


**AI Security Gateway for Dynamic Vulnerability Labs**

LLMForge is a security-first LLM control plane that powers AI-driven vulnerability simulations. It serves as the AI execution layer for [SasanLabs](https://github.com/SasanLabs) and integrates directly with the [VulnerableApp](https://github.com/SasanLabs/VulnerableApp) ecosystem, enabling dynamic exploit labs driven by language models.

---

## What is LLMForge?

Static vulnerable applications can only go so far. LLMForge introduces a new class of security training — labs that are dynamic, adaptive, and AI-native.

It acts as a policy enforcement layer, session controller, challenge engine, and logging gateway. **The model is not trusted. The gateway controls behavior.**

LLMForge enables two distinct security training modes:

### LLM as Target

Simulate real-world AI vulnerabilities against a live language model:

- Prompt injection
- System prompt extraction
- Data exfiltration
- Guardrail bypass
- Tool misuse

Structured for AI red-team experimentation and CTF-style challenge progression.

### LLM as Vulnerable System

Turn a language model into a misconfigured or flawed system:

- A vulnerable API endpoint
- A broken authentication service
- A misconfigured internal agent

Each session can generate unique exploit paths, enabling effectively infinite security training scenarios.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│                  LLMForge                   │
│                                             │
│  ┌─────────────┐     ┌─────────────────┐   │
│  │   Gateway   │────▶│  Challenge      │   │
│  │  (FastAPI)  │     │  Engine         │   │
│  └─────────────┘     └─────────────────┘   │
│         │                    │              │
│  ┌─────────────┐     ┌─────────────────┐   │
│  │  Session &  │     │  Logging &      │   │
│  │  Memory     │     │  Evaluation     │   │
│  └─────────────┘     └─────────────────┘   │
└──────────────────────┬──────────────────────┘
					   │
			  ┌────────▼────────┐
			  │     Ollama /    │
			  │  OpenAI-compat  │
			  └─────────────────┘
```

LLMForge is model-agnostic and supports:

- **Local models** via Ollama or compatible runtimes
- **OpenAI-compatible APIs**
- **Cloud-based LLM providers**

Model backends can be swapped without changing any lab logic.

---

## Quick Start

Docker Compose is the recommended way to run LLMForge. It starts both the `llmforge` gateway and the `ollama` runtime together.

```bash
docker compose up --build -d
```

> Running the app image alone is not supported unless you provide a compatible Ollama runtime accessible to the container.

**Verify the gateway is running:**

```bash
curl http://localhost:8000/health
```

**Send a prompt:**

```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Say hello"}'
```

---

## Choosing a Model

Set `MODEL_PROFILE` before startup. The `ollama-init` service waits for a healthy Ollama instance, pulls the specified model, and `llmforge` starts only after init completes.

**Bash:**

```bash
export MODEL_PROFILE=mistral:7b-instruct-q4_0
docker compose up --build
```

**PowerShell:**

```powershell
$env:MODEL_PROFILE="llama3.1:8b"
docker compose up --build
```

If `MODEL_PROFILE` is not set, the default is `phi3:mini`.

| Environment Variable  | Purpose                                          | Default           |
|-----------------------|--------------------------------------------------|-------------------|
| `MODEL_PROFILE`       | LLM model pulled and used by the gateway         | `phi3:mini`       |
| `OLLAMA_MODEL`        | Model name forwarded on inference requests       | `phi3:mini`       |
| `OLLAMA_EMBED_MODEL`  | Embedding model used for vector search           | `nomic-embed-text`|

---

## Integration with VulnerableApp

LLMForge integrates with the existing [VulnerableApp](https://github.com/SasanLabs/VulnerableApp) architecture and is designed to become the AI security backbone of the ecosystem. Labs defined in VulnerableApp can delegate AI execution, session control, and evaluation entirely to LLMForge.

---

## Disclaimer

This project is intended strictly for **educational and defensive security research**.
Do not use it against systems you do not own or have explicit permission to test.

---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.


---

## License

[Apache 2.0](https://opensource.org/licenses/Apache-2.0)
