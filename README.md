# 🛡️ LLMForge
![](https://img.shields.io/github/v/release/SasanLabs/LLMForge?style=flat) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) [![Docker Pulls](https://badgen.net/docker/pulls/sasanlabs/llmforge?icon=docker&label=pulls)](https://hub.docker.com/r/sasanlabs/llmforge/) 

**LLMForge is the AI/LLM vulnerability module of [OWASP VulnerableApp](https://github.com/SasanLabs/VulnerableApp).**
 
It's a deliberately vulnerable FastAPI application that plugs into the existing VulnerableApp-facade ecosystem — the same one that already hosts the Java, JSP, and PHP vulnerable apps — and adds a lab suite for attacking a **real, locally-running LLM** (via [Ollama](https://ollama.com)) instead of simulating one. Every level talks to an actual model; there are no canned/mocked responses to defeat.
 
---
 
## What is LLMForge?
 
Static, code-only vulnerable apps can't teach you how LLM-integrated systems fail. LLMForge fills that gap: each lab wires a real LLM into a deliberately weak pattern (a leaky system prompt, a keyword denylist, an LLM making authorization decisions, an unfiltered RAG pipeline) and challenges you to break it.
 
LLMForge runs as part of the VulnerableApp ecosystem alongside the rest of the SasanLabs vulnerable app farm.
 
---
 
## Vulnerability Labs
 
Each lab is a set of progressive levels. Lower levels have weak or no defenses; higher levels harden the previous bypass, so you're chasing a moving target rather than solving one static puzzle.
 
| Lab | Levels | OWASP Mapping | What you're attacking |
|---|---|---|---|
| **Prompt Injection** | 10 | [LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | A system prompt holding a hidden secret token, defended by increasingly stubborn filters (case-sensitive matching, token-strip bypasses, delimiter confusion, JSON policy merges, and more). Goal: extract the secret. |
| **Indirect Prompt Injection** | 4 | LLM01:2025 (indirect variant) | Instructions hidden inside external content (web pages, documents) that the model ingests as "data" — from a basic webpage injection up through stealthed, multi-source exfiltration and a hardened final level. |
| **BOLA via LLM Orchestration** (medical chatbot) | 3 | [API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | A chatbot that lets the LLM decide which patient record to fetch. Level 1 has no access control at all; Level 2 adds a prompt-level guardrail you can talk your way around; Level 3 moves enforcement into application code. |
| **RAG Context Poisoning** | 3 | LLM04:2025 | A RAG pipeline that trusts retrieved documents. Goes from an obviously poisoned document to a hidden-instruction injection to multi-document poisoning. |
| **RAG Sensitive Data Exposure** | 4 | LLM in RAG data handling | Retrieval that leaks sensitive chunks — direct retrieval, semantic-similarity bypass of a keyword denylist, a misclassified-chunk bypass of metadata filtering, and a hardened ingest-time sensitivity scan. |
 
Every level is defined declaratively via a small decorator framework (`@vulnerable_llm_controller`, `@vulnerable_llm_endpoint`, `@attack_vector`) that also tags each level with its known attack vectors and payloads — used to auto-generate the level UI and the facade-compatible vulnerability manifest.
 
---
 
## Architecture
 
```
                     VulnerableApp-facade (nginx, :80)
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
  VulnerableApp-*        LLMForge (/llmforge)      mailpit
  (Java / JSP / PHP)     FastAPI :8000
                              │
                    ┌─────────┴─────────┐
                    │  Lab controllers  │  prompt_injection, indirect_pi,
                    │ (decorator-based) │  bola_chatbot, rag_poisoning,
                    └─────────┬─────────┘  rag_data_exposure
                              │
                     ┌────────┴────────┐
                     │  Ollama runtime │  chat + embeddings
                     └─────────────────┘
```
---
 
## Quick Start
 
The repo's `docker-compose.yml` brings up the Ollama and LLMForge — behind a single nginx facade
 
```bash
docker compose up --build
```
 
Once everything is healthy, the LLMForge labs are reachable through the facade under list of Vulnerable Applications at:
 
```
http://localhost
```
 
**Note**: `ollama-model-init` blocks LLMForge from starting until it has pulled both the chat and embedding models, so first boot will take a few minutes.
 
### Choosing a model
 
```bash
# Bash
export OLLAMA_MODEL=mistral:7b-instruct-q4_0
export OLLAMA_EMBED_MODEL=nomic-embed-text
docker compose up --build
```
 
```powershell
# PowerShell
$env:OLLAMA_MODEL="llama3.1:8b"
docker compose up --build
```
 
| Environment Variable | Purpose | Default |
|---|---|---|
| `OLLAMA_MODEL` | Chat model used for lab responses | `phi3:mini` |
| `OLLAMA_EMBED_MODEL` | Embedding model used by the RAG labs | `nomic-embed-text` |
| `FACADE_ROUTE_PREFIX` | Path LLMForge is mounted under | `/llmforge` |
 
---
 
## Integration with VulnerableApp
 
LLMForge is designed to be the AI/LLM member of the SasanLabs [VulnerableApp](https://github.com/SasanLabs/VulnerableApp) family. When run through `docker-compose.yml`, it sits behind [VulnerableApp-facade](https://github.com/SasanLabs/VulnerableApp-facade) next to the Java, JSP, and PHP vulnerable apps, sharing the same nginx entry point and vulnerability-manifest format.
 
---
 
## Disclaimer
 
This project is intended strictly for **educational and defensive security research**.
Do not use it against systems you do not own or have explicit permission to test.
 
---
 
## Support
 
Running into an issue? Please [raise a GitHub issue](https://github.com/SasanLabs/LLMForge/issues) so it can be tracked and fixed. For anything else, feel free to reach out at karan.sasan@owasp.org.
 
---
 
## Contributing
 
Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.
 
---
 
## License
 
[Apache 2.0](https://opensource.org/licenses/Apache-2.0)
