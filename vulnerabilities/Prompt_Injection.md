# Prompt Injection Vulnerability

## Overview

Prompt injection is a class of vulnerability where untrusted user input alters or overrides trusted instructions in an LLM-powered system.

In this lab, each level has:

- An internal system prompt containing a hidden secret
- A different defensive pattern
- A known weakness that allows bypass

## Why It Matters

If prompt injection is not handled correctly, attackers can:

- Exfiltrate hidden system instructions
- Leak secrets from model context
- Override policy and safety constraints
- Abuse tool or agent behavior

## Lab Model

The lab is intentionally vulnerable and uses a real LLM backend (Ollama) for each request. It demonstrates common anti-patterns used in LLM applications:

- Weak deny-lists
- Shallow application-side keyword filters that still miss attacker-controlled channels
- Improper normalization
- Context delimiter abuse
- Untrusted metadata merge
- Marker and signature confusion

## Levels and Bypass Themes

1. No guardrails
2. Case-sensitive filtering
3. Token strip bypass via obfuscation
4. Delimiter channel injection
5. JSON policy override merge
6. Approval marker confusion
7. Comment stripping mismatch
8. Signature prefix validation bug

## API Pattern

- `POST /api/v1/vulnerabilities/prompt-injection/level1`
- ...
- `POST /api/v1/vulnerabilities/prompt-injection/level8`

Request body:

```json
{
  "user_input": "your payload"
}
```

## Defensive Guidance (Production)

- Isolate instruction channels from user data
- Use strict schemas and trusted orchestration boundaries
- Avoid text-based allow/deny lists as a sole defense
- Apply output validation and policy checks server-side
- Treat any model-visible user text as untrusted input
