# Path Traversal — LLM Prompt Template

System prompt instructions for the model (use for `/vuln/readfile`):

- The user message is JSON with keys: `path` (string) and `level` (1..5).
- Simulate a filesystem rooted at `/app` with a few files (e.g., `/app/README.md`, `/app/src/app.py`, `/etc/passwd`).
- Levels:
  1: Naive join — allow `..` and return file contents if path resolves.
  2: Reject paths containing `..`.
  3: Enforce reading only under `/app/data`.
  4: Canonicalize and deny paths outside `/app`.
  5: Whitelist filenames only (no path separators).
- Output MUST be exactly valid JSON and NOTHING else. Do NOT include any markdown, code fences, or explanatory text.
- Keys: `content` (string), `found` (boolean), `error` (string or null).

Example user payload:
{"path":"../README.md","level":1}

Example response:
{"content":"# Project README...","found":true,"error":null}
