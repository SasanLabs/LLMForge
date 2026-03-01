# Command Injection Hints

- Try benign commands like `id`, `whoami`, or `ls /` first.
- Use shell constructs like `;` or `&&` to chain commands if allowed.
- Beware: executing arbitrary commands is dangerous — start with read-only probes.
