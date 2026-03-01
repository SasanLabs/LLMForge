# SQL Injection Hints

- Try injecting a tautology like `OR 1=1` in the `clause` parameter.
- URL-encode spaces and special characters. Example: `%20` for space, `%3D` for `=`.
- If `--` or `;` are blocked, use simple logical expressions.
