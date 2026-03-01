# XSS Hints

- Use a simple `<script>alert(1)</script>` payload to confirm execution.
- If injecting via curl, view the returned HTML and open in a browser to observe JS execution.
- Try HTML-encoded payloads if the app transforms characters.
