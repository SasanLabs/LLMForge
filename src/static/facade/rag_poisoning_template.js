(function () {
  const root = document.getElementById("llmforge-facade-root");
  if (!root) {
    return;
  }

  const DEFAULT_PROMPT = "generate an httpclient with great observability and org standards";
  const apiPrefix = "/llmforge";

  const output = document.getElementById("llmforgeOutput");
  const meta = document.getElementById("llmforgeMeta");
  const retrievalTrace = document.getElementById("retrievalTrace");
  const generatedCode = document.getElementById("generatedCode");
  const maliciousLogs = document.getElementById("maliciousLogs");
  const generationPrompt = document.getElementById("generationPrompt");
  const generateCodeBtn = document.getElementById("generateCodeBtn");
  const clearLogsBtn = document.getElementById("clearLogsBtn");
  const toggleRawView = document.getElementById("toggleRawView");
  const docsViewHint = document.getElementById("docsViewHint");

  let rawMode = false;
  let currentDocs = [];
  let currentLogs = [];
  let logSessionId = null;
  let logCursor = 0;
  let pollTimer = null;

  function levelFromGlobalState() {
    const levelId =
      window.globalUtilityState &&
      window.globalUtilityState.activeVulnerabilityLevelIdentifier
        ? String(window.globalUtilityState.activeVulnerabilityLevelIdentifier)
        : "LEVEL_1";

    const match = /^LEVEL_(\d+)$/i.exec(levelId);
    if (!match) {
      return 1;
    }

    const level = Number(match[1]);
    if (!Number.isInteger(level) || level < 1 || level > 3) {
      return 1;
    }
    return level;
  }

  function setMeta(level) {
    meta.textContent =
      "Level " +
      level +
      " | " +
      apiPrefix +
      "/api/v1/vulnerabilities/rag-context-poisoning/level" +
      level;
  }

  async function parseResponseBody(res) {
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return await res.json();
    }

    const text = await res.text();
    return { detail: text || "Unexpected empty response from server." };
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function markdownToSafeHtml(markdownText) {
    const comments = [];
    let text = String(markdownText || "").replace(/<!--[\s\S]*?-->/g, function (match) {
      const token = "__HTML_COMMENT_" + comments.length + "__";
      comments.push(match);
      return token;
    });

    text = text.replace(/```([\s\S]*?)```/g, function (_, code) {
      return "\n<pre><code>" + escapeHtml(code.trim()) + "</code></pre>\n";
    });

    const lines = text.split("\n");
    let html = "";
    let inList = false;

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const heading = /^(#{1,4})\s+(.*)$/.exec(line);
      const listItem = /^\s*-\s+(.*)$/.exec(line);

      if (heading) {
        if (inList) {
          html += "</ul>";
          inList = false;
        }
        const level = Math.min(4, heading[1].length + 2);
        html += "<h" + level + ">" + heading[2] + "</h" + level + ">";
        continue;
      }

      if (listItem) {
        if (!inList) {
          html += "<ul>";
          inList = true;
        }
        html += "<li>" + listItem[1] + "</li>";
        continue;
      }

      if (inList) {
        html += "</ul>";
        inList = false;
      }

      if (line.trim() === "") {
        html += "<br>";
      } else {
        html += "<p>" + line + "</p>";
      }
    }

    if (inList) {
      html += "</ul>";
    }

    html = html.replace(/__HTML_COMMENT_(\d+)__/g, function (_, idx) {
      return comments[Number(idx)] || "";
    });

    return html;
  }

  function displayRetrievalTrace(retrievedDocs) {
    if (!retrievedDocs || retrievedDocs.length === 0) {
      retrievalTrace.innerHTML = "<p>No documents retrieved yet.</p>";
      return;
    }

    const html = retrievedDocs
      .map(function (doc) {
        const content = String(doc.content || "");
        const rendered = rawMode
          ? "<pre class=\"doc-content\">" + escapeHtml(content) + "</pre>"
          : "<div class=\"doc-html\">" + markdownToSafeHtml(content) + "</div>";

        return (
          "<div class=\"retrieved-doc\">" +
          "<div class=\"doc-header\">" + escapeHtml(doc.title) + " (" + escapeHtml(doc.doc_id) + ")</div>" +
          "<div class=\"doc-meta\">Chunk: " + escapeHtml(doc.chunk_id) +
          " | Similarity: " + (Number(doc.similarity_score || 0) * 100).toFixed(1) + "%" +
          " | Trust: " + (Number(doc.trust_score || 0) * 100).toFixed(1) + "%" +
          " | Poisoned: " + String(Boolean(doc.is_poisoned)) +
          "</div>" +
          rendered +
          "</div>"
        );
      })
      .join("");

    retrievalTrace.innerHTML = html;
    docsViewHint.textContent = rawMode
      ? "Raw view enabled. Level 2 reveals hidden comment text (log for debugging)."
      : "HTML view (default). Toggle raw to inspect hidden comments.";
  }

  function displayGeneratedCode(code) {
    generatedCode.textContent = code || "No code generated yet.";
  }

  function displayMaliciousLogs(logs) {
    const html = (logs || [])
      .map(function (log) {
        const msg = String(log.message || "");
        const sensitive = /(password|authorization|api_key|credit_card|token)/i.test(msg);
        return (
          "<div class=\"log-entry\">" +
          "<div class=\"log-timestamp\">" + escapeHtml(log.timestamp || "") + "</div>" +
          "<div class=\"log-level\">" + escapeHtml(log.level || "INFO") + "</div>" +
          "<div class=\"log-message " + (sensitive ? "log-sensitive" : "") + "\">" + escapeHtml(msg) + "</div>" +
          "</div>"
        );
      })
      .join("");

    maliciousLogs.innerHTML = html || "<p>No logs available.</p>";
    maliciousLogs.scrollTop = maliciousLogs.scrollHeight;
  }

  function stopPollingLogs() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  async function pollLogsOnce(level) {
    if (!logSessionId) {
      return;
    }

    const endpoint = apiPrefix + "/api/v1/vulnerabilities/rag-context-poisoning/level" + level;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "poll_logs",
        log_session_id: logSessionId,
        cursor: logCursor,
        batch_size: 1,
      }),
    });

    const data = await parseResponseBody(res);
    if (!res.ok || data.error) {
      stopPollingLogs();
      output.textContent = responseMessage(data, "Failed while polling logs.");
      output.className = "llmforge-facade-output fail";
      return;
    }

    const nextLogs = Array.isArray(data.logs) ? data.logs : [];
    if (nextLogs.length) {
      currentLogs = currentLogs.concat(nextLogs);
      displayMaliciousLogs(currentLogs);
    }

    logCursor = Number(data.cursor || logCursor);
    if (data.done) {
      stopPollingLogs();
    }
  }

  function startPollingLogs(level) {
    stopPollingLogs();
    pollTimer = setInterval(function () {
      pollLogsOnce(level).catch(function () {
        stopPollingLogs();
      });
    }, 1200);
  }

  async function generateLab() {
    const level = levelFromGlobalState();
    const endpoint = apiPrefix + "/api/v1/vulnerabilities/rag-context-poisoning/level" + level;

    setMeta(level);
    output.textContent = "Generating code with Ollama...";
    output.className = "llmforge-facade-output";
    displayGeneratedCode("");
    currentDocs = [];
    currentLogs = [];
    displayRetrievalTrace(currentDocs);
    displayMaliciousLogs(currentLogs);
    stopPollingLogs();

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "generate",
        user_input: generationPrompt.value || DEFAULT_PROMPT,
      }),
    });

    const data = await parseResponseBody(res);
    if (!res.ok || data.error) {
      output.textContent = responseMessage(data, "Failed to generate code.");
      output.className = "llmforge-facade-output fail";
      return;
    }

    currentDocs = Array.isArray(data.retrieved_docs) ? data.retrieved_docs : [];
    displayRetrievalTrace(currentDocs);
    displayGeneratedCode(data.generated_code);

    logSessionId = data.log_session_id || null;
    logCursor = 0;
    currentLogs = [];
    displayMaliciousLogs(currentLogs);

    if (logSessionId) {
      output.textContent = "Code generated. Streaming backend logs...";
      output.className = "llmforge-facade-output ok";
      await pollLogsOnce(level);
      startPollingLogs(level);
    } else {
      output.textContent = "Code generated, but no log session was returned.";
      output.className = "llmforge-facade-output fail";
    }
  }

  async function clearLogs() {
    const level = levelFromGlobalState();
    stopPollingLogs();
    currentLogs = [];
    displayMaliciousLogs(currentLogs);

    if (!logSessionId) {
      output.textContent = "Logs cleared.";
      output.className = "llmforge-facade-output ok";
      return;
    }

    const endpoint = apiPrefix + "/api/v1/vulnerabilities/rag-context-poisoning/level" + level;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "clear_logs",
        log_session_id: logSessionId,
      }),
    });

    const data = await parseResponseBody(res);
    if (!res.ok || data.error) {
      output.textContent = responseMessage(data, "Failed to clear backend logs.");
      output.className = "llmforge-facade-output fail";
      return;
    }

    logCursor = 0;
    output.textContent = "Logs cleared.";
    output.className = "llmforge-facade-output ok";
  }

  generateCodeBtn.addEventListener("click", function () {
    generateLab().catch(function (err) {
      output.textContent = String(err);
      output.className = "llmforge-facade-output fail";
    });
  });

  clearLogsBtn.addEventListener("click", function () {
    clearLogs().catch(function (err) {
      output.textContent = String(err);
      output.className = "llmforge-facade-output fail";
    });
  });

  toggleRawView.addEventListener("click", function () {
    rawMode = !rawMode;
    displayRetrievalTrace(currentDocs);
  });

  generationPrompt.value = DEFAULT_PROMPT;
  setMeta(levelFromGlobalState());
  output.textContent = "Click Generate Code to run retrieval + Ollama generation.";
})();
