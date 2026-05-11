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
  const toggleDocsPanel = document.getElementById("toggleDocsPanel");
  const toggleLogsPanel = document.getElementById("toggleLogsPanel");
  const docsPanel = root.querySelector(".retrieved-docs-panel");
  const logsPanel = root.querySelector(".malicious-logs-panel");
  const toggleRawView = document.getElementById("toggleRawView");
  const docsViewHint = document.getElementById("docsViewHint");
  const poisonedDocChallenge = document.getElementById("poisonedDocChallenge");
  const challengeDocList = document.getElementById("challengeDocList");
  const challengeFeedback = document.getElementById("challengeFeedback");
  const submitChallengeBtn = document.getElementById("submitChallengeBtn");
  const challengeDesc = root.querySelector(".challenge-desc");

  let rawMode = false;
  let currentDocs = [];
  let currentLogs = [];
  let currentLevel = 1;
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

  function setPanelCollapsed(panel, toggleBtn, collapsed) {
    if (!panel || !toggleBtn) {
      return;
    }
    panel.classList.toggle("is-collapsed", collapsed);
    toggleBtn.textContent = collapsed ? "Expand" : "Collapse";
    toggleBtn.setAttribute("aria-expanded", collapsed ? "false" : "true");
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

  function populateChallenge(retrievedDocs, level) {
    challengeFeedback.className = "challenge-feedback";
    challengeFeedback.textContent = "";
    const multipleChoice = level === 3;
    if (challengeDesc) {
      challengeDesc.textContent = multipleChoice
        ? "The generated code is unsafe because multiple retrieved documents combined into one bad behavior. Select all documents that contributed to the issue."
        : "The generated code logs sensitive headers and request bodies. Which retrieved document contained guidance that caused this bad behavior?";
    }

    const docOptions = retrievedDocs
      .map(function (doc) {
        return (
          "<label class=\"challenge-doc-option\">" +
          "<input type=\"" + (multipleChoice ? "checkbox" : "radio") + "\" name=\"poisoned_doc\" value=\"" + escapeHtml(doc.doc_id) + "\" />" +
          escapeHtml(doc.title) +
          "<span class=\"challenge-doc-source\">" + escapeHtml(doc.source || doc.doc_id) + "</span>" +
          "</label>"
        );
      })
      .join("");

    const noneOption = multipleChoice
      ? (
        "<label class=\"challenge-doc-option challenge-doc-option-none\">" +
        "<input type=\"checkbox\" name=\"poisoned_doc\" value=\"__none__\" />" +
        "None of the retrieved documents is poisoned" +
        "</label>"
      )
      : "";

    const html = docOptions + noneOption;

    challengeDocList.innerHTML = html;
    poisonedDocChallenge.style.display = "block";
  }

  function submitChallenge() {
    const selectedNodes = Array.from(challengeDocList.querySelectorAll("input[name='poisoned_doc']:checked"));
    if (selectedNodes.length === 0) {
      challengeFeedback.className = "challenge-feedback incorrect";
      challengeFeedback.textContent = "Please select a document first.";
      return;
    }

    const selectedDocIds = selectedNodes.map(function (node) { return node.value; });
    const poisonedDocs = currentDocs.filter(function (d) { return d.is_poisoned; });
    const poisonedDocIds = poisonedDocs.map(function (d) { return d.doc_id; });
    const noneSelected = selectedDocIds.includes("__none__");
    const realSelections = selectedDocIds.filter(function (id) { return id !== "__none__"; });

    const allPoisonedSelected = poisonedDocIds.every(function (id) { return realSelections.includes(id); });
    const noExtraSelections = realSelections.every(function (id) { return poisonedDocIds.includes(id); });

    let isCorrect = false;
    if (poisonedDocIds.length === 0) {
      isCorrect = noneSelected && realSelections.length === 0;
    } else {
      isCorrect = !noneSelected && allPoisonedSelected && noExtraSelections;
    }

    if (isCorrect) {
      const poisonedNames = poisonedDocs.map(function (d) { return d.title; }).join(", ");
      challengeFeedback.className = "challenge-feedback correct";
      challengeFeedback.textContent = poisonedDocIds.length === 0
        ? "\u2713 Correct! Nice catch. In this level, no single document is poisoned; the unsafe output comes from combining multiple seemingly normal sources."
        : "\u2713 Correct! \"" + poisonedNames + "\" contained hidden instructions to log the full request context " +
          "(headers and body). This caused the generated HTTP client to expose Authorization tokens, passwords, and other " +
          "sensitive data in application logs \u2014 a classic RAG context poisoning attack.";
    } else {
      const hint = currentLevel === 2 || currentLevel === 3
        ? "\u2717 Incorrect. Hint: switch to Raw View in the Retrieved Documents panel and look for hidden comments that appear as helpful developer tips."
        : "\u2717 Incorrect. Hint: check the document that pushes full request/response logging in the content.";
      challengeFeedback.className = "challenge-feedback incorrect";
      challengeFeedback.textContent = hint;
    }
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
          "<div class=\"doc-header\">" +
          "<span class=\"doc-title\">" + escapeHtml(doc.title) + "</span>" +
          "<span class=\"doc-id\">" + escapeHtml(doc.doc_id) + "</span>" +
          "</div>" +
          "<div class=\"doc-meta\">" +
          "<span class=\"doc-meta-pill\">Chunk: " + escapeHtml(doc.chunk_id) + "</span>" +
          "<span class=\"doc-meta-pill\">Similarity: " + (Number(doc.similarity_score || 0) * 100).toFixed(1) + "%</span>" +
          "<span class=\"doc-meta-pill\">Trust: " + (Number(doc.trust_score || 0) * 100).toFixed(1) + "%</span>" +
          "<span class=\"doc-meta-pill " + (doc.is_poisoned ? "pill-danger" : "pill-safe") + "\">Poisoned: " + String(Boolean(doc.is_poisoned)) + "</span>" +
          "</div>" +
          "<div class=\"doc-body\">" + rendered + "</div>" +
          "</div>"
        );
      })
      .join("");

    retrievalTrace.innerHTML = html;
    docsViewHint.textContent = rawMode
      ? "Raw view enabled. Level 2 reveals hidden helper comments in the source text."
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
    currentLevel = level;
    const endpoint = apiPrefix + "/api/v1/vulnerabilities/rag-context-poisoning/level" + level;

    setMeta(level);
    output.textContent = "Generating code...";
    output.className = "llmforge-facade-output";
    displayGeneratedCode("");
    currentDocs = [];
    currentLogs = [];
    displayRetrievalTrace(currentDocs);
    displayMaliciousLogs(currentLogs);
    poisonedDocChallenge.style.display = "none";
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
    populateChallenge(currentDocs, level);

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

  submitChallengeBtn.addEventListener("click", submitChallenge);

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

  toggleDocsPanel.addEventListener("click", function () {
    const collapsed = !docsPanel.classList.contains("is-collapsed");
    setPanelCollapsed(docsPanel, toggleDocsPanel, collapsed);
  });

  toggleLogsPanel.addEventListener("click", function () {
    const collapsed = !logsPanel.classList.contains("is-collapsed");
    setPanelCollapsed(logsPanel, toggleLogsPanel, collapsed);
  });

  toggleRawView.addEventListener("click", function () {
    rawMode = !rawMode;
    displayRetrievalTrace(currentDocs);
  });

  generationPrompt.value = DEFAULT_PROMPT;
  setPanelCollapsed(docsPanel, toggleDocsPanel, true);
  setPanelCollapsed(logsPanel, toggleLogsPanel, true);
  setMeta(levelFromGlobalState());
  output.textContent = "Click Generate Code to run retrieval and see the generated HTTP client.";
})();
