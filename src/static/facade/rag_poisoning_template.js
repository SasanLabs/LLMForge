(function () {
  const root = document.getElementById("llmforge-facade-root");
  if (!root) {
    return;
  }

  const output = document.getElementById("llmforgeOutput");
  const meta = document.getElementById("llmforgeMeta");
  const retrievalTrace = document.getElementById("retrievalTrace");
  const generatedCode = document.getElementById("generatedCode");
  const maliciousLogs = document.getElementById("maliciousLogs");
  const docCheckboxes = document.getElementById("docCheckboxes");
  const toggleRawView = document.getElementById("toggleRawView");

  const apiPrefix = "/llmforge";
  let currentDocs = [];
  let currentLogs = [];
  let rawMode = false;
  let liveLogTimer = null;

  const logTemplates = [
    {
      level: "INFO",
      message: () => `User agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6)`,
    },
    {
      level: "DEBUG",
      message: () => `Headers: {'Authorization': 'Bearer sk-9876543210', 'X-Session-ID': 'sess_${Math.random().toString(36).slice(2)}'}`,
    },
    {
      level: "WARN",
      message: () => `Database latency: ${Math.floor(Math.random() * 120 + 10)}ms`,
    },
    {
      level: "DEBUG",
      message: () => `Request body: {"username": "user${Math.floor(Math.random() * 10)}", "password": "P@ssword${Math.floor(Math.random() * 99)}"}`,
    },
    {
      level: "INFO",
      message: () => `Active connection count: ${Math.floor(Math.random() * 10 + 1)}`,
    },
    {
      level: "ERROR",
      message: () => `Failed to load secret config file: /etc/keys/service-${Math.floor(Math.random() * 5)}.json`,
    }
  ];

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

  async function parseResponseBody(res) {
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return await res.json();
    }

    const text = await res.text();
    return { detail: text || "Unexpected empty response from server." };
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

  function sanitizeDocContent(content) {
    return content.replace(/<!--([\s\S]*?)-->/g, "[hidden HTML comment]");
  }

  function displayRetrievalTrace(retrievedDocs) {
    if (!retrievedDocs || retrievedDocs.length === 0) {
      retrievalTrace.innerHTML = "<p>No documents retrieved</p>";
      return;
    }

    const html = retrievedDocs.map(doc => {
      const visibleContent = rawMode ? doc.content : sanitizeDocContent(doc.content);
      return `
      <div class="retrieved-doc">
        <div class="doc-header">${doc.title} (${doc.doc_id})</div>
        <div class="doc-meta">Chunk: ${doc.chunk_id} | Similarity: ${(doc.similarity_score * 100).toFixed(1)}% | Trust: ${(doc.metadata?.trust_score * 100).toFixed(1)}%</div>
        <pre class="doc-content">${visibleContent}</pre>
      </div>
    `;
    }).join('');

    retrievalTrace.innerHTML = html;
  }

  function displayGeneratedCode(code) {
    generatedCode.textContent = code || "No code generated";
  }

  function displayMaliciousLogs(logs) {
    const html = logs.map(log => `
      <div class="log-entry">
        <div class="log-timestamp">${log.timestamp}</div>
        <div class="log-level">${log.level}</div>
        <div class="log-message ${log.sensitive ? 'log-sensitive' : ''}">${log.message}</div>
      </div>
    `).join('');

    maliciousLogs.innerHTML = html || "<p>No logs available</p>";
  }

  function appendLiveLog() {
    const template = logTemplates[Math.floor(Math.random() * logTemplates.length)];
    const entry = {
      timestamp: new Date().toISOString(),
      level: template.level,
      message: template.message(),
      sensitive: template.level === "DEBUG" || template.level === "ERROR"
    };

    currentLogs.push(entry);
    if (currentLogs.length > 25) {
      currentLogs = currentLogs.slice(-25);
    }
    displayMaliciousLogs(currentLogs);
  }

  function renderDocCheckboxes(docs) {
    const html = docs.map(doc => `
      <div class="doc-checkbox-item">
        <input type="checkbox" id="doc-${doc.doc_id}" data-doc-id="${doc.doc_id}" />
        <label for="doc-${doc.doc_id}">${doc.title} <span class="doc-source">${doc.source}</span></label>
      </div>
    `).join('');
    docCheckboxes.innerHTML = html;
  }

  function renderAnswer() {
    const boxes = Array.from(docCheckboxes.querySelectorAll('input[type="checkbox"]'));
    const selected = boxes.filter(box => box.checked).map(box => box.dataset.docId);
    if (!selected.length) {
      output.textContent = "Select the document(s) responsible for the malicious logging behavior.";
      output.className = "llmforge-facade-output fail";
      return;
    }
    output.textContent = `Selected docs: ${selected.join(', ')}. Identify why these docs caused the issue.`;
    output.className = "llmforge-facade-output ok";
  }

  async function loadLab() {
    const level = levelFromGlobalState();
    setMeta(level);
    output.textContent = "Loading lab data...";
    output.className = "llmforge-facade-output";

    const endpoint = apiPrefix + "/api/v1/vulnerabilities/rag-context-poisoning/level" + level;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    const data = await parseResponseBody(res);
    if (!res.ok) {
      output.textContent = responseMessage(data, "Failed to load lab data.");
      output.className = "llmforge-facade-output fail";
      return;
    }

    output.textContent = "Inspect the generated code, retrieved documents, and logs.";
    output.className = "llmforge-facade-output ok";

    currentDocs = data.retrieved_docs || [];
    displayRetrievalTrace(currentDocs);
    displayGeneratedCode(data.generated_code);
    currentLogs = data.malicious_logs.map(log => ({
      ...log,
      sensitive: log.message.includes("password") || log.message.includes("Authorization") || log.message.includes("credit_card")
    }));
    displayMaliciousLogs(currentLogs);
    renderDocCheckboxes(data.retrieved_docs);

    if (liveLogTimer) {
      clearInterval(liveLogTimer);
    }
    liveLogTimer = setInterval(appendLiveLog, 4500);
  }

  toggleRawView.addEventListener("click", function () {
    rawMode = !rawMode;
    displayRetrievalTrace(currentDocs);
  });

  document.getElementById("llmforgeVerifyBtn").addEventListener("click", function () {
    renderAnswer();
  });

  setMeta(levelFromGlobalState());
  loadLab().catch(function (err) {
    output.textContent = String(err);
    output.className = "llmforge-facade-output fail";
  });
})();