(function () {
  const root = document.getElementById("llmforge-facade-root");
  if (!root) {
    return;
  }

  const payloadInput = document.getElementById("llmforgePayload");
  const runBtn = document.getElementById("llmforgeRunBtn");
  const output = document.getElementById("llmforgeOutput");
  const meta = document.getElementById("llmforgeMeta");
  const retrievalTrace = document.getElementById("retrievalTrace");
  const generatedCode = document.getElementById("generatedCode");
  const telemetrySink = document.getElementById("telemetrySink");

  const apiPrefix = "/llmforge";

  // Mock telemetry data storage
  let telemetryData = [];

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

  function responseMessage(data, fallback) {
    if (!data) {
      return fallback;
    }
    if (typeof data.assistant_output === "string" && data.assistant_output.trim()) {
      return data.assistant_output;
    }
    if (typeof data.message === "string" && data.message.trim()) {
      return data.message;
    }
    if (typeof data.detail === "string" && data.detail.trim()) {
      return data.detail;
    }
    return fallback;
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

  function displayRetrievalTrace(retrievedDocs) {
    if (!retrievedDocs || retrievedDocs.length === 0) {
      retrievalTrace.innerHTML = "<p>No documents retrieved</p>";
      return;
    }

    const html = retrievedDocs.map(doc => `
      <div class="retrieved-doc">
        <div class="doc-header">${doc.doc_id} (Chunk: ${doc.chunk_id})</div>
        <div class="doc-score">Similarity: ${(doc.similarity_score * 100).toFixed(1)}% | Trust: ${(doc.metadata?.trust_score * 100).toFixed(1)}%</div>
        <pre>${doc.content.substring(0, 200)}${doc.content.length > 200 ? '...' : ''}</pre>
      </div>
    `).join('');

    retrievalTrace.innerHTML = html;
  }

  function displayGeneratedCode(code) {
    generatedCode.textContent = code || "No code generated";
  }

  function addTelemetryEntry(data) {
    telemetryData.push({
      timestamp: new Date().toISOString(),
      data: data
    });

    // Keep only last 10 entries
    if (telemetryData.length > 10) {
      telemetryData = telemetryData.slice(-10);
    }

    updateTelemetryDisplay();
  }

  function updateTelemetryDisplay() {
    const html = telemetryData.map(entry => `
      <div class="telemetry-entry">
        <strong>${entry.timestamp}</strong>
        <pre>${JSON.stringify(entry.data, null, 2)}</pre>
      </div>
    `).join('');

    telemetrySink.innerHTML = html || "<p>No telemetry received</p>";
  }

  // Mock telemetry endpoint
  function setupMockTelemetryEndpoint() {
    // In a real implementation, this would be a separate server
    // For demo purposes, we'll simulate telemetry calls
    window.mockTelemetrySend = function(data) {
      addTelemetryEntry(data);
    };
  }

  async function runPayload() {
    const level = levelFromGlobalState();
    setMeta(level);
    output.textContent = "Generating code...";

    const endpoint =
      apiPrefix +
      "/api/v1/vulnerabilities/rag-context-poisoning/level" +
      level;

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_input: payloadInput.value || "Write a simple HTTP handler function" }),
    });

    const data = await parseResponseBody(res);
    if (!res.ok) {
      output.textContent = responseMessage(data, "Request failed.");
      output.className = "llmforge-facade-output fail";
      return;
    }

    output.textContent = "Code generated successfully.";
    output.className = "llmforge-facade-output ok";

    // Display retrieved documents
    displayRetrievalTrace(data.retrieved_docs);

    // Display generated code
    displayGeneratedCode(data.generated_code);

    // Check for telemetry calls in generated code (simple detection)
    if (data.generated_code && data.generated_code.includes('telemetry.send')) {
      // Simulate telemetry being sent
      setTimeout(() => {
        addTelemetryEntry({
          event: "debug_payload",
          level: level,
          source: "generated_code"
        });
      }, 1000);
    }
  }

  runBtn.addEventListener("click", function () {
    runPayload().catch(function (err) {
      output.textContent = String(err);
      output.className = "llmforge-facade-output fail";
    });
  });

  // Initialize
  setMeta(levelFromGlobalState());
  setupMockTelemetryEndpoint();
  updateTelemetryDisplay();
})();