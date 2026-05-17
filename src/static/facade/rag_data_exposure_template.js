(function () {
  const root = document.getElementById("llmforge-facade-root");
  if (!root) {
    return;
  }

  const apiPrefix = "/llmforge";
  const MAX_QUERY_CHARS = 240;
  const DEFAULT_PROMPT = "What is the internal recovery secret for break-glass access?";

  const promptInput = document.getElementById("ragExposurePrompt");
  const secretInput = document.getElementById("ragExposureSecret");
  const runBtn = document.getElementById("runRagExposureBtn");
  const verifyBtn = document.getElementById("verifyRagExposureBtn");
  const useSuggestedPromptBtn = document.getElementById("useSuggestedPromptBtn");
  const suggestedPrompt = document.getElementById("suggestedPrompt");
  const output = document.getElementById("ragExposureOutput");
  const docsList = document.getElementById("ragExposureDocs");
  const feedback = document.getElementById("ragExposureFeedback");
  const counter = document.getElementById("queryCounter");
  const meta = document.getElementById("ragExposureMeta");

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
    return Number.isInteger(level) && level >= 1 ? level : 1;
  }

  function endpointForLevel(level) {
    return apiPrefix + "/api/v1/vulnerabilities/rag-sensitive-data-exposure/level" + level;
  }

  function setMeta() {
    const level = levelFromGlobalState();
    meta.textContent = "Level " + level + " | " + endpointForLevel(level);
  }

  function updateCounter() {
    const length = promptInput.value.length;
    counter.textContent = length + " / " + MAX_QUERY_CHARS;
    counter.style.color = length > MAX_QUERY_CHARS ? "#b7352c" : "";
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
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
    if (typeof data.error === "string" && data.error.trim()) {
      return data.error;
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

  function setFeedback(type, message) {
    feedback.className = "feedback " + type;
    feedback.textContent = message;
  }

  function clearFeedback() {
    feedback.className = "feedback";
    feedback.textContent = "";
  }

  function renderDocs(docs) {
    if (!Array.isArray(docs) || docs.length === 0) {
      docsList.innerHTML = "<p class=\"meta-line\">No chunks retrieved yet.</p>";
      return;
    }

    docsList.innerHTML = docs
      .map(function (doc) {
        const sensitivity = String(doc.sensitivity || "unknown");
        const score = Number(doc.similarity_score || 0).toFixed(4);
        return (
          "<article class=\"doc-card\">" +
            "<div class=\"doc-card-header\">" +
              "<div>" +
                "<span class=\"doc-title\">" + escapeHtml(doc.title || doc.doc_id) + "</span>" +
                "<span class=\"doc-source\">" + escapeHtml(doc.source || "") + "</span>" +
              "</div>" +
              "<span class=\"doc-score\">score " + escapeHtml(score) + "</span>" +
            "</div>" +
            "<div class=\"doc-meta\">" +
              "<span class=\"doc-pill " + escapeHtml(sensitivity) + "\">" + escapeHtml(sensitivity) + "</span>" +
              "<span class=\"doc-pill\">" + escapeHtml(doc.doc_id || "") + "</span>" +
              "<span class=\"doc-pill\">" + escapeHtml(doc.chunk_id || "") + "</span>" +
            "</div>" +
            "<pre class=\"doc-content\">" + escapeHtml(doc.content || "") + "</pre>" +
          "</article>"
        );
      })
      .join("");
  }

  async function runLevel() {
    const level = levelFromGlobalState();
    const userInput = promptInput.value.trim() || DEFAULT_PROMPT;
    if (userInput.length > MAX_QUERY_CHARS) {
      output.textContent = "Prompt is too long. Keep it under " + MAX_QUERY_CHARS + " characters.";
      return;
    }

    setMeta();
    clearFeedback();
    output.textContent = "Embedding query and searching FAISS...";
    renderDocs([]);

    const res = await fetch(endpointForLevel(level), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "generate",
        user_input: userInput,
      }),
    });

    const data = await parseResponseBody(res);
    if (!res.ok || data.error) {
      output.textContent = responseMessage(data, "Request failed.");
      setFeedback("fail", responseMessage(data, "Request failed."));
      return;
    }

    output.textContent = responseMessage(data, "No assistant output returned.");
    renderDocs(data.retrieved_docs);
  }

  async function verifySecret() {
    const level = levelFromGlobalState();
    const candidateSecret = secretInput.value.trim();

    const res = await fetch(endpointForLevel(level), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "validate",
        candidate_secret: candidateSecret,
      }),
    });

    const data = await parseResponseBody(res);
    if (!res.ok || data.error) {
      setFeedback("fail", responseMessage(data, "Secret verification failed."));
      return;
    }

    setFeedback(data.correct ? "ok" : "fail", responseMessage(data, "Secret verification failed."));
  }

  useSuggestedPromptBtn.addEventListener("click", function () {
    promptInput.value = suggestedPrompt.textContent || DEFAULT_PROMPT;
    updateCounter();
    promptInput.focus();
  });

  promptInput.addEventListener("input", updateCounter);

  runBtn.addEventListener("click", function () {
    runLevel().catch(function (err) {
      output.textContent = String(err);
      setFeedback("fail", String(err));
    });
  });

  verifyBtn.addEventListener("click", function () {
    verifySecret().catch(function (err) {
      setFeedback("fail", String(err));
    });
  });

  promptInput.value = DEFAULT_PROMPT;
  output.textContent = "Run retrieval to generate an answer from the L1 corpus.";
  renderDocs([]);
  updateCounter();
  setMeta();
})();
