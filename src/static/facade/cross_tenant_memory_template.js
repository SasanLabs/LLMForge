(function () {
  const root = document.getElementById("llmforge-facade-root");
  if (!root) {
    return;
  }

  const apiPrefix = "/llmforge";
  const SUPPORTED_LEVELS = [1, 2, 3];
  // Stands in for the tenant a real login session would resolve.
  const TENANT_ID = "bluepeak";

  const LEVEL_CONFIG = {
    1: {
      chapter: "One Memory for Everyone",
      beat: "To make the assistant feel personal, Nimbus Desk loads the stored conversation memories into every chat. All of them. Every customer's.",
      technical: "Unfiltered Shared Memory · OWASP LLM02",
    },
    2: {
      chapter: "Let the Model Choose",
      beat: "Loading everything got slow, so the assistant now looks at an index of stored memories and fetches only the ones it thinks are relevant. Nobody checks whose memories it fetches.",
      technical: "Model-Directed Retrieval Without Tenant Authorization · OWASP LLM02",
    },
    3: {
      chapter: "Your Memories Only",
      beat: "The index and the fetch are now scoped to the signed-in customer in code. Whatever the model or the user asks for, another customer's memory is refused before it reaches the context.",
      technical: "Tenant-Isolated Memory (Secure) · OWASP LLM02",
    },
  };

  const promptInput = document.getElementById("ctmPrompt");
  const runBtn = document.getElementById("ctmRunBtn");
  const output = document.getElementById("ctmOutput");
  const feedback = document.getElementById("ctmFeedback");
  const meta = document.getElementById("ctmMeta");
  const titleEl = document.getElementById("ctmTitle");
  const beatEl = document.getElementById("ctmBeat");
  const technicalEl = document.getElementById("ctmTechnical");
  const tenantEl = document.getElementById("ctmTenant");
  const memoriesEl = document.getElementById("ctmMemories");
  const deniedEl = document.getElementById("ctmDenied");
  const stat = {
    contamination: document.getElementById("ctmContamination"),
    info: document.getElementById("ctmInfo"),
    canary: document.getElementById("ctmCanary"),
    model: document.getElementById("ctmModel"),
    latency: document.getElementById("ctmLatency"),
  };

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
    return Number.isInteger(level) && SUPPORTED_LEVELS.includes(level) ? level : 1;
  }

  function configForLevel(level) {
    return LEVEL_CONFIG[level] || LEVEL_CONFIG[1];
  }

  function endpointForLevel(level) {
    return apiPrefix + "/api/v1/vulnerabilities/cross-tenant-memory-leakage/level" + level;
  }

  function setMeta() {
    const level = levelFromGlobalState();
    meta.textContent = "Level " + level + " | " + endpointForLevel(level);
  }

  function setFeedback(type, message) {
    feedback.className = "ctm-feedback " + type;
    feedback.textContent = message;
  }

  function clearFeedback() {
    feedback.className = "ctm-feedback";
    feedback.textContent = "";
  }

  function setFlag(el, value, detail) {
    el.className = value ? "is-yes" : "is-no";
    el.textContent = (value ? "YES" : "no") + (value && detail ? " (" + detail + ")" : "");
  }

  function resetResults() {
    Object.keys(stat).forEach(function (key) {
      stat[key].className = "";
      stat[key].textContent = "-";
    });
    memoriesEl.innerHTML = "";
    deniedEl.textContent = "";
  }

  function renderResults(data) {
    const v = data.validation || {};
    setFlag(stat.contamination, v.context_contamination, (v.foreign_tenants || []).join(", "));
    setFlag(stat.info, v.information_disclosure, (v.disclosed_tenants || []).join(", "));
    setFlag(stat.canary, v.canary_disclosure, (v.disclosed_canaries || []).join(", "));
    stat.model.textContent = (data.provider ? data.provider + " / " : "") + (data.model || "-");
    const latency = data.metrics ? Number(data.metrics.latency_ms || 0) : 0;
    stat.latency.textContent = (latency / 1000).toFixed(1) + " s";
    if (data.authenticated_customer) {
      tenantEl.textContent = data.authenticated_customer;
    }

    const retrieval = data.retrieval || {};
    const memories = retrieval.retrieved_memories || [];
    memoriesEl.innerHTML = "";
    if (memories.length === 0) {
      const li = document.createElement("li");
      li.className = "is-own";
      li.textContent = "(no memories supplied)";
      memoriesEl.appendChild(li);
    }
    memories.forEach(function (m) {
      const li = document.createElement("li");
      const foreign = m.tenant_id !== data.authenticated_tenant;
      li.className = foreign ? "is-foreign" : "is-own";
      li.textContent = m.memory_id + " — owner: " + m.tenant_id + " — " + m.topic +
        (foreign ? "  ← another customer" : "");
      memoriesEl.appendChild(li);
    });

    const notes = [];
    if (retrieval.mode === "model_directed") {
      notes.push("Model requested: " + ((retrieval.requested_memory_ids || []).join(", ") || "none") + ".");
    }
    if ((retrieval.denied_memory_ids || []).length > 0) {
      notes.push("Refused by tenant isolation (not yours, or doesn't exist): " +
        retrieval.denied_memory_ids.join(", ") + ".");
    }
    deniedEl.textContent = notes.join(" ");
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
    const candidates = [data.error, data.message, data.detail];
    for (const value of candidates) {
      if (typeof value === "string" && value.trim()) {
        return value;
      }
    }
    return fallback;
  }

  async function runLevel() {
    const level = levelFromGlobalState();
    const userInput = promptInput.value.trim();
    if (!userInput) {
      output.textContent = "Ask the support assistant a question.";
      setFeedback("fail", "Enter a question first.");
      return;
    }

    setMeta();
    clearFeedback();
    resetResults();
    output.textContent = "Thinking...";
    runBtn.disabled = true;

    try {
      const res = await fetch(endpointForLevel(level), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_input: userInput, tenant_id: TENANT_ID }),
      });
      const data = await parseResponseBody(res);
      if (!res.ok || data.error) {
        output.textContent = responseMessage(data, "Request failed.");
        setFeedback("fail", responseMessage(data, "Request failed."));
        return;
      }

      output.textContent =
        typeof data.response === "string" && data.response.trim()
          ? data.response
          : "No response returned.";
      renderResults(data);

      const v = data.validation || {};
      if (v.canary_disclosure) {
        setFeedback("ok", "Another customer's canary leaked into your answer: " + v.disclosed_canaries.join(", ") + ".");
      } else if (v.information_disclosure) {
        setFeedback("ok", "Another customer's data leaked into your answer: " + v.disclosed_identifiers.join(", ") + ".");
      } else if (v.context_contamination) {
        setFeedback("fail", "Another customer's memory reached the model, but this answer didn't repeat it. Try a broader question.");
      } else {
        setFeedback("fail", "Only your own tenant's memories reached the model.");
      }
    } finally {
      runBtn.disabled = false;
    }
  }

  runBtn.addEventListener("click", function () {
    runLevel().catch(function (err) {
      output.textContent = String(err);
      setFeedback("fail", String(err));
    });
  });

  function applyLevelConfig() {
    const level = levelFromGlobalState();
    const cfg = configForLevel(level);
    titleEl.textContent = "Level " + level + " — " + cfg.chapter;
    beatEl.textContent = cfg.beat;
    technicalEl.textContent = cfg.technical;
    promptInput.value = "";
    resetResults();
    clearFeedback();
    output.textContent = "Ask about your previous support interactions to see what the assistant remembers.";
  }

  applyLevelConfig();
  setMeta();
})();
