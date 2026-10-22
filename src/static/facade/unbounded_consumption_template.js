(function () {
  const root = document.getElementById("llmforge-facade-root");
  if (!root) {
    return;
  }

  const apiPrefix = "/llmforge";
  const SUPPORTED_LEVELS = [1, 2, 3];

  const LEVEL_CONFIG = {
    1: {
      chapter: "Open Door",
      beat: "Acme shipped the summarizer as fast as it could. It accepts any amount of text and writes back as much as the model likes; the only rule is a sentence in the prompt.",
      technical: "No Limits on Input or Output · OWASP LLM10",
      inputCap: null,
      burst: false,
    },
    2: {
      chapter: "Half a Fence",
      beat: "After a customer pasted a novel into the box, Acme capped the input at a size that fits a real support ticket. Nobody thought about how much the service writes back.",
      technical: "Input Capped, Output Unbounded · OWASP LLM10",
      inputCap: 600,
      burst: false,
    },
    3: {
      chapter: "One at a Time Was Never the Rule",
      beat: "Acme capped the input and the output on every single request. Each one now behaves exactly like a real three-sentence summary should — Acme never asked how many of them could run at once.",
      technical: "Input and Output Capped, No Concurrency Control · OWASP LLM10",
      inputCap: 600,
      burst: true,
    },
  };

  const promptInput = document.getElementById("ucPrompt");
  const runBtn = document.getElementById("ucRunBtn");
  const output = document.getElementById("ucOutput");
  const feedback = document.getElementById("ucFeedback");
  const counter = document.getElementById("ucCounter");
  const meta = document.getElementById("ucMeta");
  const titleEl = document.getElementById("ucTitle");
  const beatEl = document.getElementById("ucBeat");
  const technicalEl = document.getElementById("ucTechnical");
  const meterFill = document.getElementById("ucMeterFill");
  const concurrentRow = document.getElementById("ucConcurrentRow");
  const concurrentCell = document.getElementById("ucConcurrent");
  const burstPanel = document.getElementById("ucBurstPanel");
  const burstCountInput = document.getElementById("ucBurstCount");
  const burstBtn = document.getElementById("ucBurstBtn");
  const burstSummary = document.getElementById("ucBurstSummary");
  const burstResults = document.getElementById("ucBurstResults");
  const stat = {
    billed: document.getElementById("ucBilled"),
    budget: document.getElementById("ucBudget"),
    promptTokens: document.getElementById("ucPromptTokens"),
    outputTokens: document.getElementById("ucOutputTokens"),
    duration: document.getElementById("ucDuration"),
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
    return apiPrefix + "/api/v1/vulnerabilities/unbounded-consumption/level" + level;
  }

  function setMeta() {
    const level = levelFromGlobalState();
    meta.textContent = "Level " + level + " | " + endpointForLevel(level);
  }

  function updateCounter() {
    const cap = configForLevel(levelFromGlobalState()).inputCap;
    const length = promptInput.value.length;
    counter.textContent = cap ? length + " / " + cap + " characters" : length + " characters";
    counter.style.color = cap && length > cap ? "#b7352c" : "";
  }

  function setFeedback(type, message) {
    feedback.className = "uc-feedback " + type;
    feedback.textContent = message;
  }

  function clearFeedback() {
    feedback.className = "uc-feedback";
    feedback.textContent = "";
  }

  function resetMetrics() {
    Object.keys(stat).forEach(function (key) {
      stat[key].textContent = "-";
    });
    meterFill.style.width = "0";
    meterFill.classList.remove("is-over");
    concurrentRow.hidden = true;
    concurrentCell.hidden = true;
  }

  function renderMetrics(metrics) {
    if (!metrics) {
      resetMetrics();
      return;
    }
    stat.billed.textContent = String(metrics.billed_tokens);
    stat.budget.textContent = String(metrics.budget_tokens);
    stat.promptTokens.textContent = String(metrics.prompt_tokens);
    stat.outputTokens.textContent = String(metrics.output_tokens);
    stat.duration.textContent = (Number(metrics.duration_ms || 0) / 1000).toFixed(1) + " s";
    const share = metrics.budget_tokens ? metrics.billed_tokens / metrics.budget_tokens : 0;
    meterFill.style.width = Math.min(100, Math.round(share * 100)) + "%";
    meterFill.classList.toggle("is-over", share >= 1);

    if (metrics.concurrency_budget) {
      concurrentRow.hidden = false;
      concurrentCell.hidden = false;
      concurrentCell.textContent = metrics.concurrent_requests + " / " + metrics.concurrency_budget;
    } else {
      concurrentRow.hidden = true;
      concurrentCell.hidden = true;
    }
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
      output.textContent = "Send some text to summarize.";
      setFeedback("fail", "Enter some text first.");
      return;
    }

    setMeta();
    clearFeedback();
    resetMetrics();
    output.textContent = "Summarizing...";
    runBtn.disabled = true;

    try {
      const res = await fetch(endpointForLevel(level), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_input: userInput }),
      });
      const data = await parseResponseBody(res);
      if (!res.ok || data.error) {
        output.textContent = responseMessage(data, "Request failed.");
        setFeedback("fail", responseMessage(data, "Request failed."));
        return;
      }

      output.textContent =
        typeof data.assistant_output === "string" && data.assistant_output.trim()
          ? data.assistant_output
          : responseMessage(data, "No output returned.");
      renderMetrics(data.metrics);

      if (data.input_accepted === false) {
        setFeedback("fail", responseMessage(data, "Request blocked."));
      } else if (data.bypassed) {
        const ceiling = data.metrics && data.metrics.generation_cap_hit
          ? " Generation was stopped at this request's own cap; a real service without one would have kept going."
          : "";
        setFeedback("ok", responseMessage(data, "Budget exceeded.") + ceiling);
      } else {
        setFeedback("fail", responseMessage(data, "Within budget."));
      }
    } finally {
      runBtn.disabled = false;
    }
  }

  function clearBurstResults() {
    burstResults.innerHTML = "";
    burstSummary.textContent = "";
  }

  function renderBurstItem(index, data, ok) {
    const li = document.createElement("li");
    if (!ok) {
      li.className = "is-ok";
      li.textContent = "#" + index + " — request failed";
      burstResults.appendChild(li);
      return;
    }
    const bypassed = Boolean(data.bypassed);
    li.className = bypassed ? "is-bypassed" : "is-ok";
    const inFlight = data.metrics ? data.metrics.concurrent_requests : "?";
    const budget = data.metrics ? data.metrics.concurrency_budget : "?";
    li.textContent =
      "#" + index + " — " + inFlight + "/" + budget + " in flight" +
      (bypassed ? "  → BYPASSED" : "  within limits");
    burstResults.appendChild(li);
  }

  async function runBurst() {
    const level = levelFromGlobalState();
    const n = Math.max(2, Math.min(20, Number(burstCountInput.value) || 5));
    const text = promptInput.value.trim() || "Please summarize this short support ticket about a login issue.";

    setMeta();
    clearFeedback();
    clearBurstResults();
    resetMetrics();
    output.textContent = "Firing " + n + " concurrent requests...";
    burstBtn.disabled = true;
    runBtn.disabled = true;

    try {
      const requests = Array.from({ length: n }, function () {
        return fetch(endpointForLevel(level), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_input: text }),
        })
          .then(async function (res) {
            const data = await parseResponseBody(res);
            return { ok: res.ok && !data.error, data: data };
          })
          .catch(function () {
            return { ok: false, data: null };
          });
      });

      const results = await Promise.all(requests);
      results.forEach(function (r, i) {
        renderBurstItem(i + 1, r.data, r.ok);
      });

      const bypassedCount = results.filter(function (r) {
        return r.ok && r.data.bypassed;
      }).length;
      const peak = results.reduce(function (max, r) {
        const v = r.ok && r.data.metrics ? r.data.metrics.concurrent_requests : 0;
        return Math.max(max, v || 0);
      }, 0);

      burstSummary.textContent =
        bypassedCount + " of " + n + " requests came back bypassed; peak concurrency observed: " + peak + ".";
      output.textContent =
        bypassedCount > 0
          ? "The burst worked — see the Concurrent Burst panel above for the per-request breakdown."
          : "No request was bypassed. Try raising the request count, or fire the burst again — timing between requests affects how much overlap actually happens.";

      const lastSuccessful = results.slice().reverse().find(function (r) {
        return r.ok;
      });
      if (lastSuccessful) {
        renderMetrics(lastSuccessful.data.metrics);
      }

      if (bypassedCount > 0) {
        setFeedback("ok", bypassedCount + " of " + n + " concurrent requests bypassed the per-request limits.");
      } else {
        setFeedback("fail", "No bypass yet — none of the " + n + " requests overlapped enough.");
      }
    } finally {
      burstBtn.disabled = false;
      runBtn.disabled = false;
    }
  }

  promptInput.addEventListener("input", updateCounter);

  runBtn.addEventListener("click", function () {
    runLevel().catch(function (err) {
      output.textContent = String(err);
      setFeedback("fail", String(err));
    });
  });

  burstBtn.addEventListener("click", function () {
    runBurst().catch(function (err) {
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
    updateCounter();
    resetMetrics();
    clearFeedback();
    clearBurstResults();
    burstPanel.hidden = !cfg.burst;
    output.textContent = cfg.burst
      ? "Send text to the summarizer, or fire a concurrent burst below to see what nothing limiting concurrency actually costs."
      : "Send text to the summarizer to see what the request costs.";
  }

  applyLevelConfig();
  setMeta();
})();
