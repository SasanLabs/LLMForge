(function () {
  const root = document.getElementById("llmforge-facade-root");
  if (!root) {
    return;
  }

  const payloadInput = document.getElementById("llmforgePayload");
  const sourceType = document.getElementById("llmforgeSourceType");
  const sourceValue = document.getElementById("llmforgeSourceValue");
  const secretInput = document.getElementById("llmforgeSecret");
  const runBtn = document.getElementById("llmforgeRunBtn");
  const verifyBtn = document.getElementById("llmforgeVerifyBtn");
  const output = document.getElementById("llmforgeOutput");
  const meta = document.getElementById("llmforgeMeta");

  function detectBasePath() {
    const path = window.location.pathname || "";
    const staticIndex = path.indexOf("/static/");
    if (staticIndex >= 0) {
      return path.slice(0, staticIndex);
    }
    return "";
  }

  const apiPrefix = detectBasePath();

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
    if (!Number.isInteger(level) || level < 1 || level > 4) {
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
      "/api/v1/vulnerabilities/indirect-prompt-injection/level" +
      level;
  }

  async function runPayload() {
    const level = levelFromGlobalState();
    setMeta(level);
    output.textContent = "Running...";

    const endpoint =
      apiPrefix +
      "/api/v1/vulnerabilities/indirect-prompt-injection/level" +
      level;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        user_input: payloadInput.value || " ",
        source_type: sourceType.value || "local",
        source_value: sourceValue.value || "",
      }),
    });

    const data = await parseResponseBody(res);
    if (!res.ok) {
      output.textContent = responseMessage(data, "Request failed.");
      output.className = "llmforge-facade-output fail";
      return;
    }

    output.textContent = responseMessage(data, "No assistant output returned.");
    output.className = data && data.bypassed ? "llmforge-facade-output fail" : "llmforge-facade-output ok";
  }

  async function verifySecret() {
    const level = levelFromGlobalState();
    setMeta(level);
    output.textContent = "Verifying...";

    const endpoint =
      apiPrefix +
      "/api/v1/vulnerabilities/indirect-prompt-injection/level" +
      level +
      "/verify-secret";
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ candidate_secret: secretInput.value || " " }),
    });

    const data = await parseResponseBody(res);
    if (!res.ok) {
      output.textContent = responseMessage(data, "Secret verification failed.");
      output.className = "llmforge-facade-output fail";
      return;
    }

    output.textContent = responseMessage(
      data,
      data.correct ? "Secret is correct." : "Secret is incorrect."
    );
    output.className = data && data.correct ? "llmforge-facade-output ok" : "llmforge-facade-output fail";
  }

  runBtn.addEventListener("click", function () {
    runPayload().catch(function (err) {
      output.textContent = String(err);
      output.className = "llmforge-facade-output fail";
    });
  });

  verifyBtn.addEventListener("click", function () {
    verifySecret().catch(function (err) {
      output.textContent = String(err);
      output.className = "llmforge-facade-output fail";
    });
  });

  setMeta(levelFromGlobalState());
})();
