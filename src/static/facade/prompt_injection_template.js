(function () {
  const root = document.getElementById("llmforge-facade-root");
  if (!root) {
    return;
  }

  const payloadInput = document.getElementById("llmforgePayload");
  const secretInput = document.getElementById("llmforgeSecret");
  const runBtn = document.getElementById("llmforgeRunBtn");
  const verifyBtn = document.getElementById("llmforgeVerifyBtn");
  const output = document.getElementById("llmforgeOutput");
  const meta = document.getElementById("llmforgeMeta");
  const apiPrefix = root.getAttribute("data-api-prefix") || "";

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
    if (!Number.isInteger(level) || level < 1 || level > 10) {
      return 1;
    }
    return level;
  }

  function toPrettyJson(value) {
    return JSON.stringify(value, null, 2);
  }

  function setMeta(level) {
    meta.textContent =
      "Level " +
      level +
      " | " +
      apiPrefix +
      "/api/v1/vulnerabilities/prompt-injection/level" +
      level;
  }

  async function runPayload() {
    const level = levelFromGlobalState();
    setMeta(level);
    output.textContent = "Running...";

    const endpoint =
      apiPrefix + "/api/v1/vulnerabilities/prompt-injection/level" + level;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_input: payloadInput.value || " " }),
    });

    const data = await res.json();
    output.textContent = toPrettyJson(res.ok ? data : { error: data });
    output.className = data && data.bypassed ? "llmforge-facade-output fail" : "llmforge-facade-output ok";
  }

  async function verifySecret() {
    const level = levelFromGlobalState();
    setMeta(level);
    output.textContent = "Verifying...";

    const endpoint =
      apiPrefix +
      "/api/v1/vulnerabilities/prompt-injection/level" +
      level +
      "/verify-secret";
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ candidate_secret: secretInput.value || " " }),
    });

    const data = await res.json();
    output.textContent = toPrettyJson(res.ok ? data : { error: data });
    output.className = data && data.correct ? "llmforge-facade-output ok" : "llmforge-facade-output fail";
  }

  runBtn.addEventListener("click", function () {
    runPayload().catch(function (err) {
      output.textContent = toPrettyJson({ error: String(err) });
      output.className = "llmforge-facade-output fail";
    });
  });

  verifyBtn.addEventListener("click", function () {
    verifySecret().catch(function (err) {
      output.textContent = toPrettyJson({ error: String(err) });
      output.className = "llmforge-facade-output fail";
    });
  });

  setMeta(levelFromGlobalState());
})();
