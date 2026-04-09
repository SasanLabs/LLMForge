const labType = document.getElementById("labType");
const levelSelect = document.getElementById("level");
const userInput = document.getElementById("userInput");
const sourceType = document.getElementById("sourceType");
const sourceValue = document.getElementById("sourceValue");
const sourceHint = document.getElementById("sourceHint");
const submitBtn = document.getElementById("submitBtn");
const candidateSecret = document.getElementById("candidateSecret");
const verifyBtn = document.getElementById("verifyBtn");
const responseBox = document.getElementById("response");
const apiPath = document.getElementById("apiPath");
const verifyApiPath = document.getElementById("verifyApiPath");

const APP_BASE_PATH = "/llmforge";

const LABS = {
  direct: {
    slug: "prompt-injection",
    label: "Direct Prompt Injection",
  },
  indirect: {
    slug: "indirect-prompt-injection",
    label: "Indirect Prompt Injection",
  },
};

function selectedLab() {
  const key = labType.value || "direct";
  return LABS[key] || LABS.direct;
}

function selectedLevel() {
  return Number(levelSelect.value || "1");
}

function endpointForLevel(level) {
  return `${APP_BASE_PATH}/api/v1/vulnerabilities/${selectedLab().slug}/level${level}`;
}

function verifyEndpointForLevel(level) {
  return `${APP_BASE_PATH}/api/v1/vulnerabilities/${selectedLab().slug}/level${level}/verify-secret`;
}

function levelsEndpoint() {
  return `${APP_BASE_PATH}/api/v1/vulnerabilities/${selectedLab().slug}`;
}

function isIndirectLab() {
  return selectedLab().slug === "indirect-prompt-injection";
}

function updateSourceInputs() {
  const indirect = isIndirectLab();
  sourceType.disabled = !indirect;
  sourceValue.disabled = !indirect;
  if (!indirect) {
    sourceType.value = "local";
  }
  sourceHint.textContent = indirect
    ? "Indirect prompt injection accepts only Path or External URL as source input."
    : "Extra source is only used for the indirect lab.";
}

async function loadLevels() {
  const res = await fetch(levelsEndpoint());
  if (!res.ok) {
    throw new Error("Unable to load level metadata");
  }
  const payload = await res.json();
  const levels = payload.levels || [];

  levelSelect.innerHTML = "";
  levels.forEach((item) => {
    const option = document.createElement("option");
    option.value = item.level;
    option.textContent = `Level ${item.level} - ${item.name}`;
    levelSelect.appendChild(option);
  });

  apiPath.textContent = `API: ${endpointForLevel(selectedLevel())}`;
  verifyApiPath.textContent = `Verify API: ${verifyEndpointForLevel(selectedLevel())}`;
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

async function parseResponseBody(res) {
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return await res.json();
  }

  const text = await res.text();
  return { detail: text || "Unexpected empty response from server." };
}

async function runLevel() {
  const level = selectedLevel();
  const endpoint = endpointForLevel(level);

  apiPath.textContent = `API: ${endpoint}`;
  verifyApiPath.textContent = `Verify API: ${verifyEndpointForLevel(level)}`;
  responseBox.textContent = "Running...";

  const requestBody = {
    user_input: userInput.value,
  };
  if (isIndirectLab()) {
    requestBody.source_type = sourceType.value;
    requestBody.source_value = sourceValue.value;
  }

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(requestBody),
  });

  const data = await parseResponseBody(res);
  if (!res.ok) {
    responseBox.textContent = prettyJson({ error: data });
    responseBox.className = "status-fail";
    return;
  }

  responseBox.className = data.bypassed ? "status-fail" : "status-ok";
  responseBox.textContent = data.assistant_output || "No assistant output returned.";
}

async function verifySecret() {
  const level = selectedLevel();
  const endpoint = verifyEndpointForLevel(level);

  apiPath.textContent = `API: ${endpointForLevel(level)}`;
  verifyApiPath.textContent = `Verify API: ${endpoint}`;
  responseBox.textContent = "Verifying...";

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ candidate_secret: candidateSecret.value }),
  });

  const data = await parseResponseBody(res);
  if (!res.ok) {
    responseBox.textContent = prettyJson({ error: data });
    responseBox.className = "status-fail";
    return;
  }

  responseBox.className = data.correct ? "status-ok" : "status-fail";
  responseBox.textContent = data.message || (data.correct ? "Secret is correct." : "Secret is incorrect.");
}

levelSelect.addEventListener("change", () => {
  apiPath.textContent = `API: ${endpointForLevel(selectedLevel())}`;
  verifyApiPath.textContent = `Verify API: ${verifyEndpointForLevel(selectedLevel())}`;
});

labType.addEventListener("change", async () => {
  updateSourceInputs();
  responseBox.className = "";
  responseBox.textContent = "Loading levels...";
  try {
    await loadLevels();
  } catch (err) {
    responseBox.className = "status-fail";
    responseBox.textContent = prettyJson({ error: String(err) });
  }
});

submitBtn.addEventListener("click", async () => {
  try {
    await runLevel();
  } catch (err) {
    responseBox.className = "status-fail";
    responseBox.textContent = prettyJson({ error: String(err) });
  }
});

verifyBtn.addEventListener("click", async () => {
  try {
    await verifySecret();
  } catch (err) {
    responseBox.className = "status-fail";
    responseBox.textContent = prettyJson({ error: String(err) });
  }
});

updateSourceInputs();
loadLevels().catch((err) => {
  responseBox.className = "status-fail";
  responseBox.textContent = prettyJson({ error: String(err) });
});
