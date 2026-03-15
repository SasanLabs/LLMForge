const levelSelect = document.getElementById("level");
const userInput = document.getElementById("userInput");
const submitBtn = document.getElementById("submitBtn");
const candidateSecret = document.getElementById("candidateSecret");
const verifyBtn = document.getElementById("verifyBtn");
const responseBox = document.getElementById("response");
const apiPath = document.getElementById("apiPath");
const verifyApiPath = document.getElementById("verifyApiPath");
const APP_BASE_PATH = "/llmforge";

function selectedLevel() {
  return Number(levelSelect.value || "1");
}

function endpointForLevel(level) {
  return `${APP_BASE_PATH}/api/v1/vulnerabilities/prompt-injection/level${level}`;
}

function verifyEndpointForLevel(level) {
  return `${APP_BASE_PATH}/api/v1/vulnerabilities/prompt-injection/level${level}/verify-secret`;
}

async function loadLevels() {
  const res = await fetch(`${APP_BASE_PATH}/api/v1/vulnerabilities/prompt-injection`);
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

async function runLevel() {
  const level = selectedLevel();
  const endpoint = endpointForLevel(level);

  apiPath.textContent = `API: ${endpoint}`;
  verifyApiPath.textContent = `Verify API: ${verifyEndpointForLevel(level)}`;
  responseBox.textContent = "Running...";

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ user_input: userInput.value }),
  });

  const data = await res.json();
  if (!res.ok) {
    responseBox.textContent = prettyJson({ error: data });
    responseBox.className = "status-fail";
    return;
  }

  responseBox.className = data.bypassed ? "status-fail" : "status-ok";
  responseBox.textContent = prettyJson(data);
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

  const data = await res.json();
  if (!res.ok) {
    responseBox.textContent = prettyJson({ error: data });
    responseBox.className = "status-fail";
    return;
  }

  responseBox.className = data.correct ? "status-ok" : "status-fail";
  responseBox.textContent = prettyJson(data);
}

levelSelect.addEventListener("change", () => {
  apiPath.textContent = `API: ${endpointForLevel(selectedLevel())}`;
  verifyApiPath.textContent = `Verify API: ${verifyEndpointForLevel(selectedLevel())}`;
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

loadLevels().catch((err) => {
  responseBox.className = "status-fail";
  responseBox.textContent = prettyJson({ error: String(err) });
});
