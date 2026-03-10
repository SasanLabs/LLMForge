const levelSelect = document.getElementById("level");
const userInput = document.getElementById("userInput");
const submitBtn = document.getElementById("submitBtn");
const responseBox = document.getElementById("response");
const apiPath = document.getElementById("apiPath");

function selectedLevel() {
  return Number(levelSelect.value || "1");
}

function endpointForLevel(level) {
  return `/api/v1/vulnerabilities/prompt-injection/level${level}`;
}

async function loadLevels() {
  const res = await fetch("/api/v1/vulnerabilities/prompt-injection");
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
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

async function runLevel() {
  const level = selectedLevel();
  const endpoint = endpointForLevel(level);

  apiPath.textContent = `API: ${endpoint}`;
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

levelSelect.addEventListener("change", () => {
  apiPath.textContent = `API: ${endpointForLevel(selectedLevel())}`;
});

submitBtn.addEventListener("click", async () => {
  try {
    await runLevel();
  } catch (err) {
    responseBox.className = "status-fail";
    responseBox.textContent = prettyJson({ error: String(err) });
  }
});

loadLevels().catch((err) => {
  responseBox.className = "status-fail";
  responseBox.textContent = prettyJson({ error: String(err) });
});
