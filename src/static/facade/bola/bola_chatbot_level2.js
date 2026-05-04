/* BOLA Chatbot JavaScript */

const API_PREFIX = '/llmforge';
const CONTROLLER_SLUG = 'bola-chatbot';

class BOLAChatbot {
  constructor(defaultLevel) {
    this.currentLevel = getCurrentLevel(defaultLevel);
    this.initializeElements();
    this.setupEventListeners();
  }

  initializeElements() {
    this.userQueryInput = document.getElementById('userQuery');
    this.sendBtn = document.getElementById('sendBtn');
    this.chatHistory = document.getElementById('chatHistory');
    this.chatArea = document.getElementById('chatArea');
  }

  setupEventListeners() {
    this.sendBtn.addEventListener('click', () => this.sendQuery());
    this.userQueryInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && e.ctrlKey) {
        this.sendQuery();
      }
    });
  }

  addChatMessage(role, content) {
    if (!this.chatHistory) {
      return;
    }
    if (this.chatArea) {
      this.chatArea.style.display = 'block';
    }
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${role}`;
    messageDiv.textContent = content;
    this.chatHistory.appendChild(messageDiv);
    this.chatHistory.scrollTop = this.chatHistory.scrollHeight;
  }

  async sendQuery() {
    const userInput = this.userQueryInput.value.trim();
    if (!userInput) return;

    this.addChatMessage('user', userInput);
    this.userQueryInput.value = '';
    this.sendBtn.disabled = true;

    try {
      const response = await fetch(getEndpointForLevel(this.currentLevel), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_input: userInput,
        }),
      });

      const data = await parseResponseBody(response);
      
      if (!response.ok) {
        const errorMessage = responseMessage(data, 'Request failed.');
        this.addChatMessage('bot error', `Error: ${errorMessage}`);
        return;
      }

      if (data.success) {
        const botResponse = data.response || 'No response received';
        this.addChatMessage('bot', botResponse);
      } else {
        this.addChatMessage('bot error', `Error: ${responseMessage(data, 'Unknown error')}`);
      }
    } catch (error) {
      this.addChatMessage('bot error', `Request failed: ${error.message}`);
    } finally {
      this.sendBtn.disabled = false;
    }
  }

}

// Utility Functions

function getCurrentLevel() {
  const levelIdentifier = String(window.getCurrentVulnerabilityLevel() || '');
  const match = /level[_-]?(\d+)/i.exec(levelIdentifier);
  return match ? Number(match[1]) : 1;
}

function getEndpointForLevel(level) {
  return `${API_PREFIX}/api/v1/vulnerabilities/${CONTROLLER_SLUG}/level${level}`;
}

async function parseResponseBody(response) {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return await response.json();
  }

  const text = await response.text();
  return { detail: text || 'Unexpected empty response from server.' };
}

function responseMessage(data, fallback) {
  if (!data) {
    return fallback;
  }
  if (typeof data.error === 'string' && data.error.trim()) {
    return data.error;
  }
  if (typeof data.message === 'string' && data.message.trim()) {
    return data.message;
  }
  if (typeof data.detail === 'string' && data.detail.trim()) {
    return data.detail;
  }
  return fallback;
}

function injectPrompt(prompt) {
  const input = document.getElementById('userQuery');
  input.value = prompt;
  input.focus();
}

function initializeChatbot() {
  if (!document.getElementById('sendBtn') || !document.getElementById('userQuery')) {
    return;
  }

  window.chatbot = new BOLAChatbot();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initializeChatbot(), { once: true });
} else {
  initializeChatbot();
}
