/* BOLA Chatbot JavaScript */

class BOLAChatbot {
  constructor() {
    this.currentLevel = getCurrentLevel();
    this.initializeElements();
    this.setupEventListeners();
  }

  initializeElements() {
    this.userQueryInput = document.getElementById('userQuery');
    this.sendBtn = document.getElementById('sendBtn');
    this.chatHistory = document.getElementById('chatHistory');
    this.resultPanel = document.getElementById('resultPanel');
    this.responseText = document.getElementById('responseText');
    this.dataAccessedInfo = document.getElementById('dataAccessedInfo');
    this.dataAccessedContent = document.getElementById('dataAccessedContent');
    this.securityPassedInfo = document.getElementById('securityPassedInfo');
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
      const response = await fetch(`/api/${this.currentLevel}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_input: userInput,
          temperature: 0.7,
        }),
      });

      const data = await response.json();
      
      if (data.success) {
        const botResponse = data.response || 'No response received';
        this.addChatMessage('bot', botResponse);
        this.displayResult(data);
      } else {
        this.addChatMessage('bot error', `Error: ${data.error || 'Unknown error'}`);
      }
    } catch (error) {
      this.addChatMessage('bot error', `Request failed: ${error.message}`);
    } finally {
      this.sendBtn.disabled = false;
    }
  }

  displayResult(data) {
    this.resultPanel.style.display = 'block';
    this.responseText.textContent = data.response || 'No response';

    if (data.data_accessed) {
      this.dataAccessedInfo.style.display = 'block';
      this.dataAccessedContent.textContent = JSON.stringify(data.data_accessed, null, 2);
    } else {
      this.dataAccessedInfo.style.display = 'none';
    }

    if (this.securityPassedInfo && !data.data_accessed && this.currentLevel === 'level_3') {
      this.securityPassedInfo.style.display = 'block';
    } else if (this.securityPassedInfo) {
      this.securityPassedInfo.style.display = 'none';
    }
  }
}

// Utility Functions

function getCurrentLevel() {
  const pathname = window.location.pathname;
  if (pathname.includes('level1')) return 'level_1';
  if (pathname.includes('level2')) return 'level_2';
  if (pathname.includes('level3')) return 'level_3';
  return 'level_1';
}

function injectPrompt(prompt) {
  const input = document.getElementById('userQuery');
  input.value = prompt;
  input.focus();
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  window.chatbot = new BOLAChatbot();
});
