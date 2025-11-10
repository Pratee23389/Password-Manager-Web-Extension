// LPH Password Manager - Popup Logic

let currentUrl = '';

// Get current tab URL
async function getCurrentTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || '';
}

// Extract domain from URL
function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

// Get first letter for icon
function getInitial(domain) {
  if (!domain) return '?';
  const cleanDomain = domain.replace('www.', '');
  return cleanDomain.charAt(0).toUpperCase();
}

// Check status
async function checkStatus() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'PM_STATUS' });
    return response;
  } catch (error) {
    console.error('Status check failed:', error);
    return { unlocked: false, user: null };
  }
}

// Unlock vault
async function unlock(password) {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_UNLOCK', password });
  } catch (error) {
    console.error('Unlock failed:', error);
    return { ok: false, error: error.message };
  }
}

// Lock vault
async function lock() {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_LOCK' });
  } catch (error) {
    console.error('Lock failed:', error);
    return { ok: false, error: error.message };
  }
}

// Get credentials for URL
async function getCredentials(url) {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_GET_CREDENTIALS', url });
  } catch (error) {
    console.error('Get credentials failed:', error);
    return { ok: false, credentials: [] };
  }
}

// Get all credentials
async function getAllCredentials() {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
  } catch (error) {
    console.error('Get all credentials failed:', error);
    return { ok: false, data: {} };
  }
}

// Delete credential
async function deleteCredential(url, username) {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_DELETE_CREDENTIAL', url, username });
  } catch (error) {
    console.error('Delete credential failed:', error);
    return { ok: false, error: error.message };
  }
}

// Sign out
async function signOut() {
  try {
    await chrome.runtime.sendMessage({ type: 'PM_SIGNOUT' });
    chrome.tabs.create({ url: chrome.runtime.getURL('auth.html') });
    window.close();
  } catch (error) {
    console.error('Sign out failed:', error);
  }
}

// Autofill credentials
async function autofill(username, password) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.tabs.sendMessage(tab.id, {
      type: 'PM_AUTOFILL',
      username,
      password,
    });
    window.close();
  } catch (error) {
    alert('Failed to autofill. Please refresh the page and try again.');
  }
}

// Copy to clipboard
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Copy failed:', error);
    return false;
  }
}

// Update UI based on status
function updateUI(status) {
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const lockedView = document.getElementById('lockedView');
  const unlockedView = document.getElementById('unlockedView');
  const headerActions = document.getElementById('headerActions');

  if (status.unlocked) {
    statusDot.classList.add('unlocked');
    statusText.textContent = 'Unlocked';
    lockedView.style.display = 'none';
    unlockedView.style.display = 'block';
    headerActions.style.display = 'flex';
  } else {
    statusDot.classList.remove('unlocked');
    statusText.textContent = 'Locked';
    lockedView.style.display = 'block';
    unlockedView.style.display = 'none';
    headerActions.style.display = 'none';
  }
}

// Render credentials list
async function renderCredentials(searchQuery = '') {
  const listContainer = document.getElementById('credentialsList');
  const listTitle = document.getElementById('listTitle');

  let credentials = [];
  let isSearchMode = false;

  if (searchQuery) {
    // Search mode
    isSearchMode = true;
    const allData = await getAllCredentials();
    if (allData.ok && allData.data) {
      for (const [domain, creds] of Object.entries(allData.data)) {
        for (const cred of creds) {
          if (
            domain.toLowerCase().includes(searchQuery) ||
            cred.username.toLowerCase().includes(searchQuery)
          ) {
            credentials.push({ domain, ...cred });
          }
        }
      }
    }
    listTitle.textContent = `Search results for "${searchQuery}"`;
  } else {
    // Current site mode
    const domain = getDomain(currentUrl);
    const response = await getCredentials(currentUrl);
    if (response.ok && response.credentials) {
      credentials = response.credentials.map((cred) => ({ domain, ...cred }));
    }
    listTitle.textContent = domain
      ? `Passwords for ${domain}`
      : 'Passwords for this site';
  }

  if (credentials.length === 0) {
    listContainer.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔐</div>
        <div style="font-size: 14px; margin-bottom: 8px;">No passwords found</div>
        <div style="font-size: 12px; color: #999;">${
          isSearchMode
            ? 'Try a different search term'
            : 'Save passwords as you log into websites'
        }</div>
      </div>
    `;
    return;
  }

  listContainer.innerHTML = '';

  for (const cred of credentials) {
    const card = document.createElement('div');
    card.className = 'cred-card';

    const initial = getInitial(cred.domain);
    const displayDomain = cred.domain || 'Unknown';

    card.innerHTML = `
      <div class="cred-header">
        <div class="cred-icon">${initial}</div>
        <div class="cred-info">
          <div class="cred-domain">${escapeHtml(displayDomain)}</div>
          <div class="cred-username">${escapeHtml(cred.username)}</div>
        </div>
      </div>
      <div class="cred-actions">
        <button class="autofill-btn" data-username="${escapeHtml(
          cred.username
        )}" data-password="${escapeHtml(
      cred.password
    )}">Autofill</button>
        <button class="copy-btn" data-password="${escapeHtml(
          cred.password
        )}">Copy</button>
        <button class="delete-btn" data-domain="${escapeHtml(
          cred.domain
        )}" data-username="${escapeHtml(cred.username)}">Delete</button>
      </div>
    `;
    listContainer.appendChild(card);
  }

  document.querySelectorAll('.autofill-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      autofill(btn.dataset.username, btn.dataset.password);
    });
  });

  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const success = await copyToClipboard(btn.dataset.password);
      if (success) {
        btn.textContent = '✓ Copied';
        setTimeout(() => (btn.textContent = 'Copy'), 1500);
      }
    });
  });

  document.querySelectorAll('.delete-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const { domain, username } = btn.dataset;
      if (confirm(`Delete credentials for ${username}?`)) {
        const url = `https://${domain}`;
        await deleteCredential(url, username);
        await renderCredentials(searchQuery);
      }
    });
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Initialize
async function init() {
  currentUrl = await getCurrentTabUrl();
  const status = await checkStatus();

  if (!status.user) {
  chrome.tabs.create({ url: chrome.runtime.getURL('auth.html') });
  // Delay closing to make sure tab opens first
  setTimeout(() => window.close(), 500);
  return;
}


  updateUI(status);
  if (status.unlocked) await renderCredentials();
}

// Event listeners
document.getElementById('unlockBtn')?.addEventListener('click', async () => {
  const password = document.getElementById('unlockInput').value;
  const btn = document.getElementById('unlockBtn');
  if (!password) return alert('Please enter your master password');
  btn.disabled = true;
  btn.textContent = 'Unlocking...';
  const resp = await unlock(password);
  if (resp.ok) {
    const status = await checkStatus();
    updateUI(status);
    await renderCredentials();
  } else alert(resp.error || 'Invalid password');
  btn.disabled = false;
  btn.textContent = 'Unlock Vault';
  document.getElementById('unlockInput').value = '';
});

document.getElementById('unlockInput')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('unlockBtn').click();
});

document.getElementById('lockBtn')?.addEventListener('click', async () => {
  await lock();
  updateUI(await checkStatus());
});

document.getElementById('signoutBtn')?.addEventListener('click', async () => {
  if (confirm('Sign out of LPH Password Manager?')) await signOut();
});

document.getElementById('searchInput')?.addEventListener('input', async (e) => {
  await renderCredentials(e.target.value.trim().toLowerCase());
});

document
  .getElementById('addPasswordBtn')
  ?.addEventListener('click', () =>
    chrome.tabs.create({ url: chrome.runtime.getURL('add.html') })
  );

document
  .getElementById('viewAllBtn')
  ?.addEventListener('click', () =>
    chrome.tabs.create({ url: chrome.runtime.getURL('view.html') })
  );

document.getElementById('optionsLink')?.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

document.getElementById('helpLink')?.addEventListener('click', (e) => {
  e.preventDefault();
  alert(`LPH Password Manager Help

• Save passwords automatically when you log in
• Use the popup to autofill saved passwords
• Keep your recovery phrase safe - it's the only way to recover your account
• Your data is encrypted end-to-end`);
});

// Initialize on load
init();
