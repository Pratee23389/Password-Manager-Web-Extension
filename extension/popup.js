// LPH Password Manager - Enhanced Popup with Sync

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || '';
}

async function getStatus() {
  return chrome.runtime.sendMessage({ type: 'PM_STATUS' });
}

async function unlock(password) {
  return chrome.runtime.sendMessage({ type: 'PM_UNLOCK', password });
}

async function lock() {
  return chrome.runtime.sendMessage({ type: 'PM_LOCK' });
}

async function getCredentials(url) {
  return chrome.runtime.sendMessage({ type: 'PM_GET_CREDENTIALS', url });
}

async function deleteCredential(url, username) {
  return chrome.runtime.sendMessage({ type: 'PM_DELETE_CREDENTIAL', url, username });
}

async function getAllCredentials() {
  return chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
}

async function signOut() {
  return chrome.runtime.sendMessage({ type: 'PM_SIGNOUT' });
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

async function autofillToTab(tabId, username, password) {
  await chrome.tabs.sendMessage(tabId, {
    type: 'PM_AUTOFILL',
    username,
    password,
  });
}

function updateStatus(status) {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  const lockBtn = document.getElementById('lockBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  
  if (status.unlocked) {
    dot.className = 'status-dot unlocked';
    text.textContent = 'Unlocked';
    lockBtn.style.display = 'inline-block';
  } else {
    dot.className = 'status-dot';
    text.textContent = 'Locked';
    lockBtn.style.display = 'none';
  }
  
  logoutBtn.style.display = status.user ? 'inline-block' : 'none';
}

function renderSyncInfo(status) {
  const syncInfo = document.getElementById('syncInfo');
  // Hide the sync/info block entirely so the cream block under the search bar doesn't appear.
  if (!syncInfo) return;
  syncInfo.style.display = 'none';
}

async function render() {
  const status = await getStatus();
  const url = await getActiveTabUrl();
  
  // If user is not signed in, redirect to auth page
  if (!status.user) {
    chrome.tabs.create({ url: chrome.runtime.getURL('auth.html') });
    window.close();
    return;
  }
  
  updateStatus(status);
  renderSyncInfo(status);
  
  const lockedView = document.getElementById('lockedView');
  const unlockedView = document.getElementById('unlockedView');
  
  if (!status?.unlocked) {
    lockedView.style.display = 'block';
    unlockedView.style.display = 'none';
    // focus the unlock input for convenience
    try { document.getElementById('unlockPwd')?.focus(); } catch(e) {}
  } else {
    lockedView.style.display = 'none';
    unlockedView.style.display = 'block';
    
    // Check if there's a search query
    const searchBox = document.getElementById('searchBox');
    const searchQuery = searchBox?.value?.trim().toLowerCase() || '';
    
    if (searchQuery) {
      // Search mode: show all credentials matching the search query
      await renderSearchResults(searchQuery);
    } else {
      // Normal mode: show credentials for current tab
      await renderCurrentTabCredentials(url);
    }
  }
}

async function renderCurrentTabCredentials(url) {
  const res = await getCredentials(url);
  const grid = document.getElementById('credsGrid') || document.getElementById('creds');
  grid.innerHTML = '';
  const noCreds = document.getElementById('noCreds');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const siteHost = hostFromUrl(url) || '(unknown)';
  
  // Update heading to show normal mode
  const heading = document.querySelector('#unlockedView h3');
  if (heading) {
    heading.textContent = 'Websites';
  }

  if (res?.ok && res.credentials?.length) {
    noCreds.style.display = 'none';
    for (const c of res.credentials) {
      const card = createCredentialCard(siteHost, c, tab.id, url);
      grid.appendChild(card);
    }
  } else {
    noCreds.style.display = 'block';
    noCreds.textContent = 'No saved credentials.';
  }
}

async function renderSearchResults(searchQuery) {
  const res = await getAllCredentials();
  const grid = document.getElementById('credsGrid') || document.getElementById('creds');
  grid.innerHTML = '';
  const noCreds = document.getElementById('noCreds');
  
  // Update heading to show search mode
  const heading = document.querySelector('#unlockedView h3');
  if (heading) {
    heading.textContent = `Search Results for "${searchQuery}"`;
  }
  
  if (!res?.ok || !res.data) {
    noCreds.style.display = 'block';
    noCreds.textContent = 'Search failed';
    return;
  }
  
  // Filter all credentials by search query
  const matchingResults = [];
  for (const [domain, credentials] of Object.entries(res.data)) {
    if (domain.toLowerCase().includes(searchQuery)) {
      // Domain matches
      for (const cred of credentials) {
        matchingResults.push({ domain, credential: cred });
      }
    } else {
      // Check if any username matches
      for (const cred of credentials) {
        if (cred.username.toLowerCase().includes(searchQuery)) {
          matchingResults.push({ domain, credential: cred });
        }
      }
    }
  }
  
  if (matchingResults.length === 0) {
    noCreds.style.display = 'block';
    noCreds.textContent = `No results found for "${searchQuery}"`;
    return;
  }
  
  noCreds.style.display = 'none';
  
  for (const { domain, credential } of matchingResults) {
    const url = `https://${domain}`;
    const card = createCredentialCard(domain, credential, null, url);
    grid.appendChild(card);
  }
}

function createCredentialCard(siteHost, credential, tabId, url) {
  const card = document.createElement('div');
  card.style.padding = '16px';
  card.style.border = '1px solid #d7d7d7';
  card.style.borderRadius = '8px';
  card.style.background = '#efefef';
  card.style.display = 'flex';
  card.style.flexDirection = 'column';
  card.style.boxShadow = '0 2px 2px rgba(0,0,0,0.06)';
  
  const icon = getSiteIcon(siteHost);
  card.innerHTML = `
    <div style="display:flex; align-items:center; gap:12px;">
      <div style="width:64px; height:64px; background:#ddd; border-radius:6px; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:22px;">${icon}</div>
      <div style="flex:1;">
        <div style="font-weight:700; font-size:16px;">${escapeHtml(siteHost)}</div>
        <div style="font-size:13px; color:#666;">${escapeHtml(credential.username)}</div>
      </div>
    </div>
    <div style="margin-top:12px; display:flex; gap:8px;">
      ${tabId ? '<button class="fill btn-primary" style="flex:1">Autofill</button>' : ''}
      <button class="copy btn-secondary" style="flex:1">Copy Password</button>
      <button class="del btn-danger" style="flex:1">Delete</button>
    </div>
  `;

  if (tabId) {
    card.querySelector('.fill')?.addEventListener('click', async () => {
      try {
        await autofillToTab(tabId, credential.username, credential.password);
        window.close();
      } catch (e) {
        alert('Failed to autofill. Please refresh the page and try again.');
      }
    });
  }
  
  card.querySelector('.copy')?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(credential.password);
      const btn = card.querySelector('.copy');
      const originalText = btn.textContent;
      btn.textContent = '✓ Copied';
      setTimeout(() => {
        btn.textContent = originalText;
      }, 1500);
    } catch (e) {
      alert('Failed to copy password');
    }
  });

  card.querySelector('.del')?.addEventListener('click', async () => {
    if (confirm(`Delete credentials for ${credential.username}?`)) {
      await deleteCredential(url, credential.username);
      await render();
    }
  });

  return card;
}

function getSiteIcon(host) {
  const h = (host || '').toLowerCase();
  if (h.includes('amazon')) return '🅰️';
  if (h.includes('instagram')) return '📸';
  if (h.includes('netflix')) return '🎬';
  if (h.includes('discord')) return '💬';
  if (h.includes('google')) return '🔎';
  return (host[0] || 'U').toUpperCase();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Wire up events
const unlockBtnEl = document.getElementById('unlockBtn');
if (unlockBtnEl) {
  unlockBtnEl.addEventListener('click', async () => {
  const pwd = document.getElementById('unlockPwd').value;
  if (!pwd) return;
  
    const btn = unlockBtnEl;
    btn.disabled = true;
    btn.textContent = 'Unlocking...';
  
  try {
    const res = await unlock(pwd);
    if (!res?.ok) {
      alert(res.error || 'Unlock failed');
    } else {
      await render();
    }
  } finally {
      btn.disabled = false;
      btn.textContent = 'Unlock';
  }
  });
}

const lockBtnEl = document.getElementById('lockBtn');
if (lockBtnEl) {
  lockBtnEl.addEventListener('click', async () => {
    await lock();
    await render();
  });
}

// Logout button in header
const logoutBtn = document.getElementById('logoutBtn');
if (logoutBtn) {
  logoutBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    if (!confirm('Sign out?')) return;
    await signOut();
    chrome.tabs.create({ url: chrome.runtime.getURL('auth.html') });
    window.close();
  });
}

// View all stored passwords (open dedicated page)
const viewAllBtnEl = document.getElementById('viewAllBtn');
if (viewAllBtnEl) {
  viewAllBtnEl.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: chrome.runtime.getURL('view.html') });
  });
}

const addLinkEl = document.getElementById('addLink');
if (addLinkEl) {
  addLinkEl.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: chrome.runtime.getURL('add.html') });
  });
}

const optionsLinkEl = document.getElementById('optionsLink');
if (optionsLinkEl) {
  optionsLinkEl.addEventListener('click', async (e) => {
    e.preventDefault();
    await chrome.runtime.openOptionsPage();
  });
}

// Enter key to unlock
const unlockPwdEl = document.getElementById('unlockPwd');
if (unlockPwdEl) {
  unlockPwdEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const btn = document.getElementById('unlockBtn');
      if (btn) btn.click();
    }
  });
}

// Search functionality
const searchBoxEl = document.getElementById('searchBox');
const searchBtnEl = document.getElementById('searchBtn');

if (searchBoxEl) {
  // Search on Enter key
  searchBoxEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      render();
    }
  });
  
  // Clear search and re-render when input is cleared
  searchBoxEl.addEventListener('input', (e) => {
    if (e.target.value === '') {
      render();
    }
  });
}

if (searchBtnEl) {
  searchBtnEl.addEventListener('click', () => {
    render();
  });
}

// Initial render
render();