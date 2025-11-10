// ======================================================
// 🔐 LPH Password Manager - View All Passwords Page
// ======================================================

// ---------- Fetch All Saved Credentials ----------
async function getAllCredentials() {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
  } catch (error) {
    console.error('Failed to get all credentials:', error);
    return { ok: false, data: {} };
  }
}

// ---------- Delete a Credential ----------
async function deleteCredential(url, username) {
  try {
    return await chrome.runtime.sendMessage({
      type: 'PM_DELETE_CREDENTIAL',
      url,
      username,
    });
  } catch (error) {
    console.error('Failed to delete credential:', error);
    return { ok: false, error: error.message };
  }
}

// ---------- Copy to Clipboard ----------
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Copy failed:', error);
    return false;
  }
}

// ---------- Get Icon from Domain ----------
function getIcon(domain) {
  const d = domain.toLowerCase();
  if (d.includes('google')) return '🔎';
  if (d.includes('facebook')) return '📘';
  if (d.includes('amazon')) return '🅰️';
  if (d.includes('instagram')) return '📸';
  if (d.includes('netflix')) return '🎬';
  if (d.includes('discord')) return '💬';
  return domain[0]?.toUpperCase() || '🔐';
}

// ---------- Render All Credentials ----------
async function renderAll(query = '') {
  const grid = document.getElementById('grid');
  const emptyState = document.getElementById('emptyState');

  const response = await getAllCredentials();
  if (!response.ok || !response.data) {
    grid.innerHTML = '<p style="color:red;">Error loading passwords.</p>';
    return;
  }

  let data = Object.entries(response.data);

  // Filter based on search query
  if (query) {
    query = query.toLowerCase();
    data = data.filter(([domain, creds]) =>
      domain.toLowerCase().includes(query) ||
      creds.some((c) => c.username.toLowerCase().includes(query))
    );
  }

  if (data.length === 0) {
    grid.innerHTML = '';
    emptyState.style.display = 'block';
    return;
  }

  emptyState.style.display = 'none';
  grid.innerHTML = '';

  // Render each domain as a card
  for (const [domain, creds] of data) {
    const card = document.createElement('div');
    card.className = 'card';

    card.innerHTML = `
      <div class="card-header">
        <div class="card-icon">${getIcon(domain)}</div>
        <div class="card-title">${escapeHtml(domain)}</div>
      </div>
    `;

    for (const cred of creds) {
      const item = document.createElement('div');
      item.className = 'credential-item';

      item.innerHTML = `
        <div class="credential-username">${escapeHtml(cred.username)}</div>
        <div class="credential-password" data-password="${escapeHtml(cred.password)}">••••••••</div>
        <div class="credential-actions">
          <button class="btn-show">Show</button>
          <button class="btn-copy">Copy</button>
          <button class="btn-delete">Delete</button>
        </div>
      `;

      const passwordEl = item.querySelector('.credential-password');
      const showBtn = item.querySelector('.btn-show');
      const copyBtn = item.querySelector('.btn-copy');
      const deleteBtn = item.querySelector('.btn-delete');

      // Toggle password visibility
      showBtn.addEventListener('click', () => {
        if (passwordEl.textContent.includes('•')) {
          passwordEl.textContent = passwordEl.dataset.password;
          showBtn.textContent = 'Hide';
        } else {
          passwordEl.textContent = '••••••••';
          showBtn.textContent = 'Show';
        }
      });

      // Copy password
      copyBtn.addEventListener('click', async () => {
        const success = await copyToClipboard(passwordEl.dataset.password);
        if (success) {
          copyBtn.textContent = '✓ Copied';
          setTimeout(() => (copyBtn.textContent = 'Copy'), 1500);
        }
      });

      // Delete credential
      deleteBtn.addEventListener('click', async () => {
        if (confirm(`Delete credentials for ${cred.username}?`)) {
          const url = `https://${domain}`;
          await deleteCredential(url, cred.username);
          await renderAll(query);
        }
      });

      card.appendChild(item);
    }

    grid.appendChild(card);
  }
}

// ---------- Escape HTML ----------
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ---------- Initialize ----------
async function init() {
  await renderAll();

  const searchInput = document.getElementById('searchInput');
  searchInput.addEventListener('input', async (e) => {
    const q = e.target.value.trim().toLowerCase();
    await renderAll(q);
  });
}

init();
