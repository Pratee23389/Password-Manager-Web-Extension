async function getAll() {
  return chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function createCard(domain, creds) {
  const card = document.createElement('div');
  card.className = 'card';
  const title = document.createElement('h3');
  title.innerHTML = escapeHtml(domain);
  card.appendChild(title);

  for (const c of creds) {
    const u = document.createElement('div');
    u.style.marginTop = '8px';
    u.innerHTML = `<div style="font-weight:600">${escapeHtml(c.username)}</div><div class=\"muted\">${escapeHtml(c.password).replace(/./g, '•')}</div>`;
    const actions = document.createElement('div');
    actions.className = 'actions';

    const showBtn = document.createElement('button');
    showBtn.className = 'small';
    showBtn.textContent = 'Show';
    let showing = false;
    showBtn.addEventListener('click', () => {
      const pwDiv = u.querySelector('.muted');
      if (!showing) {
        pwDiv.textContent = c.password;
        showBtn.textContent = 'Hide';
      } else {
        pwDiv.textContent = c.password.replace(/./g, '•');
        showBtn.textContent = 'Show';
      }
      showing = !showing;
    });

    const copyBtn = document.createElement('button');
    copyBtn.className = 'small btn-copy';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(c.password);
        copyBtn.textContent = 'Copied';
        setTimeout(() => (copyBtn.textContent = 'Copy'), 1200);
      } catch (e) {
        alert('Copy failed: ' + e.message);
      }
    });

    const delBtn = document.createElement('button');
    delBtn.className = 'small btn-del';
    delBtn.textContent = 'Delete';
    delBtn.addEventListener('click', async () => {
      if (!confirm(`Delete ${c.username} from ${domain}?`)) return;
      // Ask background to delete - reuse PM_DELETE_CREDENTIAL
      const res = await chrome.runtime.sendMessage({ type: 'PM_DELETE_CREDENTIAL', url: 'https://' + domain + '/', username: c.username });
      if (res?.ok) {
        card.remove();
      } else {
        alert(res?.error || 'Failed to delete');
      }
    });

    actions.appendChild(showBtn);
    actions.appendChild(copyBtn);
    actions.appendChild(delBtn);

    card.appendChild(u);
    card.appendChild(actions);
  }

  return card;
}

async function render() {
  const res = await getAll();
  const grid = document.getElementById('grid');
  const empty = document.getElementById('emptyMsg');
  grid.innerHTML = '';
  if (!res?.ok) {
    empty.textContent = 'Unable to load credentials. Unlock your vault in the popup first.';
    empty.style.display = 'block';
    return;
  }
  const data = res.data || {};
  const domains = Object.keys(data);
  if (!domains.length) {
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  for (const d of domains) {
    const card = createCard(d, data[d]);
    grid.appendChild(card);
  }
}

// Wire up open popup and search
document.getElementById('openPopup').addEventListener('click', (e) => {
  e.preventDefault();
  window.close();
  chrome.action.openPopup?.();
});

document.getElementById('searchInput').addEventListener('input', (e) => {
  const q = e.target.value.toLowerCase().trim();
  document.querySelectorAll('.card').forEach(card => {
    const title = card.querySelector('h3').textContent.toLowerCase();
    card.style.display = title.includes(q) ? '' : 'none';
  });
});

render();
