function hostFromInput(val) {
  try {
    if (!val) return '';
    if (!/^https?:\/\//i.test(val)) val = 'https://' + val;
    return new URL(val).hostname;
  } catch (e) {
    // fallback naive
    return val.replace(/^https?:\/\//, '').split('/')[0];
  }
}

function faviconUrlForDomain(domain) {
  if (!domain) return chrome.runtime.getURL('icons/logo.png');
  // use Google's favicon service (works reliably for testing)
  return `https://www.google.com/s2/favicons?sz=128&domain=${encodeURIComponent(domain)}`;
}

async function saveCredential(site, username, password) {
  // construct a canonical URL for storage
  let url = site;
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  try { new URL(url); } catch (e) { url = 'https://' + site + '/'; }
  return chrome.runtime.sendMessage({ type: 'PM_SAVE_CREDENTIALS', url, username, password });
}

// Wire up DOM
const siteInput = document.getElementById('siteInput');
const logoImg = document.getElementById('logoImg');
const logoPreview = document.getElementById('logoPreview');

siteInput.addEventListener('input', () => {
  const host = hostFromInput(siteInput.value.trim());
  const fav = faviconUrlForDomain(host);
  logoImg.src = fav;
});

// On submit
const form = document.getElementById('addForm');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const site = siteInput.value.trim();
  const username = document.getElementById('userInput').value.trim();
  const password = document.getElementById('pwdInput').value;
  if (!site || !username || !password) return alert('Fill all fields');
  const btn = document.getElementById('saveBtn');
  btn.disabled = true;
  btn.textContent = 'Saving...';
  try {
    const res = await saveCredential(site, username, password);
    if (!res?.ok) throw new Error(res?.error || 'Save failed');
    btn.textContent = 'Saved ✓';
    setTimeout(() => window.close(), 800);
  } catch (err) {
    alert('Failed to save: ' + (err.message || err));
    btn.disabled = false;
    btn.textContent = 'Save';
  }
});

// Cancel
const cancelBtn = document.getElementById('cancelBtn');
cancelBtn.addEventListener('click', () => window.close());

// Seed initial preview
(function(){
  const host = hostFromInput(siteInput.value.trim());
  logoImg.src = faviconUrlForDomain(host);
})();
