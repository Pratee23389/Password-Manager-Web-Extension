// LPH Password Manager - Content Script
// Detects login forms, offers to save on submit, and can autofill on request.

function findLoginForm() {
  // Find the first form containing a password field
  const pw = document.querySelector('input[type="password"]');
  if (!pw) return null;
  const form = pw.closest('form');
  if (!form) return null;
  // Try to guess username field
  const userField = form.querySelector('input[type="email"], input[name*="user" i], input[name*="login" i], input[type="text"]');
  return { form, userField, passField: pw };
}

function serializeUrl() {
  return location.href;
}

async function promptSave(username, password) {
  try {
    const res = await chrome.runtime.sendMessage({
      type: 'PM_SAVE_CREDENTIALS',
      url: serializeUrl(),
      username,
      password,
    });
    if (!res?.ok) throw new Error(res?.error || 'Failed');
    // Optional: show a simple toast
    showToast('Credentials saved');
  } catch (e) {
    showToast('Not saved: ' + (e.message || e));
  }
}

function showToast(text) {
  try {
    const id = 'lph-toast';
    let el = document.getElementById(id);
    if (!el) {
      el = document.createElement('div');
      el.id = id;
      el.style.cssText = 'position:fixed;bottom:16px;right:16px;background:#111;color:#fff;padding:8px 12px;border-radius:8px;font:12px system-ui;z-index:2147483647;box-shadow:0 2px 8px rgba(0,0,0,.3)';
      document.documentElement.appendChild(el);
    }
    el.textContent = text;
    el.style.display = 'block';
    setTimeout(() => (el.style.display = 'none'), 2500);
  } catch {}
}

function setupFormListener() {
  const found = findLoginForm();
  if (!found) return;
  const { form, userField, passField } = found;
  form.addEventListener('submit', () => {
    const u = userField ? userField.value : '';
    const p = passField.value;
    if (u && p) {
      chrome.runtime.sendMessage({ type: 'PM_STATUS' }).then((st) => {
        if (st?.unlocked) promptSave(u, p);
        else showToast('LPH is locked');
      });
    }
  }, { capture: true });
}

async function autofill(username, password) {
  const found = findLoginForm();
  if (!found) return false;
  const { userField, passField } = found;
  if (userField) {
    userField.focus();
    userField.value = username;
    userField.dispatchEvent(new Event('input', { bubbles: true }));
    userField.blur();
  }
  passField.focus();
  passField.value = password;
  passField.dispatchEvent(new Event('input', { bubbles: true }));
  passField.blur();
  return true;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === 'PM_AUTOFILL') {
      const ok = await autofill(msg.username, msg.password);
      sendResponse({ ok });
    }
  })();
  return true;
});

// Initialize
setupFormListener();
