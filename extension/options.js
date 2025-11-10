// ======================================================
// ⚙️ LPH Password Manager - Options / Settings Page
// ======================================================

// Elements
const userEmailEl = document.getElementById('userEmail');
const changePasswordBtn = document.getElementById('changePasswordBtn');
const changeMsg = document.getElementById('changePasswordMsg');
const wipeDataBtn = document.getElementById('wipeDataBtn');
const wipeMsg = document.getElementById('wipeMsg');

// Utility: show success/error messages
function showMessage(el, text, type = 'success') {
  el.textContent = text;
  el.className = `message ${type}`;
  el.style.display = 'block';
  setTimeout(() => {
    el.style.display = 'none';
  }, 4000);
}

// ---------------------------
// Load User Info
// ---------------------------
(async () => {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_GET_USER' });
    if (resp?.ok && resp.user?.email) {
      userEmailEl.textContent = `Signed in as: ${resp.user.email}`;
    } else {
      userEmailEl.textContent = 'Not signed in';
    }
  } catch (error) {
    console.error('Failed to load user info:', error);
    userEmailEl.textContent = 'Error loading user info';
  }
})();

// ---------------------------
// Change Master Password
// ---------------------------
changePasswordBtn.addEventListener('click', async () => {
  const currentPassword = document.getElementById('currentPassword').value.trim();
  const newPassword = document.getElementById('newPassword').value.trim();
  const confirmPassword = document.getElementById('confirmPassword').value.trim();

  changeMsg.style.display = 'none';

  if (!currentPassword || !newPassword || !confirmPassword) {
    showMessage(changeMsg, 'Please fill in all fields', 'error');
    return;
  }

  if (newPassword.length < 8) {
    showMessage(changeMsg, 'New password must be at least 8 characters', 'error');
    return;
  }

  if (newPassword !== confirmPassword) {
    showMessage(changeMsg, 'Passwords do not match', 'error');
    return;
  }

  changePasswordBtn.disabled = true;
  changePasswordBtn.textContent = 'Updating...';

  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'PM_CHANGE_PASSWORD',
      currentPassword,
      newPassword,
    });

    if (resp.ok) {
      showMessage(changeMsg, '✅ Password changed successfully. Please sign in again.', 'success');
      setTimeout(() => {
        chrome.tabs.create({ url: chrome.runtime.getURL('auth.html') });
        window.close();
      }, 2000);
    } else {
      throw new Error(resp.error || 'Failed to change password');
    }
  } catch (error) {
    console.error('Password change failed:', error);
    showMessage(changeMsg, error.message, 'error');
  } finally {
    changePasswordBtn.disabled = false;
    changePasswordBtn.textContent = 'Change Password';
  }
});

// ---------------------------
// Wipe All Data (Danger Zone)
// ---------------------------
wipeDataBtn.addEventListener('click', async () => {
  const confirm1 = confirm('⚠️ WARNING: This will permanently delete ALL saved passwords and sign you out. Continue?');
  if (!confirm1) return;

  const confirm2 = confirm('Last chance! All your data will be permanently lost. Continue?');
  if (!confirm2) return;

  wipeDataBtn.disabled = true;
  wipeDataBtn.textContent = 'Clearing...';
  wipeMsg.style.display = 'none';

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_WIPE_DATA' });

    if (resp.ok) {
      showMessage(wipeMsg, '✅ All data cleared successfully. Redirecting...', 'success');
      setTimeout(() => {
        chrome.tabs.create({ url: chrome.runtime.getURL('auth.html') });
        window.close();
      }, 2000);
    } else {
      throw new Error(resp.error || 'Failed to clear data');
    }
  } catch (error) {
    console.error('Data wipe failed:', error);
    showMessage(wipeMsg, error.message, 'error');
  } finally {
    wipeDataBtn.disabled = false;
    wipeDataBtn.textContent = 'Clear All Data';
  }
});
