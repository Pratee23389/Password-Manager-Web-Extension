// ======================================================
// 🔐 LPH Password Manager - Account Recovery Logic
// ======================================================

const form = document.getElementById('recoverForm');
const msg = document.getElementById('msg');

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  // Normalize and validate input
  const mnemonic = document
    .getElementById('mnemonic')
    .value.trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
  const newpw = document.getElementById('newpw').value;
  const confirm = document.getElementById('confirm').value;
  const btn = form.querySelector('button[type="submit"]');

  if (!mnemonic) {
    showMessage('Please enter your recovery phrase.', 'error');
    return;
  }

  const words = mnemonic.split(' ');
  if (words.length !== 12) {
    showMessage('Recovery phrase must be exactly 12 words.', 'error');
    return;
  }

  if (newpw.length < 8) {
    showMessage('New password must be at least 8 characters.', 'error');
    return;
  }

  if (newpw !== confirm) {
    showMessage('Passwords do not match.', 'error');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Recovering...';

  try {
    // Send recovery request to background script
    const resp = await chrome.runtime.sendMessage({
      type: 'PM_RECOVER_ACCOUNT',
      mnemonic,
      newPassword: newpw,
    });

    if (resp.ok) {
      showMessage(
        '✅ Recovery successful! Please sign in with your new password.',
        'success'
      );
      setTimeout(() => {
        window.location.href = 'auth.html';
      }, 2000);
    } else {
      throw new Error(resp.error || 'Recovery failed. Please check your phrase.');
    }
  } catch (err) {
    showMessage(err.message || 'Recovery failed.', 'error');
    btn.disabled = false;
    btn.textContent = 'Recover Account';
  }
});

function showMessage(text, type) {
  msg.textContent = text;
  msg.className = `message ${type}`;
  msg.style.display = 'block';
}
