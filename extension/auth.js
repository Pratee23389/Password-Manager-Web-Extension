// ======================================================
// 🔐 LPH Password Manager - Authentication Page Logic
// ======================================================

// === TAB SWITCHING ===
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const targetTab = tab.dataset.tab;

    // Update tab visuals
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    // Show/hide corresponding forms
    document.getElementById('signinForm').style.display =
      targetTab === 'signin' ? 'block' : 'none';
    document.getElementById('signupForm').style.display =
      targetTab === 'signup' ? 'block' : 'none';

    // Clear previous messages
    clearMessages();
  });
});

// === MESSAGE HELPERS ===
function showMessage(formId, text, type = 'error') {
  const msgEl = document.getElementById(`${formId}-message`);
  if (!msgEl) return;
  msgEl.textContent = text;
  msgEl.className = `message ${type}`;
  msgEl.style.display = 'block';
}

function clearMessages() {
  document.querySelectorAll('.message').forEach(el => {
    el.style.display = 'none';
    el.textContent = '';
  });
}

// === SIGN IN FORM HANDLER ===
document.getElementById('signinForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();

  const email = document.getElementById('signin-email').value.trim();
  const password = document.getElementById('signin-password').value;
  const btn = e.target.querySelector('button[type="submit"]');

  if (!email || !password) {
    showMessage('signin', 'Please fill in all fields');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in...';

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'PM_SIGNIN',
      email,
      password,
    });

    if (response.ok) {
      showMessage('signin', '✅ Signed in successfully!', 'success');
      setTimeout(() => {
        window.close();
      }, 1000);
    } else {
      throw new Error(response.error || 'Sign in failed');
    }
  } catch (error) {
    console.error('Sign-in error:', error);
    showMessage('signin', error.message || 'Failed to sign in');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
});

// === SIGN UP FORM HANDLER ===
document.getElementById('signupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();

  const email = document.getElementById('signup-email').value.trim();
  const password = document.getElementById('signup-password').value;
  const confirm = document.getElementById('signup-confirm').value;
  const btn = e.target.querySelector('button[type="submit"]');

  // Validation
  if (!email || !password || !confirm) {
    showMessage('signup', 'Please fill in all fields');
    return;
  }

  if (password !== confirm) {
    showMessage('signup', 'Passwords do not match');
    return;
  }

  if (password.length < 8) {
    showMessage('signup', 'Master password must be at least 8 characters');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Creating account...';

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'PM_GENERATE_MNEMONIC',
      email,
      password,
    });

    if (response.ok && response.mnemonic) {
      // Store mnemonic temporarily
      await chrome.storage.local.set({ pendingMnemonic: response.mnemonic });

      // Redirect to mnemonic display page
      window.location.href = 'mnemonic-display.html';
    } else {
      throw new Error(response.error || 'Sign up failed');
    }
  } catch (error) {
    console.error('Signup error:', error);
    showMessage('signup', error.message || 'Unexpected error during sign-up');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Account';
  }
});

// === CHECK IF ALREADY SIGNED IN ===
(async () => {
  try {
    const status = await chrome.runtime.sendMessage({ type: 'PM_GET_USER' });
    if (status.ok && status.user) {
      showMessage('signin', `Already signed in as ${status.user.email}`, 'success');
      setTimeout(() => window.close(), 1500);
    }
  } catch (e) {
    // not signed in, continue normally
  }
})();
