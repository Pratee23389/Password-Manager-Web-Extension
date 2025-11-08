// LPH Password Manager - Authentication Page Logic

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const targetTab = tab.dataset.tab;
    
    // Update tab styles
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    
    // Show/hide forms
    document.getElementById('signinForm').style.display = targetTab === 'signin' ? 'block' : 'none';
    document.getElementById('signupForm').style.display = targetTab === 'signup' ? 'block' : 'none';
    
    // Clear messages
    clearMessages();
  });
});

// Message helpers
function showMessage(formId, text, type = 'error') {
  const msgEl = document.getElementById(`${formId}-message`);
  msgEl.textContent = text;
  msgEl.className = `message ${type}`;
  msgEl.style.display = 'block';
}

function clearMessages() {
  document.querySelectorAll('.message').forEach(el => {
    el.style.display = 'none';
  });
}

// Sign In
document.getElementById('signinForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  
  const email = document.getElementById('signin-email').value;
  const password = document.getElementById('signin-password').value;
  const btn = e.target.querySelector('button[type="submit"]');
  
  btn.disabled = true;
  btn.textContent = 'Signing in...';
  
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'PM_SIGNIN',
      email,
      password,
    });
    
    if (response.ok) {
      showMessage('signin', '✓ Signed in successfully!', 'success');
      setTimeout(() => {
        window.close();
      }, 1000);
    } else {
      throw new Error(response.error || 'Sign in failed');
    }
  } catch (error) {
    showMessage('signin', error.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
});

// Sign Up
document.getElementById('signupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  
  const email = document.getElementById('signup-email').value;
  const password = document.getElementById('signup-password').value;
  const confirm = document.getElementById('signup-confirm').value;
  const btn = e.target.querySelector('button[type="submit"]');
  
  // Validate master password
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
      type: 'PM_SIGNUP',
      email,
      password,
    });
    
    if (response.ok) {
      showMessage('signup', 
        '✓ Account created successfully! Redirecting to extension...',
        'success'
      );
      
      // Close window after success
      setTimeout(() => {
        window.close();
      }, 1500);
    } else {
      throw new Error(response.error || 'Sign up failed');
    }
  } catch (error) {
    showMessage('signup', error.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Account';
  }
});

// Back link
document.getElementById('backLink').addEventListener('click', (e) => {
  e.preventDefault();
  window.close();
});

// Check if already signed in
(async () => {
  try {
    const status = await chrome.runtime.sendMessage({ type: 'PM_GET_USER' });
    if (status.ok && status.user) {
      showMessage('signin', `Already signed in as ${status.user.email}`, 'success');
      setTimeout(() => window.close(), 2000);
    }
  } catch (e) {
    // Not signed in, continue normally
  }
})();