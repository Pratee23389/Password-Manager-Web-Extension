async function setMasterPassword(password) {
  return chrome.runtime.sendMessage({ type: 'PM_SET_MASTER', password });
}

async function wipeAll() {
  return chrome.runtime.sendMessage({ type: 'PM_WIPE_ALL' });
}

function setMsg(id, text) {
  document.getElementById(id).textContent = text;
}

document.getElementById('setPwdBtn').addEventListener('click', async () => {
  const a = document.getElementById('newPwd').value;
  const b = document.getElementById('confirmPwd').value;
  if (!a) return setMsg('setPwdMsg', 'Enter a password');
  if (a !== b) return setMsg('setPwdMsg', 'Passwords do not match');
  const res = await setMasterPassword(a);
  if (res?.ok) setMsg('setPwdMsg', 'Master password set. LPH is unlocked now.');
  else setMsg('setPwdMsg', res?.error || 'Failed to set password');
});

document.getElementById('wipeBtn').addEventListener('click', async () => {
  if (!confirm('This will erase all stored data. Continue?')) return;
  const res = await wipeAll();
  if (res?.ok) setMsg('wipeMsg', 'All data wiped.');
  else setMsg('wipeMsg', res?.error || 'Failed to wipe');
});
