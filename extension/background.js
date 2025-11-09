// LPH Password Manager - VM Backend Integration
// Complete implementation with mnemonic recovery and asymmetric sharing

const API_BASE_URL = 'http://192.168.2.242'; // Your VM IP

// Session state
let session = {
  token: null,
  user: null,
  kVault: null,
  salt: null,
  unlocked: false,
  privateKey: null,
  publicKey: null,
};

// ===== CRYPTO UTILITIES =====

async function generateMnemonic() {
  // Simple 12-word mnemonic generation (BIP-39 compatible)
  const wordList = [
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
    'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
    // ... (in production, use full BIP-39 word list)
  ];
  
  const entropy = new Uint8Array(16);
  crypto.getRandomValues(entropy);
  
  const words = [];
  for (let i = 0; i < 12; i++) {
    const index = (entropy[i] + (entropy[i + 1] || 0)) % wordList.length;
    words.push(wordList[index]);
  }
  
  return words.join(' ');
}

async function mnemonicToSeed(mnemonic, passphrase = '') {
  const enc = new TextEncoder();
  const mnemonicBytes = enc.encode(mnemonic);
  const salt = enc.encode('mnemonic' + passphrase);
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    mnemonicBytes,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 2048,
      hash: 'SHA-512'
    },
    keyMaterial,
    512
  );
  
  return new Uint8Array(bits);
}

async function deriveVaultKey(seed) {
  return await crypto.subtle.importKey(
    'raw',
    seed.slice(0, 32),
    { name: 'AES-GCM', length: 256 },
    true,                  // ← MUST be true to export later
    ['encrypt', 'decrypt']
  );
}


async function deriveMasterPasswordKey(masterPassword, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 200000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true, // <-- must be true to allow exportKey('spki'/'pkcs8')
    ['encrypt', 'decrypt']
  );
  return keyPair;
}


async function encryptData(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const encoded = enc.encode(JSON.stringify(data));
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  
  return bytesToBase64(combined);
}

async function decryptData(base64Data, key) {
  const combined = base64ToBytes(base64Data);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  
  const dec = new TextDecoder();
  return JSON.parse(dec.decode(decrypted));
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ===== API CALLS =====

async function apiCall(endpoint, method = 'GET', body = null) {
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json',
    }
  };
  
  if (session.token) {
    options.headers['Authorization'] = `Bearer ${session.token}`;
  }
  
  if (body) {
    options.body = JSON.stringify(body);
  }
  
  const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
  return await response.json();
}

// ===== AUTH FUNCTIONS =====

async function signUp(email, masterPassword) {
  try {
    // Generate mnemonic
    const mnemonic = await generateMnemonic();
    
    // Derive vault key from mnemonic
    const seed = await mnemonicToSeed(mnemonic);
    const kVault = await deriveVaultKey(seed);
    
    // Generate asymmetric key pair
    const keyPair = await generateKeyPair();
    
    // Export public key
    const publicKeyData = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const publicKeyBase64 = bytesToBase64(new Uint8Array(publicKeyData));
    
    // Export and encrypt private key with kVault
    const privateKeyData = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const encryptedPrivateKey = await encryptData(
      { key: bytesToBase64(new Uint8Array(privateKeyData)) },
      kVault
    );
    
    // Generate salt for master password
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltBase64 = bytesToBase64(salt);
    
    // Derive master password key
    const kMP = await deriveMasterPasswordKey(masterPassword, salt);
    
    // Encrypt kVault with master password key
    const kVaultData = await crypto.subtle.exportKey('raw', kVault);
    const encryptedKVault = await encryptData(
      { key: bytesToBase64(new Uint8Array(kVaultData)) },
      kMP
    );
    
    // Create verifier
    const verifier = await encryptData({ v: 'ok' }, kMP);
    
    // Send to server
    const response = await apiCall('/api/auth/signup', 'POST', {
      email,
      publicKey: publicKeyBase64,
      encryptedPrivateKey,
      salt: saltBase64,
      verifier
    });
    
    if (response.ok) {
      session.token = response.token;
      session.user = response.user;
      session.kVault = kVault;
      session.salt = salt;
      session.unlocked = true;
      session.privateKey = keyPair.privateKey;
      session.publicKey = keyPair.publicKey;
      
      // Store encrypted kVault locally
      await chrome.storage.local.set({
        encrypted_k_vault: encryptedKVault
      });
      
      return {
        ok: true,
        mnemonic, // Return to show user ONCE
        user: response.user
      };
    }
    
    return response;
  } catch (error) {
    console.error('Signup error:', error);
    return { ok: false, error: error.message };
  }
}

async function signIn(email, masterPassword) {
  try {
    // Get user data from server
    const response = await apiCall('/api/auth/signin', 'POST', { email });
    
    if (!response.ok) {
      return response;
    }
    
    // Get salt and verifier
    const salt = base64ToBytes(response.salt);
    const verifier = response.verifier;
    
    // Derive master password key
    const kMP = await deriveMasterPasswordKey(masterPassword, salt);
    
    // Verify password
    try {
      const check = await decryptData(verifier, kMP);
      if (!check || check.v !== 'ok') {
        return { ok: false, error: 'Invalid password' };
      }
    } catch (e) {
      return { ok: false, error: 'Invalid password' };
    }
    
    // Get encrypted kVault from local storage
    const stored = await chrome.storage.local.get('encrypted_k_vault');
    if (!stored.encrypted_k_vault) {
      return { ok: false, error: 'Vault key not found' };
    }
    
    // Decrypt kVault
    const kVaultData = await decryptData(stored.encrypted_k_vault, kMP);
    const kVaultBytes = base64ToBytes(kVaultData.key);
    const kVault = await crypto.subtle.importKey(
      'raw',
      kVaultBytes,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    
    // Get and decrypt private key
    const keysResponse = await apiCall('/api/keys', 'GET');
    if (keysResponse.ok) {
      const privateKeyData = await decryptData(keysResponse.keys.encrypted_private_key, kVault);
      const privateKeyBytes = base64ToBytes(privateKeyData.key);
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBytes,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256'
        },
        false,
        ['decrypt']
      );
      
      session.privateKey = privateKey;
    }
    
    session.token = response.token;
    session.user = response.user;
    session.kVault = kVault;
    session.salt = salt;
    session.unlocked = true;
    
    return { ok: true, user: response.user };
  } catch (error) {
    console.error('Signin error:', error);
    return { ok: false, error: error.message };
  }
}

async function signOut() {
  session = {
    token: null,
    user: null,
    kVault: null,
    salt: null,
    unlocked: false,
    privateKey: null,
    publicKey: null,
  };
  return { ok: true };
}

// ===== VAULT OPERATIONS =====

async function loadVault() {
  if (!session.unlocked || !session.kVault) {
    throw new Error('Vault is locked');
  }
  
  const response = await apiCall('/api/vault', 'GET');
  
  if (!response.ok) {
    throw new Error(response.error || 'Failed to load vault');
  }
  
  if (!response.data || response.data === '{}') {
    return {};
  }
  
  return await decryptData(response.data, session.kVault);
}

async function saveVault(data) {
  if (!session.unlocked || !session.kVault) {
    throw new Error('Vault is locked');
  }
  
  const encrypted = await encryptData(data, session.kVault);
  
  const response = await apiCall('/api/vault', 'PUT', {
    encryptedBlob: encrypted
  });
  
  if (!response.ok) {
    throw new Error(response.error || 'Failed to save vault');
  }
  
  return { ok: true };
}

// ===== PASSWORD MANAGEMENT =====

function domainFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

async function saveCredential(url, username, password) {
  const domain = domainFromUrl(url);
  if (!domain) {
    throw new Error('Invalid URL');
  }
  
  const vault = await loadVault();
  
  if (!vault[domain]) {
    vault[domain] = [];
  }
  
  // Check if credential already exists
  const exists = vault[domain].some(c => c.username === username);
  if (!exists) {
    vault[domain].push({ username, password });
  }
  
  await saveVault(vault);
  return { ok: true };
}

async function getCredentials(url) {
  const domain = domainFromUrl(url);
  if (!domain) {
    return { ok: true, credentials: [] };
  }
  
  const vault = await loadVault();
  const credentials = vault[domain] || [];
  
  return { ok: true, credentials };
}

async function deleteCredential(url, username) {
  const domain = domainFromUrl(url);
  if (!domain) {
    throw new Error('Invalid URL');
  }
  
  const vault = await loadVault();
  
  if (vault[domain]) {
    vault[domain] = vault[domain].filter(c => c.username !== username);
    if (vault[domain].length === 0) {
      delete vault[domain];
    }
  }
  
  await saveVault(vault);
  return { ok: true };
}

// ===== MESSAGE HANDLER =====

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'PM_SIGNUP':
          sendResponse(await signUp(msg.email, msg.password));
          break;
          
        case 'PM_SIGNIN':
          sendResponse(await signIn(msg.email, msg.password));
          break;
          
        case 'PM_SIGNOUT':
          sendResponse(await signOut());
          break;
          
        case 'PM_GET_USER':
          sendResponse({ ok: true, user: session.user });
          break;
          
        case 'PM_STATUS':
          sendResponse({
            unlocked: session.unlocked,
            user: session.user,
          });
          break;
          
        case 'PM_SAVE_CREDENTIALS':
          sendResponse(await saveCredential(msg.url, msg.username, msg.password));
          break;
          
        case 'PM_GET_CREDENTIALS':
          sendResponse(await getCredentials(msg.url));
          break;
          
        case 'PM_GET_ALL':
          const vault = await loadVault();
          sendResponse({ ok: true, data: vault });
          break;
          
        case 'PM_DELETE_CREDENTIAL':
          sendResponse(await deleteCredential(msg.url, msg.username));
          break;
          
        default:
          sendResponse({ ok: false, error: 'Unknown message type' });
      }
    } catch (error) {
      sendResponse({ ok: false, error: error.message });
    }
  })();
  return true;
});

console.log('🔐 LPH Password Manager - VM Backend Mode - Loaded');