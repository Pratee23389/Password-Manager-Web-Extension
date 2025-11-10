// LPH Password Manager - Complete VM Backend Integration
// With mnemonic recovery, session persistence, and proper error handling

const API_BASE_URL = 'http://192.168.2.242'; // Your VM IP

// Session state with persistence
let session = {
  token: null,
  user: null,
  kVault: null,
  salt: null,
  unlocked: false,
  privateKey: null,
  publicKey: null,
};

// Storage keys
const STORAGE_KEYS = {
  SESSION_TOKEN: 'pm_session_token',
  USER_EMAIL: 'pm_user_email',
  ENCRYPTED_KVAULT: 'pm_encrypted_kvault',
  SALT: 'pm_salt',
  TEMP_SIGNUP: 'pm_temp_signup',
  TEMP_MNEMONIC: 'pm_temp_mnemonic',
};

// ===== CRYPTO UTILITIES =====

// BIP-39 compatible word list (256 words for 12-word mnemonic)
const BIP39_WORDLIST = [
  'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse',
  'access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act',
  'action','actor','actress','actual','adapt','add','addict','address','adjust','admit',
  'adult','advance','advice','aerobic','afford','afraid','again','age','agent','agree',
  'ahead','aim','air','airport','aisle','alarm','album','alcohol','alert','alien',
  'all','alley','allow','almost','alone','alpha','already','also','alter','always',
  'amateur','amazing','among','amount','amused','analyst','anchor','ancient','anger','angle',
  'angry','animal','ankle','announce','annual','another','answer','antenna','antique','anxiety',
  'any','apart','apology','appear','apple','approve','april','arch','arctic','area',
  'arena','argue','arm','armed','armor','army','around','arrange','arrest','arrive',
  'arrow','art','artefact','artist','artwork','ask','aspect','assault','asset','assist',
  'assume','asthma','athlete','atom','attack','attend','attitude','attract','auction','audit',
  'august','aunt','author','auto','autumn','average','avocado','avoid','awake','aware',
  'away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge','bag',
  'balance','balcony','ball','bamboo','banana','banner','bar','barely','bargain','barrel',
  'base','basic','basket','battle','beach','bean','beauty','because','become','beef',
  'before','begin','behave','behind','believe','below','belt','bench','benefit','best',
  'betray','better','between','beyond','bicycle','bid','bike','bind','biology','bird',
  'birth','bitter','black','blade','blame','blanket','blast','bleak','bless','blind',
  'blood','blossom','blouse','blue','blur','blush','board','boat','body','boil',
  'bomb','bone','bonus','book','boost','border','boring','borrow','boss','bottom',
  'bounce','box','boy','bracket','brain','brand','brass','brave','bread','breeze',
  'brick','bridge','brief','bright','bring','brisk','broccoli','broken','bronze','broom',
  'brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb','bulk',
  'bullet','bundle','bunker','burden','burger','burst','bus','business','busy','butter',
  'buyer','buzz','cabbage','cabin','cable','cactus','cage','cake','call','calm',
  'camera','camp','can','canal','cancel','candy','cannon','canoe','canvas','canyon',
  'capable','capital','captain','car','carbon','card','cargo','carpet','carry','cart',
  'case','cash','casino','castle','casual','cat','catalog','catch','category','cattle',
  'caught','cause','caution','cave','ceiling','celery','cement','census','century','cereal',
  'certain','chair','chalk','champion','change','chaos','chapter','charge','chase','chat',
  'cheap','check','cheese','chef','cherry','chest','chicken','chief','child','chimney',
  'choice','choose','chronic','chuckle','chunk','churn','cigar','cinnamon','circle','citizen',
  'city','civil','claim','clap','clarify','claw','clay','clean','clerk','clever',
  'click','client','cliff','climb','clinic','clip','clock','clog','close','cloth',
  'cloud','clown','club','clump','cluster','clutch','coach','coast','coconut','code',
  'coffee','coil','coin','collect','color','column','combine','come','comfort','comic',
  'common','company','concert','conduct','confirm','congress','connect','consider','control','convince',
  'cook','cool','copper','copy','coral','core','corn','correct','cost','cotton',
];

async function generateMnemonic() {
  const entropy = new Uint8Array(16);
  crypto.getRandomValues(entropy);
  
  const words = [];
  for (let i = 0; i < 12; i++) {
    const index = entropy[i] % BIP39_WORDLIST.length;
    words.push(BIP39_WORDLIST[index]);
  }
  
  return words.join(' ');
}

async function mnemonicToSeed(mnemonic, passphrase = '') {
  const enc = new TextEncoder();
  const mnemonicBytes = enc.encode(mnemonic.normalize('NFKD'));
  const salt = enc.encode('mnemonic' + passphrase.normalize('NFKD'));
  
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
    true,
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
  return await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );
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

// ===== SESSION PERSISTENCE =====

async function saveSession() {
  await chrome.storage.local.set({
    [STORAGE_KEYS.SESSION_TOKEN]: session.token,
    [STORAGE_KEYS.USER_EMAIL]: session.user?.email,
  });
}

async function restoreSession() {
  const stored = await chrome.storage.local.get([
    STORAGE_KEYS.SESSION_TOKEN,
    STORAGE_KEYS.USER_EMAIL,
  ]);
  
  if (stored[STORAGE_KEYS.SESSION_TOKEN] && stored[STORAGE_KEYS.USER_EMAIL]) {
    session.token = stored[STORAGE_KEYS.SESSION_TOKEN];
    session.user = { email: stored[STORAGE_KEYS.USER_EMAIL] };
    return true;
  }
  
  return false;
}

async function clearSession() {
  await chrome.storage.local.remove([
    STORAGE_KEYS.SESSION_TOKEN,
    STORAGE_KEYS.USER_EMAIL,
  ]);
  
  session = {
    token: null,
    user: null,
    kVault: null,
    salt: null,
    unlocked: false,
    privateKey: null,
    publicKey: null,
  };
}

// ===== API CALLS =====

async function apiCall(endpoint, method = 'GET', body = null) {
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json',
    },
    mode: 'cors',
  };
  
  if (session.token) {
    options.headers['Authorization'] = `Bearer ${session.token}`;
  }
  
  if (body) {
    options.body = JSON.stringify(body);
  }
  
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('API call failed:', error);
    throw error;
  }
}

// ===== AUTH FUNCTIONS =====

async function initiateSignup(email, password) {
  try {
    // Generate mnemonic
    const mnemonic = await generateMnemonic();
    
    // Store temporarily
    await chrome.storage.local.set({
      [STORAGE_KEYS.TEMP_SIGNUP]: { email, password },
      [STORAGE_KEYS.TEMP_MNEMONIC]: mnemonic,
    });
    
    return { ok: true, mnemonic };
  } catch (error) {
    console.error('Initiate signup error:', error);
    return { ok: false, error: error.message };
  }
}

async function completeSignup(mnemonic) {
  try {
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.TEMP_SIGNUP,
      STORAGE_KEYS.TEMP_MNEMONIC,
    ]);
    
    if (!stored[STORAGE_KEYS.TEMP_SIGNUP] || !stored[STORAGE_KEYS.TEMP_MNEMONIC]) {
      throw new Error('No signup in progress');
    }
    
    if (mnemonic.trim() !== stored[STORAGE_KEYS.TEMP_MNEMONIC]) {
      throw new Error('Mnemonic does not match');
    }
    
    const { email, password } = stored[STORAGE_KEYS.TEMP_SIGNUP];
    
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
    const kMP = await deriveMasterPasswordKey(password, salt);
    
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
        [STORAGE_KEYS.ENCRYPTED_KVAULT]: encryptedKVault,
        [STORAGE_KEYS.SALT]: saltBase64,
      });
      
      // Save session
      await saveSession();
      
      // Clear temp data
      await chrome.storage.local.remove([
        STORAGE_KEYS.TEMP_SIGNUP,
        STORAGE_KEYS.TEMP_MNEMONIC,
      ]);
      
      return { ok: true, user: response.user };
    }
    
    return response;
  } catch (error) {
    console.error('Complete signup error:', error);
    return { ok: false, error: error.message };
  }
}

async function signIn(email, password) {
  try {
    // Get user data from server
    const response = await apiCall('/api/auth/signin', 'POST', { email });
    
    if (!response.ok) {
      return response;
    }
    
    // Get salt and verifier from local storage
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.SALT,
      STORAGE_KEYS.ENCRYPTED_KVAULT,
    ]);
    
    let salt;
    if (stored[STORAGE_KEYS.SALT]) {
      salt = base64ToBytes(stored[STORAGE_KEYS.SALT]);
    } else if (response.salt) {
      salt = base64ToBytes(response.salt);
      await chrome.storage.local.set({
        [STORAGE_KEYS.SALT]: response.salt,
      });
    } else {
      throw new Error('Salt not found');
    }
    
    // Derive master password key
    const kMP = await deriveMasterPasswordKey(password, salt);
    
    // Verify password using server verifier
    if (response.verifier) {
      try {
        const check = await decryptData(response.verifier, kMP);
        if (!check || check.v !== 'ok') {
          return { ok: false, error: 'Invalid password' };
        }
      } catch (e) {
        return { ok: false, error: 'Invalid password' };
      }
    }
    
    // Get encrypted kVault from local storage
    if (!stored[STORAGE_KEYS.ENCRYPTED_KVAULT]) {
      return { ok: false, error: 'Vault key not found. Please recover your account.' };
    }
    
    // Decrypt kVault
    const kVaultData = await decryptData(stored[STORAGE_KEYS.ENCRYPTED_KVAULT], kMP);
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
    if (keysResponse.ok && keysResponse.keys) {
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
    
    // Save session
    await saveSession();
    
    return { ok: true, user: response.user };
  } catch (error) {
    console.error('Signin error:', error);
    return { ok: false, error: error.message };
  }
}

async function recoverAccount(mnemonic, newPassword) {
  try {
    // Derive vault key from mnemonic
    const seed = await mnemonicToSeed(mnemonic);
    const kVault = await deriveVaultKey(seed);
    
    // Generate new salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltBase64 = bytesToBase64(salt);
    
    // Derive new master password key
    const kMP = await deriveMasterPasswordKey(newPassword, salt);
    
    // Encrypt kVault with new master password
    const kVaultData = await crypto.subtle.exportKey('raw', kVault);
    const encryptedKVault = await encryptData(
      { key: bytesToBase64(new Uint8Array(kVaultData)) },
      kMP
    );
    
    // Store locally
    await chrome.storage.local.set({
      [STORAGE_KEYS.ENCRYPTED_KVAULT]: encryptedKVault,
      [STORAGE_KEYS.SALT]: saltBase64,
    });
    
    return { ok: true };
  } catch (error) {
    console.error('Recover account error:', error);
    return { ok: false, error: error.message };
  }
}

async function signOut() {
  await clearSession();
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
  
  // Update if exists, otherwise add
  const existingIndex = vault[domain].findIndex(c => c.username === username);
  if (existingIndex >= 0) {
    vault[domain][existingIndex].password = password;
  } else {
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

// ===== ICON LOADING =====

async function setActionIconIfAvailable() {
  try {
    const url = chrome.runtime.getURL('icons/logo.png');
    const res = await fetch(url);
    if (!res.ok) return;
    const blob = await res.blob();
    const bmp = await createImageBitmap(blob);
    const sizes = [16, 32, 48, 128];
    const imageData = {};
    for (const s of sizes) {
      imageData[s] = imageToImageData(bmp, s, s);
    }
    await chrome.action.setIcon({ imageData });
  } catch (e) {
    // No logo yet
  }
}

function imageToImageData(img, w, h) {
  const canvas = new OffscreenCanvas(w, h);
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  const ratio = Math.max(w / img.width, h / img.height);
  const nw = Math.round(img.width * ratio);
  const nh = Math.round(img.height * ratio);
  const dx = Math.round((w - nw) / 2);
  const dy = Math.round((h - nh) / 2);
  ctx.drawImage(img, dx, dy, nw, nh);
  return ctx.getImageData(0, 0, w, h);
}

// Initialize
(async () => {
  await setActionIconIfAvailable();
  await restoreSession();
})();

// ===== MESSAGE HANDLER =====

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'PM_GENERATE_MNEMONIC':
          sendResponse(await initiateSignup(msg.email, msg.password));
          break;
          
        case 'PM_GET_MNEMONIC': {
          const stored = await chrome.storage.local.get(STORAGE_KEYS.TEMP_MNEMONIC);
          sendResponse({ ok: true, mnemonic: stored[STORAGE_KEYS.TEMP_MNEMONIC] || null });
          break;
        }
          
        case 'PM_VERIFY_MNEMONIC':
          sendResponse(await completeSignup(msg.mnemonic));
          break;
          
        case 'PM_SIGNIN':
          sendResponse(await signIn(msg.email, msg.password));
          break;
          
        case 'PM_RECOVER_ACCOUNT':
          sendResponse(await recoverAccount(msg.mnemonic, msg.newPassword));
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

        case 'PM_CHANGE_PASSWORD': {
            try {
              const { currentPassword, newPassword } = msg;

              // Must be signed in
              if (!session.user?.email) {
                sendResponse({ ok: false, error: 'No user signed in' });
                break;
              }

              // Verify current password (try unlock logic)
              const verify = await signIn(session.user.email, currentPassword);
              if (!verify.ok) {
                sendResponse({ ok: false, error: 'Incorrect current password' });
                break;
              }

              // Re-derive master key and re-encrypt vault
              const salt = crypto.getRandomValues(new Uint8Array(16));
              const saltBase64 = bytesToBase64(salt);
              const kMP = await deriveMasterPasswordKey(newPassword, salt);
              const kVaultData = await crypto.subtle.exportKey('raw', session.kVault);
              const encryptedKVault = await encryptData(
                { key: bytesToBase64(new Uint8Array(kVaultData)) },
                kMP
              );

              // Save locally
              await chrome.storage.local.set({
                [STORAGE_KEYS.ENCRYPTED_KVAULT]: encryptedKVault,
                [STORAGE_KEYS.SALT]: saltBase64,
              });

              // Optional: notify your VM backend
              try {
                await apiCall('/api/auth/change-password', 'POST', {
                  email: session.user.email,
                  newPassword,
                });
              } catch (err) {
                console.warn('Server password update failed (local only):', err.message);
              }

              sendResponse({ ok: true });
            } catch (error) {
              console.error('PM_CHANGE_PASSWORD error:', error);
              sendResponse({ ok: false, error: error.message });
            }
            break;
            }

          
        default:
          sendResponse({ ok: false, error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Message handler error:', error);
      sendResponse({ ok: false, error: error.message });
    }
  })();
  return true;
});

console.log('🔐 LPH Password Manager - VM Backend - Loaded');