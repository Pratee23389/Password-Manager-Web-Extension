# LPH Password Manager - Local-Only Implementation

## Summary of Changes

All Supabase cloud sync functionality has been removed. The extension now works as a **local-only password manager** with these key features:

### What Changed

#### 1. **Authentication Flow**
- **Before**: Optional Supabase cloud auth with local fallback
- **Now**: Local-only authentication stored in `chrome.storage.local`
- Users create an account with:
  - **Email**: For account identification
  - **Account Password**: For signing in (min 6 chars)
  - **Master Password**: For encrypting the vault (min 8 chars)

#### 2. **Sign-Up Process** (`auth.html` / `auth.js`)
- Added master password fields to sign-up form
- Users must enter and confirm both account password AND master password
- Master password is set immediately during account creation
- Account creation now unlocks the vault automatically

#### 3. **Background Service** (`background.js`)
- Removed all Supabase imports and initialization
- Removed `syncEnabled` from session state
- Removed `pushVaultToCloud()` and `pullVaultFromCloud()` functions
- Simplified `signUp()` to accept `masterPassword` parameter
- Simplified `unlock()` - no cloud vault pulling
- Simplified `saveAllData()` - no auto-sync after saves
- Removed `PM_SYNC_NOW` message handler
- Removed dev test credentials loader (DEV_TEST_CREDS)
- Updated `PM_STATUS` response - removed `syncEnabled` field

#### 4. **Popup UI** (`popup.html` / `popup.js`)
- Removed sync button from header
- Removed sync-related status text (no more "Unlocked & Synced")
- Status now shows simply "Unlocked" or "Locked"
- Removed `syncNow()` functionality
- Removed sync button event listener

#### 5. **Manifest** (`manifest.json`)
- Updated description to reflect local-only storage
- Removed `config.js` from web_accessible_resources

#### 6. **Storage Keys**
Simplified storage structure:
- `pm_local_user`: User account (email + hashed password)
- `pm_salt`: Encryption salt
- `pm_verifier`: Master password verifier
- `pm_data`: Encrypted vault blob

Removed:
- `pm_supabase_session`
- `pm_sync_enabled`
- `pm_last_sync`

### Security Model

1. **Account Password**: PBKDF2-hashed (200k iterations) with random salt, stored locally
2. **Master Password**: Used to derive AES-GCM encryption key, never stored
3. **Vault Data**: Encrypted with master password, stored locally in `pm_data`

### How It Works Now

1. **Sign Up**:
   - Enter email, account password, and master password
   - Account password is hashed and stored
   - Master password encrypts the vault
   - Vault is unlocked immediately

2. **Sign In**:
   - Enter email and account password
   - Password is verified against stored hash
   - User is signed in but vault remains locked

3. **Unlock Vault**:
   - Enter master password
   - Derives encryption key and unlocks vault
   - Can now view/add/edit passwords

4. **Sign Out**:
   - Clears session and local user data
   - Redirects to auth page

### Files Modified

- `background.js` - Removed Supabase, simplified to local-only
- `auth.html` - Added master password fields to sign-up form
- `auth.js` - Updated sign-up handler to send master password
- `popup.html` - Removed sync button
- `popup.js` - Removed sync functionality
- `manifest.json` - Updated description, removed config.js

### Files No Longer Needed

- `config.js` - Supabase configuration (can be deleted)
- `users.json` - Dev test credentials (can be deleted)

### Testing Checklist

- [ ] Sign up with new account (email + account password + master password)
- [ ] Verify account is created and vault is unlocked
- [ ] Close extension and reopen - should show unlock form
- [ ] Unlock with master password
- [ ] Add a password, verify it's saved
- [ ] Sign out, verify auth page opens
- [ ] Sign in again with account password
- [ ] Unlock vault with master password
- [ ] Verify saved passwords are still there
- [ ] Delete extension data and reinstall - should show auth page

---

**Note**: All data is stored locally. If the extension is uninstalled or browser data is cleared, all passwords will be lost. Master password cannot be recovered if forgotten.
