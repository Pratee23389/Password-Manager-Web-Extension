
# LPH Password Manager (Chromium extension)

A minimal, local-first Chrome/Chromium extension that detects login forms, lets you save credentials encrypted with a master password, and autofills them later.

This is a simple educational sample, not a full-featured password manager. Use at your own risk.

## What's changed
- Renamed to "LPH Password Manager" across UI and code.
- Fixed popup layout so long site names wrap and the panel doesn't overflow.
- Added optional runtime action icon loading: place your logo at `extension/icons/logo.png` and the extension will use it automatically.

## Install (Load unpacked)
1. Open Chrome and navigate to `chrome://extensions`.
2. Enable "Developer mode" (toggle in the top-right).
3. Click "Load unpacked" and select this `extension` folder.
4. You should see "LPH Password Manager" in your extensions bar.

## Adding the provided logo

**IMPORTANT:** Save the "Los Pollos Hermanos" logo image to:
```
extension/icons/logo.png
```

Then reload the extension in Chrome (`chrome://extensions` → click the reload icon).

The extension manifest is already configured to use this logo for all icon sizes. Chrome will scale it automatically.

### Manual save steps:
1. Right-click the logo image attachment (Los Pollos Hermanos chickens)
2. Save it as `logo.png`
3. Place it in: `/Users/udaypandita/Desktop/USS Project/LPH/extension/icons/logo.png`
4. Reload the extension

On macOS you can also generate optimized sizes:

```zsh
# Replace source.png with your provided image path
cp source.png extension/icons/logo.png
sips -Z 128 source.png --out extension/icons/lph-128.png
sips -Z 48  source.png --out extension/icons/lph-48.png
sips -Z 32  source.png --out extension/icons/lph-32.png
sips -Z 16  source.png --out extension/icons/lph-16.png
```

After adding files, reload the extension from `chrome://extensions`.

## Usage
1. Click the LPH icon and open "Options" to set a master password.
2. Visit a site with a login form. In the popup, unlock with your master password.
3. Log in normally; when you submit, LPH will save the credentials if unlocked.
4. Next time on the same site, open the popup and press "Autofill" next to a saved username.

## Privacy and limitations
- All data stays local in your browser's `chrome.storage.local`. No cloud sync is implemented.
- If you forget the master password, the data cannot be recovered.
- The service worker can be suspended by the browser; you may need to re-unlock after idle periods.
- Autofill heuristics are basic and may not handle complex or multi-step login flows.

## Dev notes
- Manifest V3 background script is an ES module.
- No build step is required; files are plain JS/HTML/CSS.
