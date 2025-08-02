# Stasher Web

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Secure secret sharing for browser DevTools**. Zero-install, zero-trust, burn-after-read secret sharing that works in any browser console.

## Why?

I just wanted to share a password.  
Not spin up a server. Not register for some "secure" web app. Not trust a Slack thread.  
Just. Send. A. Secret.

So I built Stasher — for people who are busy, paranoid, or both.

- Works instantly in any browser
- Encrypts everything before it ever leaves your machine  
- Secrets self-destruct after one read or 10 minutes
- No account, no login, no metadata, no snooping
- Cross-platform — create in browser, access from terminal (and vice versa)
- Share however you like — Slack, email, QR code, carrier pigeon...

Basically, it's like a Mission Impossible tape, but for API keys.

## Quick Start

**Bookmarklet (Recommended)**
1. Copy this bookmarklet URL:
   ```javascript
   javascript:(function(){var w=window.open('https://app.stasher.dev/','stasher','width=400,height=300,resizable=yes,scrollbars=no,status=no,location=no,toolbar=no,menubar=no');if(w){w.focus();}else{alert('Popup blocked - please allow popups for this site');}})();
   ```
2. Create a new bookmark and paste the URL above
3. Click the bookmark on any page to open Stasher in a popup window

**Direct Access**
Visit **[app.stasher.dev](https://app.stasher.dev)** directly

## Usage

The popup interface provides three simple operations:

1. **enstash** - Encrypt and store a secret
   - Enter your secret text
   - Click "enstash" 
   - Get back: `a1b2c3d4-e5f6-7890-abcd-ef1234567890:base64key...`

2. **destash** - Retrieve a secret (burns after reading)
   - Enter the full token: `uuid:key`
   - Click "destash"
   - Get back your original secret

3. **unstash** - Delete a secret manually  
   - Enter token or just the UUID
   - Click "unstash"
   - Secret is permanently deleted

## Real-World Examples

```js
// Share API key with colleague
enstash`API_KEY=sk-1234567890abcdef`

// Send password over Slack
enstash`deployment-password-123`

// Share temporary access token
enstash`Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...`

// Multi-line secrets work too
enstash`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
-----END PRIVATE KEY-----`
```

## Security Features

- **AES-256-GCM Encryption** - Military-grade encryption in your browser
- **Zero-Knowledge** - Server never sees your plaintext secrets  
- **Burn-After-Read** - Secrets deleted after first access
- **Auto-Expiry** - 10-minute maximum lifetime
- **Client-Side Crypto** - All encryption happens in your browser
- **No Logs** - Secrets never logged to console or stored

## Architecture

**Frontend**: Pure ESM module with SubtleCrypto  
**Backend**: Cloudflare Workers + KV storage  
**Encryption**: AES-256-GCM with unique keys per secret  
**Distribution**: CDN-hosted, zero dependencies  

## 🌐 Browser Support

Works in all modern browsers with:
- **SubtleCrypto API** (Chrome, Firefox, Safari, Edge)
- **ES Modules** (Native `import()` support)
- **Fetch API** (Standard in all evergreen browsers)

## Related Projects

- **[Stasher CLI](https://github.com/stasher-dev/stasher-cli)** - Terminal version (`npm install -g stasher-cli or npx`)
- **[Stasher Worker](https://github.com/stasher-dev/stasher-worker)** - Cloudflare Workers API backend

## 🚀 Deployment

**File Structure:**
```
stasher-web/
├── stasher-web.mjs    # Main ESM module  
├── index.html         # Install page
├── README.md          # Documentation
└── .gitignore         # Git ignores

## Acknowledgments

- **Cloudflare** - For Workers and Pages hosting
- **Web Crypto API** - For secure client-side encryption
- **Modern Browsers** - For native ES modules support

---

Built for developers who need to share secrets quickly, securely, and without friction.