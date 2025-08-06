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
1. Visit **[stasher.dev](https://stasher.dev)** and drag the bookmarklet to your bookmark bar
2. Or create a bookmark manually with this URL:
   ```javascript
   javascript:(function(){var left=Math.floor(screen.width/2-400);var top=Math.floor(screen.height/2-225);var features='width=800,height=450,resizable=yes,scrollbars=no,status=no,location=no,toolbar=no,menubar=no,left='+left+',top='+top+',noopener,noreferrer';var w=window.open('https://app.stasher.dev/','stasher',features);if(w){w.focus();}else{alert("Popup blocked – please allow popups for this site");}})();
   ```
3. Click the bookmark on any page to open Stasher in a secure popup window

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

### Fortress-Level Security Architecture

**Crypto Isolation**
- **Web Worker Thread Isolation** - All cryptographic operations run in isolated worker threads
- **AES-256-GCM Encryption** - Military-grade encryption with secure memory wiping
- **Blob URL Workers** - Dynamic worker creation prevents code injection attacks
- **Zero-Knowledge** - Server never sees your plaintext secrets

**Transport & Content Security**
- **HSTS Preload Ready** - 2-year Strict-Transport-Security with subdomain protection
- **Enhanced CSP** - Strict Content Security Policy with monitoring for future migration
- **Origin Isolation** - Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy
- **Accept Header Validation** - Defense-in-depth content type checking

**Attack Surface Reduction**
- **X-Frame-Options: DENY** - Prevents clickjacking attacks
- **Comprehensive Permissions Policy** - Blocks geolocation, camera, microphone access
- **No Referrer Leakage** - Referrer-Policy: no-referrer
- **Window.open() Sandboxing** - Natural process isolation via popup windows

**Runtime Security**
- **Burn-After-Read** - Secrets deleted after first access
- **Auto-Expiry** - 10-minute maximum lifetime
- **Memory Wiping** - Cryptographic keys cleared from memory after use
- **Timeout Cleanup** - Automatic resource cleanup prevents memory leaks

## Architecture

### Modern Security-First Design

**Frontend Architecture**
- **Web Worker Crypto Isolation** - All encryption runs in dedicated worker threads
- **Cloudflare Workers Runtime** - Edge computing with global distribution
- **Build-Time Code Injection** - Crypto worker code embedded at build time
- **Zero External Dependencies** - Self-contained security model

**⚡ Backend Infrastructure**
- **Cloudflare Workers + KV** - Serverless edge computing with global key-value storage
- **Enhanced Security Headers** - Comprehensive HTTP security header stack
- **Content Validation** - Accept header checking and content type enforcement
- **HSTS Preload Ready** - Transport Layer Security with preload list eligibility

**Crypto Architecture**
- **Thread-Isolated AES-256-GCM** - Military-grade encryption in isolated Web Workers
- **Unique Keys Per Secret** - Each secret gets its own encryption key
- **Secure Memory Management** - Cryptographic material wiped after use
- **Blob URL Worker Creation** - Dynamic worker instantiation prevents injection

**Distribution & Access**
- **CDN Global Edge** - Low-latency access worldwide via Cloudflare's network
- **Bookmarklet Integration** - One-click access from any webpage
- **Window.open() Sandboxing** - Natural browser process isolation
- **Responsive Design** - Works across desktop and mobile browsers  

## Browser Support

**Requires Modern Browser Features:**
- **Web Workers** - For crypto thread isolation (Chrome, Firefox, Safari, Edge)
- **SubtleCrypto API** - For AES-256-GCM encryption (All evergreen browsers)
- **Blob URLs** - For dynamic worker creation (Universal support)
- **ES Modules** - Native `import()` support (IE11+ excluded)
- **Fetch API** - For API communication (Standard in all modern browsers)

**Security Features Enabled:**
- **Content Security Policy Level 3** - Enhanced CSP with report-only monitoring
- **Permissions Policy** - Advanced permission controls (Chromium-based browsers)
- **Cross-Origin Policies** - COOP/CORP isolation (Chrome 83+, Firefox 79+)

## Related Projects

- **[Stasher CLI](https://github.com/stasher-dev/stasher-cli)** - Terminal version (`npm install -g stasher-cli` or `npx`)
- **[Stasher API](https://github.com/stasher-dev/stasher-api)** - Cloudflare Workers API backend (open source)

## 🚀 Deployment

🚀 **Automated CI/CD Pipeline**

This application features automated deployment via [stasher-ci](https://github.com/stasher-dev/stasher-ci):

- **Automatic Deployment**: Pushes to `main` branch automatically deploy to [app.stasher.dev](https://app.stasher.dev)
- **Cloudflare Workers**: Deployed as a secure, high-performance edge application  
- **Build Pipeline**: ESBuild compilation, TypeScript checking, and optimization
- **Zero Downtime**: Seamless updates with Cloudflare's global edge network
- **Security Hardened**: CSP headers, nonce-based security, and fortress-level protections

**Deployment Status**: [![CI/CD Pipeline](https://github.com/stasher-dev/stasher-app/actions/workflows/ci.yml/badge.svg)](https://github.com/stasher-dev/stasher-app/actions/workflows/ci.yml)

**File Structure:**
```
stasher-app/
├── src/
│   ├── stasher_app.ts     # Main TypeScript application
│   ├── worker.ts          # Cloudflare Worker entry point
│   └── crypto-*.ts        # Encryption modules
├── dist/                  # Built output (auto-generated)
├── esbuild.config.js      # Build configuration
└── wrangler.toml          # Cloudflare deployment config

## Acknowledgments

- **Cloudflare** - For Workers and Pages hosting
- **Web Crypto API** - For secure client-side encryption
- **Modern Browsers** - For native ES modules support

---

Built for developers who need to share secrets quickly, securely, and without friction.