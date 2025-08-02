/**
 * Stasher Web Worker - Static file server
 * Serves index.html install page and stasher-web.mjs module
 */

// Embed the ESM module content
const MODULE_CONTENT = `/**
 * Stasher Web - Browser DevTools version of stasher-cli
 * Zero-dependency ESM module for secure secret sharing
 * 
 * Usage:
 *   import("https://install.stasher.dev/stasher-web.mjs").then(m => m.default())
 *   stasher() // opens secure modal
 */

// Constants (from CLI constants.ts)
const MAX_SECRET_LENGTH = 4096; // 4KB plaintext
const DEFAULT_API_BASE_URL = Object.freeze('https://api.stasher.dev'); // Prevent accidental override
const KEY_LENGTH = 32; // 256-bit key
const IV_LENGTH = 12; // 96-bit IV for GCM
const TAG_LENGTH = 16; // 128-bit auth tag

// UUID v4 validation regex (same as CLI)
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Generate random bytes using browser crypto
 */
function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Convert ArrayBuffer to base64 string
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to ArrayBuffer
 */
function base64ToArrayBuffer(base64) {
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  } catch {
    throw new Error("Invalid base64 input");
  }
}

/**
 * Format stash token (id:base64key)
 */
function formatStashToken(id, keyBuffer) {
  const keyBase64 = arrayBufferToBase64(keyBuffer);
  return \`\${id}:\${keyBase64}\`;
}

/**
 * Decode stash token (uuid:base64key) into components
 */
function decodeStashToken(token) {
  const colonIndex = token.indexOf(':');
  if (colonIndex === -1) {
    throw new Error('Invalid stash token format: missing colon separator');
  }
  
  const id = token.substring(0, colonIndex);
  const keyBase64 = token.substring(colonIndex + 1);
  const keyBuffer = base64ToArrayBuffer(keyBase64);
  
  return { id, keyBuffer };
}

/**
 * Encrypt secret using SubtleCrypto AES-256-GCM
 */
async function encrypt(secret) {
  // Generate key and IV
  const keyBuffer = randomBytes(KEY_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  
  // Import key for SubtleCrypto
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM' },
    false, // extractable: false (explicit for security)
    ['encrypt']
  );
  
  // Encrypt the secret
  const encoder = new TextEncoder(); // TextEncoder always uses UTF-8
  const secretBytes = encoder.encode(secret);
  
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: TAG_LENGTH * 8 // tagLength in bits
    },
    cryptoKey,
    secretBytes
  );
  
  // Split encrypted data into ciphertext and tag
  const encryptedArray = new Uint8Array(encrypted);
  const ciphertext = encryptedArray.slice(0, -TAG_LENGTH);
  const tag = encryptedArray.slice(-TAG_LENGTH);
  
  return {
    keyBuffer,
    iv,
    ciphertext,
    tag
  };
}

/**
 * Decrypt payload using SubtleCrypto AES-256-GCM
 */
async function decrypt(payload, keyBuffer) {
  // Convert base64 to ArrayBuffers
  const iv = base64ToArrayBuffer(payload.iv);
  const tag = base64ToArrayBuffer(payload.tag);
  const ciphertext = base64ToArrayBuffer(payload.ciphertext);
  
  // Validate lengths
  if (iv.byteLength !== IV_LENGTH) {
    throw new Error(\`Invalid IV length: must be \${IV_LENGTH} bytes\`);
  }
  if (tag.byteLength !== TAG_LENGTH) {
    throw new Error(\`Invalid auth tag length: must be \${TAG_LENGTH} bytes\`);
  }
  if (keyBuffer.byteLength !== KEY_LENGTH) {
    throw new Error(\`Invalid key length: must be \${KEY_LENGTH} bytes\`);
  }
  
  // Import key for SubtleCrypto
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM' },
    false, // extractable: false (explicit for security)
    ['decrypt']
  );
  
  // Combine ciphertext and tag for decryption
  const encryptedData = new Uint8Array(ciphertext.byteLength + tag.byteLength);
  encryptedData.set(new Uint8Array(ciphertext));
  encryptedData.set(new Uint8Array(tag), ciphertext.byteLength);
  
  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(iv),
      tagLength: TAG_LENGTH * 8
    },
    cryptoKey,
    encryptedData
  );
  
  // Convert back to string
  const decoder = new TextDecoder('utf-8'); // Explicit UTF-8 for clarity
  return decoder.decode(decrypted);
}

/**
 * Create payload structure for API
 */
function createPayload(encryptionResult) {
  return {
    iv: arrayBufferToBase64(encryptionResult.iv),
    tag: arrayBufferToBase64(encryptionResult.tag),
    ciphertext: arrayBufferToBase64(encryptionResult.ciphertext)
  };
}

/**
 * Validate secret content
 */
function validateSecretContent(secret) {
  return typeof secret === 'string' && secret.trim().length > 0;
}

/**
 * Validate secret length
 */
function validateSecretLength(secret, maxLength) {
  return secret.length <= maxLength;
}

/**
 * Validate UUID format
 */
function validateUUID(uuid) {
  return typeof uuid === 'string' && UUID_REGEX.test(uuid);
}

/**
 * Enstash - Encrypt and store a secret (tagged template literal)
 * Usage: enstash\`my secret\`
 * @param {string[]} strings - Template literal strings
 * @param {...any} values - Template literal values
 * @returns {Promise<string>} The stash token (uuid:base64key)  
 */
export async function enstash(strings, ...values) {
  // Reconstruct the string from template literal
  const secret = strings.reduce((result, string, i) => {
    return result + string + (values[i] || '');
  }, '');
  // Input validation
  if (!validateSecretContent(secret)) {
    throw new Error('Secret cannot be empty or whitespace only');
  }
  
  if (!validateSecretLength(secret, MAX_SECRET_LENGTH)) {
    throw new Error(\`Secret too long (max \${MAX_SECRET_LENGTH} characters)\`);
  }
  
  try {
    // Encrypt the secret
    const encryptionResult = await encrypt(secret);
    const payload = createPayload(encryptionResult);
    
    // Send to API
    const response = await fetch(\`\${DEFAULT_API_BASE_URL}/enstash\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(\`API error: \${response.status} \${errorText}\`);
    }
    
    const result = await response.json();
    const token = formatStashToken(result.id, encryptionResult.keyBuffer);
    
    return token;
    
  } catch (error) {
    console.error('Enstash failed:', error.message);
    throw error;
  }
}

/**
 * Destash - Retrieve and decrypt a secret (burns after reading)
 * Usage: destash\`uuid:key\`
 * @param {string[]} strings - Template literal strings
 * @param {...any} values - Template literal values
 * @returns {Promise<string>} The decrypted secret
 */
export async function destash(strings, ...values) {
  // Reconstruct the token from template literal
  const token = strings.reduce((result, string, i) => {
    return result + string + (values[i] || '');
  }, '');
  try {
    const { id, keyBuffer } = decodeStashToken(token);
    
    // Validate UUID before API call
    if (!validateUUID(id)) {
      throw new Error('Invalid UUID format in token');
    }
    
    // Retrieve from API
    const response = await fetch(\`\${DEFAULT_API_BASE_URL}/destash/\${id}\`, {
      method: 'GET'
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        const message = 'Stash not found';
        console.warn(\`\${message}\`);
        throw new Error(message);
      }
      const errorText = await response.text();
      throw new Error(\`API error: \${response.status} \${errorText}\`);
    }
    
    const payload = await response.json();
    const secret = await decrypt(payload, keyBuffer);
    
    return secret;
    
  } catch (error) {
    console.error('Destash failed:', error.message);
    throw error;
  }
}

/**
 * Unstash - Manually delete a secret before it's read
 * Usage: unstash\`uuid\` or unstash\`uuid:key\`
 * @param {string[]} strings - Template literal strings
 * @param {...any} values - Template literal values
 * @returns {Promise<string>} Success message
 */
export async function unstash(strings, ...values) {
  // Reconstruct the token/id from template literal
  const tokenOrId = strings.reduce((result, string, i) => {
    return result + string + (values[i] || '');
  }, '');
  try {
    // Extract UUID from token or use as-is if it's just an ID
    let id;
    if (tokenOrId.includes(':')) {
      const { id: extractedId } = decodeStashToken(tokenOrId);
      id = extractedId;
    } else {
      id = tokenOrId;
    }
    
    // Validate UUID before API call
    if (!validateUUID(id)) {
      throw new Error('Invalid UUID format');
    }
    
    // Delete from API
    const response = await fetch(\`\${DEFAULT_API_BASE_URL}/unstash/\${id}\`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        const message = 'Stash not found (may have already been read or expired)';
        console.warn(\`\${message}\`);
        throw new Error(message);
      }
      const errorText = await response.text();
      throw new Error(\`API error: \${response.status} \${errorText}\`);
    }
    
    const result = await response.json();
    const message = \`Secret deleted: \${result.id}\`;
    
    return message;
    
  } catch (error) {
    console.error('Unstash failed:', error.message);
    throw error;
  }
}

/**
 * Create and show the Stasher modal using Shadow DOM
 */
function createStasherModal() {
  // Create modal container
  const modalContainer = document.createElement('div');
  modalContainer.id = 'stasher-modal-container';
  
  // Attach closed Shadow DOM for security
  const shadowRoot = modalContainer.attachShadow({ mode: 'closed' });
  
  // Modal HTML structure
  shadowRoot.innerHTML = \`
    <style>
      :host {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        z-index: 999999;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
      }
      
      .backdrop {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        backdrop-filter: blur(4px);
      }
      
      .modal {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 500px;
        max-width: 90vw;
        background: #1e1e1e;
        border: 1px solid #3e3e42;
        border-radius: 8px;
        color: #cccccc;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
      }
      
      .header {
        padding: 16px 20px;
        border-bottom: 1px solid #3e3e42;
        display: flex;
        justify-content: flex-end;
      }
      
      .close {
        background: none;
        border: none;
        color: #969696;
        font-size: 18px;
        cursor: pointer;
        font-family: inherit;
      }
      
      .close:hover {
        color: #cccccc;
      }
      
      .content {
        padding: 24px;
        position: relative;
        min-height: 200px;
      }
      
      .operations {
        display: flex;
        gap: 24px;
        margin-bottom: 24px;
        justify-content: center;
      }
      
      .operation {
        background: none;
        border: none;
        font-family: inherit;
        font-size: 14px;
        font-weight: bold;
        cursor: pointer;
        padding: 8px 0;
        transition: all 0.2s ease;
      }
      
      .operation.stash {
        color: #39ff14;
      }
      
      .operation.retrieve {
        color: #ffbf00;
      }
      
      .operation.delete {
        color: #ff073a;
      }
      
      .operation:not(.active) {
        opacity: 0.5;
      }
      
      .operation:hover {
        opacity: 1;
      }
      
      .input-section {
        margin-bottom: 24px;
      }
      
      .label {
        display: block;
        margin-bottom: 8px;
        font-size: 13px;
        color: #969696;
      }
      
      .input {
        width: 100%;
        background: #2d2d30;
        border: 1px solid #3e3e42;
        border-radius: 4px;
        padding: 12px;
        color: #cccccc;
        font-family: inherit;
        font-size: 13px;
        resize: vertical;
        min-height: 80px;
      }
      
      .input:focus {
        outline: none;
        border-color: var(--active-color);
        box-shadow: 0 0 0 1px var(--active-color);
      }
      
      .button-section {
        display: flex;
        justify-content: flex-end;
        margin-bottom: 16px;
      }
      
      .action-button {
        background: var(--active-color);
        border: none;
        border-radius: 4px;
        padding: 10px 20px;
        color: #000;
        font-family: inherit;
        font-size: 13px;
        font-weight: bold;
        cursor: pointer;
        transition: all 0.2s ease;
      }
      
      .action-button:hover {
        opacity: 0.8;
      }
      
      .action-button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }
      
      .result {
        background: #2d2d30;
        border: 1px solid #3e3e42;
        border-radius: 4px;
        padding: 12px;
        margin-top: 16px;
        font-family: inherit;
        font-size: 13px;
        word-break: break-all;
        display: none;
      }
      
      .result.success {
        border-color: #39ff14;
        color: #39ff14;
      }
      
      .result.error {
        border-color: #ff073a;
        color: #ff073a;
      }
      
      .branding {
        position: absolute;
        bottom: 16px;
        left: 20px;
        color: #565656;
        font-size: 12px;
      }
      
      /* Mobile responsive */
      @media (max-width: 600px) {
        .modal {
          width: 95vw;
          margin: 20px;
        }
        
        .operations {
          gap: 16px;
        }
        
        .operation {
          font-size: 13px;
        }
      }
    </style>
    
    <div class="backdrop"></div>
    <div class="modal">
      <div class="header">
        <button class="close">×</button>
      </div>
      
      <div class="content">
        <div class="operations">
          <button class="operation stash active" data-mode="stash">STASH</button>
          <button class="operation retrieve" data-mode="retrieve">RETRIEVE</button>
          <button class="operation delete" data-mode="delete">DELETE</button>
        </div>
        
        <div class="input-section">
          <label class="label" id="input-label">Enter your secret:</label>
          <textarea class="input" id="main-input" placeholder="Type or paste here..."></textarea>
        </div>
        
        <div class="button-section">
          <button class="action-button" id="action-button">STASH</button>
        </div>
        
        <div class="result" id="result"></div>
        
        <div class="branding">stasher</div>
      </div>
    </div>
  \`;
  
  // Get elements
  const backdrop = shadowRoot.querySelector('.backdrop');
  const closeBtn = shadowRoot.querySelector('.close');
  const operations = shadowRoot.querySelectorAll('.operation');
  const input = shadowRoot.querySelector('#main-input');
  const label = shadowRoot.querySelector('#input-label');
  const actionButton = shadowRoot.querySelector('#action-button');
  const result = shadowRoot.querySelector('#result');
  const modal = shadowRoot.querySelector('.modal');
  
  let currentMode = 'stash';
  
  // Update CSS custom property for active color
  function updateActiveColor() {
    const colors = {
      stash: '#39ff14',
      retrieve: '#ffbf00', 
      delete: '#ff073a'
    };
    modal.style.setProperty('--active-color', colors[currentMode]);
  }
  
  // Update UI based on current mode
  function updateUI() {
    updateActiveColor();
    
    // Update operation buttons
    operations.forEach(op => {
      op.classList.toggle('active', op.dataset.mode === currentMode);
    });
    
    // Update input and button text
    switch(currentMode) {
      case 'stash':
        label.textContent = 'Enter your secret:';
        input.placeholder = 'Type or paste your secret here...';
        actionButton.textContent = 'STASH';
        break;
      case 'retrieve':
        label.textContent = 'Enter token:';
        input.placeholder = 'Paste your token here (uuid:key...)';
        actionButton.textContent = 'RETRIEVE';
        break;
      case 'delete':
        label.textContent = 'Enter UUID or token:';
        input.placeholder = 'Paste UUID or full token here...';
        actionButton.textContent = 'DELETE';
        break;
    }
    
    // Clear input and result
    input.value = '';
    result.style.display = 'none';
    result.className = 'result';
  }
  
  // Show result
  function showResult(text, isError = false) {
    result.textContent = text;
    result.className = \`result \${isError ? 'error' : 'success'}\`;
    result.style.display = 'block';
  }
  
  // Handle operation switching
  operations.forEach(op => {
    op.addEventListener('click', () => {
      currentMode = op.dataset.mode;
      updateUI();
    });
  });
  
  // Handle action button
  actionButton.addEventListener('click', async () => {
    const inputValue = input.value.trim();
    if (!inputValue) return;
    
    actionButton.disabled = true;
    actionButton.textContent = 'WORKING...';
    
    try {
      let result_text;
      
      switch(currentMode) {
        case 'stash':
          result_text = await enstash([inputValue], '');
          showResult(\`Token: \${result_text}\`);
          break;
          
        case 'retrieve':
          result_text = await destash([inputValue], '');
          showResult(\`Secret: \${result_text}\`);
          break;
          
        case 'delete':
          result_text = await unstash([inputValue], '');
          showResult(result_text);
          break;
      }
      
      // Clear input after successful operation
      input.value = '';
      
    } catch (error) {
      showResult(\`Error: \${error.message}\`, true);
    } finally {
      actionButton.disabled = false;
      updateUI(); // Reset button text
    }
  });
  
  // Handle close
  function closeModal() {
    document.body.removeChild(modalContainer);
  }
  
  closeBtn.addEventListener('click', closeModal);
  backdrop.addEventListener('click', closeModal);
  
  // Handle ESC key
  function handleKeydown(e) {
    if (e.key === 'Escape') {
      closeModal();
      document.removeEventListener('keydown', handleKeydown);
    }
  }
  
  document.addEventListener('keydown', handleKeydown);
  
  // Initialize UI
  updateUI();
  
  // Add to page and focus input
  document.body.appendChild(modalContainer);
  input.focus();
  
  return modalContainer;
}

/**
 * Default export - Loader function for DevTools installation
 * Creates global stasher function that shows modal
 */
export default function install() {
  // Create global stasher function
  globalThis.stasher = createStasherModal;
  
  console.log('Stasher Web loaded!');
  console.log('Usage: stasher() - opens secure modal');
  
  // Return the modal function
  return createStasherModal;
}`;

// Embed the HTML content
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stasher DevTools</title>
    <style>
        body {
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            line-height: 1.5;
            color: #333;
            background: #f8f9fa;
            margin: 0;
            padding: 2rem;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 2rem;
            border: 1px solid #ddd;
        }
        
        h1 {
            margin: 0 0 1rem 0;
            font-size: 1.5rem;
        }
        
        .install-button {
            display: inline-block;
            background: #000;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border: none;
            cursor: pointer;
            margin: 1rem 0;
        }
        
        .install-button:hover {
            background: #333;
        }
        
        .code {
            background: #f5f5f5;
            padding: 1rem;
            border: 1px solid #ddd;
            overflow-x: auto;
            margin: 1rem 0;
        }
        
        .section {
            margin: 2rem 0;
        }
        
        pre {
            margin: 0;
        }
        
        ul {
            padding-left: 1.5rem;
        }
        
        li {
            margin: 0.5rem 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Stasher DevTools</h1>
        <p>Secure secret sharing in browser console. Zero install, burn-after-read.</p>
        
        <div class="section">
            <h2>Why?</h2>
            <p>I just wanted to share a password.<br>
            Not spin up a server. Not register for some "secure" web app. Not trust a Slack thread.<br>  
            Just. Send. A. Secret.</p>
            
            <p>So I built Stasher — for people who are busy, paranoid, or both.</p>
            
            <ul>
                <li>Works instantly in any browser</li>
                <li>Encrypts everything before it ever leaves your machine</li>
                <li>Secrets self-destruct after one read or 10 minutes</li>
                <li>No account, no login, no metadata, no snooping</li>
                <li>Cross-platform — create in browser, access from terminal (and vice versa)</li>
                <li>Share however you like — Slack, email, QR code, carrier pigeon...</li>
            </ul>
            
            <p>Basically, it's like a Mission Impossible tape, but for API keys.</p>
        </div>
        
        <div class="section">
            <h2>Install</h2>
            <p>Drag this to your bookmarks bar:</p>
            <a href="javascript:(async()=>{await import('https://install.stasher.dev/stasher-web.mjs').then(m=>m.default())})();" 
               class="install-button">Install Stasher</a>
               
            <p>Or paste in DevTools console:</p>
            <div class="code">
                <pre>await import("https://install.stasher.dev/stasher-web.mjs").then(m => m.default())</pre>
            </div>
        </div>
        
        <div class="section">
            <h2>Usage</h2>
            <div class="code">
                <pre>enstash\`my secret\`           // store
destash\`uuid:key\`             // retrieve (burns)
unstash\`uuid\`                 // delete</pre>
            </div>
        </div>
        
        <div class="section">
            <h2>Examples</h2>
            <div class="code">
                <pre>enstash\`API_KEY=sk-123\`
enstash\`password123\`
enstash\`-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----\`</pre>
            </div>
        </div>
        
        <div class="section">
            <h2>Features</h2>
            <ul>
                <li>AES-256-GCM client-side encryption</li>
                <li>Burn-after-read (one-time access)</li>
                <li>10-minute auto-expiry</li>
                <li>Zero-knowledge server</li>
                <li>No logs, no tracking</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>CLI Version</h2>
            <div class="code">
                <pre>npm install -g stasher-cli
npx enstash "secret"</pre>
            </div>
        </div>
        
        <div class="section">
            <p><a href="https://github.com/stasher-dev/stasher-web">Source</a> | 
               <a href="https://github.com/stasher-dev/stasher-cli">CLI</a> | 
               <a href="https://github.com/stasher-dev/stasher-worker">Worker</a></p>
        </div>
    </div>
</body>
</html>`;


export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Serve the main install page
    if (url.pathname === '/') {
      return new Response(HTML_CONTENT, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }
    
    // Serve the ESM module from embedded content
    if (url.pathname === '/stasher-web.mjs') {
      return new Response(MODULE_CONTENT, {
        headers: {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }
    
    // 404 for everything else
    return new Response('Not Found', { status: 404 });
  }
};