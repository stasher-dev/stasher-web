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
 * Opens modal immediately and creates global stasher function
 */
export default function install() {
  // Create global stasher function for future use
  globalThis.stasher = createStasherModal;
  
  console.log('Stasher Web loaded!');
  
  // Open modal immediately
  const modal = createStasherModal();
  
  // Return the modal function for direct use
  return createStasherModal;
}`;

// Embed the popup HTML content
const POPUP_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stasher</title>
    <style>
        body {
            font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
            margin: 0;
            padding: 24px;
            padding-top: 80px;
            background: #1e1e1e;
            color: #cccccc;
            overflow: hidden;
        }
        
        .branding {
            position: absolute;
            top: 16px;
            left: 12px;
            color: #00bfff;
            font-size: 36px;
            font-weight: bold;
        }
        
        .version {
            position: absolute;
            bottom: 16px;
            left: 12px;
            color: #565656;
            font-size: 12px;
        }
        
        .operations {
            display: flex;
            gap: 4px;
            margin-top: 24px;
            justify-content: flex-end;
            padding: 0 12px;
        }
        
        .operation {
            background: none;
            border: none;
            font-family: inherit;
            font-size: 18px;
            font-weight: normal;
            cursor: pointer;
            padding: 12px 24px;
            border-radius: 4px;
            transition: all 0.2s ease;
            text-transform: lowercase;
        }
        
        .operation.enstash {
            color: #90ee90;
        }
        
        .operation.destash {
            color: #daa520;
        }
        
        .operation.unstash {
            color: #cd5c5c;
        }
        
        .operation:hover {
            opacity: 0.8;
        }
        
        .operation:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .input-section {
            margin-bottom: 24px;
            padding: 0 12px;
        }
        
        .label {
            display: block;
            margin-bottom: 8px;
            font-size: 13px;
            color: #969696;
        }
        
        .input {
            width: calc(100% - 32px);
            background: #2d2d30;
            border: 1px solid #3e3e42;
            border-radius: 6px;
            padding: 14px 16px;
            color: #cccccc;
            font-family: inherit;
            font-size: 14px;
            resize: none;
            min-height: 20px;
            max-height: 20px;
            overflow: hidden;
            text-align: left;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.3);
        }
        
        .input:focus {
            outline: none;
            border-color: #00bfff;
            box-shadow: 0 0 0 2px rgba(0, 191, 255, 0.2), inset 0 1px 3px rgba(0,0,0,0.3);
        }
        
        .input::placeholder {
            color: #565656;
        }
        
        .message {
            margin-top: 8px;
            font-size: 12px;
            color: #565656;
            text-align: left;
            min-height: 16px;
        }
        
        .message.success {
            color: #90ee90;
        }
        
        .message.error {
            color: #cd5c5c;
        }
        
    </style>
</head>
<body>
    <div class="branding">stasher</div>
    
    <div class="input-section">
        <input type="text" class="input" id="main-input" placeholder="enter secret, token, or uuid">
        <div class="message" id="message"></div>
    </div>
    
    <div class="operations">
        <button class="operation enstash" data-mode="enstash">enstash</button>
        <button class="operation destash" data-mode="destash">destash</button>
        <button class="operation unstash" data-mode="unstash">unstash</button>
    </div>
    
    <div class="version">v1.0</div>
    
    <script>
        // Constants (from CLI constants.ts)
        const MAX_SECRET_LENGTH = 4096; // 4KB plaintext
        const DEFAULT_API_BASE_URL = Object.freeze('https://api.stasher.dev'); // Prevent accidental override
        const KEY_LENGTH = 32; // 256-bit key
        const IV_LENGTH = 12; // 96-bit IV for GCM
        const TAG_LENGTH = 16; // 128-bit auth tag

        // UUID v4 validation regex (same as CLI)
        const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

        // Utility functions
        function randomBytes(length) {
            return crypto.getRandomValues(new Uint8Array(length));
        }

        function arrayBufferToBase64(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }

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

        function formatStashToken(id, keyBuffer) {
            const keyBase64 = arrayBufferToBase64(keyBuffer);
            return \`\${id}:\${keyBase64}\`;
        }

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

        async function encrypt(secret) {
            const keyBuffer = randomBytes(KEY_LENGTH);
            const iv = randomBytes(IV_LENGTH);
            
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );
            
            const encoder = new TextEncoder();
            const secretBytes = encoder.encode(secret);
            
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: TAG_LENGTH * 8
                },
                cryptoKey,
                secretBytes
            );
            
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

        async function decrypt(payload, keyBuffer) {
            const iv = base64ToArrayBuffer(payload.iv);
            const tag = base64ToArrayBuffer(payload.tag);
            const ciphertext = base64ToArrayBuffer(payload.ciphertext);
            
            if (iv.byteLength !== IV_LENGTH) {
                throw new Error(\`Invalid IV length: must be \${IV_LENGTH} bytes\`);
            }
            if (tag.byteLength !== TAG_LENGTH) {
                throw new Error(\`Invalid auth tag length: must be \${TAG_LENGTH} bytes\`);
            }
            if (keyBuffer.byteLength !== KEY_LENGTH) {
                throw new Error(\`Invalid key length: must be \${KEY_LENGTH} bytes\`);
            }
            
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );
            
            const encryptedData = new Uint8Array(ciphertext.byteLength + tag.byteLength);
            encryptedData.set(new Uint8Array(ciphertext));
            encryptedData.set(new Uint8Array(tag), ciphertext.byteLength);
            
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: new Uint8Array(iv),
                    tagLength: TAG_LENGTH * 8
                },
                cryptoKey,
                encryptedData
            );
            
            const decoder = new TextDecoder('utf-8');
            return decoder.decode(decrypted);
        }

        function createPayload(encryptionResult) {
            return {
                iv: arrayBufferToBase64(encryptionResult.iv),
                tag: arrayBufferToBase64(encryptionResult.tag),
                ciphertext: arrayBufferToBase64(encryptionResult.ciphertext)
            };
        }

        function validateSecretContent(secret) {
            return typeof secret === 'string' && secret.trim().length > 0;
        }

        function validateSecretLength(secret, maxLength) {
            return secret.length <= maxLength;
        }

        function validateUUID(uuid) {
            return typeof uuid === 'string' && UUID_REGEX.test(uuid);
        }

        async function performEnstash(secret) {
            if (!validateSecretContent(secret)) {
                throw new Error('Secret cannot be empty or whitespace only');
            }
            
            if (!validateSecretLength(secret, MAX_SECRET_LENGTH)) {
                throw new Error(\`Secret too long (max \${MAX_SECRET_LENGTH} characters)\`);
            }
            
            try {
                const encryptionResult = await encrypt(secret);
                const payload = createPayload(encryptionResult);
                
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

        async function performDestash(token) {
            try {
                const { id, keyBuffer } = decodeStashToken(token);
                
                if (!validateUUID(id)) {
                    throw new Error('Invalid UUID format in token');
                }
                
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

        async function performUnstash(tokenOrId) {
            try {
                let id;
                if (tokenOrId.includes(':')) {
                    const { id: extractedId } = decodeStashToken(tokenOrId);
                    id = extractedId;
                } else {
                    id = tokenOrId;
                }
                
                if (!validateUUID(id)) {
                    throw new Error('Invalid UUID format');
                }
                
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
        
        // Get elements
        const operations = document.querySelectorAll('.operation');
        const input = document.querySelector('#main-input');
        const message = document.querySelector('#message');
        
        // Show message
        function showMessage(text, isError = false) {
            message.textContent = text;
            message.className = \`message \${isError ? 'error' : 'success'}\`;
        }
        
        function clearMessage() {
            message.textContent = '';
            message.className = 'message';
        }
        
        // Handle operation buttons
        operations.forEach(op => {
            op.addEventListener('click', async () => {
                const inputValue = input.value.trim();
                if (!inputValue) return;
                
                const mode = op.dataset.mode;
                
                // Clear previous message
                clearMessage();
                
                // Disable all buttons
                operations.forEach(btn => btn.disabled = true);
                op.textContent = 'working...';
                
                try {
                    let result_text;
                    
                    switch(mode) {
                        case 'enstash':
                            result_text = await performEnstash(inputValue);
                            input.value = result_text;
                            showMessage('stash created');
                            break;
                            
                        case 'destash':
                            result_text = await performDestash(inputValue);
                            input.value = result_text;
                            showMessage('stash retrieved');
                            break;
                            
                        case 'unstash':
                            result_text = await performUnstash(inputValue);
                            input.value = '';
                            showMessage('stash deleted');
                            break;
                    }
                    
                } catch (error) {
                    input.value = \`Error: \${error.message}\`;
                    showMessage(\`\${error.message}\`, true);
                } finally {
                    // Re-enable all buttons and reset text
                    operations.forEach((btn, idx) => {
                        btn.disabled = false;
                        btn.textContent = ['enstash', 'destash', 'unstash'][idx];
                    });
                }
            });
        });
        
        // Initialize
        input.focus();
    </script>
</body>
</html>`;

// Embed the HTML content
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stasher</title>
    <style>
        body {
            font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
            margin: 0;
            padding: 0;
            background: #1e1e1e;
            color: #cccccc;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        
        .install-button {
            background: #39ff14;
            color: #000;
            padding: 1rem 2rem;
            text-decoration: none;
            border: none;
            cursor: grab;
            font-family: inherit;
            font-size: 16px;
            border-radius: 4px;
            transition: all 0.2s ease;
            position: relative;
        }
        
        .install-button:hover {
            opacity: 0.8;
        }
        
        .install-button:active {
            cursor: grabbing;
        }
        
        .instruction {
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translateX(-50%);
            margin-top: 10px;
            color: #969696;
            font-size: 12px;
            text-align: center;
            white-space: nowrap;
        }
    </style>
</head>
<body>
    <div style="position: relative; display: inline-block;">
        <a href="javascript:(function(){var w=500,h=600,l=(screen.width-w)/2,t=(screen.height-h)/2;window.open('https://install.stasher.dev/stasher','stasher','width='+w+',height='+h+',left='+l+',top='+t);})()" 
           onclick="return addBookmark(event);" 
           ondragstart="dragBookmarklet(event)"
           class="install-button">Install Stasher</a>
        <div class="instruction">← Drag to bookmarks bar</div>
    </div>
    
    <script>
        function dragBookmarklet(event) {
            const bookmarkUrl = "javascript:(function(){var w=700,h=400,l=(screen.width-w)/2,t=(screen.height-h)/2;window.open('https://install.stasher.dev/stasher','stasher','width='+w+',height='+h+',left='+l+',top='+t);})()";
            const bookmarkTitle = "stasher";
            
            // Set the bookmark URL and title for dragging
            event.dataTransfer.setData('text/uri-list', bookmarkUrl);
            event.dataTransfer.setData('text/plain', bookmarkUrl);
            event.dataTransfer.setData('text/x-moz-url', bookmarkUrl + '\\n' + bookmarkTitle);
            event.dataTransfer.setData('text/html', '<a href="' + bookmarkUrl + '">' + bookmarkTitle + '</a>');
            event.dataTransfer.effectAllowed = 'copy';
        }
        
        function addBookmark(event) {
            // Try to use the browser's built-in bookmark functionality
            if (navigator.userAgent.indexOf('Chrome') > -1 || navigator.userAgent.indexOf('Safari') > -1) {
                // For Chrome/Safari, show drag instruction
                alert('To install Stasher:\\n\\n→ Drag the button to your bookmarks bar\\n\\nThen click the bookmark on any website to use Stasher!');
                return false; // Prevent default href action
            } else if (window.sidebar && window.sidebar.addPanel) {
                // Firefox
                event.preventDefault();
                const bookmarkUrl = "javascript:(function(){var w=700,h=400,l=(screen.width-w)/2,t=(screen.height-h)/2;window.open('https://install.stasher.dev/stasher','stasher','width='+w+',height='+h+',left='+l+',top='+t);})()";
                window.sidebar.addPanel('stasher', bookmarkUrl, '');
                return false;
            } else if (window.external && ('AddFavorite' in window.external)) {
                // Internet Explorer
                event.preventDefault();
                const bookmarkUrl = "javascript:(function(){var w=700,h=400,l=(screen.width-w)/2,t=(screen.height-h)/2;window.open('https://install.stasher.dev/stasher','stasher','width='+w+',height='+h+',left='+l+',top='+t);})()";
                window.external.AddFavorite(bookmarkUrl, 'stasher');
                return false;
            } else {
                // Fallback - show instruction and let href work
                alert('To install Stasher:\\n\\n→ Drag the button to your bookmarks bar\\n\\nThen click the bookmark on any website to use Stasher!');
                return false;
            }
        }
    </script>
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
    
    // Serve the popup stasher page
    if (url.pathname === '/stasher') {
      return new Response(POPUP_CONTENT, {
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
          'X-Content-Type-Options': 'nosniff',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    }
    
    // 404 for everything else
    return new Response('Not Found', { status: 404 });
  }
};