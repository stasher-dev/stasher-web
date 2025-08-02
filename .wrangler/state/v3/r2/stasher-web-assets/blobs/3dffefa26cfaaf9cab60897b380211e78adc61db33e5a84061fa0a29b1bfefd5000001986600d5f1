/**
 * Stasher Web - Browser DevTools version of stasher-cli
 * Zero-dependency ESM module for secure secret sharing
 * 
 * Usage:
 *   import("https://stasher.dev/stasher-web.mjs").then(m => m.default())
 *   enstash('my secret')     // returns uuid:key token
 *   destash('uuid:key')      // returns secret
 *   unstash('uuid')          // deletes secret
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
  return `${id}:${keyBase64}`;
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
    throw new Error(`Invalid IV length: must be ${IV_LENGTH} bytes`);
  }
  if (tag.byteLength !== TAG_LENGTH) {
    throw new Error(`Invalid auth tag length: must be ${TAG_LENGTH} bytes`);
  }
  if (keyBuffer.byteLength !== KEY_LENGTH) {
    throw new Error(`Invalid key length: must be ${KEY_LENGTH} bytes`);
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
 * Usage: enstash`my secret`
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
    throw new Error(`Secret too long (max ${MAX_SECRET_LENGTH} characters)`);
  }
  
  try {
    // Encrypt the secret
    const encryptionResult = await encrypt(secret);
    const payload = createPayload(encryptionResult);
    
    // Send to API
    const response = await fetch(`${DEFAULT_API_BASE_URL}/enstash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API error: ${response.status} ${errorText}`);
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
 * Usage: destash`uuid:key`
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
    const response = await fetch(`${DEFAULT_API_BASE_URL}/destash/${id}`, {
      method: 'GET'
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        const message = 'Stash not found';
        console.warn(`${message}`);
        throw new Error(message);
      }
      const errorText = await response.text();
      throw new Error(`API error: ${response.status} ${errorText}`);
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
 * Usage: unstash`uuid` or unstash`uuid:key`
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
    const response = await fetch(`${DEFAULT_API_BASE_URL}/unstash/${id}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        const message = 'Stash not found (may have already been read or expired)';
        console.warn(`${message}`);
        throw new Error(message);
      }
      const errorText = await response.text();
      throw new Error(`API error: ${response.status} ${errorText}`);
    }
    
    const result = await response.json();
    const message = `Secret deleted: ${result.id}`;
    
    return message;
    
  } catch (error) {
    console.error('Unstash failed:', error.message);
    throw error;
  }
}

/**
 * Default export - Loader function for DevTools installation
 * Adds enstash, destash, unstash to global scope
 */
export default function install() {
  // Add functions to global scope
  Object.assign(globalThis, { enstash, destash, unstash });
  
  console.log(`Stasher Web loaded!`);
  
  // Return the functions for direct use
  return { enstash, destash, unstash };
}