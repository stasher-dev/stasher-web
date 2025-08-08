// Constants (from CLI constants.ts)
export const MAX_SECRET_LENGTH = 4096; // 4KB plaintext
export const MAX_CIPHERTEXT_BYTES = 16384; // Max ciphertext bytes (server limit)
export const DEFAULT_API_BASE_URL = Object.freeze('https://api.stasher.dev'); // Prevent accidental override
export const KEY_LENGTH = 32; // 256-bit key
export const IV_LENGTH = 12; // 96-bit IV for GCM
export const TAG_LENGTH = 16; // 128-bit auth tag

// UUID v4 validation regex (same as CLI)
export const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Base64url validation regex and helpers
const B64URL = /^[A-Za-z0-9_-]+$/;
const b64urlLen = (s: string) => {
    const mod = s.length % 4; 
    const pad = mod ? 4 - mod : 0;
    return Math.floor(((s.length + pad) * 3) / 4) - pad;
};
const assertB64UrlLen = (s: string, n: number, what: string) => {
    if (!B64URL.test(s) || b64urlLen(s) !== n) {
        throw new Error(`Invalid ${what}: must decode to ${n} bytes`);
    }
};

// Types
export interface EncryptionResult {
    keyBuffer: Uint8Array;
    iv: Uint8Array;
    ciphertext: Uint8Array;
    tag: Uint8Array;
}

export interface PayloadData {
    iv: string;
    tag: string;
    ciphertext: string;
}

export interface StashTokenData {
    id: string;
    keyBuffer: Uint8Array;
}

// Utility functions
export function randomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
}

export function arrayBufferToBase64Url(input: ArrayBuffer | ArrayBufferView): string {
    const view = input instanceof ArrayBuffer
        ? new Uint8Array(input)
        : input instanceof Uint8Array
        ? input
        : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);

    // Chunk to avoid call-arg limits and O(n²) string concatenation
    const parts: string[] = [];
    const CHUNK = 0x8000; // 32k
    for (let i = 0; i < view.length; i += CHUNK) {
        parts.push(String.fromCharCode(...view.subarray(i, i + CHUNK)));
    }
    return toBase64Url(btoa(parts.join('')));
}

function toBase64Url(b64: string): string {
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(base64url: string): Uint8Array {
    if (typeof base64url !== 'string') {
        throw new Error("Invalid base64url input: must be string");
    }
    
    // Base64url format validation (no padding, uses -_ instead of +/, require at least one character)
    if (!B64URL.test(base64url)) {
        throw new Error("Invalid base64url input: invalid characters or empty string");
    }
    
    try {
        // Convert base64url back to standard base64 for atob
        const base64 = fromBase64Url(base64url);
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } catch {
        throw new Error("Invalid base64url input: decode failed");
    }
}


function fromBase64Url(b64url: string): string {
    // Convert base64url to base64 and add padding
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4;
    if (pad) {
        b64 += '='.repeat(4 - pad);
    }
    return b64;
}

export function formatStashToken(id: string, keyBuffer: Uint8Array): string {
    if (keyBuffer.length !== KEY_LENGTH) {
        throw new Error(`Key must be ${KEY_LENGTH} bytes`);
    }
    const keyBase64Url = arrayBufferToBase64Url(keyBuffer);
    return `${id}:${keyBase64Url}`;
}

export function decodeStashToken(token: string): StashTokenData {
    if (typeof token !== 'string') {
        throw new Error('Invalid stash token: must be string');
    }
    
    // Normalize input early
    const clean = normalizeToken(token);
    if (!clean) {
        throw new Error('Invalid stash token: must be non-empty string');
    }
    
    const colonIndex = clean.indexOf(':');
    if (colonIndex === -1) {
        throw new Error('Invalid stash token format: missing colon separator');
    }
    
    const id = clean.substring(0, colonIndex).trim();
    const keyBase64 = clean.substring(colonIndex + 1).trim();
    
    // Validate components
    if (!id) {
        throw new Error('Invalid stash token: empty ID');
    }
    if (!keyBase64) {
        throw new Error('Invalid stash token: empty key');
    }
    
    // Validate UUID format
    if (!UUID_REGEX.test(id)) {
        throw new Error('Invalid stash token: malformed UUID');
    }
    
    // Fast-fail key format and length validation (32 bytes = exactly 43 base64url chars)
    assertB64UrlLen(keyBase64, KEY_LENGTH, 'stash token key');
    
    let keyBytes: Uint8Array;
    try {
        keyBytes = base64UrlToBytes(keyBase64);
    } catch (error) {
        throw new Error('Invalid stash token: malformed key encoding');
    }
    
    // Validate decoded key length (defensive check)
    if (keyBytes.length !== KEY_LENGTH) {
        throw new Error(`Invalid stash token: key must be ${KEY_LENGTH} bytes`);
    }
    
    return { id, keyBuffer: keyBytes };
}

// Safe version for user input - returns null instead of throwing
export function tryDecodeStashToken(token: string): StashTokenData | null {
    try {
        return decodeStashToken(token);
    } catch {
        return null;
    }
}

// Legacy encrypt function - now proxies to Web Worker
export async function encrypt(secret: string): Promise<EncryptionResult> {
    const { getCryptoManager } = await import('./crypto-manager');
    const manager = getCryptoManager();
    
    const { keyBuffer, payload } = await manager.encrypt(secret);
    
    // Convert payload back to EncryptionResult format for compatibility
    const iv = base64UrlToBytes(payload.iv);
    const tag = base64UrlToBytes(payload.tag);
    const ciphertext = base64UrlToBytes(payload.ciphertext);
    
    return {
        keyBuffer: new Uint8Array(keyBuffer),
        iv,
        ciphertext,
        tag
    };
}

// Legacy decrypt function - now proxies to Web Worker
export async function decrypt(payload: PayloadData, keyBuffer: Uint8Array): Promise<string> {
    const { getCryptoManager } = await import('./crypto-manager');
    const manager = getCryptoManager();
    
    return await manager.decrypt(payload, keyBuffer);
}

export function createPayload(encryptionResult: EncryptionResult): PayloadData {
    return {
        iv: arrayBufferToBase64Url(encryptionResult.iv),
        tag: arrayBufferToBase64Url(encryptionResult.tag),
        ciphertext: arrayBufferToBase64Url(encryptionResult.ciphertext)
    };
}

// Type guards
export function isPayloadData(obj: any): obj is PayloadData {
    return obj &&
        typeof obj === 'object' &&
        typeof obj.iv === 'string' &&
        typeof obj.tag === 'string' &&
        typeof obj.ciphertext === 'string';
}

// Validation functions
export function validateSecretContent(secret: string): boolean {
    return typeof secret === 'string' && secret.trim().length > 0;
}

export function validateSecretLength(secret: string, maxLength: number = MAX_SECRET_LENGTH): boolean {
    return secret.length <= maxLength;
}

export function validateUUID(uuid: string): boolean {
    return typeof uuid === 'string' && UUID_REGEX.test(uuid);
}

// Safe UUID validation for user input (handles whitespace)
export function tryValidateUUID(uuid: string): boolean {
    if (typeof uuid !== 'string') {
        return false;
    }
    return validateUUID(uuid.trim());
}

// Extract UUID from token or return null if invalid
export function parseUUID(token: string): string | null {
    if (typeof token !== 'string') {
        return null;
    }
    
    const clean = normalizeToken(token);
    
    // If it contains a colon, extract the ID part
    if (clean.includes(':')) {
        const colonIndex = clean.indexOf(':');
        const id = clean.substring(0, colonIndex).trim();
        return tryValidateUUID(id) ? id : null;
    }
    
    // Otherwise treat the whole thing as a potential UUID
    return tryValidateUUID(clean) ? clean : null;
}

// Token normalization utility
export function normalizeToken(token: string): string {
    return typeof token === 'string' ? token.trim() : '';
}

// Additional helper functions from CLI version
export function encodeKey(key: ArrayBuffer | ArrayBufferView): string {
    return arrayBufferToBase64Url(key);
}

export function encodePayload(payload: PayloadData): string {
    return JSON.stringify(payload);
}

export function parsePayload(encoded: string): PayloadData {
    if (typeof encoded !== 'string') {
        throw new Error('Invalid payload: must be string');
    }
    
    let data: any;
    try {
        data = JSON.parse(encoded);
    } catch {
        throw new Error('Invalid payload: malformed JSON');
    }
    
    // Strict runtime validation
    if (!data || typeof data !== 'object') {
        throw new Error('Invalid payload: must be object');
    }
    
    // Field existence checks
    if (typeof data.iv !== 'string') {
        throw new Error('Invalid payload: iv must be string');
    }
    if (typeof data.tag !== 'string') {
        throw new Error('Invalid payload: tag must be string');
    }
    if (typeof data.ciphertext !== 'string') {
        throw new Error('Invalid payload: ciphertext must be string');
    }
    
    // Base64url format and length validation
    assertB64UrlLen(data.iv, IV_LENGTH, 'payload iv');
    assertB64UrlLen(data.tag, TAG_LENGTH, 'payload tag');
    
    // Validate ciphertext format (length validation follows)
    if (!B64URL.test(data.ciphertext)) {
        throw new Error('Invalid payload: ciphertext must be base64url format');
    }
    
    // Validate ciphertext length
    const ctLen = b64urlLen(data.ciphertext);
    if (ctLen <= 0) {
        throw new Error('Invalid payload: ciphertext cannot be empty');
    }
    // Cap to server max ciphertext bytes (not plaintext) to fail early client-side
    if (ctLen > MAX_CIPHERTEXT_BYTES) {
        throw new Error(`Invalid payload: ciphertext too large (max ${MAX_CIPHERTEXT_BYTES} bytes)`);
    }
    
    return data;
}

// Memory safety helpers
// IMPORTANT: Use these after displaying secrets to wipe memory
// - After decrypt: zeroArrayBuffer(keyBuffer) and zeroUint8(any views)
// - Never use innerHTML for secrets, only textContent or input.value
// - Clear displayed secrets with secureErase() after user interaction
export function zeroArrayBuffer(buf?: ArrayBuffer | null): void {
    if (!buf) return;
    new Uint8Array(buf).fill(0);
}

export function zeroUint8(u8?: Uint8Array | null): void {
    if (u8) u8.fill(0);
}


// Safe version for user input - returns null instead of throwing
export function tryParsePayload(encoded: string): PayloadData | null {
    try {
        return parsePayload(encoded);
    } catch {
        return null;
    }
}