// Constants (from CLI constants.ts)
export const MAX_SECRET_LENGTH = 4096; // 4KB plaintext
export const DEFAULT_API_BASE_URL = Object.freeze('https://api.stasher.dev'); // Prevent accidental override
export const KEY_LENGTH = 32; // 256-bit key
export const IV_LENGTH = 12; // 96-bit IV for GCM
export const TAG_LENGTH = 16; // 128-bit auth tag

// UUID v4 validation regex (same as CLI)
export const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Types
export interface EncryptionResult {
    keyBuffer: ArrayBuffer;
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
    keyBuffer: ArrayBuffer;
}

// Utility functions
export function randomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
    if (typeof base64 !== 'string') {
        throw new Error("Invalid base64 input: must be string");
    }
    
    // Basic base64 format validation
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
        throw new Error("Invalid base64 input: invalid characters");
    }
    
    try {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    } catch {
        throw new Error("Invalid base64 input: decode failed");
    }
}

export function formatStashToken(id: string, keyBuffer: ArrayBuffer): string {
    const keyBase64 = arrayBufferToBase64(keyBuffer);
    return `${id}:${keyBase64}`;
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
    
    // Pre-validate base64 key length for performance (32 bytes = 44 chars base64)
    if (keyBase64.length !== 44) {
        throw new Error('Invalid stash token: key base64 length is incorrect');
    }
    
    let keyBuffer: ArrayBuffer;
    try {
        keyBuffer = base64ToArrayBuffer(keyBase64);
    } catch (error) {
        throw new Error('Invalid stash token: malformed key encoding');
    }
    
    // Validate decoded key length (defensive check)
    if (keyBuffer.byteLength !== KEY_LENGTH) {
        throw new Error(`Invalid stash token: key must be ${KEY_LENGTH} bytes`);
    }
    
    return { id, keyBuffer };
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
    const iv = base64ToArrayBuffer(payload.iv);
    const tag = base64ToArrayBuffer(payload.tag);
    const ciphertext = base64ToArrayBuffer(payload.ciphertext);
    
    return {
        keyBuffer,
        iv: new Uint8Array(iv),
        ciphertext: new Uint8Array(ciphertext),
        tag: new Uint8Array(tag)
    };
}

// Legacy decrypt function - now proxies to Web Worker
export async function decrypt(payload: PayloadData, keyBuffer: ArrayBuffer): Promise<string> {
    const { getCryptoManager } = await import('./crypto-manager');
    const manager = getCryptoManager();
    
    return await manager.decrypt(payload, keyBuffer);
}

export function createPayload(encryptionResult: EncryptionResult): PayloadData {
    return {
        iv: arrayBufferToBase64(encryptionResult.iv),
        tag: arrayBufferToBase64(encryptionResult.tag),
        ciphertext: arrayBufferToBase64(encryptionResult.ciphertext)
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
export function encodeKey(keyBuffer: ArrayBuffer): string {
    return arrayBufferToBase64(keyBuffer);
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
    
    // Use type guard for cleaner validation
    if (!isPayloadData(data)) {
        throw new Error('Invalid payload structure: missing required fields');
    }
    
    return data;
}

// Safe version for user input - returns null instead of throwing
export function tryParsePayload(encoded: string): PayloadData | null {
    try {
        return parsePayload(encoded);
    } catch {
        return null;
    }
}