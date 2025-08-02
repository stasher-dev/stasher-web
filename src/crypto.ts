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

export function formatStashToken(id: string, keyBuffer: ArrayBuffer): string {
    const keyBase64 = arrayBufferToBase64(keyBuffer);
    return `${id}:${keyBase64}`;
}

export function decodeStashToken(token: string): StashTokenData {
    const colonIndex = token.indexOf(':');
    if (colonIndex === -1) {
        throw new Error('Invalid stash token format: missing colon separator');
    }
    
    const id = token.substring(0, colonIndex);
    const keyBase64 = token.substring(colonIndex + 1);
    const keyBuffer = base64ToArrayBuffer(keyBase64);
    
    return { id, keyBuffer };
}

export async function encrypt(secret: string): Promise<EncryptionResult> {
    // Use crypto.subtle.generateKey for better security compliance
    const cryptoKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable so we can get the raw key
        ['encrypt']
    );
    
    const keyBuffer = await crypto.subtle.exportKey('raw', cryptoKey);
    const iv = randomBytes(IV_LENGTH);
    
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

export async function decrypt(payload: PayloadData, keyBuffer: ArrayBuffer): Promise<string> {
    const iv = base64ToArrayBuffer(payload.iv);
    const tag = base64ToArrayBuffer(payload.tag);
    const ciphertext = base64ToArrayBuffer(payload.ciphertext);
    
    if (iv.byteLength !== IV_LENGTH) {
        throw new Error(`Invalid IV length: must be ${IV_LENGTH} bytes`);
    }
    if (tag.byteLength !== TAG_LENGTH) {
        throw new Error(`Invalid auth tag length: must be ${TAG_LENGTH} bytes`);
    }
    if (keyBuffer.byteLength !== KEY_LENGTH) {
        throw new Error(`Invalid key length: must be ${KEY_LENGTH} bytes`);
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

export function createPayload(encryptionResult: EncryptionResult): PayloadData {
    return {
        iv: arrayBufferToBase64(encryptionResult.iv),
        tag: arrayBufferToBase64(encryptionResult.tag),
        ciphertext: arrayBufferToBase64(encryptionResult.ciphertext)
    };
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

// Additional helper functions from CLI version
export function encodeKey(keyBuffer: ArrayBuffer): string {
    return arrayBufferToBase64(keyBuffer);
}

export function encodePayload(payload: PayloadData): string {
    return JSON.stringify(payload);
}

export function parsePayload(encoded: string): PayloadData {
    return JSON.parse(encoded);
}