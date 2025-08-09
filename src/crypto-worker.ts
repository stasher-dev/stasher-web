// Crypto Web Worker - All cryptographic operations isolated in this worker thread
// No DOM access, no shared memory with main thread

// Import crypto constants and types
import type { EncryptionResult, PayloadData, CryptoWorkerAction } from './crypto-interface';

// Constants (duplicated to avoid imports in worker)
const MAX_SECRET_LENGTH = 4096;
const MAX_CIPHERTEXT_BYTES = 16384; // Max ciphertext bytes (server limit)
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

// Utility functions (duplicated to avoid imports)
function randomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
}

// Base64url encoding/decoding functions
// Note: Using atob/btoa with base64url conversion for compatibility and URL-safety
function arrayBufferToBase64Url(input: ArrayBuffer | ArrayBufferView): string {
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


function fromBase64Url(b64url: string): string {
    // Convert base64url to base64 and add padding
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4;
    if (pad) {
        b64 += '='.repeat(4 - pad);
    }
    return b64;
}

function base64UrlToBytes(base64url: string): Uint8Array {
    if (typeof base64url !== 'string') {
        throw new Error("Invalid base64url input: must be string");
    }
    
    // Base64url format validation (no padding, uses -_ instead of +/)
    const B64URL = /^[A-Za-z0-9_-]+$/;
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

// Core crypto operations
async function encryptSecret(secret: string): Promise<EncryptionResult> {
    // Validate input
    if (!secret || typeof secret !== 'string') {
        throw new Error('Invalid secret: must be non-empty string');
    }
    if (secret.length > MAX_SECRET_LENGTH) {
        throw new Error(`Secret too long: maximum ${MAX_SECRET_LENGTH} characters`);
    }

    // Generate fresh AES-GCM key
    const cryptoKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable so we can export for token
        ['encrypt']
    );
    
    const keyBuffer = new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey));
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

async function decryptSecret(payload: PayloadData, keyBuffer: Uint8Array): Promise<string> {
    // Validate inputs
    if (!payload || typeof payload !== 'object') {
        throw new Error('Invalid payload');
    }
    if (!keyBuffer || keyBuffer.length !== KEY_LENGTH) {
        throw new Error(`Invalid key: must be ${KEY_LENGTH} bytes`);
    }

    const iv = base64UrlToBytes(payload.iv);
    const tag = base64UrlToBytes(payload.tag);
    const ciphertext = base64UrlToBytes(payload.ciphertext);
    
    if (iv.length !== IV_LENGTH) {
        throw new Error(`Invalid IV length: must be ${IV_LENGTH} bytes`);
    }
    if (tag.length !== TAG_LENGTH) {
        throw new Error(`Invalid auth tag length: must be ${TAG_LENGTH} bytes`);
    }
    
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBuffer.buffer,
        { name: 'AES-GCM' },
        false, // not extractable for security
        ['decrypt']
    );
    
    const encryptedData = new Uint8Array(ciphertext.byteLength + tag.byteLength);
    encryptedData.set(new Uint8Array(ciphertext));
    encryptedData.set(new Uint8Array(tag), ciphertext.byteLength);
    
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: TAG_LENGTH * 8
        },
        cryptoKey,
        encryptedData
    );
    
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(decrypted);
}

function createPayload(encryptionResult: EncryptionResult): PayloadData {
    return {
        iv: arrayBufferToBase64Url(encryptionResult.iv),
        tag: arrayBufferToBase64Url(encryptionResult.tag),
        ciphertext: arrayBufferToBase64Url(encryptionResult.ciphertext)
    };
}

// Secure memory clearing utility
function secureWipe(buffer: ArrayBuffer | Uint8Array | null): void {
    if (!buffer) return;
    
    if (buffer instanceof ArrayBuffer) {
        new Uint8Array(buffer).fill(0);
    } else if (buffer instanceof Uint8Array) {
        buffer.fill(0);
    }
}

// Message handler - processes requests from main thread
self.onmessage = async (event: MessageEvent) => {
    // Validate message structure
    if (!event.data || typeof event.data !== 'object') {
        self.postMessage({
            id: 'unknown',
            success: false,
            error: 'Malformed message: missing or invalid data'
        });
        return;
    }
    
    const { id, action, data }: { id: string, action: CryptoWorkerAction, data: any } = event.data;
    
    // Validate required fields
    if (!id || typeof id !== 'string') {
        self.postMessage({
            id: 'unknown',
            success: false,
            error: 'Malformed message: missing or invalid id'
        });
        return;
    }
    
    if (!action || typeof action !== 'string') {
        self.postMessage({
            id,
            success: false,
            error: 'Malformed message: missing or invalid action'
        });
        return;
    }
    
    if (typeof data !== 'object' || data === null) {
        self.postMessage({
            id,
            success: false,
            error: 'Malformed message: missing or invalid data payload'
        });
        return;
    }
    
    try {
        let result: any;
        
        switch (action) {
            case 'encrypt':
                const encryptionResult = await encryptSecret(data.secret);
                const payload = createPayload(encryptionResult);
                result = {
                    keyBuffer: encryptionResult.keyBuffer,
                    payload
                };
                
                // Clear intermediate buffers from memory
                secureWipe(encryptionResult.iv);
                secureWipe(encryptionResult.ciphertext);
                secureWipe(encryptionResult.tag);
                
                // Clear secret from data (defensive)
                if (data.secret && typeof data.secret === 'string') {
                    data.secret = '[cleared]';
                }
                break;
                
            case 'decrypt':
                const decrypted = await decryptSecret(data.payload, data.keyBuffer);
                result = {
                    secret: decrypted
                };
                
                // Secure memory clearing (burn-after-read in worker memory)
                secureWipe(data.keyBuffer);
                if (data.payload) {
                    // Clear base64 strings by overwriting
                    if (data.payload.iv) data.payload.iv = '[cleared]';
                    if (data.payload.tag) data.payload.tag = '[cleared]';
                    if (data.payload.ciphertext) data.payload.ciphertext = '[cleared]';
                }
                data.keyBuffer = null;
                data.payload = null;
                break;
                
            default:
                throw new Error(`Unknown action: ${action}`);
        }
        
        // Send result back to main thread with transfer optimization
        if (action === 'encrypt') {
            // Zero-copy transfer of keyBuffer to main thread
            self.postMessage({
                id,
                success: true,
                result
            }, [result.keyBuffer.buffer]);
            
            // Zero the original keyBuffer in worker after transfer
            result.keyBuffer.fill(0);
            result.keyBuffer = null;
        } else {
            self.postMessage({
                id,
                success: true,
                result
            });
        }
        
    } catch (error) {
        // Send error back to main thread
        self.postMessage({
            id,
            success: false,
            error: error instanceof Error ? error.message : 'Unknown crypto worker error'
        });
    }
};