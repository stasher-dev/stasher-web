// Crypto Web Worker - All cryptographic operations isolated in this worker thread
// No DOM access, no shared memory with main thread

// Import crypto constants and types
import type { EncryptionResult, PayloadData, CryptoWorkerAction } from './crypto-interface';

// Constants (duplicated to avoid imports in worker)
const MAX_SECRET_LENGTH = 4096;
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

// Utility functions (duplicated to avoid imports)
function randomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
}

// Base64 encoding/decoding functions
// Note: Using atob/btoa for simplicity and compatibility
// For high-performance apps, I need to refactor with TextEncoder/Decoder with Uint8Array buffer approach
function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
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

async function decryptSecret(payload: PayloadData, keyBuffer: ArrayBuffer): Promise<string> {
    // Validate inputs
    if (!payload || typeof payload !== 'object') {
        throw new Error('Invalid payload');
    }
    if (!keyBuffer || keyBuffer.byteLength !== KEY_LENGTH) {
        throw new Error(`Invalid key length: must be ${KEY_LENGTH} bytes`);
    }

    const iv = base64ToArrayBuffer(payload.iv);
    const tag = base64ToArrayBuffer(payload.tag);
    const ciphertext = base64ToArrayBuffer(payload.ciphertext);
    
    if (iv.byteLength !== IV_LENGTH) {
        throw new Error(`Invalid IV length: must be ${IV_LENGTH} bytes`);
    }
    if (tag.byteLength !== TAG_LENGTH) {
        throw new Error(`Invalid auth tag length: must be ${TAG_LENGTH} bytes`);
    }
    
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
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
            iv: new Uint8Array(iv),
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
        iv: arrayBufferToBase64(encryptionResult.iv),
        tag: arrayBufferToBase64(encryptionResult.tag),
        ciphertext: arrayBufferToBase64(encryptionResult.ciphertext)
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
        // For encrypt operations, transfer keyBuffer ownership to main thread
        if (action === 'encrypt' && result.keyBuffer instanceof ArrayBuffer) {
            self.postMessage({
                id,
                success: true,
                result
            }, { transfer: [result.keyBuffer] });
        } else {
            self.postMessage({
                id,
                success: true,
                result
            });
        }
        
        // Defensive cleanup: wipe any remaining sensitive data
        if (action === 'encrypt') {
            // KeyBuffer is already transferred (ownership moved), but clear reference
            result.keyBuffer = null;
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