// Type-safe interface for communication between main thread and crypto worker

// Re-export existing types from crypto.ts
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

// Worker action types for reuse and type safety
export type CryptoWorkerAction = 'encrypt' | 'decrypt';

// Worker message types
export interface WorkerRequest {
    id: string;
    action: CryptoWorkerAction;
    data: EncryptRequest | DecryptRequest;
}

export interface EncryptRequest {
    secret: string;
}

export interface DecryptRequest {
    payload: PayloadData;
    keyBuffer: Uint8Array;
}

export interface WorkerResponse {
    id: string;
    success: boolean;
    result?: EncryptResult | DecryptResult;
    error?: string;
}

export interface EncryptResult {
    keyBuffer: Uint8Array;
    payload: PayloadData;
}

export interface DecryptResult {
    secret: string;
}

// Worker management interface
export interface CryptoWorkerManager {
    encrypt(secret: string): Promise<{ keyBuffer: Uint8Array; payload: PayloadData }>;
    decrypt(payload: PayloadData, keyBuffer: Uint8Array): Promise<string>;
    terminate(): void;
}