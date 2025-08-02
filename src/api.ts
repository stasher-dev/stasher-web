import {
    DEFAULT_API_BASE_URL,
    MAX_SECRET_LENGTH,
    encrypt,
    decrypt,
    createPayload,
    formatStashToken,
    decodeStashToken,
    validateSecretContent,
    validateSecretLength,
    validateUUID
} from './crypto.js';

// Allow API base URL override via query string for testing/dev
function getApiBaseUrl(): string {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('api') || DEFAULT_API_BASE_URL;
}

export async function performEnstash(secret: string): Promise<string> {
    if (!validateSecretContent(secret)) {
        throw new Error('Secret cannot be empty or whitespace only');
    }
    
    if (!validateSecretLength(secret)) {
        throw new Error(`Secret too long (max ${MAX_SECRET_LENGTH} characters)`);
    }
    
    try {
        const encryptionResult = await encrypt(secret);
        const payload = createPayload(encryptionResult);
        
        const response = await fetch(`${getApiBaseUrl()}/enstash`, {
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

export async function performDestash(token: string): Promise<string> {
    try {
        const { id, keyBuffer } = decodeStashToken(token);
        
        if (!validateUUID(id)) {
            throw new Error('Invalid UUID format in token');
        }
        
        const response = await fetch(`${getApiBaseUrl()}/destash/${id}`, {
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

export async function performUnstash(tokenOrId: string): Promise<string> {
    try {
        let id: string;
        if (tokenOrId.includes(':')) {
            const { id: extractedId } = decodeStashToken(tokenOrId);
            id = extractedId;
        } else {
            id = tokenOrId;
        }
        
        if (!validateUUID(id)) {
            throw new Error('Invalid UUID format');
        }
        
        const response = await fetch(`${getApiBaseUrl()}/unstash/${id}`, {
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