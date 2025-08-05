// Crypto Worker Manager - Proxies crypto operations to isolated Web Worker
import type { CryptoWorkerManager, PayloadData, WorkerRequest, WorkerResponse, CryptoWorkerAction } from './crypto-interface';

class CryptoWorkerManagerImpl implements CryptoWorkerManager {
    private worker: Worker | null = null;
    private workerUrl: string | null = null;
    private requestId = 0;
    private pendingRequests = new Map<string, {
        resolve: (value: any) => void;
        reject: (error: Error) => void;
        timeout: NodeJS.Timeout;
    }>();

    private async getWorker(): Promise<Worker> {
        if (!this.worker) {
            // Create worker from inlined code (injected by build system)
            const workerCode = (globalThis as any).__CRYPTO_WORKER_CODE__;
            if (!workerCode) {
                throw new Error('Crypto worker code not found - build system issue');
            }
            
            const blob = new Blob([workerCode], { type: 'application/javascript' });
            this.workerUrl = URL.createObjectURL(blob);
            this.worker = new Worker(this.workerUrl);
            
            this.worker.onmessage = (event: MessageEvent) => {
                const response: WorkerResponse = event.data;
                const pending = this.pendingRequests.get(response.id);
                
                if (pending) {
                    this.pendingRequests.delete(response.id);
                    clearTimeout(pending.timeout);
                    
                    if (response.success) {
                        pending.resolve(response.result);
                    } else {
                        pending.reject(new Error(response.error || 'Unknown worker error'));
                    }
                }
            };
            
            this.worker.onerror = (error) => {
                console.error('Crypto worker error:', error);
                // Reject all pending requests and clear timeouts
                for (const [id, pending] of this.pendingRequests) {
                    clearTimeout(pending.timeout);
                    pending.reject(new Error('Worker error'));
                    this.pendingRequests.delete(id);
                }
            };
        }
        
        return this.worker;
    }

    private async sendRequest(action: CryptoWorkerAction, data: any): Promise<any> {
        const worker = await this.getWorker();
        const id = `req-${++this.requestId}`;
        
        return new Promise((resolve, reject) => {
            // Create timeout with proper cleanup
            const timeout = setTimeout(() => {
                if (this.pendingRequests.has(id)) {
                    this.pendingRequests.delete(id);
                    reject(new Error('Crypto operation timeout'));
                }
            }, 30000);
            
            // Store request with timeout for cleanup
            this.pendingRequests.set(id, { 
                resolve: (value) => {
                    clearTimeout(timeout);
                    resolve(value);
                },
                reject: (error) => {
                    clearTimeout(timeout);
                    reject(error);
                },
                timeout
            });
            
            const request: WorkerRequest = {
                id,
                action,
                data
            };
            
            worker.postMessage(request);
        });
    }

    async encrypt(secret: string): Promise<{ keyBuffer: ArrayBuffer; payload: PayloadData }> {
        const result = await this.sendRequest('encrypt', { secret });
        return {
            keyBuffer: result.keyBuffer,
            payload: result.payload
        };
    }

    async decrypt(payload: PayloadData, keyBuffer: ArrayBuffer): Promise<string> {
        const result = await this.sendRequest('decrypt', { payload, keyBuffer });
        return result.secret;
    }

    terminate(): void {
        if (this.worker) {
            // Reject all pending requests and clear timeouts
            for (const [id, pending] of this.pendingRequests) {
                clearTimeout(pending.timeout);
                pending.reject(new Error('Worker terminated'));
                this.pendingRequests.delete(id);
            }
            
            this.worker.terminate();
            this.worker = null;
        }
        
        // Clean up worker URL
        if (this.workerUrl) {
            URL.revokeObjectURL(this.workerUrl);
            this.workerUrl = null;
        }
    }
}

// Singleton instance
let cryptoManager: CryptoWorkerManager | null = null;

export function getCryptoManager(): CryptoWorkerManager {
    if (!cryptoManager) {
        cryptoManager = new CryptoWorkerManagerImpl();
    }
    return cryptoManager;
}

export function terminateCryptoManager(): void {
    if (cryptoManager) {
        cryptoManager.terminate();
        cryptoManager = null;
    }
}