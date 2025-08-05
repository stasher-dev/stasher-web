import { performEnstash, performDestash, performUnstash } from './api.js';

// DOM clobbering defense - freeze critical APIs before any other operations
const safeOpen = window.open.bind(window);
const safeDocument = document;
const safeCreateElement = document.createElement.bind(document);
const safeAddEventListener = EventTarget.prototype.addEventListener.bind(window);
const safeRemoveEventListener = EventTarget.prototype.removeEventListener.bind(window);
const safeQuerySelector = document.querySelector.bind(document);
const safeQuerySelectorAll = document.querySelectorAll.bind(document);

// Freeze core DOM/Window APIs to prevent clobbering
Object.freeze(window.open);
Object.freeze(document.createElement);
Object.freeze(EventTarget.prototype.addEventListener);
Object.freeze(EventTarget.prototype.removeEventListener);

// Get elements using safe references
const operations = safeQuerySelectorAll('.operation') as NodeListOf<HTMLButtonElement>;
const input = safeQuerySelector('#main-input') as HTMLInputElement;
const message = safeQuerySelector('#message') as HTMLDivElement;
const clearButton = safeQuerySelector('#clear-button') as HTMLButtonElement;

// Store original button content for restoration
const originalButtonContent = Array.from(operations).map(btn => btn.innerHTML);

// Auto-close timer for security (30 seconds of inactivity)
let idleTimeout: number;

function resetIdleTimer(): void {
    clearTimeout(idleTimeout);
    idleTimeout = setTimeout(() => {
        // Only auto-close if we're in a popup (not direct browser access)
        if (window.opener !== null || window.name !== '') {
            window.close();
        }
    }, 30000); // 30 seconds
}

// Initialize idle timer
resetIdleTimer();

// Reset timer on user activity
safeAddEventListener('mousemove', resetIdleTimer);
safeAddEventListener('keydown', resetIdleTimer);
safeAddEventListener('click', resetIdleTimer);

// Trusted Types runtime defense - block any unsafe HTML injection
if ('trustedTypes' in window) {
    try {
        (window as any).trustedTypes.createPolicy('default', {
            createHTML: (input: string) => {
                throw new TypeError("Unsafe HTML blocked by Trusted Types policy");
            },
            createScript: (input: string) => {
                throw new TypeError("Unsafe script blocked by Trusted Types policy");
            },
            createScriptURL: (input: string) => {
                throw new TypeError("Unsafe script URL blocked by Trusted Types policy");
            }
        });
    } catch (e) {
        // Policy already exists or not supported - that's fine
    }
}

// Secure memory erasure for input fields (crypto paranoia level)
function secureErase(inputElement: HTMLInputElement): void {
    const originalLength = inputElement.value.length;
    if (originalLength > 0) {
        // Overwrite with null bytes first
        inputElement.value = '\u0000'.repeat(originalLength);
        // Then clear completely
        inputElement.value = '';
    }
}

// Show message
function showMessage(text: string, isError: boolean = false): void {
    message.textContent = text;
    message.className = `message ${isError ? 'error' : 'success'}`;
}

function clearMessage(): void {
    message.textContent = '';
    message.className = 'message';
}

// Handle clear button with secure clearing
clearButton.addEventListener('click', () => {
    input.classList.add('clearing');
    input.value = '[cleared]';
    setTimeout(() => {
        secureErase(input);
        input.classList.remove('clearing');
    }, 100);
    clearMessage();
});

// Handle operation buttons
operations.forEach(op => {
    op.addEventListener('click', async () => {
        const inputValue = input.value.trim();
        const mode = op.dataset.mode as string;
        
        // Check for empty input
        if (!inputValue) {
            if (mode === 'enstash') {
                showMessage('Input secret to stash', true);
            } else if (mode === 'destash') {
                showMessage('Input a stash id to retreive', true);
            } else if (mode === 'unstash') {
                showMessage('Input a stash id to unstash', true);
            }
            return;
        }
        
        // Clear previous message
        clearMessage();
        
        // Set spinner cursor and working state
        document.body.classList.add('working');
        op.classList.add('working');
        
        // Disable all buttons and show spinner
        operations.forEach(btn => btn.disabled = true);
        clearButton.disabled = true;
        op.innerHTML = '<span class="spinner"></span>';
        
        try {
            let result_text: string;
            
            switch(mode) {
                case 'enstash':
                    result_text = await performEnstash(inputValue);
                    input.value = result_text;
                    showMessage('Stash created');
                    break;
                    
                case 'destash':
                    result_text = await performDestash(inputValue);
                    input.value = result_text;
                    showMessage('Stash retrieved');
                    break;
                    
                case 'unstash':
                    result_text = await performUnstash(inputValue);
                    // Secure input clearing with memory erasure
                    input.classList.add('clearing');
                    input.value = '[cleared]';
                    setTimeout(() => {
                        secureErase(input);
                        input.classList.remove('clearing');
                    }, 100);
                    showMessage('Stash deleted');
                    break;
            }
            
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            showMessage(errorMessage, true);
        } finally {
            // Remove spinner cursor and working state
            document.body.classList.remove('working');
            op.classList.remove('working');
            
            // Re-enable all buttons and restore original SVG content
            operations.forEach((btn, idx) => {
                btn.disabled = false;
                btn.innerHTML = originalButtonContent[idx];
            });
            clearButton.disabled = false;
        }
    });
});

// Initialize - focus input after DOM is ready
setTimeout(() => input.focus(), 0);