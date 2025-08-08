import { performEnstash, performDestash, performUnstash } from './api.js';

// Lock API imports at startup to prevent malicious redefinition
const safePerformEnstash = performEnstash;
const safePerformDestash = performDestash;
const safePerformUnstash = performUnstash;

// DOM clobbering defense - freeze critical APIs before any other operations
const safeCreateElement = document.createElement.bind(document);
const safeQuerySelector = document.querySelector.bind(document);
const safeQuerySelectorAll = document.querySelectorAll.bind(document);
const add = EventTarget.prototype.addEventListener;

// Note: Not freezing prototypes to avoid breaking 3rd-party widgets

// Get elements using safe references with null guards
const operations = safeQuerySelectorAll('.operation') as NodeListOf<HTMLButtonElement>;
const input = safeQuerySelector('#main-input') as HTMLInputElement;
const message = safeQuerySelector('#message') as HTMLDivElement;
const clearButton = safeQuerySelector('#clear-button') as HTMLButtonElement;

if (!input || !message || !clearButton || operations.length === 0) {
    throw new Error('Required elements missing');
}

// Add aria-hidden to decorative SVGs BEFORE capturing button children
operations.forEach(btn => {
    btn.querySelectorAll('svg').forEach(svg => svg.setAttribute('aria-hidden', 'true'));
});
clearButton.querySelectorAll('svg').forEach(svg => svg.setAttribute('aria-hidden', 'true'));

// Store original button children for restoration (safer cloning)
const originalButtonChildren = Array.from(operations, btn => {
    const frag = document.createDocumentFragment();
    frag.append(...Array.from(btn.childNodes).map(n => n.cloneNode(true)));
    return frag;
});

// Wipe token to avoid capturing secrets in closures
// Note: currentWipeToken removed as timeout-based cancellation is more reliable
let wipeTimeout: number | null = null;

// Abort controller for in-flight operations
let inflight: AbortController | null = null;

// Hoist constants to avoid re-allocation
const allowedModes = new Set(['enstash', 'destash', 'unstash']);
const prefersReducedMotion = typeof matchMedia === 'function'
    ? matchMedia('(prefers-reduced-motion: reduce)').matches
    : false;
let lastCancelTime = 0;
let enterArmed = true;
let isBusy = false;

// Cache TextEncoder for performance
const enc = new TextEncoder();

// Track what's currently displayed for accurate wipe timer labels
let lastDisplayed: 'Token' | 'Secret' | null = null;

// Find primary button by data attribute for safer targeting
const primaryButton = safeQuerySelector('[data-mode="enstash"]') as HTMLButtonElement;

if (!primaryButton) {
    throw new Error('Primary button not found');
}


// AbortSignal timeout with fallback for older browsers
const withTimeout = (signal: AbortSignal, ms: number) => {
    if (typeof AbortSignal.any === 'function' && typeof AbortSignal.timeout === 'function') {
        return AbortSignal.any([signal, AbortSignal.timeout(ms)]);
    }
    const ctl = new AbortController();
    const t = setTimeout(() => {
        // @ts-ignore cause is not everywhere yet
        ctl.abort('timeout');
        signal.removeEventListener('abort', onAbort);
    }, ms);
    const onAbort = () => {
        clearTimeout(t);
        // @ts-ignore cause is not everywhere yet
        ctl.abort('chained-abort');
        signal.removeEventListener('abort', onAbort);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    return ctl.signal;
};

function scheduleWipe(label: 'Token' | 'Secret', delay = 60000) {
    cancelWipe();
    const snapshot = input.value;
    wipeTimeout = window.setTimeout(() => {
        if (wipeTimeout === null) return;
        if (input.value !== snapshot) return; // user changed it; don't nuke
        if (!input.value) return;
        input.classList.add('clearing');
        secureErase(input);
        input.classList.remove('clearing');
        showMessage(`${label} cleared from memory`);
        wipeTimeout = null;
    }, delay);
}

function cancelWipe() {
    if (wipeTimeout !== null) {
        clearTimeout(wipeTimeout);
        wipeTimeout = null;
    }
}

async function runOp(mode: string, value: string) {
    inflight?.abort();
    inflight = new AbortController();
    const { signal } = inflight;

    try {
        // Add timeout with fallback for older browsers
        const linkedSignal = withTimeout(signal, 10000);
        
        if (mode === 'enstash') return await safePerformEnstash(value, { signal: linkedSignal });
        if (mode === 'destash') return await safePerformDestash(value, { signal: linkedSignal });
        return await safePerformUnstash(value, { signal: linkedSignal });
    } finally {
        if (inflight?.signal === signal) inflight = null;
    }
}

function createSpinner(): HTMLElement {
    const spinner = safeCreateElement('span');
    spinner.className = prefersReducedMotion ? 'spinner no-animate' : 'spinner';
    spinner.setAttribute('role', 'progressbar');
    spinner.setAttribute('aria-label', 'Working');
    return spinner;
}

// Note: Trusted Types policy removed since we use replaceChildren() instead of innerHTML

// Secure memory erasure for input fields (crypto paranoia level)
function secureErase(inputElement: HTMLInputElement): void {
    const len = inputElement.value.length;
    if (len > 0) {
        inputElement.value = '\u0000'.repeat(len);
        void inputElement.offsetHeight; // force reflow
        inputElement.value = '';
        // Clear selection/caret if users had text selected
        const sel = window.getSelection?.();
        if (sel && sel.rangeCount) sel.removeAllRanges();
    }
}


// Show message
function showMessage(text: string, isError: boolean = false): void {
    message.textContent = text;
    message.className = `message ${isError ? 'error' : 'success'}`;
    message.setAttribute('role', isError ? 'alert' : 'status');
}

function clearMessage(): void {
    message.textContent = '';
    message.className = 'message';
    message.removeAttribute('role');
}

// Handle clear button with secure clearing
add.call(clearButton, 'click', () => {
    cancelWipe(); // Cancel any pending wipe timer
    lastDisplayed = null; // Nothing displayed after clear
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
    add.call(op, 'click', async () => {
        if (isBusy || op.classList.contains('working') || inflight) return; // Prevent double-clicks and race conditions
        
        const inputValue = input.value.trim();
        
        // Length guard before calling APIs (fast-fail huge pastes) - check bytes not chars
        const inputBytes = enc.encode(inputValue);
        if (inputBytes.length > 4096) {
            showMessage('Input is too large (max 4KB).', true);
            return;
        }
        
        // Normalize and bound mode values
        const mode = (op.dataset.mode ?? '').toLowerCase();
        if (!allowedModes.has(mode)) {
            showMessage('Invalid operation', true);
            return;
        }
        
        // Check for empty input
        if (!inputValue) {
            showMessage(
                mode === 'enstash' ? 'Input secret to stash'
                : mode === 'destash' ? 'Input a stash id to retrieve'
                : 'Input a stash id to unstash',
                true
            );
            return;
        }
        
        // Only lock after we know we're running the op
        isBusy = true;
        
        // Clear previous message
        clearMessage();
        
        // Cancel any previous wipe and set working state
        cancelWipe();
        document.body.classList.add('working');
        document.body.setAttribute('aria-busy', 'true');
        op.classList.add('working');
        
        // Disable all buttons and show spinner
        operations.forEach(btn => {
            btn.disabled = true;
            btn.setAttribute('aria-disabled', 'true');
        });
        // Only set aria-busy on the active button
        op.setAttribute('aria-busy', 'true');
        clearButton.disabled = true;
        clearButton.setAttribute('aria-disabled', 'true');
        op.replaceChildren(createSpinner());
        
        try {
            let result_text: string;
            
            switch(mode) {
                case 'enstash':
                    result_text = await runOp(mode, inputValue);
                    input.value = result_text;
                    lastDisplayed = 'Token';
                    try {
                        input.select(); // Auto-select for quick copy
                    } catch {
                        // Ignore selection errors on mobile
                    }
                    let canClipboardNow = false;
                    try {
                        canClipboardNow = !!navigator.clipboard?.writeText;
                    } catch {}
                    
                    if (canClipboardNow && document.hasFocus?.()) {
                        try {
                            await navigator.clipboard.writeText(input.value);
                            (document.activeElement as HTMLElement | null)?.blur?.();
                            const sel = window.getSelection?.();
                            sel?.rangeCount && sel.removeAllRanges();
                            showMessage('Stash created and copied to clipboard');
                            // Reset wipe timer after successful copy (users often paste and return)
                            cancelWipe();
                        } catch {
                            showMessage('Stash created. Copy it manually (clipboard blocked).');
                            cancelWipe(); // Let them copy without 30s surprise nuke
                        }
                    } else {
                        const httpsHint = location.protocol !== 'https:' ? ' (needs HTTPS)' : '';
                        const focusHint = !document.hasFocus?.() ? ' (page needs focus)' : '';
                        showMessage(`Stash created. Copy it manually (no Clipboard API${httpsHint}${focusHint}).`);
                    }
                    result_text = ''; // Clear sensitive reference early
                    scheduleWipe('Token');
                    break;
                    
                case 'destash':
                    result_text = await runOp(mode, inputValue);
                    input.value = result_text;
                    lastDisplayed = 'Secret';
                    result_text = ''; // Clear sensitive reference early
                    // Clear selection consistently
                    const sel = window.getSelection?.();
                    sel?.rangeCount && sel.removeAllRanges();
                    (document.activeElement as HTMLElement | null)?.blur?.();
                    showMessage('Stash retrieved');
                    scheduleWipe('Secret');
                    break;
                    
                case 'unstash':
                    result_text = await runOp(mode, inputValue);
                    result_text = ''; // Clear sensitive reference early
                    lastDisplayed = null; // Nothing to wipe after unstash
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
            
        } catch (error: any) {
            if (error?.name === 'AbortError') {
                if (String(error?.message || error?.cause).includes('timeout')) {
                    showMessage('Request timed out. Please try again.', true);
                }
                return;
            }
            showMessage(error instanceof Error ? error.message : 'Unknown error', true);
        } finally {
            // Remove spinner cursor and working state
            document.body.classList.remove('working');
            document.body.removeAttribute('aria-busy');
            op.classList.remove('working');
            
            // Re-enable all buttons and restore original HTML
            operations.forEach((btn, idx) => {
                btn.disabled = false;
                btn.removeAttribute('aria-disabled');
                // Only remove aria-busy if we set it
                if (btn.hasAttribute('aria-busy')) {
                    btn.removeAttribute('aria-busy');
                }
                // Restore from cloned fragments (safe from mutations)
                btn.replaceChildren(originalButtonChildren[idx].cloneNode(true));
                // Re-apply aria-hidden to any SVGs in case content changed
                btn.querySelectorAll('svg').forEach(svg => svg.setAttribute('aria-hidden', 'true'));
            });
            clearButton.disabled = false;
            clearButton.removeAttribute('aria-disabled');
            isBusy = false;
        }
    });
});

// Memory hygiene - wipe field on tab hidden or page navigation
add.call(document, 'visibilitychange', () => {
    if (document.hidden && input.value) {
        inflight?.abort(); // Cancel any in-flight operations
        cancelWipe(); // Cancel any pending wipe
        lastDisplayed = null; // Nothing displayed after clear
        input.classList.add('clearing');
        secureErase(input);
        input.classList.remove('clearing');
        showMessage('Field cleared on tab hide');
    }
}, { passive: true });

add.call(window, 'pagehide', () => {
    inflight?.abort(); // Cancel any in-flight operations
    cancelWipe(); // Cancel any pending wipe
    lastDisplayed = null; // Nothing displayed after clear
    if (input.value) {
        secureErase(input);
    }
}, { passive: true });

// Handle Enter key for primary action (enstash) with key-repeat prevention
add.call(input, 'keydown', (e: KeyboardEvent) => {
    if (e.key === 'Enter' && enterArmed && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
        enterArmed = false;
        e.preventDefault();
        if (primaryButton && !primaryButton.disabled && !primaryButton.classList.contains('working')) {
            primaryButton.click();
        }
        setTimeout(() => { enterArmed = true; }, 250);
    }
});

// Cancel wipe if user starts typing something new or loses focus
add.call(input, 'input', () => cancelWipe());
add.call(input, 'blur', cancelWipe);

// Cancel wipe when user copies, then re-arm to avoid surprise nuke during clipboard workflow
add.call(input, 'copy', () => {
    cancelWipe();
    setTimeout(() => { if (lastDisplayed) scheduleWipe(lastDisplayed); }, 1000);
});

// Cancel operations on Escape key with debounced acknowledgment
add.call(document, 'keydown', (e: KeyboardEvent) => {
    if (e.key === 'Escape' && inflight) {
        inflight.abort();
        const now = Date.now();
        if (now - lastCancelTime > 500) {
            showMessage('Operation cancelled', true);
        }
        lastCancelTime = now;
    }
});

// Configure input for secrets - disable auto-everything
input.autocomplete = 'new-password'; // Reduce autofill nags
input.autocapitalize = 'off';
input.spellcheck = false;
(input as any).enterKeyHint = 'done';
(input as any).inputMode = 'text';
input.setAttribute('autocorrect', 'off'); // iOS fix
// Keep password managers away
input.setAttribute('data-1p-ignore', 'true'); // 1Password
input.setAttribute('data-lpignore', 'true');  // LastPass

// Prevent drag/drop and middle-click paste (avoid accidental secret dumps)
add.call(input, 'drop', (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
});
add.call(input, 'dragover', (e: DragEvent) => e.preventDefault());
add.call(input, 'auxclick', (e: MouseEvent) => {
    if (e.button === 1) e.preventDefault(); // Block middle-click paste
});

// Note: role="status" already implies aria-live="polite", so no need for explicit aria-live

// Block default form submit if wrapped in a form (consistent with clobbering defenses)
const form = safeQuerySelector('form');
if (form) {
    add.call(form, 'submit', (e: Event) => e.preventDefault());
}

// Initialize - focus input after DOM is ready
queueMicrotask(() => {
    if (document.hasFocus?.()) {
        try {
            input.focus();
        } catch {}
    }
});