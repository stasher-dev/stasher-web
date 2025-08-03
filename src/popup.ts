import { performEnstash, performDestash, performUnstash } from './api.js';

// Get elements
const operations = document.querySelectorAll('.operation') as NodeListOf<HTMLButtonElement>;
const input = document.querySelector('#main-input') as HTMLInputElement;
const message = document.querySelector('#message') as HTMLDivElement;
const clearButton = document.querySelector('#clear-button') as HTMLButtonElement;

// Store original button content for restoration
const originalButtonContent = Array.from(operations).map(btn => btn.innerHTML);

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
        input.value = '';
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
                showMessage('No secret to stash', true);
            } else if (mode === 'destash') {
                showMessage('No stash id to retreive', true);
            } else if (mode === 'unstash') {
                showMessage('No stash id to unstash', true);
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
                    // Secure input clearing - overwrite then clear (invisibly)
                    input.classList.add('clearing');
                    input.value = '[cleared]';
                    setTimeout(() => {
                        input.value = '';
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