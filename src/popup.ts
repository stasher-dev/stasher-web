import { performEnstash, performDestash, performUnstash } from './api.js';

// Get elements
const operations = document.querySelectorAll('.operation') as NodeListOf<HTMLButtonElement>;
const input = document.querySelector('#main-input') as HTMLInputElement;
const message = document.querySelector('#message') as HTMLDivElement;
const clearButton = document.querySelector('#clear-button') as HTMLButtonElement;

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
    input.value = '[cleared]';
    setTimeout(() => input.value = '', 100);
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
                showMessage('Please enter a secret to stash', true);
            } else if (mode === 'destash') {
                showMessage('Please enter a token to retrieve', true);
            } else if (mode === 'unstash') {
                showMessage('Please enter a token or UUID to delete', true);
            }
            return;
        }
        
        // Clear previous message
        clearMessage();
        
        // Set spinner cursor and working state
        document.body.classList.add('working');
        op.classList.add('working');
        
        // Disable all buttons
        operations.forEach(btn => btn.disabled = true);
        clearButton.disabled = true;
        op.textContent = 'working...';
        
        try {
            let result_text: string;
            
            switch(mode) {
                case 'enstash':
                    result_text = await performEnstash(inputValue);
                    input.value = result_text;
                    showMessage('stash created');
                    break;
                    
                case 'destash':
                    result_text = await performDestash(inputValue);
                    input.value = result_text;
                    showMessage('stash retrieved');
                    break;
                    
                case 'unstash':
                    result_text = await performUnstash(inputValue);
                    // Secure input clearing - overwrite then clear
                    input.value = '[cleared]';
                    setTimeout(() => input.value = '', 100);
                    showMessage('stash deleted');
                    break;
            }
            
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            input.value = `Error: ${errorMessage}`;
            showMessage(errorMessage, true);
        } finally {
            // Remove spinner cursor and working state
            document.body.classList.remove('working');
            op.classList.remove('working');
            
            // Re-enable all buttons and reset text
            operations.forEach((btn, idx) => {
                btn.disabled = false;
                btn.textContent = ['enstash', 'destash', 'unstash'][idx];
            });
            clearButton.disabled = false;
        }
    });
});

// Initialize
input.focus();