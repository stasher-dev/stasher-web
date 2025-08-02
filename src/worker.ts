/**
 * Stasher Web Worker - Crypto tool interface
 * Serves secure popup for enstash/destash/unstash operations
 */

// HTML content injected at build time
declare const __POPUP_HTML__: string;

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    
    // Serve the crypto tool at root
    if (url.pathname === '/') {
      return new Response(__POPUP_HTML__, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src https://api.stasher.dev;"
        }
      });
    }
    
    // Simple favicon (empty response to avoid 404s)
    if (url.pathname === '/favicon.ico') {
      return new Response('', {
        status: 204,
        headers: {
          'Cache-Control': 'public, max-age=86400'
        }
      });
    }
    
    // 404 for everything else
    return new Response('Not Found', { status: 404 });
  }
};