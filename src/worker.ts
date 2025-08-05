/**
 * Stasher Web Worker - Secure crypto tool
 * Direct app serving with enhanced security headers
 * 
 * NOTE: We use CSP with 'unsafe-inline' for MVP support,
 * and Report-Only to test future switch to 'strict-dynamic' + script hashes.
 */

// HTML content injected at build time
declare const __STASHER_APP_HTML__: string;

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    
    // Serve the stasher app directly at root (with Accept header check for defense-in-depth)
    if (url.pathname === '/' && request.headers.get('Accept')?.includes('text/html')) {
      return new Response(__STASHER_APP_HTML__, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src https://api.stasher.dev; worker-src blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests;",
          'Content-Security-Policy-Report-Only': "default-src 'none'; script-src 'strict-dynamic'; style-src 'unsafe-inline'; connect-src https://api.stasher.dev; worker-src blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';",
          'Cross-Origin-Opener-Policy': 'same-origin',
          'Cross-Origin-Resource-Policy': 'cross-origin',
          'Referrer-Policy': 'no-referrer',
          'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()',
          'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
        }
      });
    }
    
    // Handle root path requests that don't accept HTML
    if (url.pathname === '/') {
      return new Response('Stasher - Secure Secret Sharing', {
        status: 200,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
        }
      });
    }
    
    // Simple favicon (empty response to avoid 404s)
    if (url.pathname === '/favicon.ico') {
      return new Response('', {
        status: 204,
        headers: {
          'Cache-Control': 'public, max-age=86400',
          'Content-Type': 'image/x-icon'
        }
      });
    }
    
    // 404 for everything else
    return new Response('Not Found', { status: 404 });
  }
};