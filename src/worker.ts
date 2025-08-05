/**
 * Stasher Web Worker - Secure crypto tool
 * Direct app serving with enhanced security headers
 */

// HTML content injected at build time
declare const __POPUP_HTML__: string;

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    
    // Serve the stasher app directly at root
    if (url.pathname === '/') {
      return new Response(__POPUP_HTML__, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests;",
          'Cross-Origin-Opener-Policy': 'same-origin',
          'Cross-Origin-Resource-Policy': 'cross-origin',
          'Referrer-Policy': 'no-referrer',
          'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()'
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