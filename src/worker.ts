/**
 * Stasher Web Worker - Fortress-level security crypto tool
 * 
 * Security Features:
 * - Nonce-based CSP with strict-dynamic (no unsafe-inline)
 * - DOM clobbering protection with frozen APIs
 * - Auto-close popup timer (30s inactivity)
 * - Trusted Types enforcement
 * - Cross-origin isolation (COEP/COOP)
 * - Anti-fingerprinting window names
 */

// HTML content and nonce injected at build time
declare const __STASHER_APP_HTML__: string;
declare const __SCRIPT_NONCE__: string;

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
          'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${__SCRIPT_NONCE__}' 'strict-dynamic'; style-src 'unsafe-inline'; connect-src https://api.stasher.dev; worker-src blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; upgrade-insecure-requests;`,
          'Cross-Origin-Opener-Policy': 'same-origin',
          'Cross-Origin-Embedder-Policy': 'require-corp',
          'Cross-Origin-Resource-Policy': 'cross-origin',
          'Referrer-Policy': 'no-referrer',
          'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()',
          'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
          'ETag': '"v2-stasher-hardened"'
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
    
    // 404 for everything else with structured response
    return new Response('{"error":"Route not found","available_routes":["/"],"app":"stasher"}', {
      status: 404,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
      }
    });
  }
};