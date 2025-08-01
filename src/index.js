/**
 * Stasher Web Worker - Static file server
 * Serves index.html install page and stasher-web.mjs module
 */

// Embed the HTML content
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stasher DevTools</title>
    <style>
        body {
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            line-height: 1.5;
            color: #333;
            background: #f8f9fa;
            margin: 0;
            padding: 2rem;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 2rem;
            border: 1px solid #ddd;
        }
        
        h1 {
            margin: 0 0 1rem 0;
            font-size: 1.5rem;
        }
        
        .install-button {
            display: inline-block;
            background: #000;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border: none;
            cursor: pointer;
            margin: 1rem 0;
        }
        
        .install-button:hover {
            background: #333;
        }
        
        .code {
            background: #f5f5f5;
            padding: 1rem;
            border: 1px solid #ddd;
            overflow-x: auto;
            margin: 1rem 0;
        }
        
        .section {
            margin: 2rem 0;
        }
        
        pre {
            margin: 0;
        }
        
        ul {
            padding-left: 1.5rem;
        }
        
        li {
            margin: 0.5rem 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Stasher DevTools</h1>
        <p>Secure secret sharing in browser console. Zero install, burn-after-read.</p>
        
        <div class="section">
            <h2>Why?</h2>
            <p>I just wanted to share a password.<br>
            Not spin up a server. Not register for some "secure" web app. Not trust a Slack thread.<br>  
            Just. Send. A. Secret.</p>
            
            <p>So I built Stasher — for people who are busy, paranoid, or both.</p>
            
            <ul>
                <li>Works instantly in any browser</li>
                <li>Encrypts everything before it ever leaves your machine</li>
                <li>Secrets self-destruct after one read or 10 minutes</li>
                <li>No account, no login, no metadata, no snooping</li>
                <li>Cross-platform — create in browser, access from terminal (and vice versa)</li>
                <li>Share however you like — Slack, email, QR code, carrier pigeon...</li>
            </ul>
            
            <p>Basically, it's like a Mission Impossible tape, but for API keys.</p>
        </div>
        
        <div class="section">
            <h2>Install</h2>
            <p>Drag this to your bookmarks bar:</p>
            <a href="javascript:(async()=>{await import('https://install.stasher.dev/stasher-web.mjs').then(m=>m.default())})();" 
               class="install-button">Install Stasher</a>
               
            <p>Or paste in DevTools console:</p>
            <div class="code">
                <pre>await import("https://install.stasher.dev/stasher-web.mjs").then(m => m.default())</pre>
            </div>
        </div>
        
        <div class="section">
            <h2>Usage</h2>
            <div class="code">
                <pre>enstash\`my secret\`           // store
destash\`uuid:key\`             // retrieve (burns)
unstash\`uuid\`                 // delete</pre>
            </div>
        </div>
        
        <div class="section">
            <h2>Examples</h2>
            <div class="code">
                <pre>enstash\`API_KEY=sk-123\`
enstash\`password123\`
enstash\`-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----\`</pre>
            </div>
        </div>
        
        <div class="section">
            <h2>Features</h2>
            <ul>
                <li>AES-256-GCM client-side encryption</li>
                <li>Burn-after-read (one-time access)</li>
                <li>10-minute auto-expiry</li>
                <li>Zero-knowledge server</li>
                <li>No logs, no tracking</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>CLI Version</h2>
            <div class="code">
                <pre>npm install -g stasher-cli
npx enstash "secret"</pre>
            </div>
        </div>
        
        <div class="section">
            <p><a href="https://github.com/stasher-dev/stasher-web">Source</a> | 
               <a href="https://github.com/stasher-dev/stasher-cli">CLI</a> | 
               <a href="https://github.com/stasher-dev/stasher-worker">Worker</a></p>
        </div>
    </div>
</body>
</html>`;


export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Serve the main install page
    if (url.pathname === '/') {
      return new Response(HTML_CONTENT, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }
    
    // Serve the ESM module from R2 storage
    if (url.pathname === '/stasher-web.mjs') {
      const object = await env.R2_BUCKET.get('stasher-web.mjs');
      if (!object) {
        return new Response('Module not found', { status: 404 });
      }
      
      return new Response(object.body, {
        headers: {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Content-Type-Options': 'nosniff',
          'ETag': object.etag,
          'Last-Modified': object.uploaded.toUTCString()
        }
      });
    }
    
    // 404 for everything else
    return new Response('Not Found', { status: 404 });
  }
};