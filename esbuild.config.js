import { build } from 'esbuild';
import { readFileSync, writeFileSync } from 'fs';

// Build the crypto worker first
const cryptoWorkerBuild = await build({
  entryPoints: ['src/crypto-worker.ts'],
  bundle: true,
  format: 'iife',
  target: 'es2022',
  platform: 'browser',
  minify: true,
  sourcemap: false,
  external: [],
  write: false
});

const cryptoWorkerJS = cryptoWorkerBuild.outputFiles[0].text;

// Build the stasher app JavaScript
const stasherAppBuild = await build({
  entryPoints: ['src/stasher_app.ts'],
  bundle: true,
  format: 'iife',
  target: 'es2022',
  platform: 'browser',
  minify: true,
  sourcemap: false,
  external: [],
  define: {
    __CRYPTO_WORKER_CODE__: JSON.stringify(cryptoWorkerJS)
  },
  write: false
});

const stasherAppJS = stasherAppBuild.outputFiles[0].text;

// Read HTML template
let stasherAppHTML = readFileSync('./src/stasher_app.html', 'utf8');

// Inline JavaScript into the secure app
stasherAppHTML = stasherAppHTML.replace(
  '<script type="module" src="./stasher_app.js"></script>',
  `<script>
    // Inject crypto worker code into global scope
    globalThis.__CRYPTO_WORKER_CODE__ = ${JSON.stringify(cryptoWorkerJS)};
    // Main application code
    ${stasherAppJS}
  </script>`
);

// Build the worker with HTML injection
await build({
  entryPoints: ['src/worker.ts'],
  bundle: true,
  outfile: 'dist/worker.js',
  format: 'esm',
  target: 'es2022',
  platform: 'neutral',
  define: {
    __STASHER_APP_HTML__: JSON.stringify(stasherAppHTML)
  },
  minify: true,
  sourcemap: false,
  external: []
});

console.log('✓ Build complete');