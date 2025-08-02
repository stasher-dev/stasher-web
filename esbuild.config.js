import { build } from 'esbuild';
import { readFileSync, writeFileSync } from 'fs';

// Build the popup JavaScript first
const popupBuild = await build({
  entryPoints: ['src/popup.ts'],
  bundle: true,
  format: 'iife',
  target: 'es2022',
  platform: 'browser',
  minify: true,
  sourcemap: false,
  external: [],
  write: false
});

const popupJS = popupBuild.outputFiles[0].text;

// Read HTML template and inline the JavaScript
let popupHTML = readFileSync('./src/popup.html', 'utf8');
popupHTML = popupHTML.replace(
  '<script type="module" src="./popup.js"></script>',
  `<script>${popupJS}</script>`
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
    __POPUP_HTML__: JSON.stringify(popupHTML)
  },
  minify: true,
  sourcemap: false,
  external: []
});

console.log('✓ Build complete');