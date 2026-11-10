/**
 * build.mjs — esbuild config to produce a single IIFE bundle for Univer
 * exposing UniverBundle.createUniverSheets(containerId, ydoc, options)
 *         UniverBundle.createUniverDocs(containerId, ydoc, options)
 *
 * CSS is imported as text, bundled into the JS, and injected at runtime.
 * Output: ../js/univer-bundle.js  (~3-5MB minified with tree-shake)
 */

import * as esbuild from 'esbuild';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dir = dirname(fileURLToPath(import.meta.url));

const result = await esbuild.build({
    entryPoints: [resolve(__dir, 'src/univer-entry.mjs')],
    bundle: true,
    format: 'iife',
    globalName: 'UniverBundle',
    outfile: resolve(__dir, '../js/univer-bundle.js'),
    minify: true,
    // Inline CSS as text strings
    loader: { '.css': 'text', '.svg': 'text' },
    define: {
        'process.env.NODE_ENV': '"production"',
    },
    // Suppress React DevTools overlay
    inject: [],
    // Target modern browsers
    target: ['chrome90', 'firefox90', 'safari14'],
    // Allow large bundle
    logLevel: 'info',
});

if (result.errors.length) {
    console.error('Build errors:', result.errors);
    process.exit(1);
}
console.log('Build complete → ../js/univer-bundle.js');
