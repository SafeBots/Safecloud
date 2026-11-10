"use strict";
/**
 * Safecloud 2.9 — Playwright browser test runner.
 *
 * Bundles the data-structure modules for the browser, serves them
 * from a local HTTP server, opens a headless Chromium, and checks
 * that every test in browser_test.html passes.
 *
 * Usage:  node tests/browser_test.playwright.js
 */

const { execSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const testsDir = __dirname;

// 1. Build the browser bundle
console.log('Building browser bundle…');
execSync('node ' + path.join(testsDir, 'browser_bundle.js'), { stdio: 'inherit' });

// 2. Serve the test files over HTTP
const server = http.createServer((req, res) => {
    let filePath;
    if (req.url === '/' || req.url === '/browser_test.html') {
        filePath = path.join(testsDir, 'browser_test.html');
    } else if (req.url === '/browser_tests.bundle.js') {
        filePath = path.join(testsDir, 'browser_tests.bundle.js');
    } else {
        res.writeHead(404);
        res.end('Not found');
        return;
    }

    const content = fs.readFileSync(filePath);
    const ext = path.extname(filePath);
    const types = { '.html': 'text/html', '.js': 'application/javascript' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain' });
    res.end(content);
});

async function run() {
    // Start server on a random port
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const url = `http://127.0.0.1:${port}/browser_test.html`;
    console.log(`Test server on ${url}`);

    let exitCode = 1;
    try {
        // Launch headless browser
        const { chromium } = require('playwright');
        const browser = await chromium.launch({ headless: true });
        const page = await browser.newPage();

        // Collect console output
        page.on('console', msg => {
            console.log('[browser]', msg.text());
        });

        // Navigate to test page
        await page.goto(url, { waitUntil: 'networkidle' });

        // Wait for test results
        const results = await page.evaluate(() => window.__testResults);

        if (!results) {
            console.error('ERROR: No test results found on page');
        } else {
            console.log(`\nBrowser tests: ${results.pass} passed, ${results.fail} failed`);
            if (results.fail === 0) {
                console.log('All browser tests passed!');
                exitCode = 0;
            } else {
                console.error('Some browser tests failed!');
            }
        }

        await browser.close();
    } catch (err) {
        console.error('Playwright error:', err.message);
    }

    server.close();
    process.exit(exitCode);
}

run();
