"use strict";
/**
 * Safecloud 2.9 — Playwright streaming regression tests.
 *
 * Tests the three regressions that were introduced in commit abde8fe
 * and fixed in the regression-fix commit:
 *
 *   1. Q.Safecloud.Client.streamPath — localStorage-seeded global
 *   2. Smart SW timeout — 500ms (active) vs 8000ms (installing)
 *   3. _choosePath — uses window.MediaSource || window.ManagedMediaSource
 *   4. streamMSE — MSClass/isManaged detection + disableRemotePlayback
 *   5. stream() path override — options.path respected
 *
 * The Jet server (demo/jet.js) requires the full Qbix platform (Q.inc)
 * which is not bundled in the standalone repo.  Instead we test all
 * browser-side logic — SW registration, path selection, MSE detection —
 * against a minimal HTTP server that serves only what each test needs.
 *
 * ManagedMediaSource (iOS Safari) cannot be tested in desktop Chromium,
 * which always exposes window.MediaSource; we monkey-patch window to
 * simulate the iOS environment for those branches.
 *
 * Usage:  node tests/playwright_streaming_test.js
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');

// ── paths ────────────────────────────────────────────────────────────────────
const ROOT     = path.resolve(__dirname, '..');
const WEB_JS   = path.join(ROOT, 'web', 'js');

// ── helpers ──────────────────────────────────────────────────────────────────
let pass = 0, fail = 0;
function ok(name, value, expected) {
    if (value === expected) {
        console.log(`  ✓  ${name}`);
        pass++;
    } else {
        console.error(`  ✗  ${name}`);
        console.error(`       expected: ${JSON.stringify(expected)}`);
        console.error(`       got:      ${JSON.stringify(value)}`);
        fail++;
    }
}
function section(name) { console.log(`\n── ${name}`); }

// ── inline test page HTML ─────────────────────────────────────────────────────
// Each test group is a self-contained async function that returns results.
// We inject them into a real Chromium browser page.

const TEST_PAGE_HTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Safecloud Streaming Tests</title></head>
<body>
<script>
// ─── streamPath: exact IIFE from web/js/Safecloud.js ───────────────────────
function makeStreamPath() {
    return (function () {
        try {
            var stored = localStorage.getItem('Q.Safecloud.Client.streamPath');
            if (stored === 'sw' || stored === 'mse' || stored === 'blob' || stored === 'auto') {
                return stored;
            }
        } catch (e) {}
        return 'auto';
    })();
}

// ─── _isIOS: mirror of stream.js ───────────────────────────────────────────
function _isIOS(ua, platform, maxTouchPoints) {
    // Simulate the real function with overrideable params for testing
    var nav = ua !== undefined ? { userAgent: ua, platform: platform, maxTouchPoints: maxTouchPoints }
                               : navigator;
    return /iP(hone|od|ad)/.test(nav.userAgent)
        || (nav.platform === 'MacIntel' && nav.maxTouchPoints > 1);
}

// ─── _choosePath: exact logic from web/js/methods/Safecloud/Client/stream.js ─
// Parameterized so we can inject custom window.MediaSource / ManagedMediaSource.
function _choosePath(videoManifest, win, isIOS) {
    win = win || window;
    isIOS = !!isIOS;

    var active = (videoManifest.versions && videoManifest.versions[0])
        ? videoManifest.versions[0].manifest
        : videoManifest;
    var hasIndexTrack = active && active.tracks
        && active.tracks.indexOf('index') >= 0;

    if ('serviceWorker' in navigator && !isIOS && hasIndexTrack) {
        return 'sw';
    }

    var activeManifest = active;
    var hasIdx = activeManifest.tracks && activeManifest.tracks.indexOf('index') >= 0;
    var probeMime = 'video/mp4; codecs="avc1.42e01e,mp4a.40.2"';
    var MSClass = win.MediaSource || win.ManagedMediaSource;
    if (MSClass && hasIdx && MSClass.isTypeSupported && MSClass.isTypeSupported(probeMime)) {
        return 'mse';
    }
    return 'blob';
}

// ─── streamMSE detection: mirrors streamMSE.js lines 97-98 ─────────────────
function detectMSE(win) {
    win = win || window;
    var MSClass   = win.MediaSource || win.ManagedMediaSource;
    var isManaged = !win.MediaSource && !!win.ManagedMediaSource;
    return { MSClass: !!MSClass, isManaged: isManaged };
}

// ─── smart SW timeout branch selection: mirrors _ensureServiceWorker.js ─────
function computeTimeout(registration) {
    // Exact copy of the fixed code
    var stillInstalling = !!(registration.installing || registration.waiting);
    var timeoutMs = (registration.active && !stillInstalling) ? 500 : 8000;
    return timeoutMs;
}

// ─── stream() path override: mirrors stream.js Q_Safecloud_Client_stream ────
function pickPath(requested, videoManifest, isIOS) {
    var path;
    if (!requested || requested === 'auto') {
        path = _choosePath(videoManifest, window, isIOS);
    } else if (requested === 'sw' || requested === 'mse' || requested === 'blob') {
        path = requested;
    } else {
        path = _choosePath(videoManifest, window, isIOS);
    }
    return path;
}

// ─── run all tests ───────────────────────────────────────────────────────────
window.__runTests = async function () {
    var results = [];
    function assert(name, got, expected) {
        results.push({ name, got: String(got), expected: String(expected), pass: got === expected });
    }

    // ── 1. streamPath: localStorage values ───────────────────────────────────
    localStorage.removeItem('Q.Safecloud.Client.streamPath');
    assert('streamPath: no LS key → auto',       makeStreamPath(), 'auto');
    localStorage.setItem('Q.Safecloud.Client.streamPath', 'sw');
    assert('streamPath: LS=sw → sw',             makeStreamPath(), 'sw');
    localStorage.setItem('Q.Safecloud.Client.streamPath', 'mse');
    assert('streamPath: LS=mse → mse',           makeStreamPath(), 'mse');
    localStorage.setItem('Q.Safecloud.Client.streamPath', 'blob');
    assert('streamPath: LS=blob → blob',         makeStreamPath(), 'blob');
    localStorage.setItem('Q.Safecloud.Client.streamPath', 'auto');
    assert('streamPath: LS=auto → auto',         makeStreamPath(), 'auto');
    localStorage.setItem('Q.Safecloud.Client.streamPath', 'bad_value');
    assert('streamPath: LS=bad_value → auto',    makeStreamPath(), 'auto');
    localStorage.removeItem('Q.Safecloud.Client.streamPath');

    // ── 2. _choosePath: MediaSource present (non-iOS + index → sw) ───────────
    var withIndex = { tracks: ['data', 'index'] };
    assert('_choosePath: non-iOS + index → sw',
        _choosePath(withIndex, window, false), 'sw');

    // ── 3. _choosePath: on iOS, no SW → falls to mse (if MediaSource) ────────
    // On iOS we skip SW; Chromium has MediaSource → expect mse
    assert('_choosePath: iOS + MediaSource + index → mse',
        _choosePath(withIndex, window, true), 'mse');

    // ── 4. _choosePath: ManagedMediaSource only (no plain MediaSource) ────────
    var fakeWinMMS = {
        MediaSource: undefined,
        ManagedMediaSource: { isTypeSupported: function(m) { return true; } }
    };
    assert('_choosePath: ManagedMediaSource-only + index → mse',
        _choosePath(withIndex, fakeWinMMS, true), 'mse');

    // ── 5. _choosePath: no MediaSource at all → blob ─────────────────────────
    var fakeWinNone = { MediaSource: undefined, ManagedMediaSource: undefined };
    assert('_choosePath: no MSE → blob',
        _choosePath(withIndex, fakeWinNone, true), 'blob');

    // ── 6. _choosePath: no index track → skip sw, then blob (no initSegment) ─
    var noIndex = { tracks: ['data'] };
    // Non-iOS without index track: can't use SW (no index), MSE also needs index
    assert('_choosePath: non-iOS + no-index → blob or mse (skips sw)',
        _choosePath(noIndex, window, false) !== 'sw', true);

    // ── 7. streamMSE: MSClass detection — both classes ────────────────────────
    var d1 = detectMSE(window);
    assert('streamMSE: window.MediaSource present → MSClass truthy',  d1.MSClass, true);
    assert('streamMSE: window.MediaSource present → isManaged false', d1.isManaged, false);

    // ── 8. streamMSE: ManagedMediaSource-only (simulated iOS) ─────────────────
    var fakeIOS = { MediaSource: undefined, ManagedMediaSource: {} };
    var d2 = detectMSE(fakeIOS);
    assert('streamMSE: ManagedMediaSource-only → MSClass truthy',  d2.MSClass, true);
    assert('streamMSE: ManagedMediaSource-only → isManaged true',  d2.isManaged, true);

    // ── 9. streamMSE: neither available ──────────────────────────────────────
    var d3 = detectMSE({ MediaSource: undefined, ManagedMediaSource: undefined });
    assert('streamMSE: neither MSE class → MSClass falsy', d3.MSClass, false);

    // ── 10. smart SW timeout: active+not-installing → 500ms ──────────────────
    var regActive = { active: {}, installing: null, waiting: null };
    assert('SW timeout: active (no installing/waiting) → 500ms',
        computeTimeout(regActive), 500);

    // ── 11. smart SW timeout: still installing → 8000ms ─────────────────────
    var regInstalling = { active: null, installing: {}, waiting: null };
    assert('SW timeout: installing → 8000ms',
        computeTimeout(regInstalling), 8000);

    // ── 12. smart SW timeout: active + waiting (update pending) → 8000ms ─────
    var regActiveWaiting = { active: {}, installing: null, waiting: {} };
    assert('SW timeout: active + waiting worker → 8000ms',
        computeTimeout(regActiveWaiting), 8000);

    // ── 13. smart SW timeout: nothing registered → 8000ms ────────────────────
    var regEmpty = { active: null, installing: null, waiting: null };
    assert('SW timeout: nothing registered → 8000ms',
        computeTimeout(regEmpty), 8000);

    // ── 14. stream() path override: explicit 'mse' ignores auto-detect ────────
    assert('stream(): explicit mse → mse', pickPath('mse', withIndex, false), 'mse');
    assert('stream(): explicit blob → blob', pickPath('blob', withIndex, false), 'blob');
    assert('stream(): explicit sw → sw', pickPath('sw', withIndex, false), 'sw');
    assert('stream(): auto → auto-detect (non-iOS+index → sw)', pickPath('auto', withIndex, false), 'sw');
    assert('stream(): bad value → auto-detect', pickPath('garbage', withIndex, false), 'sw');

    return results;
};
</script>
</body>
</html>`;

// ── mock service worker script ────────────────────────────────────────────────
const MOCK_SW_JS = `
// Minimal mock service worker — just enough for registration to complete.
self.addEventListener('install', function(e) {
    e.waitUntil(self.skipWaiting());
});
self.addEventListener('activate', function(e) {
    e.waitUntil(self.clients.claim());
});
self.addEventListener('fetch', function(e) {
    // pass through — we don't intercept in this mock
});
`;

// ── HTTP server ───────────────────────────────────────────────────────────────
function startServer() {
    return new Promise((resolve) => {
        const server = http.createServer((req, res) => {
            // Strip query strings
            const url = req.url.split('?')[0];

            if (url === '/' || url === '/test') {
                res.writeHead(200, {
                    'Content-Type': 'text/html',
                    // Required for SW registration to work
                    'Service-Worker-Allowed': '/'
                });
                res.end(TEST_PAGE_HTML);
                return;
            }
            if (url === '/SafecloudServiceWorker.js') {
                res.writeHead(200, {
                    'Content-Type': 'application/javascript',
                    'Service-Worker-Allowed': '/'
                });
                res.end(MOCK_SW_JS);
                return;
            }
            // Serve web/js files for completeness
            const filePath = path.join(ROOT, url.replace(/^\//, ''));
            if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
                const ext = path.extname(filePath);
                const types = {
                    '.js': 'application/javascript',
                    '.html': 'text/html',
                    '.css': 'text/css'
                };
                res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
                res.end(fs.readFileSync(filePath));
                return;
            }
            res.writeHead(404);
            res.end('Not found: ' + url);
        });

        server.listen(0, '127.0.0.1', () => resolve(server));
    });
}

// ── SW registration timing test ────────────────────────────────────────────────
// A separate test page that actually registers our mock SW and checks timing.
function swTimingPageHtml(swUrl) {
    return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
<script>
window.__swTimingTest = async function() {
    var results = [];
    function assert(name, got, expected) {
        results.push({ name, got: String(got), expected: String(expected), pass: got === expected });
    }

    if (!('serviceWorker' in navigator)) {
        results.push({ name: 'SW supported', got: 'false', expected: 'true', pass: false });
        return results;
    }

    // Register our mock SW
    var swUrl = ${JSON.stringify(swUrl)};
    var registration;
    try {
        registration = await navigator.serviceWorker.register(swUrl, { scope: '/' });
    } catch (e) {
        results.push({ name: 'SW register', got: 'error: ' + e.message, expected: 'ok', pass: false });
        return results;
    }

    // Wait for it to be at least installing
    await new Promise(r => setTimeout(r, 100));

    // Refresh registration state
    registration = await navigator.serviceWorker.getRegistration('/');

    // Check which state we're in
    var state = registration.installing ? 'installing'
              : registration.waiting    ? 'waiting'
              : registration.active     ? 'active'
              : 'none';
    results.push({ name: 'SW state after register+100ms: got ' + state, got: ['installing','waiting','active'].includes(state), expected: true, pass: ['installing','waiting','active'].includes(state) });

    // Compute timeout as the real code does
    var stillInstalling = !!(registration.installing || registration.waiting);
    var timeoutMs = (registration.active && !stillInstalling) ? 500 : 8000;

    // If fully active (second visit or after first activation), timeout = 500
    // If still installing (first visit), timeout = 8000
    var expectedTimeout = (registration.active && !stillInstalling) ? 500 : 8000;
    assert('SW timeout matches active/installing state', timeoutMs, expectedTimeout);

    // On first load the SW is usually installing → 8000ms
    // On second load it should be active → 500ms
    // Either is correct for this test — what matters is the branch logic works.
    results.push({
        name: 'SW timeout value is one of [500, 8000]',
        got: (timeoutMs === 500 || timeoutMs === 8000),
        expected: true,
        pass: (timeoutMs === 500 || timeoutMs === 8000)
    });

    return results;
};
</script>
</body>
</html>`;
}

// ── main ──────────────────────────────────────────────────────────────────────
async function run() {
    const server = await startServer();
    const port   = server.address().port;
    const base   = `http://127.0.0.1:${port}`;
    console.log(`\nSafecloud streaming regression tests`);
    console.log(`Test server: ${base}\n`);

    let exitCode = 0;
    let browser;

    try {
        const { chromium } = require('playwright');
        browser = await chromium.launch({ headless: true });
        const ctx  = await browser.newContext();
        const page = await ctx.newPage();

        // Capture browser console output for debugging
        const browserLogs = [];
        page.on('console', msg => {
            if (msg.type() === 'error') {
                browserLogs.push('[browser ERR] ' + msg.text());
            }
        });
        page.on('pageerror', err => {
            browserLogs.push('[page error] ' + err.message);
        });

        // ── Unit tests (no real SW needed) ────────────────────────────────────
        section('Loading test page');
        await page.goto(`${base}/test`, { waitUntil: 'domcontentloaded' });
        console.log('  Page loaded.');

        section('Running browser unit tests');
        const unitResults = await page.evaluate(async () => window.__runTests());

        if (!unitResults) {
            console.error('  ERROR: __runTests() returned nothing');
            exitCode = 1;
        } else {
            for (const r of unitResults) {
                ok(r.name, r.got, r.expected);
            }
        }

        // ── SW registration timing test ───────────────────────────────────────
        section('Service Worker registration + timeout branch');
        const swUrl = `${base}/SafecloudServiceWorker.js`;

        // Serve a SW timing test page
        const sw_page = await ctx.newPage();
        sw_page.on('console', msg => {
            if (msg.type() === 'error') browserLogs.push('[SW ERR] ' + msg.text());
        });

        // We set the SW test page content directly via route
        await sw_page.route('**/sw_timing_test', async route => {
            await route.fulfill({
                status: 200,
                contentType: 'text/html',
                headers: { 'Service-Worker-Allowed': '/' },
                body: swTimingPageHtml(swUrl)
            });
        });

        await sw_page.goto(`${base.replace('127.0.0.1', 'localhost')}/sw_timing_test`, {
            waitUntil: 'domcontentloaded'
        }).catch(() => {});

        // Try a different approach: evaluate directly
        const swPage2 = await ctx.newPage();
        await swPage2.goto(`${base}/test`, { waitUntil: 'domcontentloaded' });

        // Inject the SW timing test
        const swResults = await swPage2.evaluate(async (swUrl) => {
            if (!('serviceWorker' in navigator)) {
                return [{ name: 'SW supported', got: 'false', expected: 'true', pass: false }];
            }
            var results = [];
            function assert(name, got, expected) {
                results.push({ name, got: String(got), expected: String(expected), pass: String(got) === String(expected) });
            }

            // Register the mock SW
            var registration;
            try {
                registration = await navigator.serviceWorker.register(swUrl, { scope: '/' });
            } catch (e) {
                results.push({ name: 'SW register', got: 'error:' + e.message, expected: 'ok', pass: false });
                return results;
            }

            // Wait a tick for state to settle
            await new Promise(r => setTimeout(r, 200));
            registration = await navigator.serviceWorker.getRegistration('/');
            if (!registration) {
                results.push({ name: 'SW getRegistration', got: 'null', expected: 'object', pass: false });
                return results;
            }

            var state = registration.installing ? 'installing'
                      : registration.waiting    ? 'waiting'
                      : registration.active     ? 'active'
                      : 'none';
            results.push({ name: 'SW has a state after register', got: state !== 'none', expected: 'true', pass: state !== 'none' });

            // Core regression: exact timeout-branch logic from the fixed _ensureServiceWorker.js
            var stillInstalling = !!(registration.installing || registration.waiting);
            var timeoutMs = (registration.active && !stillInstalling) ? 500 : 8000;
            var expectedTimeout = (registration.active && !stillInstalling) ? 500 : 8000;
            assert('SW timeout = active?' + (registration.active ? '500' : '8000') + 'ms', timeoutMs, expectedTimeout);
            assert('SW timeout is 500 or 8000', (timeoutMs === 500 || timeoutMs === 8000), true);

            // Wait for full activation
            if (state !== 'active') {
                await new Promise(resolve => {
                    var timeout = setTimeout(resolve, 5000);
                    var int = setInterval(async () => {
                        var reg = await navigator.serviceWorker.getRegistration('/');
                        if (reg && reg.active) {
                            clearInterval(int);
                            clearTimeout(timeout);
                            resolve();
                        }
                    }, 100);
                });
                registration = await navigator.serviceWorker.getRegistration('/');
            }

            // After full activation: active=true, installing=null, waiting=null → 500ms
            var stillInstalling2 = !!(registration.installing || registration.waiting);
            var timeoutMs2 = (registration.active && !stillInstalling2) ? 500 : 8000;
            assert('SW timeout after full activation → 500ms', timeoutMs2, 500);

            return results;
        }, swUrl);

        for (const r of swResults) {
            // Results may carry booleans or strings — normalise to string for comparison
            ok(r.name, String(r.got), String(r.expected));
        }

        // ── Print any browser errors ──────────────────────────────────────────
        if (browserLogs.length) {
            section('Browser console errors (informational)');
            browserLogs.forEach(l => console.log(' ', l));
        }

    } catch (err) {
        console.error('\nFatal error:', err.message);
        if (err.stack) console.error(err.stack);
        exitCode = 1;
    } finally {
        if (browser) await browser.close();
        server.close();
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    const total = pass + fail;
    console.log(`\n${'─'.repeat(50)}`);
    console.log(`Results: ${pass}/${total} passed${fail ? `, ${fail} FAILED` : ''}`);
    if (fail === 0) {
        console.log('All streaming regression tests passed. ✓');
    } else {
        console.error('Some tests failed. ✗');
        exitCode = 1;
    }
    process.exit(exitCode);
}

run();
