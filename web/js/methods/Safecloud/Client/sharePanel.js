/**
 * Q.Safecloud.Client.sharePanel — render a share panel after Client.store().
 *
 * Everything an author needs the moment their upload finishes:
 *   - share link (from createShareLink; split-entropy passphrase optional)
 *   - copy-paste embed snippet (iframe → embed.html)
 *   - the revenue policy, EDITABLE BEFORE SHARING (it's baked into what
 *     viewers sign; changing it later means a new manifest)
 *
 * Usage:
 *   Q.Safecloud.Client.sharePanel(containerElement, {
 *       manifest:  manifest,           // from Client.store()
 *       rootKey:   rootKeyHex,         // for link generation
 *       playerUrl: 'https://safestrea.ms/embed.html',
 *       split:     true,               // 4-word passphrase share (optional)
 *       onPolicy:  function (policy) {} // called when author edits the split
 *   });
 */
(function (Q) {
'use strict';

Q.Safecloud = Q.Safecloud || {};
Q.Safecloud.Client = Q.Safecloud.Client || {};

Q.Safecloud.Client.sharePanel = function (container, opts) {
    opts = opts || {};
    var manifest  = opts.manifest || {};
    var playerUrl = opts.playerUrl || (location.origin + '/embed.html');
    var policy    = (manifest.revenue && manifest.revenue.policy) || {
        payees:            [],
        fractions:         [9000],   // 90% creator default
        dynamicBps:        1000,     // 10% to whoever serves
        dynamicConstraint: '0x' + '00'.repeat(32),
        targets:           []
    };

    function h(html) { var d = document.createElement('div'); d.innerHTML = html; return d.firstElementChild; }
    function copyBtn(getText) {
        var b = h('<button style="background:#238636;color:#fff;border:0;' +
            'border-radius:6px;padding:6px 12px;cursor:pointer;font-size:.85rem">Copy</button>');
        b.onclick = function () {
            navigator.clipboard.writeText(getText()).then(function () {
                b.textContent = 'Copied ✓';
                setTimeout(function () { b.textContent = 'Copy'; }, 1500);
            });
        };
        return b;
    }

    var panel = h('<div style="font-family:system-ui;background:#161b22;' +
        'border:1px solid #30363d;border-radius:10px;padding:16px;color:#e6edf3"></div>');

    // ── Share link ────────────────────────────────────────────────────────
    var linkRow = h('<div style="margin-bottom:14px"><div style="color:#8b949e;' +
        'font-size:.85rem;margin-bottom:4px">Share link</div></div>');
    var linkBox = h('<code style="display:block;background:#21262d;padding:8px;' +
        'border-radius:6px;word-break:break-all;font-size:.8rem;margin-bottom:6px">generating…</code>');
    linkRow.appendChild(linkBox);

    function buildLink() {
        var mk = Q.Safecloud.Client.createShareLink;
        if (typeof mk !== 'function') {
            linkBox.textContent = playerUrl + '#m=' +
                encodeURIComponent(manifest.rootCid || '');
            linkRow.appendChild(copyBtn(function () { return linkBox.textContent; }));
            return;
        }
        Promise.resolve(mk({
            manifest: manifest,
            rootKey:  opts.rootKey,
            baseUrl:  playerUrl,
            split:    !!opts.split
        })).then(function (r) {
            linkBox.textContent = (r && r.url) || String(r);
            linkRow.appendChild(copyBtn(function () { return linkBox.textContent; }));
            if (r && r.passphrase) {
                linkRow.appendChild(h('<div style="margin-top:6px;color:#d29922;' +
                    'font-size:.85rem">Passphrase (tell the viewer separately): ' +
                    '<b>' + r.passphrase + '</b></div>'));
            }
        }).catch(function (e) {
            linkBox.textContent = 'link generation failed: ' + e.message;
        });
    }

    // ── Embed snippet ─────────────────────────────────────────────────────
    var embedRow = h('<div style="margin-bottom:14px"><div style="color:#8b949e;' +
        'font-size:.85rem;margin-bottom:4px">Embed on any site</div></div>');
    var embedBox = h('<code style="display:block;background:#21262d;padding:8px;' +
        'border-radius:6px;word-break:break-all;font-size:.8rem;margin-bottom:6px"></code>');
    function embedSnippet() {
        return '<iframe src="' + (linkBox.textContent || playerUrl) +
            '" width="640" height="360" frameborder="0" allowfullscreen ' +
            'allow="autoplay; encrypted-media"></iframe>';
    }
    embedBox.textContent = embedSnippet();
    embedRow.appendChild(embedBox);
    embedRow.appendChild(copyBtn(embedSnippet));

    // ── Revenue policy editor ─────────────────────────────────────────────
    var creatorBp = (policy.fractions && policy.fractions[0]) || 9000;
    var polRow = h('<div><div style="color:#8b949e;font-size:.85rem;' +
        'margin-bottom:4px">Revenue split (locked into viewer signatures ' +
        'once shared)</div></div>');
    var slider = h('<input type="range" min="5000" max="9500" step="100" ' +
        'value="' + creatorBp + '" style="width:100%">');
    var label  = h('<div style="font-size:.9rem;margin-top:4px"></div>');
    function renderLabel() {
        var c = Number(slider.value);
        label.innerHTML = 'You keep <b>' + (c / 100) + '%</b> · infrastructure ' +
            'earns <b>' + ((10000 - c) / 100) + '%</b>';
    }
    renderLabel();
    slider.oninput = function () {
        renderLabel();
        policy.fractions  = [Number(slider.value)];
        policy.dynamicBps = 10000 - Number(slider.value);
        if (manifest.revenue) { manifest.revenue.policy = policy; }
        if (typeof opts.onPolicy === 'function') { opts.onPolicy(policy); }
    };
    polRow.appendChild(slider);
    polRow.appendChild(label);

    panel.appendChild(linkRow);
    panel.appendChild(embedRow);
    panel.appendChild(polRow);
    container.appendChild(panel);
    buildLink();
    return panel;
};

})(window.Q = window.Q || {});
