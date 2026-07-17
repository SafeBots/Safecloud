(function (Q, $) {

/**
 * @module Safecloud
 */

/**
 * Safecloud Drop node dashboard.
 * Handles WebAuthn PRF init, live stats polling, and Safebux claim UI.
 *
 * @class Safecloud drop
 * @constructor
 * @param {Object} [options]
 *   @param {String}  [options.jetUrl]      Jet server URL. Defaults to Q.nodeUrl().
 *   @param {Number}  [options.pollMs=1000] Stats poll interval in ms.
 *   @param {Q.Event} [options.onConnected] Fired after successful init.
 *   @param {Q.Event} [options.onError]     Fired on error.
 */
Q.Tool.define('Safecloud/drop', function (options) {
    var tool  = this;
    var state = tool.state;

    // Merge English defaults so the UI is never blank before text file loads
    // Seed English defaults so UI is never blank before text file loads.
    // Keys match text/content/en.json (capitalized leaves).
    tool.text.drop = Q.extend({
        Tagline:           'Drop Node Dashboard',
        JetUrlPlaceholder: 'Jet server URL',
        ConnectButton:     'Connect to Safecloud',
        ClaimButton:       'Claim Safebux',
        EvmAddress:        'EVM Address',
        DropId:            'Drop ID',
        Stored:            'Stored',
        Served:            'Served',
        Safebux:           'Safebux Earned',
        Uptime:            'Uptime',
        ProllyRoot:        'Prolly Root',
        InitialisingWebAuthn: 'Initialising WebAuthn PRF…',
        PluginNotLoaded:   'Safecloud plugin not loaded.',
        Connected:         'Connected'
    }, tool.text.drop || {});

    tool.refresh();
},

{
    jetUrl:      null,
    pollMs:      1000,
    onConnected: new Q.Event(),
    onError:     new Q.Event(function (err) {
        console.warn('Safecloud/drop error:', err);
    })
},

{
    refresh: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        // Check if already connected (page reload)
        var alreadyConnected = false;
        try {
            var s = Q.Safecloud.Drops && Q.Safecloud.Drops._ && Q.Safecloud.Drops._._state;
            alreadyConnected = !!(s && s.dropId);
        } catch (e) {}

        Q.Template.render('Safecloud/drop', {
            text:      tool.text,
            jetUrl:    state.jetUrl || Q.nodeUrl(),
            connected: alreadyConnected
        }, function (err, html) {
            if (err) return Q.handle(state.onError, tool, [err]);
            $te.html(html, true).activate(function () {
                tool.addEvents();
                if (alreadyConnected) {
                    tool.showDashboard();
                }
            });
        });
    },

    addEvents: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);

        $te.on(Q.Pointer.fastclick, '.Safecloud_drop_connect_btn', function () {
            tool.doConnect();
        });

        $te.on(Q.Pointer.fastclick, '.Safecloud_drop_claim_btn', function () {
            tool.doClaim();
        });
    },

    doConnect: function () {
        var tool  = this;
        var state = tool.state;
        var $te   = $(tool.element);
        var $btn  = $te.find('.Safecloud_drop_connect_btn');
        var $st   = $te.find('.Safecloud_drop_status');
        var url   = $te.find('.Safecloud_drop_jet_url').val().trim()
                 || state.jetUrl || Q.nodeUrl();

        $btn.prop('disabled', true).addClass('Q_working');
        $st.text(Q.getObject('drop.InitialisingWebAuthn', tool.text) || 'Initialising WebAuthn PRF…')
           .removeClass('error ok');

        if (!Q.Safecloud || !Q.Safecloud.Drops) {
            $st.text(Q.getObject('drop.PluginNotLoaded', tool.text) || 'Safecloud plugin not loaded.').addClass('error');
            $btn.prop('disabled', false).removeClass('Q_working');
            return;
        }

        Q.Safecloud.Drops.init({ jetUrl: url }, function (err) {
            $btn.prop('disabled', false).removeClass('Q_working');
            if (err) {
                $st.text(err.message || String(err)).addClass('error');
                Q.handle(state.onError, tool, [err]);
                return;
            }
            $st.text(Q.getObject('drop.Connected', tool.text) || 'Connected').addClass('ok');
            Q.handle(state.onConnected, tool);
            tool.showDashboard();
        });
    },

    showDashboard: function () {
        var tool = this;
        var $te  = $(tool.element);

        $te.find('.Safecloud_drop_connect_screen').hide();
        $te.find('.Safecloud_drop_dashboard').show();

        // Start polling
        if (tool._pollInterval) { clearInterval(tool._pollInterval); }
        tool._pollInterval = setInterval(function () {
            tool.renderStats();
        }, tool.state.pollMs);
        tool.renderStats();
    },

    renderStats: function () {
        var tool = this;
        var $te  = $(tool.element);
        var s    = {};

        try {
            if (Q.Safecloud && Q.Safecloud.Drops
            &&  typeof Q.Safecloud.Drops.getStats === 'function') {
                s = Q.Safecloud.Drops.getStats();
            }
        } catch (e) {}

        // Update each stat element if present
        _set($te, '.Safecloud_drop_stat_evmAddress',   s.evmAddress   || '–');
        _set($te, '.Safecloud_drop_stat_dropId',       s.dropId       || '–');
        _set($te, '.Safecloud_drop_stat_storedMB',     (s.storedMB    || 0).toFixed(3) + ' MB');
        _set($te, '.Safecloud_drop_stat_storedChunks', (s.storedChunks|| 0).toLocaleString());
        _set($te, '.Safecloud_drop_stat_servedMB',     (s.servedMB    || 0).toFixed(3) + ' MB');
        _set($te, '.Safecloud_drop_stat_servedChunks', (s.servedChunks|| 0).toLocaleString());
        _set($te, '.Safecloud_drop_stat_safebux',      (s.safebuxEarned || 0).toFixed(6) + ' SBUX');
        _set($te, '.Safecloud_drop_stat_requests',
            ((s.servedChunks || 0) + (s.storedChunks || 0) + (s.challenges || 0))
                .toLocaleString()
            + ' (' + (s.challenges || 0) + ' ' 
            + (Q.getObject('drop.Challenges', tool.text) || 'challenges') + ')');
        _set($te, '.Safecloud_drop_stat_prollyRoot',   _short(s.prollyRoot));

        // Activity feed (most recent first)
        var $feed = $te.find('.Safecloud_drop_activity');
        if ($feed.length && s.activity) {
            var html = s.activity.slice().reverse().map(function (a) {
                var t = new Date(a.t).toLocaleTimeString();
                var what = a.kind;
                if (a.bytes) { what += ' ' + (a.bytes / 1024).toFixed(1) + ' KB'; }
                if (a.kind === 'get' && a.paid) { what += ' · paid'; }
                return '<li><span class="t">' + t + '</span> ' + what + '</li>';
            }).join('');
            if ($feed.data('html') !== html) {
                $feed.data('html', html).html(html);
            }
        }

        // Served-rate sparkline (last 60 samples)
        tool._spark = tool._spark || [];
        var last = tool._sparkLastServed || 0;
        tool._spark.push(Math.max(0, (s.servedBytes || 0) - last));
        tool._sparkLastServed = s.servedBytes || 0;
        if (tool._spark.length > 60) { tool._spark.shift(); }
        var $spark = $te.find('.Safecloud_drop_spark');
        if ($spark.length) {
            var max = Math.max.apply(null, tool._spark.concat([1]));
            var pts = tool._spark.map(function (v, i) {
                return (i * 2) + ',' + (20 - Math.round(v / max * 18));
            }).join(' ');
            $spark.html('<svg width="120" height="20" viewBox="0 0 120 20"'
                + ' preserveAspectRatio="none"><polyline fill="none"'
                + ' stroke="currentColor" stroke-width="1.5" points="'
                + pts + '"/></svg>');
        }

        var elapsed = s.uptime ? s.uptime / 1000 : 0;
        var h = Math.floor(elapsed / 3600);
        var m = Math.floor((elapsed % 3600) / 60);
        var sec = Math.floor(elapsed % 60);
        _set($te, '.Safecloud_drop_stat_uptime',
            [h, m, sec].map(function (n) { return String(n).padStart(2,'0'); }).join(':'));

        // Claimable tokens (real, from IndexedDB) drive the claim button.
        // Throttled: getPaymentStats hits IndexedDB.
        var now = Date.now();
        if (!tool._payStatsAt || now - tool._payStatsAt > 3000) {
            tool._payStatsAt = now;
            if (Q.Safecloud.Drops.getPaymentStats) {
                Q.Safecloud.Drops.getPaymentStats(function (err, ps) {
                    if (err || !ps) { return; }
                    _set($te, '.Safecloud_drop_stat_pending',
                        ps.tokens + ' token' + (ps.tokens === 1 ? '' : 's')
                        + ' · ' + ps.totalSbux.toFixed(6) + ' SBUX');
                    $te.find('.Safecloud_drop_claim_btn')
                        .prop('disabled', !ps.claimable);
                });
            }
        }
    },

    doClaim: function () {
        var tool = this;
        var $btn = $(tool.element).find('.Safecloud_drop_claim_btn');
        $btn.addClass('Q_working');
        Q.Safecloud.Drops.claimPayments({}, function (err, result) {
            $btn.removeClass('Q_working');
            if (err) {
                return Q.handle(tool.state.onError, tool, [err]);
            }
            Q.alert('Claimed ' + (result.claimed || 0) + ' tokens.');
        });
    },

    Q: {
        beforeRemove: function () {
            if (this._pollInterval) {
                clearInterval(this._pollInterval);
            }
        }
    }
});

function _set($te, sel, val) {
    var $el = $te.find(sel);
    if ($el.length && $el.text() !== String(val)) { $el.text(val); }
}
function _short(h) {
    if (!h) return 'null';
    return h.length > 16 ? h.slice(0,8)+'…'+h.slice(-4) : h;
}

Q.Template.set('Safecloud/drop',
    '<div class="Safecloud_drop_tool">' +

    '{{#unless connected}}' +
    '<div class="Safecloud_drop_connect_screen">' +
        '<div class="Safecloud_drop_logo">SafeCloud<br>Drop</div>' +
        '<div class="Safecloud_drop_tagline">{{text.drop.Tagline}}</div>' +
        '<input class="Safecloud_drop_jet_url" type="text"' +
               ' placeholder="{{text.drop.JetUrlPlaceholder}}"' +
               ' value="{{jetUrl}}">' +
        '<button class="Safecloud_drop_connect_btn Q_button">' +
            '{{text.drop.ConnectButton}}' +
        '</button>' +
        '<div class="Safecloud_drop_status"></div>' +
    '</div>' +
    '{{/unless}}' +

    '<div class="Safecloud_drop_dashboard"' +
         '{{#unless connected}}style="display:none"{{/unless}}>' +
        '<table class="Safecloud_drop_stats_table">' +
            '<tr><th>{{text.drop.EvmAddress}}</th>' +
                '<td class="Safecloud_drop_stat_evmAddress g">–</td></tr>' +
            '<tr><th>{{text.drop.DropId}}</th>' +
                '<td class="Safecloud_drop_stat_dropId">–</td></tr>' +
            '<tr><th>{{text.drop.Stored}}</th>' +
                '<td><span class="Safecloud_drop_stat_storedMB">0.000 MB</span>' +
                ' (<span class="Safecloud_drop_stat_storedChunks">0</span>)</td></tr>' +
            '<tr><th>{{text.drop.Served}}</th>' +
                '<td><span class="Safecloud_drop_stat_servedMB">0.000 MB</span>' +
                ' (<span class="Safecloud_drop_stat_servedChunks">0</span>)</td></tr>' +
            '<tr><th>{{text.drop.Safebux}}</th>' +
                '<td class="Safecloud_drop_stat_safebux a">0.000000 SBUX</td></tr>' +
            '<tr><th>{{text.drop.Pending}}</th>' +
                '<td class="Safecloud_drop_stat_pending">0 tokens · 0.000000 SBUX</td></tr>' +
            '<tr><th>{{text.drop.Requests}}</th>' +
                '<td><span class="Safecloud_drop_stat_requests">0</span>' +
                ' <span class="Safecloud_drop_spark d"></span></td></tr>' +
            '<tr><th>{{text.drop.Uptime}}</th>' +
                '<td class="Safecloud_drop_stat_uptime">00:00:00</td></tr>' +
            '<tr><th>{{text.drop.ProllyRoot}}</th>' +
                '<td class="Safecloud_drop_stat_prollyRoot d">null</td></tr>' +
        '</table>' +
        '<button class="Safecloud_drop_claim_btn Q_button" disabled>' +
            '{{text.drop.ClaimButton}}' +
        '</button>' +
        '<div class="Safecloud_drop_activity_wrap">' +
            '<div class="Safecloud_drop_activity_title">{{text.drop.Activity}}</div>' +
            '<ul class="Safecloud_drop_activity"></ul>' +
        '</div>' +
    '</div>' +

    '</div>'
);

})(Q, Q.jQuery);
