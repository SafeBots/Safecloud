'use strict';
/**
 * Safecloud Drop dashboard page.
 * plugins/Safecloud/web/js/pages/drop.js
 *
 * The Safecloud/drop tool activates itself from the PHP view;
 * this page script just reads the config passed from PHP and
 * sets the Jet URL before Q activates tools on the page.
 */
Q.page('Safecloud/drop', function () {

    var jetUrl = Q.getObject('Safecloud.drop.jetUrl', Q.plugins)
              || Q.nodeUrl();

    // The Q/tool element in the PHP view already has the jetUrl attribute,
    // but set it on the Jets namespace too so connect() uses it immediately.
    if (jetUrl && Q.Safecloud && Q.Safecloud.Jets) {
        Q.Safecloud.Jets.url = jetUrl;
    }

    // Nothing else needed — Safecloud/drop tool handles its own lifecycle.

    return function () {
        // page teardown
    };

}, 'Safecloud/drop');
