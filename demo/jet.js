'use strict';
/**
 * Safecloud Jet Server — demo bootstrap.
 *
 * Usage:
 *   node jet.js
 *
 * Config in local/app.json (minimal):
 * {
 *   "Safecloud": {
 *     "requirePayment": false,
 *     "drop": { "storageGB": 10, "offlineGraceMs": 60000 },
 *     "safebux": { "perChunkWei": "0", "chainId": "eip155:97" },
 *     "jet":  { "address": "0x0000000000000000000000000000000000000000" },
 *     "openclaiming": { "address": "0x0000000000000000000000000000000000000000" }
 *   }
 * }
 */

require('../Q.inc')(function (Q) {

    // Users plugin manages socket.io auth middleware
    Q.plugins.Users.listen();

    // Start the Safecloud Jet
    // Registers /Safecloud/cloud socket.io namespace + HTTP chunk routes
    Q.plugins.Safecloud.listen();

    Q.log('Safecloud Jet ready at ' + Q.nodeUrl(), 'Safecloud');
});
