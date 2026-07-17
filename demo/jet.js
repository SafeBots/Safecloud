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
 *     "safebux": { "perChunkWei": "0", "chainId": "eip155:56" },   // eip155:97 for BSC testnet
 *     "jet":  { "address": "0x0000000000000000000000000000000000000000" },
 *     "openclaiming": { "address": "0x0000000000000000000000000000000000000000" },
 *     "swarm": {
 *       "enabled":   true,
 *       "seed":      "YOUR_32_BYTE_HEX_SEED_HERE",
 *       "networkId": "safecloud:jet:v1",
 *       "secureIds": false,
 *       "bootstrap": null
 *     }
 *   }
 * }
 *
 * Generate a persistent swarm seed (run once, store in local/app.json):
 *   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 *
 * Mode 2 (Sybil-resistant node IDs):
 *   Set "secureIds": true once JetEpoch.js is implemented.
 *   Mode 2 Jets will ignore Mode 1 Jets that lack epoch proofs.
 */

// Resolve Q.inc across the usual layouts:
//   plugins/Safecloud/demo/jet.js → APP_DIR/Q.inc          (../../..)
//   sibling platform checkout     → APP_DIR/../platform/…  (…/Q.inc)
// or set Q_INC=/absolute/path/to/Q.inc explicitly.
var path = require('path');
function requireQinc() {
    var candidates = [
        process.env.Q_INC,
        path.resolve(__dirname, '../../../Q.inc'),
        path.resolve(__dirname, '../../../../platform/Q.inc'),
        path.resolve(__dirname, '../Q.inc')
    ].filter(Boolean);
    for (var i = 0; i < candidates.length; i++) {
        try { return require(candidates[i]); } catch (e) { /* try next */ }
    }
    console.error(
        'Safecloud demo/jet.js: could not locate Q.inc.\n' +
        'Run this from inside a Qbix app (plugins/Safecloud/demo/jet.js),\n' +
        'or set the Q_INC environment variable to its absolute path.\n' +
        'Tried: ' + candidates.join(', ')
    );
    process.exit(1);
}

requireQinc()(function (Q) {

    // Users plugin manages socket.io auth middleware
    Q.plugins.Users.listen();

    // Start the Safecloud Jet
    // Registers /Safecloud/cloud socket.io namespace + HTTP chunk routes
    // + JetSwarm inter-Jet peer discovery (if Safecloud.swarm.enabled)
    Q.plugins.Safecloud.listen();

    Q.log('Safecloud Jet ready at ' + Q.nodeUrl(), 'Safecloud');
    Q.log('Safecloud JetSwarm stats: '
        + JSON.stringify(require('../classes/Safecloud/JetSwarm').stats()), 'Safecloud');
});
