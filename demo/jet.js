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

require('../Q.inc')(function (Q) {

    // Users plugin manages socket.io auth middleware
    Q.plugins.Users.listen();

    // Start the Safecloud Jet
    // Registers /Safecloud/cloud socket.io namespace + HTTP chunk routes
    // + JetSwarm inter-Jet peer discovery (if Safecloud.swarm.enabled)
    Q.plugins.Safecloud.listen();

    Q.log('Safecloud Jet ready at ' + Q.nodeUrl(), 'Safecloud');
    Q.log('Safecloud JetSwarm stats: '
        + JSON.stringify(require('./classes/Safecloud/JetSwarm').stats()), 'Safecloud');
});
