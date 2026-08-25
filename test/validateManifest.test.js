'use strict';
// Standalone unit test — resolves require('Q') to the shim in test/shims.
process.env.NODE_PATH = require('path').join(__dirname, 'shims');
require('module').Module._initPaths();

var assert = require('assert');
var Client = require('../classes/Safecloud/Client.js');

function manifest(overrides) {
    var m = {
        v: 1, rootCid: 'b' + 'a'.repeat(58),
        encryptionRootPublicKey: 'AA==', accessRootPublicKey: 'BB==',
        bindingProof: { statement: {}, proof: {} },
        chunkCount: 4, chunkSize: 262144, size: 1000000, name: 'file.bin'
    };
    return Object.assign(m, overrides || {});
}

assert.strictEqual(Client.validateManifest(manifest()).ok, true, 'valid manifest accepted');
assert.strictEqual(Client.validateManifest(null).ok, false, 'null rejected');
assert.strictEqual(Client.validateManifest('x').ok, false, 'non-object rejected');
assert.strictEqual(Client.validateManifest(manifest({ v: 2 })).ok, false, 'wrong version rejected');

['v','rootCid','encryptionRootPublicKey','accessRootPublicKey',
 'bindingProof','chunkCount','chunkSize','size','name'].forEach(function (f) {
    var m = manifest(); m[f] = null;
    var r = Client.validateManifest(m);
    assert.strictEqual(r.ok, false, 'missing ' + f + ' rejected');
    assert.ok(r.reason.indexOf(f) >= 0, 'reason names the field: ' + f);
});

console.log('validateManifest: all assertions passed');
