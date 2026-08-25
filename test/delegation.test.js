'use strict';
// Roundtrip test for the JetSessionDelegation sign/verify pair in Router.js.
// Requires `npm install` (ethers). Resolves require('Q') to the local shim.
process.env.NODE_PATH = require('path').join(__dirname, 'shims');
require('module').Module._initPaths();

var assert = require('assert');
var ethers = require('ethers');
var Router = require('../classes/Safecloud/Router.js');

var wallet   = ethers.Wallet.createRandom();
var noiseHex = Buffer.from(Array.from({length:32}, function(_,i){return i;})).toString('hex');
var conn     = { remotePublicKey: Buffer.from(noiseHex, 'hex') };
var otherConn= { remotePublicKey: Buffer.alloc(32, 7) };

Router._buildJetDelegation(wallet.privateKey, noiseHex).then(function (d) {
    assert.strictEqual(d.ocp, 1);
    assert.ok(d.sig[0].signature.length > 100, 'signature present');

    var hello    = { evmAddress: wallet.address, delegation: d };
    var mallory  = { evmAddress: ethers.Wallet.createRandom().address, delegation: d };
    var expired  = JSON.parse(JSON.stringify(d));
    expired.stm.exp = Math.floor(Date.now()/1000) - 10;

    return Promise.all([
        Router._verifyDelegation(hello, conn),                     // genuine
        Router._verifyDelegation(mallory, conn),                   // wrong claimed address
        Router._verifyDelegation(hello, otherConn),                // replay on other connection
        Router._verifyDelegation({evmAddress: wallet.address,
            delegation: expired}, conn),                           // expired
        Router._verifyDelegation({evmAddress: wallet.address,
            delegation: {stm:{exp: d.stm.exp}, iss: d.iss, sig: []}}, conn) // unsigned
    ]);
}).then(function (r) {
    assert.strictEqual(r[0], true,  'genuine delegation verifies');
    assert.strictEqual(r[1], false, 'wrong evmAddress rejected');
    assert.strictEqual(r[2], false, 'replay on different Noise connection rejected');
    assert.strictEqual(r[3], false, 'expired delegation rejected');
    assert.strictEqual(r[4], false, 'unsigned delegation rejected by default');
    console.log('delegation: all assertions passed');
}).catch(function (e) { console.error(e); process.exit(1); });
