/**
 * Minimal Q shim so pure-logic units in classes/ can be tested standalone.
 * Only the surface actually touched at module-load or by the units under
 * test is provided. Real deployments use the Qbix platform's Q.
 */
var EventEmitter = require('events');
module.exports = {
    Config: { get: function (path, def) { return def; } },
    log: function () {},
    makeEventEmitter: function (obj) {
        var em = new EventEmitter();
        obj.emit = em.emit.bind(em);
        obj.on   = em.on.bind(em);
    },
    Crypto: {},
    Data:   {}
};
