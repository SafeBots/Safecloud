/**
 * Lazy-loads Q.Data.Merkle, Q.Data.Prolly and Q.Data.Bloom.
 *
 * These are generic Q platform primitives (not Safecloud-specific), but the
 * wiring lives here because Safecloud is currently their only consumer.
 * Implementations are loaded on demand from
 *   {{Q}}/js/methods/Q/Data/Merkle/<method>.js  etc.
 *
 * @module Safecloud
 */
(function (Q) {

/**
 * Ordered Merkle tree for chunk integrity.
 * @class Q.Data.Merkle
 * @static
 */
Q.Data.Merkle = Q.Method.define({
	build:  new Q.Method(),
	verify: new Q.Method(),
	proof:  new Q.Method()
}, "{{Q}}/js/methods/Q/Data/Merkle", function () {
	return [Q];
}, {
	require: "_internal"
});

/**
 * Probabilistic B-tree for inventory reconciliation.
 * @class Q.Data.Prolly
 * @static
 */
Q.Data.Prolly = Q.Method.define({
	build:  new Q.Method(),
	get:    new Q.Method(),
	set:    new Q.Method(),
	delete: new Q.Method(),
	diff:   new Q.Method()
}, "{{Q}}/js/methods/Q/Data/Prolly", function () {
	return [Q];
}, {
	require: "_internal"
});

/**
 * Bloom filter for cold-start inventory hints.
 * @class Q.Data.Bloom
 * @static
 */
Q.Data.Bloom = Q.Method.define({
	create:       new Q.Method(),
	fromElements: new Q.Method(),
	fromBytes:    new Q.Method(),
	fromBase64:   new Q.Method()
}, "{{Q}}/js/methods/Q/Data/Bloom", function () {
	return [Q];
}, {
	require: "_internal"
});

})(Q);
