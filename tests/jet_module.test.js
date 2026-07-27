// Loads the ACTUAL Jets.js with a minimal Q stub and exercises its real
// exported + reachable logic. This tests shipped code, not a reimplementation.
const ethers = require('ethers');
const path = require('path');
const Module = require('module');

let pass = 0, fail = 0;
function check(n, c) { c ? (pass++, console.log('  \u2713', n)) : (fail++, console.log('  \u2717 FAIL:', n)); }

// ── Minimal Q stub: config store + the handful of helpers the module calls ──
const configStore = {};
function cfgGet(keys, def) {
  let o = configStore;
  for (const k of keys) { if (o == null) return def; o = o[k]; }
  return o === undefined ? def : o;
}
const Q = {
  Config: {
    get: cfgGet,
    set: (keys, v) => { let o = configStore; for (let i=0;i<keys.length-1;i++){ o[keys[i]]=o[keys[i]]||{}; o=o[keys[i]]; } o[keys[keys.length-1]]=v; }
  },
  log: () => {},
  extend: Object.assign,
  getObject: (keys, from) => { let o = from; for (const k of keys) { if (o==null) return undefined; o=o[k]; } return o; },
  makeEventEmitter: (obj) => { const ls={}; obj.on=(e,f)=>{(ls[e]=ls[e]||[]).push(f);}; obj.emit=(e,...a)=>{(ls[e]||[]).forEach(f=>f(...a));}; },
  listen: () => ({ attached: { express: { post:()=>{}, get:()=>{}, put:()=>{}, use:()=>{} } } }),
  require: () => { throw new Error('no plugin'); },
  app: { DIR: '/tmp/nonexistent' },
  Crypto: {},
  Data: {},
  Assets: {},
  Socket: {},
  Safecloud: {}
};

// Inject Q + sibling modules into the resolver
const origResolve = Module._resolveFilename;
const stubs = {
  'Q': null,
  './Client': { verifyGrant: async()=>true },
  './Drops': {},
  './JetSwarm': { init: async()=>{}, stats:()=>({peerCount:0}) }
};
const origLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === 'Q') return Q;
  if (request === './Client') return stubs['./Client'];
  if (request === './Drops') return stubs['./Drops'];
  if (request === './JetSwarm') return stubs['./JetSwarm'];
  return origLoad.apply(this, arguments);
};

let Jets;
try {
  Jets = require(path.join(process.cwd(), 'classes/Safecloud/Jets.js'));
  check('Jets.js loads with Q stub', !!Jets);
} catch (e) {
  check('Jets.js loads with Q stub', false);
  console.log('    load error:', e.message);
  console.log('\n' + pass + ' passed, ' + (fail) + ' failed');
  process.exit(1);
}

// The public methods exist
check('exposes _checkPayerBalance', typeof Jets._checkPayerBalance === 'function');
check('exposes _evmProvider', typeof Jets._evmProvider === 'function');
check('exposes selectDrops', typeof Jets.selectDrops === 'function');
check('exposes verifySubtreeGrant', typeof Jets.verifySubtreeGrant === 'function');
check('drops registry initialized', typeof Jets.drops === 'object');

(async () => {
  // verifySubtreeGrant: no grants + requireGrants=false => allowed (public)
  configStore.Safecloud = { requireGrants: false };
  const r1 = await Jets.verifySubtreeGrant([], 'bafyRoot', ['track','data'], null);
  check('public content (no grants, requireGrants=false) => ok', r1.ok === true);

  // no grants + requireGrants=true => rejected
  configStore.Safecloud = { requireGrants: true };
  const r2 = await Jets.verifySubtreeGrant([], 'bafyRoot', ['track','data'], null);
  check('private content (no grants, requireGrants=true) => rejected', r2.ok === false);

  // requirePayment must NOT affect grant gating (the bug we fixed)
  configStore.Safecloud = { requirePayment: true, requireGrants: false };
  const r3 = await Jets.verifySubtreeGrant([], 'bafyRoot', ['track','data'], null);
  check('requirePayment=true alone does NOT force grants', r3.ok === true);

  // selectDrops on empty registry returns []
  const sel = await Jets.selectDrops(['cid1'], { forGet: true });
  check('selectDrops empty registry => []', Array.isArray(sel) && sel.length === 0);

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
