/**
 * Real Safecloud_Router logic: drop weighting, weighted-random selection,
 * and the reliability EMA. `drop.storage` comes straight from the untrusted
 * Drop registration payload, so weighting must not be crashable or gameable.
 */
const path=require('path');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }
function section(t){ console.log('\n\u2500\u2500 '+t+' \u2500\u2500'); }

const configStore={Safecloud:{}};
const Q={Config:{get:(k,d)=>{let o=configStore;for(const x of k){if(o==null)return d;o=o[x];}return o===undefined?d:o;},set:()=>{}},
 log:()=>{},extend:Object.assign,getObject:(k,f)=>{let o=f;for(const x of k){if(o==null)return undefined;o=o[x];}return o;},
 makeEventEmitter:(o)=>{o.on=()=>{};o.emit=()=>{};},
 listen:()=>({attached:{express:{post:()=>{},get:()=>{},put:()=>{},use:()=>{}}}}),
 require:()=>{throw new Error('no');},app:{DIR:'/tmp/x'},Crypto:{},Data:{},Assets:{},Socket:{},
 Safecloud:{}};
const M=require('module'); const ol=M._load;
M._load=function(r){ if(r==='Q')return Q; if(r==='./Client')return{}; if(r==='./Drops')return{};
 if(r==='./Jets')return{drops:{}}; if(r==='./JetSwarm')return{init:async()=>{},stats:()=>({peerCount:0})};
 return ol.apply(this,arguments); };

let Router;
try { Router = require(path.join(process.cwd(),'classes/Safecloud/Router.js')); check('Router.js loads',!!Router); }
catch(e){ check('Router.js loads',false,e.message); console.log('\n'+pass+' passed, '+(fail)+' failed'); process.exit(1); }

const noThrow = (label, fn) => { try { const r = fn(); check(label,true); return r; }
  catch(e){ check(label,false,'threw: '+e.message); return null; } };

// ══ _weightDrop with hostile / degenerate records ══
section('_weightDrop — untrusted storage values');
const hostile = [
  ['missing storage',      { dropId:'a' }],
  ['storage null',         { dropId:'b', storage:null }],
  ['GB as string "5"',     { dropId:'c', storage:{GB:'5'} }],
  ['GB as string "abc"',   { dropId:'d', storage:{GB:'abc'} }],
  ['GB negative',          { dropId:'e', storage:{GB:-100} }],
  ['GB object',            { dropId:'f', storage:{GB:{}} }],
  ['GB array',             { dropId:'g', storage:{GB:[1,2]} }],
  ['used as string',       { dropId:'h', storage:{GB:10}, used:'abc' }],
  ['used negative',        { dropId:'i', storage:{GB:10}, used:-5 }],
  ['GB huge (1e12)',       { dropId:'j', storage:{GB:1e12} }],
  ['GB = Number.MAX_VALUE',{ dropId:'k', storage:{GB:Number.MAX_VALUE} }]
];
const weights={};
for (const [label,d] of hostile) {
  const w = noThrow('weight computes for: '+label, ()=>Router._weightDrop(d));
  weights[d.dropId]=w;
}
check('non-numeric GB yields a finite, non-negative weight (not NaN)',
  Number.isFinite(weights.d) && weights.d>=0, 'got '+weights.d);
check('object GB yields a finite weight (not NaN)',
  Number.isFinite(weights.f) && weights.f>=0, 'got '+weights.f);
check('negative GB clamps to 0 weight', weights.e===0, 'got '+weights.e);
check('non-numeric used does not poison the weight',
  Number.isFinite(weights.h) && weights.h>=0, 'got '+weights.h);
check('MAX_VALUE GB does not become Infinity',
  Number.isFinite(weights.k), 'got '+weights.k);

// ══ Selection fairness / gameability ══
section('_weightedRandomSelect — fairness under a lying Drop');
const honest = [
  { dropId:'h1', storage:{GB:10} }, { dropId:'h2', storage:{GB:10} }, { dropId:'h3', storage:{GB:10} }
];
const sel1 = noThrow('selection works on honest drops', ()=>Router._weightedRandomSelect(honest,2));
check('returns the requested count', Array.isArray(sel1) && sel1.length===2, sel1&&sel1.length);
check('returns distinct drops (no duplicates)',
  sel1 && sel1[0].dropId!==sel1[1].dropId, sel1&&sel1.map(d=>d.dropId).join(','));

// A Drop claiming absurd storage should not be able to capture every slot
const withLiar = honest.concat([{ dropId:'LIAR', storage:{GB:1e15} }]);
let liarWins=0; const N=200;
for (let i=0;i<N;i++){ const s=Router._weightedRandomSelect(withLiar,1); if(s[0]&&s[0].dropId==='LIAR') liarWins++; }
check('a Drop claiming 1e15 GB does not deterministically capture routing',
  liarWins < N, liarWins+'/'+N+' selections');
console.log('      (note: liar won '+liarWins+'/'+N+' — claimed storage is unverified by design)');

// NaN/Infinity weights must not break selection
const broken = [{dropId:'n1',storage:{GB:'abc'}},{dropId:'n2',storage:{GB:NaN}},{dropId:'n3',storage:{GB:Infinity}}];
const sel2 = noThrow('selection survives NaN/Infinity weights', ()=>Router._weightedRandomSelect(broken,2));
check('selection with all-broken weights still returns drops',
  Array.isArray(sel2) && sel2.length>0, sel2&&sel2.length);
noThrow('selection with empty list does not throw', ()=>Router._weightedRandomSelect([],3));
noThrow('selection with n=0 does not throw', ()=>Router._weightedRandomSelect(honest,0));
noThrow('selection with n negative does not throw', ()=>Router._weightedRandomSelect(honest,-1));

// ══ Reliability EMA ══
section('_updateReliability — EMA behavior');
Router._updateReliability('r1', true);
const after1 = Router._weightDrop({dropId:'r1', storage:{GB:1}});
Router._updateReliability('r1', true);
for (let i=0;i<50;i++) Router._updateReliability('r1', true);
const afterMany = Router._weightDrop({dropId:'r1', storage:{GB:1}});
check('repeated successes raise reliability (weight increases)', afterMany >= after1,
  after1+' → '+afterMany);
check('reliability stays within [0,1] after 50 successes', afterMany<=1.0001, String(afterMany));

for (let i=0;i<200;i++) Router._updateReliability('r2', false);
const failW = Router._weightDrop({dropId:'r2', storage:{GB:1}});
check('repeated failures drive reliability toward 0 (never negative)',
  failW>=0 && failW<0.1, String(failW));

noThrow('_updateReliability with null dropId does not throw', ()=>Router._updateReliability(null,true));
noThrow('_updateReliability with undefined success does not throw', ()=>Router._updateReliability('r3',undefined));

// ══ Self-correction: a lying Drop must be demoted quickly ══
section('Routing self-correction against a capacity liar');
const liarSet = [{dropId:'x1',storage:{GB:10}},{dropId:'x2',storage:{GB:10}},
                 {dropId:'x3',storage:{GB:10}},{dropId:'XLIAR',storage:{GB:1e15}}];
const winRate = (n) => { let w=0; for(let i=0;i<n;i++){ const s=Router._weightedRandomSelect(liarSet,1);
  if(s[0]&&s[0].dropId==='XLIAR') w++; } return w/n; };
const fresh = winRate(300);
check('claimed storage is clamped (liar cannot win 100% even fresh)', fresh < 1.0,
  (fresh*100).toFixed(1)+'%');
for (let i=0;i<10;i++){ Router._updateReliability('XLIAR',false);
  ['x1','x2','x3'].forEach(id=>Router._updateReliability(id,true)); }
const after10 = winRate(300);
check('after 10 failed serves the liar is already minority traffic', after10 < 0.5,
  (after10*100).toFixed(1)+'%');
for (let i=0;i<10;i++) Router._updateReliability('XLIAR',false);
const after20 = winRate(300);
check('after 20 failed serves the liar is effectively demoted (<10%)', after20 < 0.10,
  (after20*100).toFixed(1)+'%');
check('demotion is monotonic (fresh > after10 > after20)',
  fresh > after10 && after10 >= after20,
  [fresh,after10,after20].map(v=>(v*100).toFixed(1)+'%').join(' → '));

// An honest, reliable Drop must NOT be punished by the asymmetric weights
for (let i=0;i<50;i++) Router._updateReliability('honest1', true);
const beforeBlip = Router._weightDrop({dropId:'honest1', storage:{GB:10}});
Router._updateReliability('honest1', false);          // one transient failure
for (let i=0;i<5;i++) Router._updateReliability('honest1', true);
const afterBlip = Router._weightDrop({dropId:'honest1', storage:{GB:10}});
check('one failure in ~56 serves costs an honest Drop <25% of its weight',
  afterBlip > beforeBlip * 0.75, beforeBlip.toFixed(3)+' → '+afterBlip.toFixed(3));

// ══ Pause / Resume lifecycle ══
section('onDropPause / onDropResume — lifecycle hooks');

// Set up Q.Safecloud.Jets.drops so selectForGet/selectForPut can access them
Q.Safecloud.Jets = Q.Safecloud.Jets || {};
Q.Safecloud.Jets.drops = {};

// Register three Drops with CID coverage
const mkDrop = (id, gb) => ({ dropId: id, storage: { GB: gb || 10 }, evmAddress: '0x' + id });
['pDrop1','pDrop2','pDrop3'].forEach(id => {
    const d = mkDrop(id, 10);
    Q.Safecloud.Jets.drops[id] = d;
    Router.onDropRegistered(d, 'root-abc');
    Router.onDropAnnounce(d, [{ cid: 'cid-pause-test', added: true }]);
});

// Verify all three are candidates before any pause
(async () => {
    // selectForGet returns a Promise
    let found = {};
    for (let i = 0; i < 60; i++) {
        const drop = await Router.selectForGet('cid-pause-test');
        if (drop) found[drop.dropId] = true;
    }
    check('all 3 Drops are selectable before pause',
        Object.keys(found).length === 3, Object.keys(found).join(','));

    // Pause pDrop2
    Router.onDropPause({ dropId: 'pDrop2' }, 'battery low');

    found = {};
    for (let i = 0; i < 60; i++) {
        const drop = await Router.selectForGet('cid-pause-test');
        if (drop) found[drop.dropId] = true;
    }
    check('paused Drop is excluded from selectForGet',
        !found.pDrop2, 'got: ' + Object.keys(found).join(','));
    check('unpaused Drops still selected',
        found.pDrop1 && found.pDrop3, Object.keys(found).join(','));

    // selectForPut should also exclude paused
    const putDrops = await Router.selectForPut(['cid-new-put'], { replicationFactor: 5 });
    const putIds = putDrops.map(d => d.dropId);
    check('paused Drop excluded from selectForPut',
        putIds.indexOf('pDrop2') < 0, putIds.join(','));

    // Resume pDrop2
    Router.onDropResume({ dropId: 'pDrop2' }, { type: 'wifi', effectiveType: '4g' });
    found = {};
    for (let i = 0; i < 90; i++) {
        const drop = await Router.selectForGet('cid-pause-test');
        if (drop) found[drop.dropId] = true;
    }
    check('after resume, pDrop2 is selectable again',
        !!found.pDrop2, Object.keys(found).join(','));

    // ══ preferDrops ══
    section('selectForGet — preferDrops parameter');

    // With preferDrops, the first valid preferred Drop should be returned
    const pref = await Router.selectForGet('cid-pause-test', { preferDrops: ['pDrop3'] });
    check('preferDrops returns the preferred Drop',
        pref && pref.dropId === 'pDrop3', pref && pref.dropId);

    // preferDrops with first choice paused, should fall to second
    Router.onDropPause({ dropId: 'pDrop1' }, 'plugged-only');
    const pref2 = await Router.selectForGet('cid-pause-test', { preferDrops: ['pDrop1', 'pDrop3'] });
    check('preferDrops skips paused Drop and selects next',
        pref2 && pref2.dropId === 'pDrop3', pref2 && pref2.dropId);

    // preferDrops with all preferred paused — should fall back to weighted random
    Router.onDropPause({ dropId: 'pDrop3' }, 'wifi-only');
    const pref3 = await Router.selectForGet('cid-pause-test', { preferDrops: ['pDrop1', 'pDrop3'] });
    check('preferDrops fallback to weighted-random when all preferred paused',
        pref3 && pref3.dropId === 'pDrop2', pref3 && pref3.dropId);

    // preferDrops with exclude
    Router.onDropResume({ dropId: 'pDrop1' });
    Router.onDropResume({ dropId: 'pDrop3' });
    const pref4 = await Router.selectForGet('cid-pause-test', {
        preferDrops: ['pDrop1', 'pDrop3'],
        exclude: ['pDrop1']
    });
    check('preferDrops respects exclude list',
        pref4 && pref4.dropId === 'pDrop3', pref4 && pref4.dropId);

    // ══ onDropDisconnected cleanup ══
    section('onDropDisconnected — pause state cleanup');

    Router.onDropPause({ dropId: 'pDrop2' }, 'test');
    Router.onDropDisconnected({ dropId: 'pDrop2' });
    // After disconnect, pause state should be cleaned up
    // Re-register pDrop2 — fresh drop record, fresh coverage
    const freshDrop2 = mkDrop('pDrop2', 10);
    Q.Safecloud.Jets.drops.pDrop2 = freshDrop2;
    Router.onDropRegistered(freshDrop2, 'root-abc');
    Router.onDropAnnounce(freshDrop2, [{ cid: 'cid-pause-test', added: true }]);
    // Boost reliability so weighted-random can actually pick it
    for (let i = 0; i < 30; i++) Router._updateReliability('pDrop2', true);
    found = {};
    for (let i = 0; i < 200; i++) {
        const drop = await Router.selectForGet('cid-pause-test');
        if (drop) found[drop.dropId] = true;
    }
    check('after disconnect + re-register, Drop is selectable (pause cleared)',
        !!found.pDrop2, Object.keys(found).join(','));

    console.log(`\n${pass} passed, ${fail} failed`);
    process.exit(fail ? 1 : 0);
})().catch(e => {
    console.error('Async test failed:', e);
    process.exit(1);
});
