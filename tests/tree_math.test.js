/**
 * Merkle tree path/range math — loads the REAL Jets.js and tests the
 * exported _chunkRangeForLink plus the round-trip invariant that decides
 * which chunks a viewer's link request maps to. A bug here = wrong/missing
 * chunks served. Pure logic, fully executable in Node.
 */
const path = require('path');
const ethers = require('ethers');
let pass=0, fail=0;
function check(n,c,d){ c?(pass++,console.log('  \u2713',n)):(fail++,console.log('  \u2717 FAIL:',n,d?('— '+d):'')); }

// Load real Jets.js with a Q stub (reuse the pattern that worked)
const configStore = {};
const Q = {
  Config:{ get:(k,d)=>{let o=configStore;for(const x of k){if(o==null)return d;o=o[x];}return o===undefined?d:o;}, set:()=>{} },
  log:()=>{}, extend:Object.assign, getObject:(k,f)=>{let o=f;for(const x of k){if(o==null)return undefined;o=o[x];}return o;},
  makeEventEmitter:(o)=>{o.on=()=>{};o.emit=()=>{};}, listen:()=>({attached:{express:{post:()=>{},get:()=>{},put:()=>{},use:()=>{}}}}),
  require:()=>{throw new Error('no');}, app:{DIR:'/tmp/x'}, Crypto:{}, Data:{}, Assets:{}, Socket:{}, Safecloud:{}
};
const Module = require('module');
const origLoad = Module._load;
Module._load = function(req){ if(req==='Q')return Q; if(req==='./Client')return{verifyGrant:async()=>true};
  if(req==='./Drops')return{}; if(req==='./JetSwarm')return{init:async()=>{},stats:()=>({peerCount:0})}; return origLoad.apply(this,arguments); };

const Jets = require(path.join(process.cwd(),'classes/Safecloud/Jets.js'));
check('Jets.js exposes _chunkRangeForLink', typeof Jets._chunkRangeForLink === 'function');

// ── Binary tree, depth 3 → 8 leaves ──
const m8 = { treeN:2, treeDepth:3, chunkCount:8 };
// Root covers all 8
let r = Jets._chunkRangeForLink(['track','data'], m8);
check('depth-3 root covers [0,8)', r.start===0 && r.end===8);
// Left subtree ["...","0"] covers [0,4)
r = Jets._chunkRangeForLink(['track','data','0'], m8);
check('left subtree covers [0,4)', r.start===0 && r.end===4);
// Right subtree ["...","1"] covers [4,8)
r = Jets._chunkRangeForLink(['track','data','1'], m8);
check('right subtree covers [4,8)', r.start===4 && r.end===8);
// Deeper: ["...","1","0"] covers [4,6)
r = Jets._chunkRangeForLink(['track','data','1','0'], m8);
check('["1","0"] covers [4,6)', r.start===4 && r.end===6);
// Leaf ["...","1","0","1"] covers [5,6)
r = Jets._chunkRangeForLink(['track','data','1','0','1'], m8);
check('leaf ["1","0","1"] covers exactly [5,6)', r.start===5 && r.end===6);

// ── ROUND-TRIP INVARIANT (the safety property) ──
// For every chunk index i, the leaf path for i must map back to a range
// containing exactly i. This is what guarantees correct chunk mapping.
function leafPathFor(absIndex, m) {
  // mirrors _chunkLinkPath
  const path = ['track','data']; let n = Math.pow(m.treeN, m.treeDepth); let idx = absIndex;
  for (let d=0; d<m.treeDepth; d++){ n=n/m.treeN; path.push(String(Math.floor(idx/n))); idx=idx%n; }
  return path;
}
let allRoundTrip = true;
for (let i=0;i<8;i++){
  const lp = leafPathFor(i, m8);
  const rr = Jets._chunkRangeForLink(lp, m8);
  if (!(rr.start===i && rr.end===i+1)) { allRoundTrip=false; console.log('    mismatch at',i,'→',JSON.stringify(rr)); }
}
check('round-trip: every leaf index maps to its own range (depth 3)', allRoundTrip);

// ── 4-ary tree, depth 2 → 16 leaves ──
const m16 = { treeN:4, treeDepth:2, chunkCount:16 };
r = Jets._chunkRangeForLink(['track','data','2'], m16);
check('4-ary: node "2" covers [8,12)', r.start===8 && r.end===12);
r = Jets._chunkRangeForLink(['track','data','2','3'], m16);
check('4-ary: leaf "2","3" covers [11,12)', r.start===11 && r.end===12);
let rt4=true;
for (let i=0;i<16;i++){ const rr=Jets._chunkRangeForLink(leafPathFor(i,m16),m16); if(!(rr.start===i&&rr.end===i+1))rt4=false; }
check('round-trip: 4-ary depth-2 all 16 leaves correct', rt4);

// ── Ragged tree: chunkCount not a power of treeN (real videos) ──
const m5 = { treeN:2, treeDepth:3, chunkCount:5 }; // 5 chunks in an 8-leaf tree
r = Jets._chunkRangeForLink(['track','data'], m5);
check('ragged: root end clamps to chunkCount (5, not 8)', r.end===5);
r = Jets._chunkRangeForLink(['track','data','1'], m5);
check('ragged: right subtree clamps to [4,5)', r.start===4 && r.end===5);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
