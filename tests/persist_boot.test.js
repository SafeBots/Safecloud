// Confirm _cidIndex persistence round-trips through a simulated restart.
const { PersistentIndex } = require('../classes/Safecloud/Jets/_bounded.js');
const os=require('os'), path=require('path'), fs=require('fs');
const p = path.join(os.tmpdir(), 'cidtest-'+Date.now()+'.json');
let pass=0,fail=0; const c=(n,ok)=>{ok?pass++:fail++;console.log(`  ${ok?'\u2713':'\u2717'} ${n}`);};

// simulate a Jet writing during PUT
const idx = new PersistentIndex(p, {debounceMs:1});
const cidIndex = idx.data;
cidIndex['bafyRoot'] = {};
cidIndex['bafyRoot']['track/data'] = ['cid0','cid1','cid2'];
cidIndex['bafyRoot']['_treeN'] = 2;
cidIndex['bafyRoot']['_perChunkWei'] = '500';
idx.markDirty();

setTimeout(()=>{
  // simulate restart: new PersistentIndex on same path
  const idx2 = new PersistentIndex(p);
  const restored = idx2.data;
  c('rootCid survived restart', !!restored['bafyRoot']);
  c('track/data array intact', JSON.stringify(restored['bafyRoot']['track/data'])===JSON.stringify(['cid0','cid1','cid2']));
  c('_treeN survived', restored['bafyRoot']['_treeN']===2);
  c('_perChunkWei survived', restored['bafyRoot']['_perChunkWei']==='500');
  // Object.values still works (used at line 2485)
  c('Object.values works on restored index', Object.values(restored).length===1);
  fs.unlinkSync(p);
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
}, 60);
