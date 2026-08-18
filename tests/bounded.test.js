const { BoundedMap, PersistentIndex } = require('../classes/Safecloud/Jets/_bounded.js');
const fs = require('fs'), os = require('os'), path = require('path');
let pass=0, fail=0; const c=(n,ok)=>{ok?pass++:fail++; console.log(`  ${ok?'\u2713':'\u2717'} ${n}`);};

// BoundedMap cap
const m = new BoundedMap({max:3});
m.set('a',1); m.set('b',2); m.set('c',3); m.set('d',4); // evicts 'a'
c('cap enforced: size==3', m.size()===3);
c('oldest evicted (a gone)', m.get('a')===undefined);
c('newest kept (d present)', m.get('d')===4);

// LRU refresh on set
const m2 = new BoundedMap({max:2});
m2.set('x',1); m2.set('y',2); m2.set('x',9); m2.set('z',3); // touching x makes y oldest
c('refresh-on-set: y evicted, x kept', m2.get('x')===9 && m2.get('y')===undefined && m2.get('z')===3);

// TTL
const m3 = new BoundedMap({max:100, ttlMs:50});
m3.set('t',1);
c('ttl: present before expiry', m3.get('t')===1);
const start=Date.now(); while(Date.now()-start<70){} // busy wait 70ms
c('ttl: absent after expiry', m3.get('t')===undefined);

// PersistentIndex round-trip
const p = path.join(os.tmpdir(), 'pidx-'+Date.now()+'.json');
const idx = new PersistentIndex(p, {debounceMs:1});
idx.data['root1'] = {'track/data':['cid0','cid1']};
idx.flushSync();
const idx2 = new PersistentIndex(p);
c('persistence: reload sees data', JSON.stringify(idx2.data.root1)===JSON.stringify({'track/data':['cid0','cid1']}));

// corrupt file → empty, no throw
fs.writeFileSync(p, '{not valid json');
let ok=true; try { const idx3=new PersistentIndex(p); ok = (JSON.stringify(idx3.data)==='{}'); } catch(e){ ok=false; }
c('persistence: corrupt snapshot → empty, no crash', ok);
fs.unlinkSync(p);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
