const M=require('module'); const ol=M._load;
const Q={Config:{get:(k,d)=>d},log:()=>{},Crypto:{OpenClaim:{}}};
M._load=function(r){ if(r==='Q')return Q; return ol.apply(this,arguments); };
const EVM=require('./Crypto/OpenClaim/EVM.js');
const OC='0x99999febd42cad798fe10ab0b1c563002fc99999';
const A='0x'+'a1'.repeat(20), T='0x'+'b0'.repeat(20), R='0x'+'c2'.repeat(20);
const h=r=>'0x'+Buffer.from(r.digest).toString('hex');
(async()=>{
  const p = await EVM.hashTypedData({payer:A,token:T,recipients:[R],max:'100000',line:'0',
    nbf:'0',exp:'9999999999',chainId:'eip155:56',contract:OC});
  const a = await EVM.hashTypedData({authority:A,subject:R,contractAddress:T,method:'0x12345678',
    paramsHash:'0x'+'00'.repeat(32),minimum:'0',fraction:'0',delay:'0',
    invoker:'0x'+'d4'.repeat(20),nbf:'0',exp:'9999999999',chainId:'eip155:56',contract:OC});
  const et = EVM.endpointType('https');
  const cm = EVM.endpointCommitment('https://example.com/ocp-inbox','0x'+'2b'.repeat(32));
  const m = await EVM.hashTypedData({account:A,endpointType:et,commitment:cm,
    chainId:'eip155:56',contract:OC});
  console.log(JSON.stringify({payments:h(p),actions:h(a),messages:h(m)}));
})();
