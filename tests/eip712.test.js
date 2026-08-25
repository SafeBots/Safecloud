const ethers = require('ethers');

const DOMAIN = { name: 'OpenClaiming', version: '1', chainId: 56,
                 verifyingContract: '0x99999febd42cad798fe10ab0b1c563002fc99999' };
const TYPES = { Payment: [
  { name: 'payer', type: 'address' }, { name: 'token', type: 'address' },
  { name: 'recipientsHash', type: 'bytes32' }, { name: 'max', type: 'uint256' },
  { name: 'line', type: 'uint256' }, { name: 'nbf', type: 'uint256' },
  { name: 'exp', type: 'uint256' }, { name: 'contract', type: 'address' }
]};

let pass = 0, fail = 0;
function check(name, cond) { cond ? (pass++, console.log('  \u2713', name)) : (fail++, console.log('  \u2717 FAIL:', name)); }

(async () => {
  const encoder = ethers.TypedDataEncoder.from(TYPES);
  const typeString = encoder.encodeType('Payment');
  console.log('Type string:', typeString);
  check('typehash matches contract PAYMENTS_TYPEHASH',
    typeString === 'Payment(address payer,address token,bytes32 recipientsHash,uint256 max,uint256 line,uint256 nbf,uint256 exp,address contract)');

  const wallet = new ethers.Wallet('0x' + '11'.repeat(32));
  const value = {
    payer: wallet.address, token: '0x' + '22'.repeat(20),
    recipientsHash: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address[]'], [[wallet.address]])),
    max: 100000n, line: 0n, nbf: 0n, exp: 9999999999n, contract: DOMAIN.verifyingContract
  };
  const sig = await wallet.signTypedData(DOMAIN, TYPES, value);
  check('sign->recover round-trips', ethers.verifyTypedData(DOMAIN, TYPES, value, sig).toLowerCase() === wallet.address.toLowerCase());

  const rh = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['address[]'], [[wallet.address]]));
  const manual = ethers.keccak256('0x'
    + '0000000000000000000000000000000000000000000000000000000000000020'
    + '0000000000000000000000000000000000000000000000000000000000000001'
    + wallet.address.slice(2).toLowerCase().padStart(64, '0'));
  check('recipientsHash abi.encode == manual Buffer layout', rh === manual);

  const WRONG = { Payment: [
    { name: 'payer', type: 'address' }, { name: 'token', type: 'address' },
    { name: 'max', type: 'uint256' }, { name: 'line', type: 'uint256' },
    { name: 'nbf', type: 'uint256' }, { name: 'exp', type: 'uint256' },
    { name: 'recipientsHash', type: 'bytes32' }, { name: 'contract', type: 'address' }
  ]};
  check('reordered struct -> different digest',
    ethers.TypedDataEncoder.hash(DOMAIN, TYPES, value) !== ethers.TypedDataEncoder.hash(DOMAIN, WRONG, value));

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
