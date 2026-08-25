/**
 * Compiles the REAL OpenClaiming.sol (plus a minimal test ERC-20) with solc,
 * using the same settings as production: optimizer on, viaIR: true.
 * Writes artifacts to tests/evm/artifacts.json for the on-chain tests.
 */
const fs = require('fs');
const path = require('path');
const solc = require('solc');

const OC_PATH = path.join(process.cwd(), 'references/OpenClaiming.sol');
const source = fs.readFileSync(OC_PATH, 'utf8');

// Minimal ERC-20 with permit-less approve/transferFrom — enough to settle.
const ERC20 = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract TestToken {
    string public name = "TestBux";
    string public symbol = "TBX";
    uint8  public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; emit Transfer(address(0), to, amt); }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; emit Approval(msg.sender, s, a); return true; }
    function transfer(address to, uint256 a) external returns (bool) {
        require(balanceOf[msg.sender] >= a, "bal"); balanceOf[msg.sender] -= a; balanceOf[to] += a; emit Transfer(msg.sender, to, a); return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        require(balanceOf[f] >= a, "bal"); require(allowance[f][msg.sender] >= a, "allow");
        allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[t] += a; emit Transfer(f, t, a); return true; }
}`;

const input = {
  language: 'Solidity',
  sources: {
    'OpenClaiming.sol': { content: source },
    'TestToken.sol':    { content: ERC20 }
  },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    viaIR: true,                       // REQUIRED for OpenClaiming
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } }
  }
};

console.log('Compiling OpenClaiming.sol with solc', solc.version(), '(optimizer + viaIR)…');
const out = JSON.parse(solc.compile(JSON.stringify(input)));

let errors = 0;
(out.errors || []).forEach(e => {
  if (e.severity === 'error') { errors++; console.log('  ERROR:', e.formattedMessage.split('\n')[0]); }
  else if (e.severity === 'warning') { console.log('  warning:', (e.formattedMessage||'').split('\n')[0]); }
});
if (errors) { console.log('\nCOMPILATION FAILED with ' + errors + ' error(s)'); process.exit(1); }

const artifacts = {};
for (const file of Object.keys(out.contracts || {})) {
  for (const name of Object.keys(out.contracts[file])) {
    const c = out.contracts[file][name];
    artifacts[name] = { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object };
    console.log('  ✓ ' + name + ': ' + (c.evm.bytecode.object.length/2) + ' bytes'
      + (name === 'OpenClaiming' ? '  (EIP-170 limit 24576)' : ''));
  }
}
fs.writeFileSync(path.join(process.cwd(),'tests/evm/artifacts.json'), JSON.stringify(artifacts, null, 1));
console.log('\nArtifacts → tests/evm/artifacts.json');
