/**
 * Compile Solidity contracts using solc-js directly.
 * Bypasses Hardhat's compiler download (blocked by network proxy).
 * Outputs ABI + bytecode JSON to artifacts/ for each contract.
 */
const solc = require('solc');
const fs = require('fs');
const path = require('path');

const CONTRACTS_DIR = path.join(__dirname, 'contracts');
const ARTIFACTS_DIR = path.join(__dirname, 'artifacts');
const NODE_MODULES = path.join(__dirname, 'node_modules');

// Gather all .sol files in contracts/
const solFiles = fs.readdirSync(CONTRACTS_DIR)
  .filter(f => f.endsWith('.sol'));

const sources = {};
for (const file of solFiles) {
  sources[file] = {
    content: fs.readFileSync(path.join(CONTRACTS_DIR, file), 'utf8')
  };
}

const input = {
  language: 'Solidity',
  sources,
  settings: {
    viaIR: true,
    optimizer: { enabled: true, runs: 200 },
    outputSelection: {
      '*': {
        '*': ['abi', 'evm.bytecode.object', 'evm.bytecode.linkReferences']
      }
    }
  }
};

// Import callback to resolve @openzeppelin and other node_modules imports
function findImports(importPath) {
  // Try node_modules first
  const nmPath = path.join(NODE_MODULES, importPath);
  if (fs.existsSync(nmPath)) {
    return { contents: fs.readFileSync(nmPath, 'utf8') };
  }
  // Try contracts dir
  const localPath = path.join(CONTRACTS_DIR, importPath);
  if (fs.existsSync(localPath)) {
    return { contents: fs.readFileSync(localPath, 'utf8') };
  }
  return { error: `File not found: ${importPath}` };
}

console.log('Compiling contracts:', solFiles.join(', '));
const output = JSON.parse(solc.compile(JSON.stringify(input), { import: findImports }));

// Check for errors
if (output.errors) {
  const fatal = output.errors.filter(e => e.severity === 'error');
  if (fatal.length > 0) {
    console.error('Compilation errors:');
    fatal.forEach(e => console.error(e.formattedMessage));
    process.exit(1);
  }
  // Print warnings
  output.errors.filter(e => e.severity === 'warning').forEach(e =>
    console.warn('Warning:', e.formattedMessage)
  );
}

// Write artifacts
fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
let count = 0;
for (const [fileName, fileContracts] of Object.entries(output.contracts || {})) {
  for (const [contractName, contract] of Object.entries(fileContracts)) {
    const artifact = {
      contractName,
      abi: contract.abi,
      bytecode: '0x' + contract.evm.bytecode.object,
      linkReferences: contract.evm.bytecode.linkReferences
    };
    const outPath = path.join(ARTIFACTS_DIR, `${contractName}.json`);
    fs.writeFileSync(outPath, JSON.stringify(artifact, null, 2));
    console.log(`  ${contractName} -> artifacts/${contractName}.json (${(artifact.bytecode.length / 2).toLocaleString()} bytes)`);
    count++;
  }
}
console.log(`\nCompiled ${count} contracts successfully.`);
