/**
 * Deploy MyICEStore to Lightchain Mainnet
 * Run: node deploy-myicestore.js
 */
import { ethers } from '/home/keiko/Desktop/lightdex/contracts/node_modules/ethers/lib.esm/index.js';
import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Config ────────────────────────────────────────────────────────────────────
// NEVER hardcode keys — set in env only: export PRIVATE_KEY=0x… (or LIGHTCHAIN_PRIVATE_KEY)
const RPC      = 'https://rpc.mainnet.lightchain.ai';
const CHAIN_ID = 9200;
const PRIV_KEY = (process.env.PRIVATE_KEY || process.env.LIGHTCHAIN_PRIVATE_KEY || '').trim();
if (!PRIV_KEY || !PRIV_KEY.startsWith('0x') || PRIV_KEY.length < 66) {
  console.error('Missing PRIVATE_KEY (or LIGHTCHAIN_PRIVATE_KEY) env var. Never commit keys.');
  process.exit(1);
}

// ── Compile with solc ─────────────────────────────────────────────────────────
console.log('Compiling MyICEStore.sol...');
const solc = (await import('/home/keiko/Desktop/lightdex/contracts/node_modules/solc/index.js')).default;

const source = readFileSync(path.join(__dirname, 'MyICEStore.sol'), 'utf8');
const input = {
  language: 'Solidity',
  sources: { 'MyICEStore.sol': { content: source } },
  settings: {
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    optimizer: { enabled: true, runs: 200 }
  }
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));
if (output.errors) {
  const errs = output.errors.filter(e => e.severity === 'error');
  if (errs.length) { console.error('Compile errors:', errs); process.exit(1); }
  output.errors.filter(e => e.severity === 'warning').forEach(w => console.warn('⚠', w.message));
}

const contract = output.contracts['MyICEStore.sol']['MyICEStore'];
const abi      = contract.abi;
const bytecode = '0x' + contract.evm.bytecode.object;
console.log('✅ Compiled. Bytecode length:', bytecode.length);

// ── Deploy ────────────────────────────────────────────────────────────────────
const provider = new ethers.JsonRpcProvider(RPC, { chainId: CHAIN_ID, name: 'lightchain' });
const wallet   = new ethers.Wallet(PRIV_KEY, provider);

console.log('Deployer:', wallet.address);
const bal = await provider.getBalance(wallet.address);
console.log('Balance :', ethers.formatEther(bal), 'LCAI');

const factory = new ethers.ContractFactory(abi, bytecode, wallet);
console.log('\nDeploying MyICEStore...');
const deployed = await factory.deploy({ gasLimit: 1_000_000 });
await deployed.waitForDeployment();
const address = await deployed.getAddress();

console.log('\n✅ MyICEStore deployed!');
console.log('Address:', address);
console.log('Verify: https://lightscan.app/address/' + address);

// Save result
const result = { address, abi, deployedAt: new Date().toISOString() };
writeFileSync(path.join(__dirname, 'myicestore-deployment.json'), JSON.stringify(result, null, 2));
console.log('\nSaved to myicestore-deployment.json');
