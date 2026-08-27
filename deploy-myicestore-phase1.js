/**
 * Deploy MyICEStorePhase1 to Lightchain Mainnet
 * Run: LIGHTCHAIN_PRIVATE_KEY=0x… node deploy-myicestore-phase1.js
 */
import { ethers } from '/home/keiko/Desktop/lightdex/contracts/node_modules/ethers/lib.esm/index.js';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RPC = 'https://rpc.mainnet.lightchain.ai';
const CHAIN_ID = 9200;
const PRIV_KEY = (process.env.PRIVATE_KEY || process.env.LIGHTCHAIN_PRIVATE_KEY || '').trim();
if (!PRIV_KEY || !PRIV_KEY.startsWith('0x') || PRIV_KEY.length < 66) {
  console.error('Missing PRIVATE_KEY / LIGHTCHAIN_PRIVATE_KEY');
  process.exit(1);
}

console.log('Compiling MyICEStorePhase1.sol...');
const solc = (await import('/home/keiko/Desktop/lightdex/contracts/node_modules/solc/index.js')).default;
const source = readFileSync(path.join(__dirname, 'MyICEStorePhase1.sol'), 'utf8');
const input = {
  language: 'Solidity',
  sources: { 'MyICEStorePhase1.sol': { content: source } },
  settings: {
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    optimizer: { enabled: true, runs: 200 }
  }
};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
if (output.errors) {
  const errs = output.errors.filter(e => e.severity === 'error');
  if (errs.length) { console.error(errs); process.exit(1); }
}
const c = output.contracts['MyICEStorePhase1.sol']['MyICEStorePhase1'];
const abi = c.abi;
const bytecode = '0x' + c.evm.bytecode.object;
console.log('Compiled. bytecode len', bytecode.length);

const provider = new ethers.JsonRpcProvider(RPC, { chainId: CHAIN_ID, name: 'lightchain' });
const wallet = new ethers.Wallet(PRIV_KEY, provider);
console.log('Deployer/sponsor:', wallet.address);
const bal = await provider.getBalance(wallet.address);
console.log('Balance:', ethers.formatEther(bal), 'LCAI');
if (bal === 0n) { console.error('Zero balance — abort'); process.exit(1); }

const factory = new ethers.ContractFactory(abi, bytecode, wallet);
console.log('Deploying MyICEStorePhase1(sponsor=' + wallet.address + ')...');
const deployed = await factory.deploy(wallet.address, { gasLimit: 1_500_000 });
await deployed.waitForDeployment();
const address = await deployed.getAddress();
console.log('Deployed:', address);

// Sanity: sponsor() matches
const sponsor = await deployed.sponsor();
console.log('sponsor():', sponsor);
if (sponsor.toLowerCase() !== wallet.address.toLowerCase()) {
  console.error('Sponsor mismatch!');
  process.exit(1);
}

const result = {
  address,
  abi,
  sponsor: wallet.address,
  contract: 'MyICEStorePhase1',
  previousAddress: '0x2902Ff4e773E3dEB8C193d77442CE22e7d96299a',
  deployedAt: new Date().toISOString(),
  chainId: CHAIN_ID
};
writeFileSync(path.join(__dirname, 'myicestore-phase1-deployment.json'), JSON.stringify(result, null, 2));
writeFileSync(path.join(__dirname, 'myicestore-deployment.json'), JSON.stringify({
  address, abi, deployedAt: result.deployedAt, contract: 'MyICEStorePhase1', sponsor: wallet.address
}, null, 2));
console.log('Saved myicestore-phase1-deployment.json');
console.log('DONE', address);
