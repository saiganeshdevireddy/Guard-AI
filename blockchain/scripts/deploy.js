const { ethers } = require('hardhat');
const fs = require('node:fs');
const path = require('node:path');

async function main() {
  const factory = await ethers.getContractFactory('GuardAuditRegistry');
  const registry = await factory.deploy();
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  const deployment = {
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    contractAddress: address,
    deployedAt: new Date().toISOString(),
  };
  const output = path.join(__dirname, '..', 'deployments', 'localhost.json');
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(deployment, null, 2)}\n`, { flag: 'w' });
  console.log(`GuardAuditRegistry deployed at ${address}`);
  console.log(`Deployment metadata saved to ${output}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
