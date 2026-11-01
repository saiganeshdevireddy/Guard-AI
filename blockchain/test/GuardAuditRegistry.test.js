const assert = require('node:assert/strict');
const { ethers } = require('hardhat');

describe('GuardAuditRegistry', function () {
  async function deployRegistry() {
    const Registry = await ethers.getContractFactory('GuardAuditRegistry');
    const registry = await Registry.deploy();
    await registry.waitForDeployment();
    return registry;
  }

  it('registers and verifies an audit hash without storing event details', async function () {
    const registry = await deployRegistry();
    const auditId = ethers.id('guard-ai-audit:1');
    const eventHash = ethers.sha256(ethers.toUtf8Bytes('non-sensitive test event'));
    const tx = await registry.registerEventHash(auditId, eventHash);
    const receipt = await tx.wait();
    assert.equal(receipt.status, 1);
    assert.equal(await registry.verifyEventHash(auditId, eventHash), true);
    assert.equal(await registry.verifyEventHash(auditId, ethers.ZeroHash), false);
  });

  it('rejects duplicate identifiers so an anchored record cannot be silently replaced', async function () {
    const registry = await deployRegistry();
    const auditId = ethers.id('guard-ai-audit:2');
    await registry.registerEventHash(auditId, ethers.id('first hash'));
    let rejected = false;
    try { await registry.registerEventHash(auditId, ethers.id('modified hash')); }
    catch (error) { rejected = error.message.includes('AlreadyRegistered'); }
    assert.equal(rejected, true, 'duplicate audit identifiers must revert');
  });
});
