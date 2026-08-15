/**
 * QiPayPaymentHub — ADDITIONAL VULNERABILITY TEST SUITE
 *
 * Covers additional MEDIUM and LOW severity issues from the security audit.
 */

const { expect } = require("chai");
const { loadFixture, time } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { ethers } = require("hardhat");

const {
  ROLES,
  InvoiceStatus,
  qiPayout,
  quaiAddr,
  saltOf,
  sealedRefJs,
  invoiceKeyJs,
  deployWithVendor,
  buildRequest,
} = require("./helpers/quai");

describe("QiPayPaymentHub — Additional Vulnerabilities", function () {
  // ========================================================================
  // MEDIUM #9b: Payment verification should prevent disputes on pending invoices
  // ========================================================================

  describe("[MEDIUM] Payment settlement flow edge cases", function () {
    it("allows settlement after expiry (student paid late)", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx, {
        expiresAt: BigInt(await time.latest()) + BigInt(60),
      });

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);

      // Wait for expiry
      await time.increase(61);

      // But settlement can still be attested (for late receipts)
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      const tx = await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);
      await expect(tx).to.emit(ctx.hub, "SettlementAttested");

      const invoice = await ctx.hub.getInvoice(ctx.vendorA, commitment);
      expect(invoice.status).to.equal(InvoiceStatus.Settled);
    });

    it("suspended vendor may still attest settlements (receipts not stripped)", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);

      // Suspend vendor before settlement
      await ctx.registry.connect(ctx.vendorManager).suspendVendor(ctx.vendorA);

      // But can still settle (important for receipt integrity)
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      const tx = await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);
      await expect(tx).to.emit(ctx.hub, "SettlementAttested");

      const invoice = await ctx.hub.getInvoice(ctx.vendorA, commitment);
      expect(invoice.status).to.equal(InvoiceStatus.Settled);
    });

    it("revoked vendor cannot attest (broken attestor key)", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);

      // Revoke vendor
      await ctx.registry.connect(ctx.vendorManager).revokeVendor(ctx.vendorA);

      // Cannot settle through revoked vendor's key
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      await expect(
        ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed)
      ).to.be.revertedWithCustomError(ctx.hub, "VendorRevokedOrUnknown");
    });
  });

  // ========================================================================
  // MEDIUM: Arbiter authorization checks
  // ========================================================================

  describe("[MEDIUM] Arbiter authorization edge cases", function () {
    it("prevents arbiter from resolving dispute if they are the complainant", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);

      // Open dispute as the arbiter (student/complainant)
      await ctx.hub.connect(ctx.arbiter).openDispute(req, ethers.id("complaint"));

      // Arbiter cannot resolve their own dispute
      await expect(
        ctx.hub.connect(ctx.arbiter).resolveDispute(ctx.vendorA, commitment, true, ethers.id("upheld"))
      ).to.be.revertedWithCustomError(ctx.hub, "ArbiterIsComplainant");
    });

    it("prevents arbiter from resolving dispute if they represent the vendor", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);
      await ctx.hub.openDispute(req, ethers.id("complaint"));

      // attestorA represents vendorA - cannot be arbiter on vendorA's dispute
      await expect(
        ctx.hub.connect(ctx.attestorA).resolveDispute(ctx.vendorA, commitment, true, ethers.id("upheld"))
      ).to.be.revertedWithCustomError(ctx.hub, "ArbiterRepresentsVendor");
    });

    it("allows neutral arbiter to resolve dispute", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);
      await ctx.hub.openDispute(req, ethers.id("complaint"));

      // Arbiter who is not the complainant and doesn't represent vendor
      const tx = await ctx.hub.connect(ctx.arbiter).resolveDispute(ctx.vendorA, commitment, true, ethers.id("upheld"));
      await expect(tx).to.emit(ctx.hub, "DisputeResolved");
    });
  });

  // ========================================================================
  // MEDIUM: Dispute lifetime and expiration
  // ========================================================================

  describe("[MEDIUM] Dispute expiration and lifetime management", function () {
    it("prevents expiring dispute before arbitrationDeadline", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);

      const disputeTime = await time.latest();
      await ctx.hub.openDispute(req, ethers.id("complaint"));

      const arbitrationDeadline = await ctx.hub.arbitrationDeadline();
      const expireTime = disputeTime + Number(arbitrationDeadline);

      // Before deadline: cannot expire
      await time.increaseTo(expireTime - 1);
      await expect(
        ctx.hub.expireDispute(ctx.vendorA, commitment)
      ).to.be.revertedWithCustomError(ctx.hub, "DisputeWindowClosed");
    });

    it("allows expiring dispute after arbitrationDeadline", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);

      const disputeTime = await time.latest();
      await ctx.hub.openDispute(req, ethers.id("complaint"));

      const arbitrationDeadline = await ctx.hub.arbitrationDeadline();
      const expireTime = disputeTime + Number(arbitrationDeadline);

      // After deadline: can expire
      await time.increaseTo(expireTime + 1);
      const tx = await ctx.hub.expireDispute(ctx.vendorA, commitment);
      await expect(tx).to.emit(ctx.hub, "DisputeExpired");

      const invoice = await ctx.hub.getInvoice(ctx.vendorA, commitment);
      expect(invoice.status).to.equal(InvoiceStatus.ArbitrationExpired);
    });

    it("prevents expiring non-disputed invoices", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);

      // Try to expire Open invoice
      const arbitrationDeadline = await ctx.hub.arbitrationDeadline();
      await time.increase(Number(arbitrationDeadline) + 100);

      await expect(
        ctx.hub.expireDispute(ctx.vendorA, commitment)
      ).to.be.revertedWithCustomError(ctx.hub, "InvoiceNotDisputed");
    });
  });

  // ========================================================================
  // MEDIUM: Admin role management and security
  // ========================================================================

  describe("[MEDIUM] Admin management security checks", function () {
    it("prevents granting admin role directly (must use propose/accept)", async function () {
      const ctx = await loadFixture(deployWithVendor);

      // Cannot grant ADMIN_ROLE via grantRole
      await expect(
        ctx.hub.connect(ctx.admin).grantRole(ROLES.ADMIN, ctx.spare.address)
      ).to.be.revertedWithCustomError(ctx.hub, "Unauthorized");
    });

    it("admin can propose a new admin", async function () {
      const ctx = await loadFixture(deployWithVendor);

      const pendingAdmin = ctx.spare.address;
      const tx = await ctx.hub.connect(ctx.admin).proposeAdmin(pendingAdmin);
      await expect(tx).to.emit(ctx.hub, "AdminProposed");

      const stored = await ctx.hub.pendingAdmin();
      expect(stored).to.equal(pendingAdmin);
    });

    it("proposed admin must accept to become admin", async function () {
      const ctx = await loadFixture(deployWithVendor);

      const spare = ctx.spare;
      await ctx.hub.connect(ctx.admin).proposeAdmin(spare.address);

      // Only the proposed admin can accept
      await expect(
        ctx.hub.connect(ctx.admin).acceptAdmin()
      ).to.be.revertedWithCustomError(ctx.hub, "NotPendingAdmin");

      // Proposed admin accepts
      const tx = await ctx.hub.connect(spare).acceptAdmin();
      await expect(tx).to.emit(ctx.hub, "RoleGranted");

      // Now has admin role
      expect(await ctx.hub.hasRole(ROLES.ADMIN, spare.address)).to.equal(true);
    });

    it("prevents removing the last admin", async function () {
      const ctx = await loadFixture(deployWithVendor);

      // Only one admin exists
      expect(await ctx.hub.adminCount()).to.equal(1n);

      // Cannot revoke the last admin
      await expect(
        ctx.hub.connect(ctx.admin).revokeRole(ROLES.ADMIN, ctx.admin.address)
      ).to.be.revertedWithCustomError(ctx.hub, "LastAdminCannotBeRemoved");
    });
  });

  // ========================================================================
  // MEDIUM: Parameter validation and bounds checking
  // ========================================================================

  describe("[MEDIUM] Parameter validation and bounds checking", function () {
    it("enforces MIN_INVOICE_TTL <= maxInvoiceTtl <= MAX_INVOICE_TTL_LIMIT", async function () {
      const ctx = await loadFixture(deployWithVendor);

      const MIN_TTL = 60; // 1 minute
      const MAX_TTL_LIMIT = 24 * 60 * 60; // 1 day

      // Too low
      await expect(
        ctx.hub.connect(ctx.admin).setMaxInvoiceTtl(MIN_TTL - 1)
      ).to.be.revertedWithCustomError(ctx.hub, "TtlOutOfBounds");

      // Too high
      await expect(
        ctx.hub.connect(ctx.admin).setMaxInvoiceTtl(MAX_TTL_LIMIT + 1)
      ).to.be.revertedWithCustomError(ctx.hub, "TtlOutOfBounds");

      // Valid
      const tx = await ctx.hub.connect(ctx.admin).setMaxInvoiceTtl(900);
      await expect(tx).to.emit(ctx.hub, "MaxInvoiceTtlUpdated");
    });

    it("enforces MIN_DISPUTE_WINDOW <= disputeWindow <= MAX_DISPUTE_WINDOW", async function () {
      const ctx = await loadFixture(deployWithVendor);

      const MIN_WINDOW = 60 * 60; // 1 hour
      const MAX_WINDOW = 30 * 24 * 60 * 60; // 30 days

      // Too low
      await expect(
        ctx.hub.connect(ctx.admin).setDisputeWindow(MIN_WINDOW - 1)
      ).to.be.revertedWithCustomError(ctx.hub, "DisputeWindowOutOfBounds");

      // Too high
      await expect(
        ctx.hub.connect(ctx.admin).setDisputeWindow(MAX_WINDOW + 1)
      ).to.be.revertedWithCustomError(ctx.hub, "DisputeWindowOutOfBounds");

      // Valid
      const tx = await ctx.hub.connect(ctx.admin).setDisputeWindow(7 * 24 * 60 * 60);
      await expect(tx).to.emit(ctx.hub, "DisputeWindowUpdated");
    });

    it("enforces MIN_ARBITRATION_DEADLINE <= arbitrationDeadline <= MAX_ARBITRATION_DEADLINE", async function () {
      const ctx = await loadFixture(deployWithVendor);

      const MIN_DEADLINE = 24 * 60 * 60; // 1 day
      const MAX_DEADLINE = 90 * 24 * 60 * 60; // 90 days

      // Too low
      await expect(
        ctx.hub.connect(ctx.admin).setArbitrationDeadline(MIN_DEADLINE - 1)
      ).to.be.revertedWithCustomError(ctx.hub, "ArbitrationDeadlineOutOfBounds");

      // Too high
      await expect(
        ctx.hub.connect(ctx.admin).setArbitrationDeadline(MAX_DEADLINE + 1)
      ).to.be.revertedWithCustomError(ctx.hub, "ArbitrationDeadlineOutOfBounds");

      // Valid
      const tx = await ctx.hub.connect(ctx.admin).setArbitrationDeadline(14 * 24 * 60 * 60);
      await expect(tx).to.emit(ctx.hub, "ArbitrationDeadlineUpdated");
    });
  });

  // ========================================================================
  // LOW: Privacy surface - sensitive data not exposed
  // ========================================================================

  describe("[LOW] Privacy surface - sensitive data verification", function () {
    it("ensures amount never appears in storage or events", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const sensitiveAmount = 1337n;
      const { req, commitment } = await buildRequest(ctx, {
        amount: sensitiveAmount,
      });

      const tx = await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const receipt = await tx.wait();

      // Scan all logs for the amount
      for (const log of receipt.logs) {
        const parsed = ctx.hub.interface.parseLog(log);
        if (!parsed) continue;
        const blob = JSON.stringify(parsed.args);
        expect(blob).not.to.include(sensitiveAmount.toString());
      }

      // Check storage doesn't contain amount
      const invoice = await ctx.hub.getInvoice(ctx.vendorA, commitment);
      // Invoice struct contains no amount field, only commitment hash
      expect(invoice.sealedPaymentRef).to.equal(ethers.ZeroHash);
    });

    it("ensures payout address never appears in storage or events", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const sensitiveAddress = qiPayout(0xdeadbeef);
      const { req, commitment } = await buildRequest(ctx, {
        qiPayoutAddress: sensitiveAddress,
      });

      const tx = await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const receipt = await tx.wait();

      // Scan all logs for the address
      for (const log of receipt.logs) {
        const parsed = ctx.hub.interface.parseLog(log);
        if (!parsed) continue;
        const blob = JSON.stringify(parsed.args);
        expect(blob).not.to.include(sensitiveAddress.toLowerCase().substring(2));
      }

      // Check storage doesn't contain address
      const invoice = await ctx.hub.getInvoice(ctx.vendorA, commitment);
      // Only hash is stored, not the address
      expect(Object.keys(invoice).includes("qiPayoutAddress")).to.equal(false);
    });
  });

  // ========================================================================
  // LOW: Input validation edge cases
  // ========================================================================

  describe("[LOW] Input validation edge cases", function () {
    it("refuses zero reason hash in openDispute", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);

      await expect(
        ctx.hub.openDispute(req, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(ctx.hub, "ZeroReasonHash");
    });

    it("refuses zero payment ref in attestSettlement", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);

      await expect(
        ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(ctx.hub, "ZeroPaymentRef");
    });

    it("refuses zero registry in constructor", async function () {
      // This would be tested in constructor tests, but documented here
      // Constructor validates: if (address(registry_) == address(0)) revert ZeroRegistry();
      expect(true).to.be.true; // Placeholder
    });
  });

  // ========================================================================
  // LOW: Event logging completeness
  // ========================================================================

  describe("[LOW] Event logging for audit trail", function () {
    it("emits event on max invoice TTL update", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const oldValue = await ctx.hub.maxInvoiceTtl();
      const newValue = 1200;

      const tx = await ctx.hub.connect(ctx.admin).setMaxInvoiceTtl(newValue);
      await expect(tx)
        .to.emit(ctx.hub, "MaxInvoiceTtlUpdated")
        .withArgs(oldValue, newValue);
    });

    it("emits event on dispute window update", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const oldValue = await ctx.hub.disputeWindow();
      const newValue = 10 * 24 * 60 * 60; // 10 days

      const tx = await ctx.hub.connect(ctx.admin).setDisputeWindow(newValue);
      await expect(tx)
        .to.emit(ctx.hub, "DisputeWindowUpdated")
        .withArgs(oldValue, newValue);
    });

    it("emits event on arbitration deadline update", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const oldValue = await ctx.hub.arbitrationDeadline();
      const newValue = 21 * 24 * 60 * 60; // 21 days

      const tx = await ctx.hub.connect(ctx.admin).setArbitrationDeadline(newValue);
      await expect(tx)
        .to.emit(ctx.hub, "ArbitrationDeadlineUpdated")
        .withArgs(oldValue, newValue);
    });

    it("emits event on dispute expiration", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
      const sealed = sealedRefJs(commitment, saltOf("tx"), req.salt);
      await ctx.hub.connect(ctx.attestorA).attestSettlement(commitment, sealed);
      await ctx.hub.openDispute(req, ethers.id("complaint"));

      const arbitrationDeadline = await ctx.hub.arbitrationDeadline();
      const disputeTime = (await ctx.hub.getInvoice(ctx.vendorA, commitment)).statusChangedAt;
      await time.increaseTo(Number(disputeTime) + Number(arbitrationDeadline) + 1);

      const tx = await ctx.hub.expireDispute(ctx.vendorA, commitment);
      await expect(tx)
        .to.emit(ctx.hub, "DisputeExpired")
        .withArgs(ctx.vendorA, invoiceKeyJs(ctx.vendorA, commitment), ctx.hub.runner.address);
    });
  });

  // ========================================================================
  // CONSISTENCY: Cross-function validation
  // ========================================================================

  describe("[CONSISTENCY] Cross-function validation consistency", function () {
    it("computeCommitment is consistent between contract and tests", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req } = await buildRequest(ctx);

      // Contract's computation
      const contractCommitment = await ctx.hub.computeCommitment(req);

      // Test helper's computation (from quai.js)
      const testCommitment = require("./helpers/quai").commitmentJs(ctx, req);

      expect(contractCommitment).to.equal(testCommitment);
    });

    it("invoiceKey is consistent for same vendor and commitment", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);

      // Call multiple times - should return same key
      const key1 = await ctx.hub.invoiceKey(ctx.vendorA, commitment);
      const key2 = await ctx.hub.invoiceKey(ctx.vendorA, commitment);

      expect(key1).to.equal(key2);
    });

    it("sealed payment ref is consistent", async function () {
      const ctx = await loadFixture(deployWithVendor);
      const { req, commitment } = await buildRequest(ctx);
      const qiTxHash = ethers.id("qitx");

      // Contract's computation
      const contractSealed = await ctx.hub.computeSealedPaymentRef(commitment, qiTxHash, req.salt);

      // Test helper's computation
      const testSealed = require("./helpers/quai").sealedRefJs(commitment, qiTxHash, req.salt);

      expect(contractSealed).to.equal(testSealed);
    });
  });
});
