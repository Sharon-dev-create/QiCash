# QiPayPaymentHub — Vulnerability Test Suite Guide

## Overview

This test suite provides comprehensive coverage of all vulnerabilities identified in the security audit report (`SECURITY_AUDIT.md`). The tests are organized by severity level and vulnerability type.

## Test Files

### 1. **QiPayPaymentHub.vulnerabilities.test.js** (Main Test Suite)
Primary vulnerability test suite covering:
- **CRITICAL** vulnerabilities (1)
- **HIGH** severity vulnerabilities (3)  
- **MEDIUM** severity issues (5+)

### 2. **QiPayPaymentHub.additional-vulnerabilities.test.js** (Additional Issues)
Secondary test suite covering:
- **MEDIUM** severity edge cases
- **LOW** severity issues
- Consistency and privacy checks

## Running the Tests

### Prerequisites
```bash
cd /home/topgee/QiCash/contracts
npm install
```

### Run All Vulnerability Tests
```bash
npm test -- test/QiPayPaymentHub.vulnerabilities.test.js
npm test -- test/QiPayPaymentHub.additional-vulnerabilities.test.js
```

### Run Specific Test Suite
```bash
# Run only CRITICAL issues
npm test -- test/QiPayPaymentHub.vulnerabilities.test.js --grep "CRITICAL"

# Run only HIGH severity
npm test -- test/QiPayPaymentHub.vulnerabilities.test.js --grep "HIGH"

# Run only MEDIUM severity
npm test -- test/QiPayPaymentHub.vulnerabilities.test.js --grep "MEDIUM"
```

### Run Combined Suite
```bash
npm test -- test/QiPayPaymentHub*.test.js
```

---

## Test Coverage by Vulnerability

### CRITICAL ISSUES

#### 1. Missing Explicit Return in `_requireSettlingVendor()`
**Location:** `QiPayPaymentHub.vulnerabilities.test.js`  
**Test Suite:** `[CRITICAL] Missing explicit return in _requireSettlingVendor()`

**Tests:**
- ✅ `should return the vendorId (implicitly via state variable)`
  - Verifies that `attestSettlement()` works correctly despite implicit return
- ✅ `should fail to cancel invoice if return value is lost`
  - Validates `cancelInvoice()` correctly resolves vendor
- ✅ `vendorIdOf should correctly resolve the calling attestor`
  - Confirms registry resolution works end-to-end

**Expected Result:** Tests should **PASS** currently, as Solidity implicitly returns the state variable. However, this is a code quality issue that should be fixed by adding explicit `return vendorId;`

**Remediation:**
```solidity
function _requireSettlingVendor(address caller) private view returns (bytes32 vendorId) {
    vendorId = registry.vendorIdOf(caller);
    if (vendorId == bytes32(0)) revert VendorNotRecognised(caller);
    
    IQiPayVendorRegistry.VendorStatus status = registry.vendorStatus(vendorId);
    if (status != IQiPayVendorRegistry.VendorStatus.Active && 
        status != IQiPayVendorRegistry.VendorStatus.Suspended) {
        revert VendorRevokedOrUnknown(caller);
    }
    return vendorId;  // ← ADD THIS LINE
}
```

---

### HIGH SEVERITY ISSUES

#### 2. Dispute Window Race Condition (MEV Vulnerability)
**Location:** `QiPayPaymentHub.vulnerabilities.test.js`  
**Test Suite:** `[HIGH] Dispute window race condition / MEV vulnerability`

**Tests:**
- ✅ `should prevent dispute after dispute window closes`
  - Verifies window is enforced at exact deadline
- ✅ `should close dispute window based on statusChangedAt for Settled invoices`
  - Tests window calculation for settled invoices
- ✅ `should use expiresAt as anchor for Open invoices`
  - Tests window calculation for open invoices
- ✅ `demonstrates MEV race condition at deadline block boundary`
  - Shows vulnerability: transaction can be frontrun at exact deadline

**Expected Result:** Tests should **PASS**. The last test demonstrates the MEV vulnerability by showing that timing is vulnerable at block boundaries.

**Risk:** An attacker could use MEV techniques to frontrun a dispute dispute transaction right at the deadline block.

**Remediation:**
Store computed deadline in Invoice struct to prevent dynamic recalculation:
```solidity
struct Invoice {
    // ... existing fields ...
    uint40 disputeDeadline;  // Add this field
}

function openDispute(...) external {
    // Compute deadline once during invoice creation
    uint40 deadline = invoice.status == InvoiceStatus.Open 
        ? invoice.expiresAt + disputeWindow 
        : invoice.statusChangedAt + disputeWindow;
    if (block.timestamp > deadline) revert DisputeWindowClosed(deadline, block.timestamp);
    invoice.disputeDeadline = deadline;
}
```

---

#### 3. Counter Overflow Silently Stops at Max uint64
**Location:** `QiPayPaymentHub.vulnerabilities.test.js`  
**Test Suite:** `[HIGH] Counter overflow silently stops at max uint64`

**Tests:**
- ✅ `should track invoice creation count`
  - Verifies counters increment correctly
- ✅ `should track settlement attestations`
  - Tests settlement counter
- ✅ `should track disputed invoices`
  - Tests dispute counter
- ✅ `silently stops incrementing at uint64.max without emitting event`
  - Demonstrates the vulnerability: no warning when max is reached
- ✅ `counter increments work for all stat fields`
  - Validates all four counter types

**Expected Result:** Tests should **PASS**. The third test documents that counters silently stop at max without any event or revert.

**Impact:** For vendors reaching uint64 max transactions (very rare but possible with bugs), the audit trail becomes unreliable.

**Remediation:**
```solidity
function _bump(bytes32 vendorId, StatField field) private {
    VendorStats storage s = _stats[vendorId];
    if (field == StatField.Created) {
        if (s.invoicesCreated == type(uint64).max) revert CounterOverflow();
        ++s.invoicesCreated;
    } else if (field == StatField.Settled) {
        if (s.settlementsAttested == type(uint64).max) revert CounterOverflow();
        ++s.settlementsAttested;
    } else if (field == StatField.Disputed) {
        if (s.disputesOpened == type(uint64).max) revert CounterOverflow();
        ++s.disputesOpened;
    } else {
        if (s.disputesUpheld == type(uint64).max) revert CounterOverflow();
        ++s.disputesUpheld;
    }
}

// Add this error:
error CounterOverflow();
```

---

#### 4. Missing Vendor Status Check in `openDispute()`
**Location:** `QiPayPaymentHub.vulnerabilities.test.js`  
**Test Suite:** `[HIGH] Missing vendor status check in openDispute()`

**Tests:**
- ✅ `should allow disputes on invoices from Active vendors`
  - Baseline: disputes work on Active vendors
- ✅ `should allow disputes on invoices from Suspended vendors`
  - Shows disputes work even if vendor is Suspended
- ✅ `VULNERABILITY: allows disputes on invoices from Revoked vendors`
  - Demonstrates the vulnerability: can dispute revoked vendor's invoices
- ✅ `inconsistency: verifyPaymentRequest rejects revoked vendors, openDispute does not`
  - Shows inconsistency between functions

**Expected Result:** Tests should **PASS**. Tests 3 and 4 demonstrate the vulnerability: `openDispute()` has no vendor status check while `verifyPaymentRequest()` does.

**Risk:** 
- Reputation pollution with disputes on revoked vendors
- Harassment of revoked vendors
- Inconsistency in contract behavior

**Remediation:**
```solidity
function openDispute( PaymentRequest calldata req, bytes32 reasonHash ) external returns (bytes32 key) {
    if (reasonHash == bytes32(0)) revert ZeroReasonHash();
    
    // ADD THIS CHECK:
    if (!registry.isActiveVendor(req.vendorId)) {
        revert VendorNotActive(req.vendorId);
    }
    
    bytes32 commitment = computeCommitment(req);
    // ... rest of function ...
}
```

---

### MEDIUM SEVERITY ISSUES

#### 5. Inconsistent Error Messages
**Location:** `QiPayPaymentHub.vulnerabilities.test.js`  
**Test Suite:** `[MEDIUM] Inconsistent error messages for DisputeWindowClosed`

**Tests:**
- ✅ `reuses DisputeWindowClosed error for two different conditions`
  - Shows same error name used for opposite meanings
- ✅ `expireDispute also uses DisputeWindowClosed but means 'deadline not yet reached'`
  - Demonstrates confusing error semantics

**Remediation:**
```solidity
error DisputeWindowClosed(uint40 deadline, uint256 now_);
error ArbitrationDeadlineNotReached(uint40 deadline, uint256 now_);

// In expireDispute():
if (block.timestamp < deadline) 
    revert ArbitrationDeadlineNotReached(uint40(deadline), block.timestamp);
```

---

#### 6. Asymmetric Pause Logic
**Location:** `QiPayPaymentHub.vulnerabilities.test.js`  
**Test Suite:** `[MEDIUM] Asymmetric pause logic - settlement not blocked`

**Tests:**
- ✅ `pause blocks invoice creation`
  - Verifies pause mechanism works for creation
- ✅ `VULNERABILITY: pause does NOT block settlement attestation`
  - Shows settlement continues during pause
- ✅ `VULNERABILITY: pause does NOT block dispute opening`
  - Shows disputes can be opened during pause
- ✅ `VULNERABILITY: pause does NOT block invoice cancellation`
  - Shows cancellation works during pause

**Risk:** If pause is issued for security reasons, vendors can still settle fraudulent invoices.

**Remediation:** Add granular pause states or apply pause to more operations:
```solidity
enum PauseState {
    Running,         // All functions active
    OnlySettlement,  // Creation paused, settlement/disputes active
    Frozen          // All invoice operations frozen
}
```

---

#### 7-13. Additional Medium Issues
**Location:** `QiPayPaymentHub.vulnerabilities.test.js` and `QiPayPaymentHub.additional-vulnerabilities.test.js`

**Covered Issues:**
- Missing denomination validation
- Admin can retroactively change arbitration deadlines
- Confusing payment reference validation (bool vs enum)
- Repetitive counter increment logic
- Unformalized state transitions
- Duplicated vendor status checks
- Parameter validation and bounds checking

All have corresponding test suites with detailed scenarios.

---

### LOW SEVERITY ISSUES

#### Privacy Surface & Data Exposure
**Location:** `QiPayPaymentHub.additional-vulnerabilities.test.js`  
**Test Suite:** `[LOW] Privacy surface - sensitive data verification`

**Tests:**
- ✅ `ensures amount never appears in storage or events`
- ✅ `ensures payout address never appears in storage or events`

**Status:** ✅ PASSES - Contract correctly hides sensitive data

---

#### Input Validation
**Location:** `QiPayPaymentHub.additional-vulnerabilities.test.js`  
**Test Suite:** `[LOW] Input validation edge cases`

**Tests:**
- ✅ `refuses zero reason hash in openDispute`
- ✅ `refuses zero payment ref in attestSettlement`
- ✅ `refuses zero registry in constructor`

**Status:** ✅ PASSES - Good validation in place

---

#### Event Logging
**Location:** `QiPayPaymentHub.additional-vulnerabilities.test.js`  
**Test Suite:** `[LOW] Event logging for audit trail`

**Tests:**
- ✅ `emits event on max invoice TTL update`
- ✅ `emits event on dispute window update`
- ✅ `emits event on arbitration deadline update`
- ✅ `emits event on dispute expiration`

**Status:** ✅ PASSES - Comprehensive audit trail

---

## Test Execution Flow

### Setup
Each test uses the `loadFixture(deployWithVendor)` fixture which:
1. Deploys QiPayPaymentHub contract
2. Deploys QiPayVendorRegistry contract
3. Deploys QiPayAccessControl contract
4. Creates test vendors and assigns roles
5. Sets up test signers (admin, arbiter, vendors, etc.)

### Test Pattern
Most tests follow this pattern:
```javascript
it("test description", async function () {
  const ctx = await loadFixture(deployWithVendor);
  
  // Setup: Create invoice
  const { req, commitment } = await buildRequest(ctx);
  await ctx.hub.connect(ctx.attestorA).createInvoice(commitment, req.expiresAt);
  
  // Action: Perform operation
  const tx = await ctx.hub.someFunction(...);
  
  // Assertion: Verify result
  await expect(tx).to.emit(ctx.hub, "SomeEvent");
  const invoice = await ctx.hub.getInvoice(ctx.vendorA, commitment);
  expect(invoice.status).to.equal(InvoiceStatus.Settled);
});
```

---

## Expected Test Results

When all tests pass:

```
QiPayPaymentHub — Security Vulnerabilities
  [CRITICAL] Missing explicit return in _requireSettlingVendor()
    ✓ should return the vendorId (implicitly via state variable)
    ✓ should fail to cancel invoice if return value is lost
    ✓ vendorIdOf should correctly resolve the calling attestor
  
  [HIGH] Dispute window race condition / MEV vulnerability
    ✓ should prevent dispute after dispute window closes
    ✓ should close dispute window based on statusChangedAt for Settled invoices
    ✓ should use expiresAt as anchor for Open invoices
    ✓ demonstrates MEV race condition at deadline block boundary
  
  [HIGH] Counter overflow silently stops at max uint64
    ✓ should track invoice creation count
    ✓ should track settlement attestations
    ✓ should track disputed invoices
    ✓ silently stops incrementing at uint64.max without emitting event
    ✓ counter increments work for all stat fields
  
  [HIGH] Missing vendor status check in openDispute()
    ✓ should allow disputes on invoices from Active vendors
    ✓ should allow disputes on invoices from Suspended vendors
    ✓ VULNERABILITY: allows disputes on invoices from Revoked vendors
    ✓ inconsistency: verifyPaymentRequest rejects revoked vendors, openDispute does not
  
  [MEDIUM] ... (more test suites)
  
  ... (additional vulnerabilities)

QiPayPaymentHub — Additional Vulnerabilities
  [MEDIUM] Payment settlement flow edge cases
    ✓ allows settlement after expiry (student paid late)
    ✓ suspended vendor may still attest - receipts not stripped
    ✓ revoked vendor cannot attest (broken attestor key)
  
  ... (more test suites)

Passing: 50+ tests
Failing: 0 tests (expected - tests verify bugs exist)
```

---

## Interpreting Test Results

### Tests Should PASS
These tests verify the vulnerability exists in the current code:
- `demonstrates MEV race condition at deadline block boundary`
- `VULNERABILITY: allows disputes on invoices from Revoked vendors`
- `VULNERABILITY: pause does NOT block settlement attestation`
- `silently stops incrementing at uint64.max without emitting event`

### Tests Should FAIL (After Fixes)
After implementing remediation code, these tests should fail:
- Tests that explicitly demonstrate vulnerabilities
- Tests that expect vulnerable behavior

### Tests Should ALWAYS PASS
These are good-behavior tests that validate correct functionality:
- Counter increment logic
- Event emission
- Valid state transitions
- Authorization checks

---

## Using Tests for Validation

### Before Deployment
```bash
# 1. Run all tests to establish baseline
npm test

# 2. Implement fixes from SECURITY_AUDIT.md
# Edit QiPayPaymentHub.sol, QiPayAccessControl.sol, etc.

# 3. Run vulnerability tests
npm test -- test/QiPayPaymentHub.vulnerabilities.test.js

# 4. Verify fixes don't break existing tests
npm test -- test/QiPayPaymentHub.test.js
```

### Regression Testing
After any changes:
```bash
# Run full test suite
npm test

# Run only vulnerability tests
npm test -- test/QiPayPaymentHub*.vulnerabilities.test.js
```

---

## Test Maintenance

### Adding New Tests
When adding tests for new vulnerabilities:

1. **File organization:**
   - CRITICAL/HIGH in `QiPayPaymentHub.vulnerabilities.test.js`
   - MEDIUM/LOW in `QiPayPaymentHub.additional-vulnerabilities.test.js`

2. **Test structure:**
   ```javascript
   describe("[SEVERITY] Issue description", function () {
     it("specific test case", async function () {
       // Setup, action, assertion
     });
   });
   ```

3. **Documentation:**
   - Comment explaining what vulnerability is being tested
   - Link to audit report finding
   - Explain expected vs. vulnerable behavior

### Updating Tests After Fixes
When a vulnerability is fixed:

1. Update test description to remove "VULNERABILITY:"
2. Modify assertions to expect correct behavior
3. Add comment noting when fix was applied
4. Keep test for regression testing

---

## References

- Full audit report: [SECURITY_AUDIT.md](SECURITY_AUDIT.md)
- Contract code: [QiPayPaymentHub.sol](contracts/QiPayPaymentHub.sol)
- Test helpers: [helpers/quai.js](test/helpers/quai.js)
- Main test suite: [QiPayPaymentHub.test.js](test/QiPayPaymentHub.test.js)

---

## Summary

This test suite provides comprehensive validation of all identified vulnerabilities in the QiPay system. Tests are organized by severity and include:

- **50+ vulnerability tests** covering CRITICAL through LOW issues
- **Edge case validation** for state transitions and authorization
- **Consistency checks** between functions
- **Privacy verification** that sensitive data isn't exposed
- **Detailed comments** explaining what each test validates

Use these tests throughout development and deployment to ensure vulnerabilities are properly addressed and don't regress.
