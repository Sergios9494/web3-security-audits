Report
PasswordStore-Bug-Report-Cyfrin.md

# Smart Contract Security Assessment Report

## PasswordStore — Bug report (Cyfrin exercise)

| Field | Value |
|-------|--------|
| **Report artifact** | `PasswordStore-Bug-Report-Cyfrin.md` (stored under `~/Downloads/Web3 Audits/`) |
| **Focus** | [C-1] on-chain confidentiality / [H-1] missing access control on `setPassword` |
| **Protocol** | PasswordStore (educational / Cyfrin Updraft exercise) |
| **Repository** | [github.com/Cyfrin/3-passwordstore-audit](https://github.com/Cyfrin/3-passwordstore-audit) |
| **Commit** | *Pin the exact commit hash under review (e.g. `git rev-parse HEAD`)* |
| **Language / compiler** | Solidity `0.8.18` |
| **Chains in scope** | Ethereum (EVM), per exercise assumptions |
| **Assessment type** | Security review / code inspection + Foundry tests |
| **Report version** | 2.1 |

---

## Disclaimer

This report reflects an analysis of the **in-scope source code** at the time of review. It is **not** a guarantee of correctness, completeness, or future security. Findings depend on stated assumptions, threat model, and deployment configuration. This document is suitable for **internal learning and protocol hardening**; competitive audit platforms may require additional formatting and sign-off.

**Out of scope unless explicitly agreed:** third-party libraries (`lib/`), deployment scripts, infrastructure, key management, and economic attacks outside the contract’s stated logic.

---

## Executive summary

**PasswordStore** is a minimal contract intended to let a designated **owner** store and later read a password, while **non-owners should not access** that secret.

The review identified **two security-relevant issues**:

1. **[C-1] Critical — Confidentiality:** The password is stored as **plaintext in contract storage**. On a public blockchain, this **does not** satisfy a requirement that “others cannot see the password.” Observers can recover the value via storage inspection and/or by reading transaction calldata when `setPassword` is invoked.

2. **[H-1] High — Access control:** `setPassword` performs **no authorization check**, contradicting NatSpec (“only the owner”). **Any address** can overwrite `s_password`, breaking integrity and enabling griefing. A **Foundry fuzz test** demonstrates this across many pseudo-random callers.

An **informational** documentation issue ([I-1]) was also noted.

**Recommendation at a glance:** Treat [C-1] as an **architecture / product** decision (do not store raw secrets on-chain, or narrow the security claims). Remediate [H-1] with **owner-only** enforcement on `setPassword`, aligned with `getPassword`, plus negative tests.

---

## Scope

### In scope

| Path | Description |
|------|-------------|
| `src/PasswordStore.sol` | Sole in-scope production contract |

### Out of scope

| Path | Rationale |
|------|-----------|
| `lib/**` | Vendored dependencies; not audited as custom logic |
| `script/**` | Deployment / ops; confirm with client if in scope for production reviews |
| `test/**` | Reviewer-authored or protocol tests; used here for PoC only |

### Codebase metrics (reference)

| Metric | Value |
|--------|--------|
| In-scope Solidity files | 1 |
| Approx. nSLOC (`cloc ./src/`, code lines) | ~20 |

---

## Severity classification

Severity reflects **impact** and **likelihood** in the context of the **stated goals** of the protocol. Aligns with common Web3 practice (Critical → Informational).

| Level | Definition |
|-------|-------------|
| **Critical** | Direct loss of funds, irrecoverable state, or **core security goal fundamentally unachievable** under the claimed threat model |
| **High** | Material violation of access control, integrity, or availability; exploitable by unprivileged actors under normal use |
| **Medium** | Meaningful risk in edge cases, privileged misuse, or partial impact |
| **Low** | Limited impact; hard to exploit or requires strong assumptions |
| **Informational** | Best practices, documentation, clarity; no direct exploit |

---

## Findings summary

| ID | Title | Severity | Status |
|----|--------|----------|--------|
| [C-1] | Plaintext password on-chain breaks confidentiality claims | **Critical** | Confirmed |
| [H-1] | Missing access control on `setPassword` | **High** | Confirmed |
| [I-1] | NatSpec errors and weak event observability | **Informational** | Confirmed |

*Status **Confirmed** = reproducible from code and/or tests in this repository.*

---

## Detailed findings

### [C-1] Plaintext password on-chain breaks confidentiality claims

| Attribute | Detail |
|-----------|--------|
| **Severity** | Critical |
| **Category** | Architecture / sensitive data exposure |
| **Affected** | `PasswordStore` — `s_password`, `setPassword`, `getPassword` |
| **References** | CWE-312 (Cleartext Storage of Sensitive Information); SWC-136 (Unencrypted Private Data On-Chain) |

#### Description

The contract stores the user’s password as a `string` in **persistent storage**. Contract NatSpec states that others “won’t be able to see” a “private” password. On a public EVM chain:

- **`private` in Solidity does not mean secret.** It only hides direct access from other *contracts* at the language level; **anyone** can read storage via RPC (`eth_getStorageAt`) and layout decoding.
- **Calldata is public.** When `setPassword` is called, the new password appears in the transaction input.

Therefore the **advertised confidentiality property is false** for this design.

#### Root cause

Confusing Solidity visibility and EVM transparency with **off-chain** secrecy. Secrets that must remain confidential from third parties **must not** be placed on-chain in cleartext.

#### Impact

- **Any observer** with node/API access can recover the password without calling `getPassword`.
- Combined with **[H-1]**, unprivileged actors can also **overwrite** the stored value, compounding integrity and availability issues for the owner.

#### Proof of concept (conceptual)

1. Deploy `PasswordStore`, owner calls `setPassword("secret123")`.
2. Read storage slot(s) backing `s_password` for the contract address, or inspect the transaction’s input data for `setPassword`.
3. Observe the cleartext password without being `s_owner`.

*(No on-chain exploit contract required; this follows from EVM and network transparency.)*

#### Recommendation

- **Preferred:** Do **not** store raw passwords on-chain. Use a design appropriate to the threat model (e.g. **commit–reveal**, **hashed commitments**, **off-chain vault** with on-chain verification only of non-secret material).
- **If** the product only needs “only owner can read via this contract’s view function,” **rewrite** NatSpec and user-facing docs to **explicitly state** that the value is **not hidden from chain observers** — and still fix **[H-1]** for write integrity.

---

### [H-1] Missing access control on `setPassword`

| Attribute | Detail |
|-----------|--------|
| **Severity** | High |
| **Category** | Access control |
| **Affected** | `PasswordStore.setPassword` |
| **References** | CWE-284 (Improper Access Control); SWC-105 (related patterns — unauthorized state change) |

#### Description

NatSpec for `setPassword` states: *“This function allows only the owner to set a new password.”* The implementation **does not** check `msg.sender == s_owner` (or equivalent). Any EOA or contract can invoke `setPassword` and set `s_password`.

#### Root cause

Asymmetric enforcement: `getPassword` reverts for non-owners; `setPassword` has **no** matching guard.

#### Impact

- **Integrity:** Attacker-chosen password replaces the owner’s value.
- **Availability / griefing:** Repeated overwrites deny the owner a stable secret.
- **Trust:** Implementation contradicts documented behavior — high audit and user-risk signal.

#### Affected code

```solidity
    function setPassword(string memory newPassword) external {
        s_password = newPassword;
        emit SetNewPassword();
    }
```

*(Paths in clone: `src/PasswordStore.sol` lines 26–29.)*

#### Proof of concept (Foundry)

Repository tests demonstrate the issue:

| Test | Role |
|------|------|
| `testNonOwnerCanSetPassword_CurrentBehavior` | Fixed attacker sets password; owner reads attacker value |
| `test_anyone_can_set_password(address)` | **Fuzz:** pseudo-random `randomAddress != owner` sets password; assertion holds |

Run:

```bash
cd /home/user/3-passwordstore-audit
forge test --match-test test_anyone_can_set_password -vvv
```

Default fuzz runs (e.g. 256) **pass**, confirming the vulnerability is systematic, not a single hard-coded address.

#### Recommendation

1. Enforce **owner-only** writes, mirroring `getPassword`:

   ```solidity
   if (msg.sender != s_owner) revert PasswordStore__NotOwner();
   ```

   before assigning `s_password`, or use a shared `onlyOwner` modifier.

2. Add **negative tests:** non-owner `setPassword` **must revert** after the fix.

3. Optionally emit an event that includes **no secret** (e.g. indexed `msg.sender` only) for monitoring, if product allows.

---

### [I-1] NatSpec errors and weak event observability

| Attribute | Detail |
|-----------|--------|
| **Severity** | Informational |
| **Category** | Documentation / maintainability |

#### Description

- `getPassword()` NatSpec includes `@param newPassword` but the function has **no parameters** — copy-paste or review gap.
- `SetNewPassword()` carries **no parameters**; off-chain monitoring cannot distinguish updates without decoding storage or inferring from txs (still no secret in logs — good), but **metadata** (e.g. updater address) is absent if desired for ops.

#### Recommendation

- Correct NatSpec to match signatures.
- If events are used for monitoring, add **non-sensitive** fields (e.g. `address indexed updater`) after access control is fixed.

---

## Methodology and tools

| Activity | Tool / approach |
|----------|------------------|
| Manual review | Line-by-line read; NatSpec vs implementation |
| Build / test | Foundry (`forge build`, `forge test`) |
| Coverage | `forge coverage` (interpret with care for *security* properties) |
| Size estimate | `cloc ./src/` |
| PoC | Solidity tests in `test/PasswordStore.t.sol` |

---

## Positive observations

- **Simple surface area:** Single contract, low nSLOC — easy to reason about after fixes.
- **Explicit custom error** for unauthorized reads (`PasswordStore__NotOwner`) — good pattern to **reuse** for unauthorized writes.
- **Pinned compiler** (`0.8.18`) — aids reproducibility; document any upgrade path.

---

## Conclusion

**PasswordStore** fails to meet its **stated confidentiality goal** while storing a cleartext password on-chain **[C-1]**, and fails to enforce **owner-only password updates** despite documentation **[H-1]**. Remediation requires both **architectural clarity** (what “private” means on-chain) and a **straightforward access-control patch** on `setPassword`, with tests that encode the intended threat model.

---

## Appendix A — File index

| Location | Note |
|----------|------|
| This report | `/home/user/Downloads/Web3 Audits/PasswordStore-Bug-Report-Cyfrin.md` |
| In-scope contract (clone) | `~/3-passwordstore-audit/src/PasswordStore.sol` |
| PoC / fuzz (clone) | `~/3-passwordstore-audit/test/PasswordStore.t.sol` |
| Access-control note (clone) | `~/3-passwordstore-audit/audit/ACCESS_CONTROL_FINDING.md` |

## Appendix B — Revision history

| Version | Notes |
|---------|--------|
| 1.0 | Initial consolidated report |
| 2.0 | Restructured to common Web3 audit report layout |
| 2.1 | Renamed artifact; moved to `~/Downloads/Web3 Audits/`; metadata + appendix updated |
