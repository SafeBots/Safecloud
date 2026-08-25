// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
*********************************************
OFFICIAL OPENCLAIMING PROTOCOL IMPLEMENTATION
*********************************************

Although this code is available for viewing on GitHub and here, the general public is NOT given a license to freely deploy smart contracts based on this code, on any blockchains.
To prevent confusion and increase trust in the audited code bases of smart contracts we produce, we intend for there to be only ONE official Factory address on the blockchain producing the corresponding smart contracts, and we are going to point a blockchain domain name at it.
Copyright (c) Intercoin Inc. All rights reserved.

ALLOWED USAGE.
Provided they agree to all the conditions of this Agreement listed below, anyone is welcome to interact with the official Factory Contract at the this address to produce smart contract instances, or to interact with instances produced in this manner by others.
Any user of software powered by this code MUST agree to the following, in order to use it. If you do not agree, refrain from using the software:

DISCLAIMERS AND DISCLOSURES.
Customer expressly recognizes that nearly any software may contain unforeseen bugs or other defects, due to the nature of software development. Moreover, because of the immutable nature of smart contracts, any such defects will persist in the software once it is deployed onto the blockchain. Customer therefore expressly acknowledges that any responsibility to obtain outside audits and analysis of any software produced by Developer rests solely with Customer.
Customer understands and acknowledges that the Software is being delivered as-is, and may contain potential defects. While Developer and its staff and partners have exercised care and best efforts in an attempt to produce solid, working software products, Developer EXPRESSLY DISCLAIMS MAKING ANY GUARANTEES, REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, ABOUT THE FITNESS OF THE SOFTWARE, INCLUDING LACK OF DEFECTS, MERCHANTABILITY OR SUITABILITY FOR A PARTICULAR PURPOSE.
Customer agrees that neither Developer nor any other party has made any representations or warranties, nor has the Customer relied on any representations or warranties, express or implied, including any implied warranty of merchantability or fitness for any particular purpose with respect to the Software. Customer acknowledges that no affirmation of fact or statement (whether written or oral) made by Developer, its representatives, or any other party outside of this Agreement with respect to the Software shall be deemed to create any express or implied warranty on the part of Developer or its representatives.

INDEMNIFICATION.
Customer agrees to indemnify, defend and hold Developer and its officers, directors, employees, agents and contractors harmless from any loss, cost, expense (including attorney's fees and expenses), associated with or related to any demand, claim, liability, damages or cause of action of any kind or character (collectively referred to as "claim"), in any manner arising out of or relating to any third party demand, dispute, mediation, arbitration, litigation, or any violation or breach of any provision of this Agreement by Customer.
NO WARRANTY.
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY. DEVELOPER SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL, CONSEQUENTIAL, OR EXEMPLARY DAMAGES FOR BREACH OF THE LIMITED WARRANTY. TO THE MAXIMUM EXTENT PERMITTED BY LAW, DEVELOPER EXPRESSLY DISCLAIMS, AND CUSTOMER EXPRESSLY WAIVES, ALL OTHER WARRANTIES, WHETHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING WITHOUT LIMITATION ALL IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR USE, OR ANY WARRANTY ARISING OUT OF ANY PROPOSAL, SPECIFICATION, OR SAMPLE, AS WELL AS ANY WARRANTIES THAT THE SOFTWARE (OR ANY ELEMENTS THEREOF) WILL ACHIEVE A PARTICULAR RESULT, OR WILL BE UNINTERRUPTED OR ERROR-FREE. THE TERM OF ANY IMPLIED WARRANTIES THAT CANNOT BE DISCLAIMED UNDER APPLICABLE LAW SHALL BE LIMITED TO THE DURATION OF THE FOREGOING EXPRESS WARRANTY PERIOD. SOME STATES DO NOT ALLOW THE EXCLUSION OF IMPLIED WARRANTIES AND/OR DO NOT ALLOW LIMITATIONS ON THE AMOUNT OF TIME AN IMPLIED WARRANTY LASTS, SO THE ABOVE LIMITATIONS MAY NOT APPLY TO CUSTOMER. THIS LIMITED WARRANTY GIVES CUSTOMER SPECIFIC LEGAL RIGHTS. CUSTOMER MAY HAVE OTHER RIGHTS WHICH VARY FROM STATE TO STATE.

LIMITATION OF LIABILITY.
TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL DEVELOPER BE LIABLE UNDER ANY THEORY OF LIABILITY FOR ANY CONSEQUENTIAL, INDIRECT, INCIDENTAL, SPECIAL, PUNITIVE OR EXEMPLARY DAMAGES OF ANY KIND, INCLUDING, WITHOUT LIMITATION, DAMAGES ARISING FROM LOSS OF PROFITS, REVENUE, DATA OR USE, OR FROM INTERRUPTED COMMUNICATIONS OR DAMAGED DATA, OR FROM ANY DEFECT OR ERROR OR IN CONNECTION WITH CUSTOMER'S ACQUISITION OF SUBSTITUTE GOODS OR SERVICES OR MALFUNCTION OF THE SOFTWARE, OR ANY SUCH DAMAGES ARISING FROM BREACH OF CONTRACT OR WARRANTY OR FROM NEGLIGENCE OR STRICT LIABILITY, EVEN IF DEVELOPER OR ANY OTHER PERSON HAS BEEN ADVISED OR SHOULD KNOW OF THE POSSIBILITY OF SUCH DAMAGES, AND NOTWITHSTANDING THE FAILURE OF ANY REMEDY TO ACHIEVE ITS INTENDED PURPOSE. WITHOUT LIMITING THE FOREGOING OR ANY OTHER LIMITATION OF LIABILITY HEREIN, REGARDLESS OF THE FORM OF ACTION, WHETHER FOR BREACH OF CONTRACT, WARRANTY, NEGLIGENCE, STRICT LIABILITY IN TORT OR OTHERWISE, CUSTOMER'S EXCLUSIVE REMEDY AND THE TOTAL LIABILITY OF DEVELOPER OR ANY SUPPLIER OF SERVICES TO DEVELOPER FOR ANY CLAIMS ARISING IN ANY WAY IN CONNECTION WITH OR RELATED TO THIS AGREEMENT, THE SOFTWARE, FOR ANY CAUSE WHATSOEVER, SHALL NOT EXCEED 1,000 USD.

TRADEMARKS.
This Agreement does not grant you any right in any trademark or logo of Developer or its affiliates.

LINK REQUIREMENTS.
Operators of any Websites and Apps which make use of smart contracts based on this code must conspicuously include the following phrase in their website, featuring a clickable link that takes users to intercoin.app:
"Visit https://intercoin.app to launch your own NFTs, DAOs and other Web3 solutions."

STAKING OR SPENDING REQUIREMENTS.
In the future, Developer may begin requiring staking or spending of Intercoin tokens in order to take further actions (such as producing series and minting tokens). Any staking or spending requirements will first be announced on Developer's website (intercoin.org) four weeks in advance. Staking requirements will not apply to any actions already taken before they are put in place.

CUSTOM ARRANGEMENTS.
Reach out to us at intercoin.org if you are looking to obtain Intercoin tokens in bulk, remove link requirements forever, remove staking requirements forever, or get custom work done with your Web3 projects.

ENTIRE AGREEMENT
This Agreement contains the entire agreement and understanding among the parties hereto with respect to the subject matter hereof, and supersedes all prior and contemporaneous agreements, understandings, inducements and conditions, express or implied, oral or written, of any nature whatsoever with respect to the subject matter hereof. The express terms hereof control and supersede any course of performance and/or usage of the trade inconsistent with any of the terms hereof. Provisions from previous Agreements executed between Customer and Developer., which are not expressly dealt with in this Agreement, will remain in effect.

SUCCESSORS AND ASSIGNS
This Agreement shall continue to apply to any successors or assigns of either party, or any corporation or other entity acquiring all or substantially all the assets and business of either party whether by operation of law or otherwise.

ARBITRATION
All disputes related to this agreement shall be governed by and interpreted in accordance with the laws of New York, without regard to principles of conflict of laws. The parties to this agreement will submit all disputes arising under this agreement to arbitration in New York City, New York before a single arbitrator of the American Arbitration Association ("AAA"). The arbitrator shall be selected by application of the rules of the AAA, or by mutual agreement of the parties, except that such arbitrator shall be an attorney admitted to practice law New York. No party to this agreement will challenge the jurisdiction or venue provisions as provided in this section. No party to this agreement will challenge the jurisdiction or venue provisions as provided in this section.
**/

/**
 * @title OpenClaiming
 * @author Intercoin Inc.
 * @notice Canonical EIP-712 verifier and execution layer for the OpenClaiming
 *         Protocol. Two standard extensions: payments and actions.
 *
 * @dev Self-contained: no imports, no external dependencies, not upgradeable.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PAYMENTS EXTENSION
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * 1. SIGNED STRUCT. The payer signs an EIP-712 Payment off-chain; anyone may
 *    present it; the contract verifies the signature, enforces the channel
 *    ceiling, and moves the payer's own tokens to committed recipients.
 *    recipientsHash is third; the verifying `contract` address is an
 *    explicit signed field (visible in wallet UIs, validated ==
 *    address(this)):
 *
 *      Payment(address payer, address token, bytes32 recipientsHash,
 *              uint256 max, uint256 line, uint256 nbf, uint256 exp,
 *              address contract, bytes32 policyHash)
 *
 *    Domain: { name: "OpenClaiming", version: "1", chainId, verifyingContract }
 *
 * 2. SIGNED POLICIES (policyHash != 0). The payer commits to a distribution
 *    Policy — static payees with basis-point fractions, per-payee hook
 *    targets, and one constrained dynamic-payee slot the claimant fills at
 *    execution time. The rail itself splits every settlement atomically:
 *    nobody can collect their share without every other committed party
 *    being paid in the same transaction. Fractions are enforced IN the
 *    contract; targets are PINNED by the signature. policyHash == 0 gives
 *    single-recipient behavior (claimant picks one member of the signed
 *    set and an amount).
 *
 * 3. HOOK TARGETS (custody / lockups). A policy may route any payee's share
 *    through a target contract: the rail transfers the share TO the target,
 *    then calls target.pay(payee, share). Compatible with IncomeContract
 *    (owner calls addManager(payee, <this rail>) once) and with any custom
 *    custody contract implementing pay(address,uint256). Use case: an
 *    author's revenue lands in a vesting contract with gradual unlock, so
 *    the author cannot cycle payments through their own content and respend
 *    immediately. The rail never grants pull rights against itself — funds
 *    move outward only, then the target is notified. (Deliberate decision:
 *    a transient "transferFrom-back" allowance was considered and rejected;
 *    transfer-then-notify covers custody with strictly less attack surface.)
 *
 * 4. PUBLIC REDEMPTION LEDGERS. Anyone can read who redeemed what without
 *    parsing logs:
 *        redeemed[token][payer][recipient]  — cumulative payer→recipient
 *        receivedTotal[token][recipient]    — cumulative recipient inflow
 *        lines[payer][line]                 — {max, spent, open, closed}
 *
 * 5. IMPLICIT LINE OPENING. A valid payer signature naming line >= 1 is
 *    itself consent for that line to exist: never-opened lines auto-open on
 *    first execution (max = 0, unlimited at line level; the claim max still
 *    governs). Gasless payers and transient counterparties need no lineOpen
 *    transaction. Lines explicitly closed via lineClose() stay closed until
 *    reopened — auto-open never overrides an owner's revocation.
 *
 * 6. lineAvailable() subtracts spent on every line including the default
 *    line, matching execution-path accounting exactly.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SETTLEMENT SEMANTICS (unchanged foundations)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Lines are cumulative watermark channels: lines[payer][line].spent grows
 * monotonically and every claim's max is checked against it. Claims are
 * monotonic vouchers; only the latest (highest-max) claim per channel is
 * live. Funding is allowance-based: token.transferFrom(payer → destination),
 * so payers approve this contract once (use an EIP-2612 permit token to keep
 * fresh addresses gasless — bundle permit + execute in one transaction).
 * Execution is permissionless. Under a policy, a partial settlement of any
 * amount splits proportionally by the signed fractions.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SECURITY MODEL
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * - The rail holds NOTHING. Every wei moves payer→destination under the
 *   payer's own allowance, gated by the payer's own signature. There is no
 *   custodied balance to drain and no ambient authority to confuse.
 * - Checks-Effects-Interactions: line spent and both public ledgers are
 *   updated before any external call.
 * - nonReentrant on every state-changing entrypoint (own two-slot guard).
 * - Policy settlements are ATOMIC: if any payee's transfer or hook call
 *   fails, the entire settlement reverts (no partial splits, no accrual —
 *   the rail cannot accrue what it never holds). A broken hook makes that
 *   policy unsettleable, harming only parties to that policy; claimants
 *   should eth_call-simulate before serving.
 * - Signatures: 65-byte r||s||v, low-s enforced (EIP-2), v normalized,
 *   ecrecover zero-address rejected.
 * - The signed `contract` field must equal address(this) — belt on top of
 *   the domain separator's verifyingContract.
 * - Native coin (token == address(0)) is supported only on the non-policy
 *   path and only payer-submitted. Policies are ERC-20 only.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ACTIONS EXTENSION
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The second protocol extension authorizes ControlContract.invoke()+endorse()
 * governance flows via off-chain multisignature. Signers sign a shared Action
 * digest; the rail verifies, dedups, and either calls directly (direct path,
 * invoker == 0, rail must hold the roles) or EIP-2771-forwards each signer's
 * identity (forwarded path, invoker != 0, rail must be a TrustedForwarder).
 * Payments never forward payer identity (a random counterparty), but actions
 * DO forward signer identity (governance members whose on-chain roles must
 * resolve) — the two extensions have deliberately different forwarding rules.
 */

/// @dev ControlContract interface matching the deployed contract. invoke()
///      takes 3 params (minimum/fraction/delay are stored per-method via
///      addMethod, not passed). For the direct path the rail must hold the
///      invoke+endorse roles in the Community; for the forwarded path the
///      ControlContract must register the rail as TrustedForwarder.
interface IControlContract {
    function invoke(
        address contractAddress,
        string  calldata method,
        string  calldata params
    ) external returns (uint256 invokeID, uint40 invokeIDWei);
    function endorse(uint256 invokeID) external;
}

contract OpenClaiming {

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    error InvalidSignature();
    error InvalidSignatureLength();
    error InvalidSignatureV();
    error InvalidSignatureS();
    error NotYetValid(uint256 nbf);
    error Expired(uint256 exp);
    error WrongContract(address expected, address actual);
    error UnauthorizedLineOperator(address account, address caller);
    error LineClosed(address account, uint256 line);
    error PaymentRecipientsHashMismatch();
    error InvalidRecipient(address recipient);
    error InsufficientCapacity(uint256 requested, uint256 available);
    error PayerMismatch(address expected, address actual);
    error NativeCoinDelegationUnsupported();
    error NativeCoinValueMismatch(uint256 expected, uint256 actual);
    error NativeCoinPolicyUnsupported();
    error TransferFailed();
    error HookCallFailed(address target);
    error PolicyHashMismatch();
    error PolicyInvalid();
    error DynamicPayeeInvalid(address supplied);
    error Reentrancy();
    // actions
    error InvokerNotInSigners();
    error InvalidSignerCount();
    error ParamsHashMismatch();

    // ─────────────────────────────────────────────────────────────────────────
    // EIP-712 constants
    // ─────────────────────────────────────────────────────────────────────────

    bytes32 public constant VERSION_HASH = keccak256(bytes("1"));

    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev Single protocol domain (per original design), not per-extension.
    bytes32 public constant NAME_HASH = keccak256(bytes("OpenClaiming"));

    /// @dev Nine fields. Note the field literally named "contract" in the
    ///      type string — Solidity cannot use that as a struct member name,
    ///      so the struct calls it contractAddr; the ENCODING ORDER is what
    ///      the hash binds, and it matches this string exactly.
    /// @dev 8-field struct — matches the original protocol design exactly.
    ///      recipientsHash carries EITHER keccak(abi.encode(address[])) for
    ///      plain payments OR keccak(abi.encode(Policy)) for policy payments.
    ///      The two shapes can never collide (different abi.encode prefixes).
    bytes32 public constant PAYMENTS_TYPEHASH = keccak256(
        "Payment(address payer,address token,bytes32 recipientsHash,uint256 max,uint256 line,uint256 nbf,uint256 exp,address contract)"
    );

    /// @dev Actions uses the SAME single protocol domain (NAME_HASH) as
    ///      payments, per the original design — not a per-extension domain.
    bytes32 public constant ACTIONS_TYPEHASH = keccak256(
        "Action(address authority,address subject,address contractAddress,bytes4 method,bytes32 paramsHash,uint256 minimum,uint256 fraction,uint256 delay,address invoker,uint256 nbf,uint256 exp)"
    );

    uint256 internal constant SECP256K1N_OVER_2 =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    // ─────────────────────────────────────────────────────────────────────────
    // Policy constants
    // ─────────────────────────────────────────────────────────────────────────

    uint256 public constant FRACTION = 10000; // basis points denominator

    /// @dev dynamicConstraint values:
    ///        DYNAMIC_ANY            — any non-zero address may fill the slot
    ///        DYNAMIC_IN_RECIPIENTS  — must be a member of the signed
    ///                                 recipients array (outer envelope)
    ///        anything else          — treated as a Merkle root; the claimant
    ///                                 supplies a sorted-pair proof over
    ///                                 keccak256(abi.encodePacked(address))
    bytes32 public constant DYNAMIC_ANY           = bytes32(0);
    bytes32 public constant DYNAMIC_IN_RECIPIENTS = bytes32(uint256(1));

    uint256 public constant DEFAULT_LINE = 0;

    // ─────────────────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice EIP-712 typed struct. See PAYMENTS_TYPEHASH for field order.
    /// @param contractAddr Named "contract" in the signed type string. Must
    ///        equal address(this) at execution — an explicit, wallet-visible
    ///        binding of the claim to this deployment.
    /// @param recipientsHash commits to the authorized recipient set:
    ///        - Plain: keccak256(abi.encode(address[])) — single/multi recipient
    ///        - Policy: keccak256(abi.encode(Policy)) — enforced split with
    ///          fractions, dynamic payee, per-payee hooks. The two encodings
    ///          never collide (different abi.encode type prefixes).
    struct Payment {
        address payer;
        address token;
        bytes32 recipientsHash;
        uint256 max;
        uint256 line;
        uint256 nbf;
        uint256 exp;
        address contractAddr;
    }

    /// @notice Distribution policy, committed by Payment.policyHash.
    ///
    /// @param payees     Static payees, fixed by the signature. Each MUST be
    ///                   a member of the signed recipients array.
    /// @param fractions  Basis points per static payee (each > 0).
    ///                   sum(fractions) + dynamicBps == 10000.
    /// @param dynamicBps Basis points for the claimant-supplied dynamic payee
    ///                   (the party only known at execution time — e.g. the
    ///                   node that actually served). 0 disables the slot.
    /// @param dynamicConstraint Bounds who may fill the dynamic slot. See
    ///                   DYNAMIC_ANY / DYNAMIC_IN_RECIPIENTS / Merkle root.
    /// @param targets    Per-payee hook contracts. Empty array = all plain
    ///                   transfers. Otherwise length == payees.length;
    ///                   address(0) entries are plain transfers, non-zero
    ///                   entries receive the share then get pay(payee, share).
    ///                   The dynamic payee is always a plain transfer.
    struct Policy {
        address[] payees;
        uint256[] fractions;
        uint256   dynamicBps;
        bytes32   dynamicConstraint;
        address[] targets;
    }

    /// @notice Watermark channel state.
    /// @param max    Line-level ceiling set by lineOpen. 0 = unlimited.
    /// @param spent  Monotonic cumulative total executed on this channel.
    /// @param open   True once opened (explicitly or implicitly).
    /// @param closed True only after an explicit lineClose(); blocks
    ///               auto-opening until the owner reopens.
    struct Line {
        uint256 max;
        uint256 spent;
        bool    open;
        bool    closed;
    }

    /// @notice EIP-712 typed struct for a governance action.
    /// @param invoker address(0) → direct path (rail calls invoke/endorse as
    ///        itself; must hold the roles). non-zero → forwarded path (rail
    ///        EIP-2771-forwards invoke as invoker and endorse as each signer;
    ///        ControlContract must trust the rail as forwarder).
    struct Action {
        address authority;
        address subject;
        address contractAddress;
        bytes4  method;
        bytes32 paramsHash;
        uint256 minimum;
        uint256 fraction;
        uint256 delay;
        address invoker;
        uint256 nbf;
        uint256 exp;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // State — all public, readable without logs
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice lines[payer][lineId] → channel state.
    mapping(address => mapping(uint256 => Line)) public lines;

    /// @notice redeemed[token][payer][recipient] → cumulative amount ever
    ///         executed from payer to recipient in that token. For hook
    ///         payouts, `recipient` is the beneficiary payee (not the hook).
    mapping(address => mapping(address => mapping(address => uint256))) public redeemed;

    /// @notice receivedTotal[token][recipient] → cumulative inflow DIRECTED
    ///         to a recipient across all payers. Authors and nodes read their
    ///         lifetime earnings in one call. NOTE: when a payee's share is
    ///         routed through a custody/lockup hook, this counts the amount
    ///         directed to that payee — the tokens themselves sit in the hook
    ///         under its vesting schedule until released. "Directed", not
    ///         necessarily "spendable".
    mapping(address => mapping(address => uint256)) public receivedTotal;

    /// @dev Reentrancy guard (own implementation; 1 = idle, 2 = entered).
    uint256 private _entered = 1;

    modifier nonReentrant() {
        if (_entered != 1) revert Reentrancy();
        _entered = 2;
        _;
        _entered = 1;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Events (ledgers above are the primary read path; events are the feed)
    // ─────────────────────────────────────────────────────────────────────────

    event LineOpened(address indexed account, uint256 indexed line, uint256 max, bool implicit);
    event LineClosedEvent(address indexed account, uint256 indexed line);

    /// @notice One event per payout leg. Under a policy, a single settlement
    ///         emits one of these per payee (recipient = beneficiary; target
    ///         = hook it was routed through, or address(0) for plain).
    event PaymentsExecuted(
        address indexed payer,
        address indexed token,
        address indexed recipient,
        uint256 line,
        uint256 amount,
        uint256 newSpent,
        address target,
        bytes32 recipientsHash
    );

    event ActionsExecuted(
        address indexed authority,
        address indexed subject,
        address indexed contractAddress,
        bytes4  method,
        uint256 invokeID
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Line management
    // ─────────────────────────────────────────────────────────────────────────

    function lineOpen(address account, uint256 line, uint256 max) external {
        _requireLineOperator(account, msg.sender);
        Line storage l = lines[account][line];
        l.max    = max;
        l.open   = true;
        l.closed = false;
        emit LineOpened(account, line, max, false);
    }

    /// @notice Explicitly revoke a channel. spent is preserved; auto-open
    ///         will NOT resurrect a closed line — only lineOpen() can.
    function lineClose(address account, uint256 line) external {
        require(line != DEFAULT_LINE, "OpenClaiming: cannot close default line");
        _requireLineOperator(account, msg.sender);
        Line storage l = lines[account][line];
        l.open   = false;
        l.closed = true;
        emit LineClosedEvent(account, line);
    }

    /// @notice True if executions can currently draw on this line.
    ///         Default line: always. Named lines: open, or never-touched
    ///         (implicit-open eligible). Explicitly closed: false.
    function lineIsOpen(address account, uint256 line) public view returns (bool) {
        if (line == DEFAULT_LINE) return true;
        Line storage l = lines[account][line];
        if (l.open)   return true;
        if (l.closed) return false;
        return true; // never opened, never closed → auto-opens on first use
    }

    /// @notice Remaining collectable on a line under a given claim max.
    ///         spent is netted on every line, including the default line.
    function lineAvailable(
        address account,
        uint256 line,
        uint256 claimMax
    ) external view returns (uint256) {
        Line storage l = lines[account][line];
        if (line != DEFAULT_LINE && l.closed && !l.open) return 0;

        uint256 spent = l.spent;
        uint256 claimRemaining = claimMax == 0
            ? type(uint256).max
            : (spent >= claimMax ? 0 : claimMax - spent);
        uint256 lineRemaining = (line == DEFAULT_LINE || l.max == 0)
            ? type(uint256).max
            : (spent >= l.max ? 0 : l.max - spent);
        return claimRemaining < lineRemaining ? claimRemaining : lineRemaining;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signature primitives
    // ─────────────────────────────────────────────────────────────────────────

    function recoverSigner(
        bytes32 digest,
        bytes calldata signature
    ) public pure returns (address signer) {
        if (signature.length != 65) revert InvalidSignatureLength();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > SECP256K1N_OVER_2) revert InvalidSignatureS();
        if (v == 0 || v == 1) v += 27;
        if (v != 27 && v != 28) revert InvalidSignatureV();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
    }

    function verify(
        bytes32 digest,
        bytes calldata signature,
        address expectedSigner
    ) public pure returns (bool) {
        return recoverSigner(digest, signature) == expectedSigner;
    }

    function verifySignatures(
        bytes32            digest,
        address[] calldata signers,
        bytes[]   calldata signatures,
        uint256            minValid
    ) public view returns (bool) {
        if (signers.length != signatures.length) return false;
        if (minValid == 0) return false;
        uint256 valid = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            address signer = signers[i];
            if (signer == address(0) || signatures[i].length == 0) continue;
            bool dup = false;
            for (uint256 j = 0; j < i; j++) {
                if (signers[j] == signer) { dup = true; break; }
            }
            if (dup) continue;
            try this.recoverSigner(digest, signatures[i]) returns (address recovered) {
                if (recovered == signer) {
                    valid++;
                    if (valid >= minValid) return true;
                }
            } catch {}
        }
        return valid >= minValid;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hash helpers
    // ─────────────────────────────────────────────────────────────────────────

    function paymentsDomainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH,
            block.chainid, address(this)
        ));
    }

    /// @notice keccak256(abi.encode(address[])) — compute off-chain via
    ///         eth_call before signing.
    function paymentsHashRecipients(
        address[] calldata recipients
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(recipients));
    }

    /// @notice Canonical policy hash for Payment.policyHash. Off-chain:
    ///         keccak256(abiEncode(['address[]','uint256[]','uint256',
    ///         'bytes32','address[]'], [payees, fractions, dynamicBps,
    ///         dynamicConstraint, targets])).
    function hashPolicy(Policy calldata policy) public pure returns (bytes32) {
        return keccak256(abi.encode(
            policy.payees,
            policy.fractions,
            policy.dynamicBps,
            policy.dynamicConstraint,
            policy.targets
        ));
    }

    function paymentsHash(Payment calldata p) public pure returns (bytes32) {
        return keccak256(abi.encode(
            PAYMENTS_TYPEHASH,
            p.payer, p.token, p.recipientsHash,
            p.max, p.line, p.nbf, p.exp,
            p.contractAddr
        ));
    }

    function paymentsDigest(Payment calldata p) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01", paymentsDomainSeparator(), paymentsHash(p)
        ));
    }

    function paymentsRecoverSigner(
        Payment calldata p,
        bytes   calldata sig
    ) public view returns (address) {
        return recoverSigner(paymentsDigest(p), sig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Execute — plain path (recipientsHash commits to address[])
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Execute a plain payment (no policy): one recipient from the
     *         signed set, optional courtesy hook.
     *
     * @param hook address(0) → direct transferFrom(payer, recipient, amount).
     *             Otherwise: transferFrom(payer, hook, amount) then
     *             hook.pay(recipient, amount) — funds land in the hook
     *             (custody/lockups), the beneficiary is credited there.
     *             UNSIGNED on this path — a claimant courtesy for simple
     *             integrations. To PIN a hook, use a policy.
     */
    function paymentsExecute(
        Payment        calldata p,
        address[] calldata recipients,
        bytes     calldata sig,
        address            recipient,
        uint256            amount,
        address            hook
    ) external payable nonReentrant returns (bool) {
        _validatePlain(p, recipients, amount);
        _requireMember(recipients, recipient);
        _requireSigner(p, sig);
        _consume(p, amount);
        _payoutOne(p, recipient, amount, hook);
        return true;
    }

    /// @notice Multisig variant (treasury / group payers).
    function paymentsExecuteSignatures(
        Payment        calldata p,
        address[] calldata recipients,
        address            recipient,
        uint256            amount,
        address[] calldata signers,
        bytes[]   calldata signatures,
        uint256            minValid,
        address            hook
    ) external payable nonReentrant returns (bool) {
        _validatePlain(p, recipients, amount);
        _requireMember(recipients, recipient);
        if (!verifySignatures(paymentsDigest(p), signers, signatures, minValid)) {
            revert InvalidSignature();
        }
        _consume(p, amount);
        _payoutOne(p, recipient, amount, hook);
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Execute — policy path (policyHash != 0; atomic enforced split)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Settle `amount` under the payer-signed distribution policy.
     *         The split is proportional (partial settlements allowed) and
     *         ATOMIC: every committed payee is paid in this transaction or
     *         the whole call reverts. ERC-20 only.
     *
     * @param policy       Plaintext policy; hashPolicy(policy) must equal
     *                     the signed p.policyHash.
     * @param dynamicPayee The execution-time payee (serving node). Required
     *                     non-zero iff policy.dynamicBps > 0; must satisfy
     *                     policy.dynamicConstraint.
     * @param dynamicProof Merkle proof when the constraint is a Merkle root;
     *                     empty otherwise.
     */
    function paymentsExecutePolicy(
        Payment        calldata p,
        bytes     calldata sig,
        uint256            amount,
        Policy         calldata policy,
        address            dynamicPayee,
        bytes32[] calldata dynamicProof
    ) external nonReentrant returns (bool) {
        _requireSigner(p, sig);
        _executePolicy(p, amount, policy, dynamicPayee, dynamicProof);
        return true;
    }

    /// @notice Multisig variant of the policy path.
    function paymentsExecuteSignaturesPolicy(
        Payment        calldata p,
        uint256            amount,
        Policy         calldata policy,
        address            dynamicPayee,
        bytes32[] calldata dynamicProof,
        address[] calldata signers,
        bytes[]   calldata signatures,
        uint256            minValid
    ) external nonReentrant returns (bool) {
        if (!verifySignatures(paymentsDigest(p), signers, signatures, minValid)) {
            revert InvalidSignature();
        }
        _executePolicy(p, amount, policy, dynamicPayee, dynamicProof);
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // actions — hash helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice keccak256 of raw params bytes, for Action.paramsHash.
    function actionsHashParams(bytes calldata params) public pure returns (bytes32) {
        return keccak256(params);
    }

    function actionsHash(Action calldata a) public pure returns (bytes32) {
        return keccak256(abi.encode(
            ACTIONS_TYPEHASH,
            a.authority, a.subject, a.contractAddress, a.method, a.paramsHash,
            a.minimum, a.fraction, a.delay, a.invoker, a.nbf, a.exp
        ));
    }

    function actionsDigest(Action calldata a) public view returns (bytes32) {
        // Same protocol domain as payments (NAME_HASH).
        return keccak256(abi.encodePacked(
            "\x19\x01", paymentsDomainSeparator(), actionsHash(a)
        ));
    }

    function actionsRecoverSigner(
        Action calldata a,
        bytes  calldata sig
    ) public view returns (address) {
        return recoverSigner(actionsDigest(a), sig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // actions — verify
    // ─────────────────────────────────────────────────────────────────────────

    function actionsVerify(Action calldata a, bytes calldata sig)
        external view returns (bool)
    {
        _actionsValidateCore(a);
        if (actionsRecoverSigner(a, sig) != a.authority) revert InvalidSignature();
        return true;
    }

    function actionsVerifySignatures(
        Action         calldata a,
        address[] calldata signers,
        bytes[]   calldata signatures,
        uint256            minValid
    ) external view returns (bool) {
        _actionsValidateCore(a);
        return verifySignatures(actionsDigest(a), signers, signatures, minValid);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // actions — execute (direct path: invoker == 0, rail holds roles)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Execute a governance action by calling invoke()+endorse()
     *         directly as this rail. ControlContract sees msg.sender ==
     *         address(this); the rail must hold both roles in the Community.
     *         invokeID is re-derived to match the deployed generateInvokeID:
     *         keccak256(timestamp, difficulty/prevrandao, address(this)).
     *         Only one endorsement per tx on this path.
     */
    function actionsExecute(
        Action         calldata a,
        bytes          calldata params,
        address[] calldata signers,
        bytes[]   calldata signatures,
        uint256            minValid
    ) external nonReentrant returns (bool) {
        if (a.invoker != address(0)) revert InvokerNotInSigners(); // use actionsInvoke
        _actionsValidateCore(a);
        if (keccak256(params) != a.paramsHash) revert ParamsHashMismatch();
        if (signers.length == 0 || signers.length != signatures.length) {
            revert InvalidSignerCount();
        }

        bytes32 digest = actionsDigest(a);
        uint256 valid = _countUniqueValid(digest, signers, signatures);
        if (valid < minValid) revert InvalidSignature();

        IControlContract(a.subject).invoke(
            a.contractAddress, _bytes4ToHex(a.method), _bytesToHex(params)
        );

        // Match ControlContract.generateInvokeID (block.difficulty ==
        // prevrandao post-merge; identical bytes on BSC).
        uint256 invokeID = uint256(keccak256(abi.encodePacked(
            block.timestamp, block.prevrandao, address(this)
        )));
        IControlContract(a.subject).endorse(invokeID);

        emit ActionsExecuted(a.authority, a.subject, a.contractAddress, a.method, invokeID);
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // actions — invoke (forwarded path: invoker != 0, EIP-2771)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Execute via EIP-2771 forwarding: invoke() as a.invoker, endorse()
     *         as each valid signer individually (multi-endorser quorum in one
     *         tx). ControlContract must register this rail as TrustedForwarder
     *         and use _msgSender() throughout. Signature verification runs in
     *         its own frame before any dispatch (calldata pointers isolated).
     */
    function actionsInvoke(
        Action         calldata a,
        bytes          calldata params,
        address[] calldata signers,
        bytes[]   calldata signatures,
        uint256            minValid
    ) external nonReentrant returns (bool) {
        if (a.invoker == address(0)) revert InvokerNotInSigners();
        _actionsValidateCore(a);
        if (keccak256(params) != a.paramsHash) revert ParamsHashMismatch();
        if (signers.length == 0 || signers.length != signatures.length) {
            revert InvalidSignerCount();
        }

        (address[] memory validSigners, uint256 validCount) =
            _collectValidSigners(actionsDigest(a), signers, signatures, minValid, a.invoker);

        _invokeAndEndorse(a, params, validSigners, validCount);
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal — validation
    // ─────────────────────────────────────────────────────────────────────────

    function _requireSigner(Payment calldata p, bytes calldata sig) internal view {
        address signer = paymentsRecoverSigner(p, sig);
        if (signer != p.payer) revert PayerMismatch(p.payer, signer);
    }

    function _requireMember(
        address[] calldata recipients,
        address member
    ) internal pure {
        for (uint256 i = 0; i < recipients.length; i++) {
            if (recipients[i] == member) return;
        }
        revert InvalidRecipient(member);
    }

    function _validatePlain(
        Payment        calldata p,
        address[] calldata recipients,
        uint256            amount
    ) internal view {
        if (paymentsHashRecipients(recipients) != p.recipientsHash) {
            revert PaymentRecipientsHashMismatch();
        }
        _validateCoreShared(p, amount);
    }

    function _validateCoreShared(
        Payment calldata p,
        uint256          amount
    ) internal view {
        if (p.contractAddr != address(this)) {
            revert WrongContract(address(this), p.contractAddr);
        }
        if (p.nbf != 0 && block.timestamp < p.nbf) revert NotYetValid(p.nbf);
        if (p.exp != 0 && block.timestamp > p.exp) revert Expired(p.exp);

        Line storage l = lines[p.payer][p.line];

        if (p.line != DEFAULT_LINE && l.closed && !l.open) {
            revert LineClosed(p.payer, p.line);
        }

        uint256 spent = l.spent;
        uint256 claimRemaining = p.max == 0
            ? type(uint256).max
            : (spent >= p.max ? 0 : p.max - spent);
        uint256 lineRemaining = (p.line == DEFAULT_LINE || l.max == 0)
            ? type(uint256).max
            : (spent >= l.max ? 0 : l.max - spent);
        uint256 available = claimRemaining < lineRemaining
            ? claimRemaining : lineRemaining;

        if (amount == 0 || amount > available) {
            revert InsufficientCapacity(amount, available);
        }
    }

    /// @dev EFFECTS: consume channel capacity + implicit-open. Runs before
    ///      any external interaction (CEI).
    function _consume(Payment calldata p, uint256 amount) internal {
        Line storage l = lines[p.payer][p.line];
        if (p.line != DEFAULT_LINE && !l.open) {
            // never-opened → the payer's signature over this line id IS the
            // consent to open it (implicit lineOpen, unlimited line max)
            l.open = true;
            emit LineOpened(p.payer, p.line, 0, true);
        }
        l.spent += amount;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal — plain payout
    // ─────────────────────────────────────────────────────────────────────────

    function _payoutOne(
        Payment calldata p,
        address          recipient,
        uint256          amount,
        address          hook
    ) internal {
        uint256 newSpent = lines[p.payer][p.line].spent;

        if (p.token == address(0)) {
            // Native coin: payer-submitted only, no hooks
            if (hook != address(0))        revert NativeCoinPolicyUnsupported();
            if (msg.sender != p.payer)     revert NativeCoinDelegationUnsupported();
            if (msg.value != amount)       revert NativeCoinValueMismatch(amount, msg.value);
            _ledger(address(0), p.payer, recipient, amount);
            (bool ok,) = payable(recipient).call{value: amount}("");
            if (!ok) revert TransferFailed();
            emit PaymentsExecuted(p.payer, address(0), recipient, p.line,
                amount, newSpent, address(0), p.recipientsHash);
            return;
        }

        if (msg.value != 0) revert NativeCoinValueMismatch(0, msg.value);

        _ledger(p.token, p.payer, recipient, amount);
        if (hook == address(0)) {
            _erc20TransferFrom(p.token, p.payer, recipient, amount);
        } else {
            _erc20TransferFrom(p.token, p.payer, hook, amount);
            _callHookPay(hook, recipient, amount);
        }
        emit PaymentsExecuted(p.payer, p.token, recipient, p.line,
            amount, newSpent, hook, p.recipientsHash);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal — policy payout
    // ─────────────────────────────────────────────────────────────────────────

    function _executePolicy(
        Payment        calldata p,
        uint256            amount,
        Policy         calldata policy,
        address            dynamicPayee,
        bytes32[] calldata dynamicProof
    ) internal {
        if (p.token == address(0))      revert NativeCoinPolicyUnsupported();
        if (msg.value != 0)             revert NativeCoinValueMismatch(0, msg.value);
        if (hashPolicy(policy) != p.recipientsHash) revert PolicyHashMismatch();

        _validateCoreShared(p, amount);
        _validatePolicy(policy, dynamicPayee, dynamicProof);
        _consume(p, amount);
        _distribute(p, amount, policy, dynamicPayee);
    }

    /// @dev Payout loop in its own frame (stack depth). Effects (_ledger)
    ///      before interactions per leg; whole loop is atomic — any failed
    ///      transfer or hook reverts the entire settlement.
    function _distribute(
        Payment calldata p,
        uint256          amount,
        Policy  calldata policy,
        address          dynamicPayee
    ) internal {
        uint256 newSpent = lines[p.payer][p.line].spent;
        uint256 distributed = 0;

        for (uint256 i = 0; i < policy.payees.length; i++) {
            uint256 share = (policy.dynamicBps == 0 && i == policy.payees.length - 1)
                ? amount - distributed
                : (amount * policy.fractions[i]) / FRACTION;
            distributed += share;
            if (share == 0) continue;
            _payLeg(
                p,
                policy.payees[i],
                policy.targets.length != 0 ? policy.targets[i] : address(0),
                share,
                newSpent
            );
        }

        if (policy.dynamicBps > 0 && amount > distributed) {
            // dynamic payee absorbs rounding dust
            _payLeg(p, dynamicPayee, address(0), amount - distributed, newSpent);
        }
    }

    /// @dev One payout leg: ledger, transfer (direct or via hook), event.
    function _payLeg(
        Payment calldata p,
        address          payee,
        address          target,
        uint256          share,
        uint256          newSpent
    ) internal {
        _ledger(p.token, p.payer, payee, share);
        if (target == address(0)) {
            _erc20TransferFrom(p.token, p.payer, payee, share);
        } else {
            _erc20TransferFrom(p.token, p.payer, target, share);
            _callHookPay(target, payee, share);
        }
        emit PaymentsExecuted(p.payer, p.token, payee, p.line,
            share, newSpent, target, p.recipientsHash);
    }

    function _validatePolicy(
        Policy         calldata policy,
        address            dynamicPayee,
        bytes32[] calldata dynamicProof
    ) internal pure {
        uint256 len = policy.payees.length;
        if (policy.fractions.length != len) revert PolicyInvalid();
        if (policy.targets.length != 0 && policy.targets.length != len) {
            revert PolicyInvalid();
        }
        if (len == 0 && policy.dynamicBps == 0) revert PolicyInvalid();

        uint256 sum = policy.dynamicBps;
        for (uint256 i = 0; i < len; i++) {
            if (policy.payees[i] == address(0)) revert PolicyInvalid();
            if (policy.fractions[i] == 0)       revert PolicyInvalid();
            sum += policy.fractions[i];
        }
        if (sum != FRACTION) revert PolicyInvalid();

        if (policy.dynamicBps > 0) {
            if (dynamicPayee == address(0)) revert DynamicPayeeInvalid(dynamicPayee);
            bytes32 c = policy.dynamicConstraint;
            if (c == DYNAMIC_ANY) {
                // any non-zero address
            } else if (c == DYNAMIC_IN_RECIPIENTS) {
                // In this mode, dynamicPayee must be one of the static payees
                bool found = false;
                for (uint256 i = 0; i < len; i++) {
                    if (policy.payees[i] == dynamicPayee) { found = true; break; }
                }
                if (!found) revert DynamicPayeeInvalid(dynamicPayee);
            } else {
                // Merkle root over keccak256(abi.encodePacked(address))
                if (!_merkleVerify(
                        keccak256(abi.encodePacked(dynamicPayee)),
                        dynamicProof, c)) {
                    revert DynamicPayeeInvalid(dynamicPayee);
                }
            }
        } else if (dynamicPayee != address(0)) {
            revert DynamicPayeeInvalid(dynamicPayee);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal — ledgers, transfers, hooks, merkle
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Public-ledger effects, applied BEFORE the external call.
    function _ledger(address token, address payer, address recipient, uint256 amount) internal {
        redeemed[token][payer][recipient] += amount;
        receivedTotal[token][recipient]   += amount;
    }

    function _erc20TransferFrom(
        address token, address from, address to, uint256 amount
    ) internal {
        (bool ok, bytes memory data) = token.call(
            abi.encodeWithSelector(0x23b872dd, from, to, amount) // transferFrom
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert TransferFailed();
        }
    }

    /// @dev Notify a custody/lockup target after its share has landed.
    ///      Interface: pay(address recipient, uint256 amount). msg.sender is
    ///      this rail — an IncomeContract accepts after its owner runs
    ///      addManager(recipient, <this rail>) once. No EIP-2771 suffix is
    ///      appended: the payer is a random counterparty, not a manager;
    ///      forwarding their identity would only break the target's checks.
    function _callHookPay(address target, address recipient, uint256 amount) internal {
        // Require code at the target: an EOA would accept the funds (already
        // transferred) and silently no-op on the call, stranding the payee's
        // share. Reverting protects an honest payer from a mis-typed target
        // in their own signed policy. (Not a theft vector — the payer signed
        // the target — but a footgun worth closing loudly.)
        if (target.code.length == 0) revert HookCallFailed(target);
        (bool ok,) = target.call(
            abi.encodeWithSelector(0xc4076876, recipient, amount) // pay(address,uint256)
        );
        if (!ok) revert HookCallFailed(target);
    }

    /// @dev Sorted-pair Merkle verification (OpenZeppelin-compatible).
    function _merkleVerify(
        bytes32            leaf,
        bytes32[] calldata proof,
        bytes32            root
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 el = proof[i];
            computed = computed <= el
                ? keccak256(abi.encodePacked(computed, el))
                : keccak256(abi.encodePacked(el, computed));
        }
        return computed == root;
    }

    function _requireLineOperator(address account, address caller) internal view {
        if (caller == account) return;
        (bool ok, bytes memory data) = account.staticcall(
            abi.encodeWithSelector(0x8da5cb5b) // owner()
        );
        if (ok && data.length == 32 && abi.decode(data, (address)) == caller) return;
        revert UnauthorizedLineOperator(account, caller);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal — actions
    // ─────────────────────────────────────────────────────────────────────────

    function _actionsValidateCore(Action calldata a) internal view {
        if (a.nbf != 0 && block.timestamp < a.nbf) revert NotYetValid(a.nbf);
        if (a.exp != 0 && block.timestamp > a.exp) revert Expired(a.exp);
    }

    /// @dev Count unique valid signatures over a digest (reverts on a present-
    ///      but-invalid signature — strict: a bad signature is an error,
    ///      not a skip).
    function _countUniqueValid(
        bytes32            digest,
        address[] calldata signers,
        bytes[]   calldata signatures
    ) internal pure returns (uint256 validCount) {
        address[] memory seen = new address[](signers.length);
        for (uint256 i = 0; i < signers.length; i++) {
            address signer = signers[i];
            if (signer == address(0) || signatures[i].length == 0) continue;
            if (recoverSigner(digest, signatures[i]) != signer) revert InvalidSignature();
            bool dup = false;
            for (uint256 j = 0; j < validCount; j++) {
                if (seen[j] == signer) { dup = true; break; }
            }
            if (!dup) { seen[validCount] = signer; validCount++; }
        }
    }

    /// @dev Verify sigs in an isolated frame; also confirm the invoker signed.
    function _collectValidSigners(
        bytes32            digest,
        address[] calldata signers,
        bytes[]   calldata signatures,
        uint256            minValid,
        address            invoker
    ) internal pure returns (address[] memory validSigners, uint256 validCount) {
        validSigners = new address[](signers.length);
        bool invokerFound = false;
        for (uint256 i = 0; i < signers.length; i++) {
            address signer = signers[i];
            if (signer == address(0) || signatures[i].length == 0) continue;
            if (recoverSigner(digest, signatures[i]) != signer) revert InvalidSignature();
            bool dup = false;
            for (uint256 j = 0; j < validCount; j++) {
                if (validSigners[j] == signer) { dup = true; break; }
            }
            if (!dup) {
                validSigners[validCount] = signer;
                validCount++;
                if (signer == invoker) invokerFound = true;
            }
        }
        if (validCount < minValid) revert InvalidSignature();
        if (!invokerFound)         revert InvokerNotInSigners();
    }

    /// @dev EIP-2771 forward invoke() as invoker, endorse() as each signer.
    function _invokeAndEndorse(
        Action         calldata a,
        bytes          calldata params,
        address[] memory        validSigners,
        uint256                 validCount
    ) internal {
        _forwardCall(
            a.subject,
            abi.encodeWithSelector(
                IControlContract.invoke.selector,
                a.contractAddress, _bytes4ToHex(a.method), _bytesToHex(params)
            ),
            a.invoker
        );

        uint256 invokeID = uint256(keccak256(abi.encodePacked(
            block.timestamp, block.prevrandao, a.invoker
        )));

        bytes memory endorseCall = abi.encodeWithSelector(
            IControlContract.endorse.selector, invokeID
        );
        for (uint256 i = 0; i < validCount; i++) {
            _forwardCall(a.subject, endorseCall, validSigners[i]);
        }

        emit ActionsExecuted(a.authority, a.subject, a.contractAddress, a.method, invokeID);
    }

    /// @dev Append signer as trailing 20 calldata bytes (EIP-2771). The
    ///      target's _msgSender() strips and returns it.
    function _forwardCall(address target, bytes memory data, address signer) internal {
        (bool ok,) = target.call(abi.encodePacked(data, signer));
        require(ok, "OpenClaiming: forwarded call failed");
    }

    function _bytes4ToHex(bytes4 b) internal pure returns (string memory) {
        bytes memory h = new bytes(8);
        bytes memory chars = "0123456789abcdef";
        for (uint256 i = 0; i < 4; i++) {
            h[i * 2]     = chars[uint8(b[i]) >> 4];
            h[i * 2 + 1] = chars[uint8(b[i]) & 0x0f];
        }
        return string(h);
    }

    function _bytesToHex(bytes calldata b) internal pure returns (string memory) {
        bytes memory h = new bytes(b.length * 2);
        bytes memory chars = "0123456789abcdef";
        for (uint256 i = 0; i < b.length; i++) {
            h[i * 2]     = chars[uint8(b[i]) >> 4];
            h[i * 2 + 1] = chars[uint8(b[i]) & 0x0f];
        }
        return string(h);
    }
}
