// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {
    ERC20Upgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {
    PausableUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {
    UUPSUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title WrappedBDX (wBDX) — the EVM side of the Beldex Sovereign Bridge (Phase H).
///
/// A signer-gated, domain-separated, replay-guarded, fixed-window-capped ERC-20 whose
/// **mint authority is the `Pevm` masternode-committee key** (secp256k1 / CGGMP21),
/// verified by `ecrecover`. Deliberately **not** `Ownable`: the party that authorizes
/// mints (the committee **signer**) is separate from the party that manages the signer
/// set, configuration, and upgrades (the timelocked **admin**). A separate guardian can
/// only pause and veto rotations. Governance is ultimately trusted because it can appoint
/// mint authority or upgrade the implementation; the timelock makes that power observable.
///
/// ## Byte-exact agreement with the off-chain signer (load-bearing)
/// The mint digest is `keccak256(abi.encode(MINT_TAG, block.chainid, address(this),
/// keyEpoch, to, amount, beldexTxid, outputIndex))`. Every field, order, and tag value
/// must match the Rust signer's
/// `watch.rs::MintEvent::mint_preimage` exactly — otherwise `ecrecover` fails.
///
/// **`MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V2")`**. V2 adds `keyEpoch` and the
/// Beldex gateway `outputIndex`; the signer must use the same precomputed hash. The
/// keccak form (vs. a raw right-padded string literal) is the conventional domain-
/// separation approach and is not limited to 32-character tags.
///
/// ## Redeem
/// `redeemToNative` burns wBDX and emits `RedeemToNative(address,uint256,bytes)` — the
/// exact event the E.2 EVM watcher (`evm_watcher.rs`) decodes: `from` indexed, and
/// `abi.encode(amount, beldexAddress)` in the data. The *release* cap that mirrors the
/// mint cap lives on the L1 gateway in consensus (Phase A.3), since releases move locked
/// BDX, not wBDX; the contract bounds a burn only by `perTxMax` for UX.
///
/// ## Decimals
/// 9 decimals to match Beldex `COIN = 10^9`, so 1 wBDX unit == 1 atomic BDX — no
/// 10^9<->10^18 rescaling anywhere in the mint/redeem path.
contract WrappedBDX is Initializable, ERC20Upgradeable, PausableUpgradeable, UUPSUpgradeable {
    // --- Domain-separation tags (keccak256 of the domain string) ---------------------
    /// @dev V2 binds the signer epoch and Beldex output index into every mint.
    bytes32 public constant MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V2");
    /// @dev Rotation hand-off tag; the signer's future rotate-signing must mirror this
    ///      (same keccak convention as MINT_TAG).
    bytes32 public constant ROTATE_TAG = keccak256("BELDEX_BRIDGE_ROTATE_V2");
    /// @dev The incoming committee signs this before the outgoing key is retired.
    bytes32 public constant ACTIVATE_TAG = keccak256("BELDEX_BRIDGE_ACTIVATE_V1");

    uint8 private constant DECIMALS = 9;
    uint8 public constant BELDEX_MAINNET = 0;
    uint8 public constant BELDEX_TESTNET = 1;
    uint8 public constant BELDEX_DEVNET = 2;

    // --- Committee mint authority ----------------------------------------------------
    /// @notice The active `Pevm` committee key that authorizes mints and signs rotations.
    address public currentSigner;
    /// @notice Monotonic key generation; a rotation may only move it forward (anti-rollback).
    uint64 public keyEpoch;
    /// @notice Admin-managed recovery signer set. Effective authorization is additionally
    ///         scoped by `signerEpoch`, so entries automatically expire on rotation.
    mapping(address => bool) public isSigner;

    // --- Rotation challenge window (H.6) ---------------------------------------------
    address public pendingSigner;
    uint64 public pendingKeyEpoch;
    uint256 public pendingActivateAt;
    bool public rotationVetoed;
    /// @notice Challenge-window duration between a valid rotate proposal and activation.
    uint256 public rotateTimelock;

    // --- Replay guard + fixed-calendar-window mint cap (H.2, §7-bis β=1) -------------
    mapping(bytes32 => bool) public processedDeposits;
    /// @notice Calendar window length in seconds (fixed; window resets on the boundary).
    uint256 public epochSeconds;
    uint256 public windowId;
    uint256 public windowMinted;
    uint256 public windowMintCap;
    uint256 public perTxMax;

    // --- Bond-before-caps guard (§7-bis) ---------------------------------------------
    /// @notice Governance-set backing allocated to this EVM deployment. Fixed windows
    ///         have a worst-case boundary burst of 2x, so the cap may use at most half.
    uint256 public bondBackingCapLimit;

    // --- Admin (a TimelockController + multisig in production) ------------------------
    address public admin;

    // --- Appended upgrade-safe state (consumes four slots from __gap) ----------------
    /// @notice Permanently vetoed rotation tuples, unless governance explicitly clears one.
    mapping(bytes32 => bool) public vetoedProposals;
    /// @notice Epoch in which an `isSigner` recovery key is effective.
    mapping(address => uint64) public signerEpoch;
    /// @notice Fast incident responder: may pause and veto, but never unpause or upgrade.
    address public guardian;
    /// @notice Candidate for two-step admin transfer.
    address public pendingAdmin;
    /// @notice Number of outgoing-committee rotation authorizations consumed. Each
    ///         proposal must carry exactly the next value, making signatures single-use.
    uint64 public rotationNonce;
    /// @notice Native address network accepted by `redeemToNative`. Existing proxies
    ///         default to zero (`BELDEX_MAINNET`), preserving the pre-upgrade policy.
    uint8 public beldexNetwork;
    /// @notice Smallest native redemption. This bounds permanent L1 replay-index growth
    ///         from dust burns; existing proxies may set it through `initializeV3`.
    uint256 public minRedeemAmount;

    // --- Events ----------------------------------------------------------------------
    event Minted(
        address indexed to, uint256 amount, bytes32 indexed beldexTxid, uint32 outputIndex
    );
    event RedeemToNative(address indexed from, uint256 amount, bytes beldexAddress);
    event RotationProposed(
        address indexed newSigner,
        uint64 newKeyEpoch,
        uint64 nonce,
        uint256 authorizationDeadline,
        uint256 activateAt
    );
    event Rotated(address indexed newSigner, uint64 newKeyEpoch);
    event RotationVetoed(address indexed pendingSigner, uint64 pendingKeyEpoch);
    event VetoedProposalCleared(address indexed signer, uint64 keyEpoch);
    event BreakGlassSignerSet(address indexed newSigner, uint64 newKeyEpoch);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event CapsSet(uint256 windowMintCap, uint256 perTxMax);
    event BondBackingCapLimitSet(uint256 bondBackingCapLimit);
    event MinimumRedeemAmountSet(uint256 minimumRedeemAmount);
    event BeldexNetworkSet(uint8 network);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);
    event GuardianSet(address indexed previousGuardian, address indexed newGuardian);
    event Paused_(address indexed by);
    event Unpaused_(address indexed by);

    error NotAdmin();
    error ZeroAddress();
    error BadSigner();
    error Replay();
    error PerTxCap();
    error WindowCap();
    error NoPendingRotation();
    error RotationNotReady();
    error RotationIsVetoed();
    error IncomingNotReady();
    error PendingRotationExists();
    error InvalidEpoch();
    error InvalidRotationNonce();
    error RotationAuthorizationExpired();
    error CapAboveBondBacking();
    error CapBelowCurrentExposure();
    error InvalidConfiguration();
    error BadRedeemAddress();
    error ZeroAmount();
    error BelowMinimumRedeem();
    error NotGuardianOrAdmin();
    error NotPendingAdmin();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyGuardianOrAdmin() {
        if (msg.sender != guardian && msg.sender != admin) revert NotGuardianOrAdmin();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param admin_               Timelocked governance admin (signer-set / pause / upgrade).
    /// @param initialSigner        Genesis `Pevm` committee mint key.
    /// @param guardian_            Fast pause/veto authority (must not be the signer).
    /// @param windowMintCap_       Per-window mint cap (must be <= half the allocated backing).
    /// @param perTxMax_            Per-transaction max (mint and redeem).
    /// @param bondBackingCapLimit_ Ceiling reflecting the L1 bond backing (bond-before-caps).
    /// @param epochSeconds_        Fixed calendar-window length (e.g. 86400 for daily).
    /// @param rotateTimelock_      H.6 rotation challenge-window duration.
    function initialize(
        address admin_,
        address guardian_,
        address initialSigner,
        uint256 windowMintCap_,
        uint256 perTxMax_,
        uint256 bondBackingCapLimit_,
        uint256 epochSeconds_,
        uint256 rotateTimelock_
    ) external initializer {
        _initialize(
            admin_,
            guardian_,
            initialSigner,
            windowMintCap_,
            perTxMax_,
            bondBackingCapLimit_,
            epochSeconds_,
            rotateTimelock_,
            BELDEX_MAINNET,
            1
        );
    }

    /// @notice Network-aware initializer for non-mainnet deployments. Keeping this as a
    ///         separate entrypoint preserves the existing production initializer ABI and
    ///         makes a devnet deployment explicit rather than weakening mainnet checks.
    function initializeForNetwork(
        address admin_,
        address guardian_,
        address initialSigner,
        uint256 windowMintCap_,
        uint256 perTxMax_,
        uint256 bondBackingCapLimit_,
        uint256 epochSeconds_,
        uint256 rotateTimelock_,
        uint8 beldexNetwork_,
        uint256 minRedeemAmount_
    ) external initializer {
        _initialize(
            admin_,
            guardian_,
            initialSigner,
            windowMintCap_,
            perTxMax_,
            bondBackingCapLimit_,
            epochSeconds_,
            rotateTimelock_,
            beldexNetwork_,
            minRedeemAmount_
        );
    }

    function _initialize(
        address admin_,
        address guardian_,
        address initialSigner,
        uint256 windowMintCap_,
        uint256 perTxMax_,
        uint256 bondBackingCapLimit_,
        uint256 epochSeconds_,
        uint256 rotateTimelock_,
        uint8 beldexNetwork_,
        uint256 minRedeemAmount_
    ) internal {
        if (admin_ == address(0) || guardian_ == address(0) || initialSigner == address(0)) {
            revert ZeroAddress();
        }
        if (admin_ == guardian_ || admin_ == initialSigner || guardian_ == initialSigner) {
            revert InvalidConfiguration();
        }
        _validateConfiguration(
            windowMintCap_, perTxMax_, bondBackingCapLimit_, epochSeconds_, rotateTimelock_
        );
        if (beldexNetwork_ > BELDEX_DEVNET || minRedeemAmount_ == 0 || minRedeemAmount_ > perTxMax_)
        {
            revert InvalidConfiguration();
        }

        __ERC20_init("Wrapped BDX", "wBDX");
        __Pausable_init();
        // NOTE: OZ upgradeable v5 removed __UUPSUpgradeable_init() -- UUPSUpgradeable
        // is stateless there; inheriting + overriding _authorizeUpgrade is sufficient.

        admin = admin_;
        guardian = guardian_;
        currentSigner = initialSigner;
        keyEpoch = 1;
        windowMintCap = windowMintCap_;
        perTxMax = perTxMax_;
        bondBackingCapLimit = bondBackingCapLimit_;
        epochSeconds = epochSeconds_;
        rotateTimelock = rotateTimelock_;
        beldexNetwork = beldexNetwork_;
        minRedeemAmount = minRedeemAmount_;
        windowId = block.timestamp / epochSeconds_;

        emit AdminTransferred(address(0), admin_);
        emit GuardianSet(address(0), guardian_);
        emit Rotated(initialSigner, 1);
        emit CapsSet(windowMintCap_, perTxMax_);
        emit BondBackingCapLimitSet(bondBackingCapLimit_);
        emit BeldexNetworkSet(beldexNetwork_);
        emit MinimumRedeemAmountSet(minRedeemAmount_);
    }

    /// @notice Atomic migration hook for proxies deployed with the V1 initializer.
    /// @dev Use as the calldata of `upgradeToAndCall`. It refuses to activate V2 while
    ///      the pre-existing fixed-window cap lacks coverage for its 2x boundary burst.
    ///      Legacy recovery signers intentionally become ineffective until governance
    ///      re-adds them, which scopes each one to the current `keyEpoch`.
    function initializeV2(address guardian_, uint256 bondBackingCapLimit_)
        external
        reinitializer(2)
        onlyAdmin
    {
        if (guardian_ == address(0)) revert ZeroAddress();
        if (guardian_ == admin || guardian_ == pendingSigner || isAuthorizedSigner(guardian_)) {
            revert InvalidConfiguration();
        }
        if (windowMintCap > bondBackingCapLimit_ / 2) revert CapAboveBondBacking();

        emit GuardianSet(guardian, guardian_);
        guardian = guardian_;
        bondBackingCapLimit = bondBackingCapLimit_;
        emit BondBackingCapLimitSet(bondBackingCapLimit_);
    }

    /// @notice Migration hook for proxies deployed before network-aware redemption and the
    ///         minimum redemption were added. Intended as `upgradeToAndCall` calldata.
    function initializeV3(uint8 beldexNetwork_, uint256 minRedeemAmount_)
        external
        reinitializer(3)
        onlyAdmin
    {
        if (beldexNetwork_ > BELDEX_DEVNET || minRedeemAmount_ == 0 || minRedeemAmount_ > perTxMax)
        {
            revert InvalidConfiguration();
        }
        // A legacy V1 proxy must run initializeV2 first; calling V3 out of order would
        // permanently skip the guardian migration because reinitializer versions advance.
        if (guardian == address(0)) revert InvalidConfiguration();
        beldexNetwork = beldexNetwork_;
        minRedeemAmount = minRedeemAmount_;
        emit BeldexNetworkSet(beldexNetwork_);
        emit MinimumRedeemAmountSet(minRedeemAmount_);
    }

    /// @dev A fixed-window cap can release almost 2x across a boundary. The allocated
    ///      backing therefore covers two full windows. `perTxMax` must describe a
    ///      realizable operation within the window.
    function _validateConfiguration(
        uint256 mintCap,
        uint256 txMax,
        uint256 backing,
        uint256 epochLength,
        uint256 rotationDelay
    ) internal pure {
        if (mintCap == 0 || txMax == 0 || txMax > mintCap || epochLength == 0 || rotationDelay == 0)
        {
            revert InvalidConfiguration();
        }
        if (mintCap > backing / 2) revert CapAboveBondBacking();
    }

    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }

    // =================================================================================
    // Mint (H.2) — committee-signed, domain-separated, replay-guarded, window-capped
    // =================================================================================
    /// @notice Mint one Beldex gateway output. A native transaction can contain several
    ///         deposits, so replay identity is `(beldexTxid, outputIndex)`, not the bare txid.
    /// @param outputIndex Index of the gateway output within the Beldex transaction.
    /// @param sig 65-byte secp256k1 signature (r‖s‖v) from the committee key.
    function mint(
        address to,
        uint256 amount,
        bytes32 beldexTxid,
        uint32 outputIndex,
        bytes calldata sig
    ) external whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        bytes32 digest = keccak256(
            abi.encode(
                MINT_TAG,
                block.chainid,
                address(this),
                keyEpoch,
                to,
                amount,
                beldexTxid,
                outputIndex
            )
        );
        address recovered = ECDSA.recover(digest, sig);
        if (!isAuthorizedSigner(recovered)) revert BadSigner();

        // Upgrade compatibility: deposits processed by V1 were stored under the raw txid.
        // Keeping this check prevents every historical deposit from reopening after upgrade.
        if (processedDeposits[beldexTxid]) revert Replay();
        bytes32 id = depositId(beldexTxid, outputIndex);
        if (processedDeposits[id]) revert Replay();

        // Fixed windows admit a worst-case 2x boundary burst. Configuration explicitly
        // collateralizes that burst by requiring 2 * windowMintCap <= allocated backing.
        uint256 w = block.timestamp / epochSeconds;
        if (w != windowId) {
            windowId = w;
            windowMinted = 0;
        }
        if (amount > perTxMax) revert PerTxCap();
        if (windowMinted + amount > windowMintCap) revert WindowCap();

        processedDeposits[id] = true;
        windowMinted += amount;
        _mint(to, amount);
        emit Minted(to, amount, beldexTxid, outputIndex);
    }

    /// @notice True only for the active committee or a recovery signer scoped to this epoch.
    function isAuthorizedSigner(address signer) public view returns (bool) {
        return signer == currentSigner || (isSigner[signer] && signerEpoch[signer] == keyEpoch);
    }

    /// @notice Canonical replay key for one output in a native Beldex transaction.
    function depositId(bytes32 beldexTxid, uint32 outputIndex) public pure returns (bytes32) {
        return keccak256(abi.encode(beldexTxid, outputIndex));
    }

    /// @notice Includes the legacy raw-txid marker so upgrade tooling cannot misreport
    ///         a V1 deposit as spendable under V2.
    function isDepositProcessed(bytes32 beldexTxid, uint32 outputIndex)
        external
        view
        returns (bool)
    {
        return processedDeposits[beldexTxid]
            || processedDeposits[depositId(beldexTxid, outputIndex)];
    }

    // =================================================================================
    // Redeem (H.3) — burn wBDX, emit the watcher-decoded RedeemToNative
    // =================================================================================
    /// @notice Burn `amount` wBDX and request a native BDX release to `beldexAddress`.
    ///         The L1 gateway (Phase A.3) enforces the release cap in consensus; here we
    ///         bound by `minRedeemAmount` and `perTxMax`. The address is fully decoded and
    ///         checked against this deployment's configured Beldex network plus its
    ///         CryptoNote checksum before the irreversible burn. Only standard addresses
    ///         are supported by the native gateway payout builder.
    function redeemToNative(uint256 amount, string calldata beldexAddress) external whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        if (amount < minRedeemAmount) revert BelowMinimumRedeem();
        if (amount > perTxMax) revert PerTxCap();
        bytes memory addr = bytes(beldexAddress);
        if (!_isValidBeldexAddress(addr, beldexNetwork)) revert BadRedeemAddress();

        _burn(msg.sender, amount);
        emit RedeemToNative(msg.sender, amount, addr);
    }

    function _isValidMainnetBeldexAddress(bytes memory encoded) internal pure returns (bool) {
        return _isValidBeldexAddress(encoded, BELDEX_MAINNET);
    }

    function _isValidBeldexAddress(bytes memory encoded, uint8 network)
        internal
        pure
        returns (bool)
    {
        (bool ok, bytes memory decoded) = _decodeCryptoNoteBase58(encoded);
        if (!ok) return false;

        // Match the native gateway->wallet builder: it supports standard addresses
        // only, rejecting subaddresses and integrated payment IDs. Accepting those
        // here would irreversibly burn tokens for an unfulfillable release.
        // Mainnet prefix 209 is varint d1 01. Lengths include the 4-byte checksum.
        bool prefixOk;
        if (network == BELDEX_MAINNET) {
            prefixOk =
                decoded.length == 70 && uint8(decoded[0]) == 0xd1 && uint8(decoded[1]) == 0x01;
        } else if (network == BELDEX_TESTNET) {
            prefixOk = decoded.length == 69 && uint8(decoded[0]) == 53;
        } else if (network == BELDEX_DEVNET) {
            prefixOk = decoded.length == 69 && uint8(decoded[0]) == 24;
        } else {
            return false;
        }
        if (!prefixOk) return false;

        uint256 payloadLength = decoded.length - 4;
        bytes memory payload = new bytes(payloadLength);
        for (uint256 i = 0; i < payloadLength; ++i) {
            payload[i] = decoded[i];
        }
        bytes32 checksum = keccak256(payload);
        for (uint256 i = 0; i < 4; ++i) {
            if (decoded[payloadLength + i] != checksum[i]) return false;
        }
        return true;
    }

    /// @dev CryptoNote base58 decodes 11 characters into each 8-byte block. The final
    ///      block has one of the canonical encoded sizes below; rejecting all other
    ///      remainders also rejects non-canonical/ambiguous encodings.
    function _decodeCryptoNoteBase58(bytes memory encoded)
        internal
        pure
        returns (bool ok, bytes memory decoded)
    {
        uint256 fullBlocks = encoded.length / 11;
        uint256 remainder = encoded.length % 11;
        uint256 lastSize;
        if (remainder == 0) lastSize = 0;
        else if (remainder == 2) lastSize = 1;
        else if (remainder == 3) lastSize = 2;
        else if (remainder == 5) lastSize = 3;
        else if (remainder == 6) lastSize = 4;
        else if (remainder == 7) lastSize = 5;
        else if (remainder == 9) lastSize = 6;
        else if (remainder == 10) lastSize = 7;
        else return (false, new bytes(0));

        decoded = new bytes(fullBlocks * 8 + lastSize);
        for (uint256 blockNo = 0; blockNo < fullBlocks; ++blockNo) {
            if (!_decodeBase58Block(encoded, blockNo * 11, 11, decoded, blockNo * 8, 8)) {
                return (false, new bytes(0));
            }
        }
        if (remainder != 0) {
            if (!_decodeBase58Block(
                    encoded, fullBlocks * 11, remainder, decoded, fullBlocks * 8, lastSize
                )) return (false, new bytes(0));
        }
        return (true, decoded);
    }

    function _decodeBase58Block(
        bytes memory encoded,
        uint256 inputOffset,
        uint256 encodedSize,
        bytes memory decoded,
        uint256 outputOffset,
        uint256 decodedSize
    ) internal pure returns (bool) {
        uint256 value;
        for (uint256 i = 0; i < encodedSize; ++i) {
            (bool valid, uint8 digit) = _base58Digit(uint8(encoded[inputOffset + i]));
            if (!valid) return false;
            value = value * 58 + digit;
        }
        if (decodedSize < 8 && value >= (uint256(1) << (decodedSize * 8))) return false;
        for (uint256 i = decodedSize; i > 0; --i) {
            decoded[outputOffset + i - 1] = bytes1(uint8(value));
            value >>= 8;
        }
        return value == 0;
    }

    function _base58Digit(uint8 c) internal pure returns (bool, uint8) {
        if (c >= 49 && c <= 57) return (true, c - 49); // 1..9
        if (c >= 65 && c <= 72) return (true, c - 56); // A..H
        if (c >= 74 && c <= 78) return (true, c - 57); // J..N
        if (c >= 80 && c <= 90) return (true, c - 58); // P..Z
        if (c >= 97 && c <= 107) return (true, c - 64); // a..k
        if (c >= 109 && c <= 122) return (true, c - 65); // m..z
        return (false, 0);
    }

    // =================================================================================
    // Signer rotation (H.6) — self-authorizing committee hand-off
    // =================================================================================
    /// @notice Propose a new committee signer, authorized by the **outgoing** signer.
    ///         Permissionless relay: anyone may submit the outgoing committee's signature.
    ///         Enters a challenge window rather than switching immediately (H.6.2).
    /// @param nonce Must equal `rotationNonce + 1`; consumed even if the proposal is
    ///        subsequently vetoed, so an old authorization can never be staged again.
    /// @param deadline Last timestamp at which this authorization may be relayed.
    function rotateSigner(
        address newSigner,
        uint64 newKeyEpoch,
        uint64 nonce,
        uint256 deadline,
        bytes calldata outgoingSig
    ) external whenNotPaused {
        if (pendingActivateAt != 0) revert PendingRotationExists();
        if (keyEpoch == type(uint64).max || newKeyEpoch != keyEpoch + 1) revert InvalidEpoch();
        if (newSigner == address(0)) revert ZeroAddress();
        if (newSigner == currentSigner) revert InvalidConfiguration();
        if (newSigner == admin || newSigner == guardian || newSigner == pendingAdmin) {
            revert InvalidConfiguration();
        }
        if (vetoedProposals[_proposalId(newSigner, newKeyEpoch)]) revert RotationIsVetoed();
        if (block.timestamp > deadline) revert RotationAuthorizationExpired();
        if (rotationNonce == type(uint64).max || nonce != rotationNonce + 1) {
            revert InvalidRotationNonce();
        }

        bytes32 digest = keccak256(
            abi.encode(
                ROTATE_TAG, block.chainid, address(this), newKeyEpoch, newSigner, nonce, deadline
            )
        );
        if (ECDSA.recover(digest, outgoingSig) != currentSigner) revert BadSigner();

        rotationNonce = nonce;
        pendingSigner = newSigner;
        pendingKeyEpoch = newKeyEpoch;
        pendingActivateAt = block.timestamp + rotateTimelock;
        rotationVetoed = false;
        emit RotationProposed(newSigner, newKeyEpoch, nonce, deadline, pendingActivateAt);
    }

    function _proposalId(address signer, uint64 epoch) internal pure returns (bytes32) {
        return keccak256(abi.encode(signer, epoch));
    }

    /// @notice Activate after the challenge window with proof that the incoming key is live.
    ///         Anyone may relay `incomingSig`; the pending threshold key must produce it.
    function activateRotation(bytes calldata incomingSig) external whenNotPaused {
        // Timestamp is the intended clock for a multi-hour/day governance challenge window;
        // bounded validator skew cannot bypass a materially configured delay.
        // forge-lint: disable-next-line(block-timestamp)
        if (pendingActivateAt == 0 || block.timestamp < pendingActivateAt) {
            revert RotationNotReady();
        }
        if (rotationVetoed) revert RotationIsVetoed();

        bytes32 digest = keccak256(
            abi.encode(ACTIVATE_TAG, block.chainid, address(this), pendingKeyEpoch, pendingSigner)
        );
        if (ECDSA.recover(digest, incomingSig) != pendingSigner) revert IncomingNotReady();

        currentSigner = pendingSigner;
        keyEpoch = pendingKeyEpoch;
        emit Rotated(currentSigner, keyEpoch);

        delete pendingSigner;
        delete pendingKeyEpoch;
        delete pendingActivateAt;
    }

    /// @notice Veto a pending rotation (freeze trigger). In production this is driven by
    ///         the Beldex watchers detecting that `pendingSigner` != the DKG address the
    ///         consensus-selected committee actually generated (H.6.2c). Modeled here as
    ///         an admin (freeze-authority) action.
    function vetoRotation() external onlyGuardianOrAdmin {
        if (pendingActivateAt == 0) revert NoPendingRotation();

        address rejectedSigner = pendingSigner;
        uint64 rejectedEpoch = pendingKeyEpoch;
        vetoedProposals[_proposalId(rejectedSigner, rejectedEpoch)] = true;

        delete pendingSigner;
        delete pendingKeyEpoch;
        delete pendingActivateAt;
        rotationVetoed = true;
        emit RotationVetoed(rejectedSigner, rejectedEpoch);
    }

    function clearVetoedProposal(address signer, uint64 epoch) external onlyAdmin {
        delete vetoedProposals[_proposalId(signer, epoch)];
        emit VetoedProposalCleared(signer, epoch);
    }

    /// @notice Break-glass (H.6.2d / H.6.3): admin sets the signer directly when no valid
    ///         hand-off lands (mass exit / refusal). The deliberate fallback, not the
    ///         default path. Still cannot mint — only names the mint authority.
    ///
    ///         Emits `Rotated` **in addition to** `BreakGlassSignerSet`: a break-glass is
    ///         functionally a signer rotation (it advances `keyEpoch`), so the L1
    ///         bond-release gate (H.6.3) treats "the key moved past your epoch" uniformly,
    ///         however it moved. This prevents a refusing minority from freezing honest
    ///         departers' bonds — governance moving the key on-chain releases them too.
    ///         `BreakGlassSignerSet` is retained so the *provenance* (governance override
    ///         vs. self-authorized hand-off) stays visible on-chain for audit/telemetry.
    function breakGlassSetSigner(address newSigner, uint64 newKeyEpoch) external onlyAdmin {
        if (newSigner == address(0)) revert ZeroAddress();
        if (newSigner == currentSigner) revert InvalidConfiguration();
        if (newSigner == admin || newSigner == guardian || newSigner == pendingAdmin) {
            revert InvalidConfiguration();
        }
        if (keyEpoch == type(uint64).max || newKeyEpoch != keyEpoch + 1) revert InvalidEpoch();
        currentSigner = newSigner;
        keyEpoch = newKeyEpoch;
        delete pendingSigner;
        delete pendingKeyEpoch;
        delete pendingActivateAt;
        rotationVetoed = false;
        emit Rotated(newSigner, newKeyEpoch);
        emit BreakGlassSignerSet(newSigner, newKeyEpoch);
    }

    // =================================================================================
    // Admin (H.4) — pause, break-glass signer set, caps, upgrade. All admin-only.
    // =================================================================================
    function pause() external onlyGuardianOrAdmin {
        _pause();
        emit Paused_(msg.sender);
    }

    function unpause() external onlyAdmin {
        _unpause();
        emit Unpaused_(msg.sender);
    }

    /// @notice Break-glass signer-set additions (overlap-never-gap, S11). Not the normal
    ///         churn path (that is `rotateSigner`).
    function addSigner(address signer) external onlyAdmin {
        if (signer == address(0)) revert ZeroAddress();
        if (signer == admin || signer == guardian || signer == pendingAdmin) {
            revert InvalidConfiguration();
        }
        isSigner[signer] = true;
        signerEpoch[signer] = keyEpoch;
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlyAdmin {
        isSigner[signer] = false;
        delete signerEpoch[signer];
        emit SignerRemoved(signer);
    }

    /// @notice Raise/lower the bond-backing ceiling. Governance sets this to mirror the
    ///         actual on-chain `BRIDGE_BOND`; `setCaps` cannot exceed it — encoding the
    ///         "raise the bond before the caps" rule on-chain (§7-bis).
    function setBondBackingCapLimit(uint256 newLimit) external onlyAdmin {
        if (windowMintCap > newLimit / 2) revert CapBelowCurrentExposure();
        bondBackingCapLimit = newLimit;
        emit BondBackingCapLimitSet(newLimit);
    }

    /// @notice Set the per-window and per-tx caps. Refuses a window cap above the current
    ///         bond backing — so a cap raise not preceded by a bond raise reverts.
    function setCaps(uint256 newWindowMintCap, uint256 newPerTxMax) external onlyAdmin {
        if (newWindowMintCap == 0 || newPerTxMax == 0 || newPerTxMax > newWindowMintCap) {
            revert InvalidConfiguration();
        }
        if (newWindowMintCap > bondBackingCapLimit / 2) revert CapAboveBondBacking();
        if (newPerTxMax < minRedeemAmount) revert InvalidConfiguration();
        windowMintCap = newWindowMintCap;
        perTxMax = newPerTxMax;
        emit CapsSet(newWindowMintCap, newPerTxMax);
    }

    function setMinimumRedeemAmount(uint256 newMinimum) external onlyAdmin {
        if (newMinimum == 0 || newMinimum > perTxMax) revert InvalidConfiguration();
        minRedeemAmount = newMinimum;
        emit MinimumRedeemAmountSet(newMinimum);
    }

    function setGuardian(address newGuardian) external onlyAdmin {
        if (
            newGuardian == address(0) || newGuardian == admin || newGuardian == pendingAdmin
                || newGuardian == pendingSigner || isAuthorizedSigner(newGuardian)
        ) {
            revert InvalidConfiguration();
        }
        emit GuardianSet(guardian, newGuardian);
        guardian = newGuardian;
    }

    /// @notice Start a two-step admin transfer. The candidate must explicitly accept.
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        if (newAdmin == guardian || newAdmin == pendingSigner || isAuthorizedSigner(newAdmin)) {
            revert InvalidConfiguration();
        }
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        if (msg.sender == guardian || msg.sender == pendingSigner || isAuthorizedSigner(msg.sender))
        {
            revert InvalidConfiguration();
        }
        address previousAdmin = admin;
        admin = msg.sender;
        delete pendingAdmin;
        emit AdminTransferred(previousAdmin, msg.sender);
    }

    /// @dev UUPS upgrade authority: admin (a TimelockController) only.
    function _authorizeUpgrade(address) internal override onlyAdmin { }

    /// @dev Storage gap for future upgrades (this contract's own vars only; OZ v5 bases
    ///      use ERC-7201 namespaced storage and need no gap).
    // `rotationNonce` packs into the unused bytes of the preceding `pendingAdmin`
    // address slot, so adding it does not consume a gap slot.
    uint256[35] private __gap;
}
