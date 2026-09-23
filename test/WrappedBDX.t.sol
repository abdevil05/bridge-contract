// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {
    UUPSUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// A trivial V2 to prove UUPS upgrades are admin-gated (adds one function).
contract WrappedBDXV2 is WrappedBDX {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract WrappedBDXAddressHarness is WrappedBDX {
    function validAddress(string calldata value) external pure returns (bool) {
        return _isValidMainnetBeldexAddress(bytes(value));
    }

    function validAddressForNetwork(string calldata value, uint8 network)
        external
        pure
        returns (bool)
    {
        return _isValidBeldexAddress(bytes(value), network);
    }
}

contract WrappedBDXTest is Test {
    WrappedBDX internal w;

    address internal admin = address(0xA11CE);
    address internal guardian = address(0xBEEF01);
    address internal alice = address(0xB0B);
    address internal relayer = address(0xF00D);

    // Committee Pevm key (a normal secp256k1 key here; in production it is the
    // CGGMP21 group key's address). vm.sign lets us produce the committee signature.
    uint256 internal committeePk = 0xC0FFEE;
    address internal committee;

    uint256 internal constant COIN = 1e9; // 9 decimals
    uint256 internal constant WINDOW_CAP = 1_000_000 * COIN;
    uint256 internal constant PER_TX_MAX = 100_000 * COIN;
    uint256 internal constant BOND_LIMIT = 2_400_000 * COIN; // covers the 2x fixed-window burst
    uint256 internal constant EPOCH_SECONDS = 1 days;
    uint256 internal constant ROTATE_TIMELOCK = 2 days;
    string internal constant VALID_BDX_ADDRESS =
        "bxbvtWFZzkG3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ19VznYdFi";
    string internal constant VALID_BDX_SUBADDRESS =
        "83kGvLy7goj6i8totRApfb6i8totRApfb6i8totRApfb6i8totRApfb6i8totRApfb6i8totRApfb6i8totRApfb4r4r4YR";
    string internal constant VALID_BDX_INTEGRATED =
        "4DGKGVvUGwL9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9XoXC9Kh3Gz1vFG2Nb";
    string internal constant VALID_DEVNET_BDX_ADDRESS =
        "52Uf16SYAhv3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ3rZwuSi5uqJ2yfJf3y";

    function setUp() public {
        committee = vm.addr(committeePk);
        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initializeForNetworkWithFee,
            (
                WrappedBDX.InitializationConfig(
                    admin,
                    guardian,
                    committee,
                    WINDOW_CAP,
                    PER_TX_MAX,
                    BOND_LIMIT,
                    EPOCH_SECONDS,
                    ROTATE_TIMELOCK,
                    0,
                    1
                ),
                uint256(0)
            )
        );
        w = WrappedBDX(address(new ERC1967Proxy(address(impl), init)));
        vm.warp(10 * EPOCH_SECONDS + 123); // land mid-window, deterministic
    }

    // ---- signing helpers -----------------------------------------------------------
    function _mintDigest(address to, uint256 amount, bytes32 txid) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                w.MINT_TAG(), block.chainid, address(w), w.keyEpoch(), to, amount, txid, uint32(0)
            )
        );
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v); // r‖s‖v, the 65-byte layout ECDSA.recover wants
    }

    function _mintSig(uint256 pk, address to, uint256 amount, bytes32 txid)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _mintDigest(to, amount, txid));
    }

    function _mintSigAt(uint256 pk, address to, uint256 amount, bytes32 txid, uint32 outputIndex)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = keccak256(
            abi.encode(
                w.MINT_TAG(), block.chainid, address(w), w.keyEpoch(), to, amount, txid, outputIndex
            )
        );
        return _sign(pk, digest);
    }

    function _rotateDigest(uint64 newEpoch, address newSigner) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                w.ROTATE_TAG(),
                block.chainid,
                address(w),
                newEpoch,
                newSigner,
                uint64(1),
                block.timestamp + 1 days
            )
        );
    }

    function _rotateSigner(address newSigner, uint64 newEpoch, bytes memory sig) internal {
        w.rotateSigner(newSigner, newEpoch, 1, block.timestamp + 1 days, sig);
    }

    function _activateDigest(uint64 newEpoch, address newSigner) internal view returns (bytes32) {
        return
            keccak256(abi.encode(w.ACTIVATE_TAG(), block.chainid, address(w), newEpoch, newSigner));
    }

    function _activateSig(uint256 pk, uint64 newEpoch, address newSigner)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _activateDigest(newEpoch, newSigner));
    }

    // =================================================================================
    // Tag value: keccak256 of the domain string, byte-for-byte equal to the signer's
    // hardcoded `watch.rs::MINT_TAG`.
    // =================================================================================
    function test_MintTag_isKeccakOfDomainString() public view {
        assertEq(w.MINT_TAG(), keccak256("BELDEX_BRIDGE_MINT_V2"));
        assertEq(w.ROTATE_TAG(), keccak256("BELDEX_BRIDGE_ROTATE_V2"));
        assertEq(w.ACTIVATE_TAG(), keccak256("BELDEX_BRIDGE_ACTIVATE_V1"));
        assertEq(w.decimals(), 9);
    }

    // =================================================================================
    // Mint (H.2)
    // =================================================================================
    function test_Mint_validCommitteeSig_mintsOnce() public {
        bytes32 txid = keccak256("dep-1");
        uint256 amt = 1_000 * COIN;
        bytes memory sig = _mintSig(committeePk, alice, amt, txid);

        vm.prank(relayer); // permissionless relay
        w.mint(alice, amt, txid, 0, sig);

        assertEq(w.balanceOf(alice), amt);
        assertEq(w.windowMinted(), amt);
        assertTrue(w.processedDeposits(keccak256(abi.encode(txid, uint32(0)))));
    }

    function test_Mint_replayReverts() public {
        bytes32 txid = keccak256("dep-replay");
        uint256 amt = 1_000 * COIN;
        bytes memory sig = _mintSig(committeePk, alice, amt, txid);
        w.mint(alice, amt, txid, 0, sig);

        vm.expectRevert(WrappedBDX.Replay.selector);
        w.mint(alice, amt, txid, 0, sig);
    }

    function test_Mint_multipleOutputsOfOneTransactionAreIndependent() public {
        bytes32 txid = keccak256("batch-deposit");
        w.mint(alice, 1 * COIN, txid, 0, _mintSigAt(committeePk, alice, 1 * COIN, txid, 0));
        w.mint(alice, 2 * COIN, txid, 1, _mintSigAt(committeePk, alice, 2 * COIN, txid, 1));
        assertEq(w.balanceOf(alice), 3 * COIN);

        bytes memory replay = _mintSigAt(committeePk, alice, 2 * COIN, txid, 1);
        vm.expectRevert(WrappedBDX.Replay.selector);
        w.mint(alice, 2 * COIN, txid, 1, replay);
    }

    function test_Mint_signatureBindsOutputIndex() public {
        bytes32 txid = keccak256("output-binding");
        bytes memory forZero = _mintSigAt(committeePk, alice, 1 * COIN, txid, 0);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, txid, 1, forZero);
    }

    function test_Mint_zeroAmountReverts() public {
        bytes32 txid = keccak256("zero");
        bytes memory sig = _mintSig(committeePk, alice, 0, txid);
        vm.expectRevert(WrappedBDX.ZeroAmount.selector);
        w.mint(alice, 0, txid, 0, sig);
    }

    function test_Mint_legacyRawTxidEntryRemainsClosedAfterUpgrade() public {
        bytes32 txid = keccak256("legacy-deposit");
        vm.store(address(w), keccak256(abi.encode(txid, uint256(6))), bytes32(uint256(1)));
        bytes memory sig = _mintSigAt(committeePk, alice, 1 * COIN, txid, 0);
        vm.expectRevert(WrappedBDX.Replay.selector);
        w.mint(alice, 1 * COIN, txid, 0, sig);
    }

    function test_Mint_nonSignerReverts() public {
        uint256 roguePk = 0xBADBAD;
        bytes32 txid = keccak256("dep-rogue");
        bytes memory sig = _mintSig(roguePk, alice, 1 * COIN, txid);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, txid, 0, sig);
    }

    function test_Mint_adminCannotMint() public {
        // The admin holds no committee key; a "mint" it could author is just a non-signer
        // signature. Prove the admin address cannot conjure a valid mint.
        uint256 adminPk = 0xA11CE; // arbitrary; not the committee key
        bytes32 txid = keccak256("dep-admin");
        bytes memory sig = _mintSig(adminPk, alice, 1 * COIN, txid);
        vm.prank(admin);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, txid, 0, sig);
    }

    function test_Mint_wrongChain_reverts() public {
        bytes32 txid = keccak256("dep-chain");
        uint256 amt = 1 * COIN;
        bytes memory sig = _mintSig(committeePk, alice, amt, txid); // signed under current chainid

        vm.chainId(block.chainid + 1); // domain separation: a different chain's digest differs
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, amt, txid, 0, sig);
    }

    function test_Mint_wrongContract_reverts() public {
        // Deploy a second instance; a signature bound to `w` must not mint on `w2`.
        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initialize,
            (
                admin,
                guardian,
                committee,
                WINDOW_CAP,
                PER_TX_MAX,
                BOND_LIMIT,
                EPOCH_SECONDS,
                ROTATE_TIMELOCK
            )
        );
        WrappedBDX w2 = WrappedBDX(address(new ERC1967Proxy(address(impl), init)));

        bytes32 txid = keccak256("dep-addr");
        uint256 amt = 1 * COIN;
        bytes memory sigForW = _mintSig(committeePk, alice, amt, txid); // bound to address(w)

        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w2.mint(alice, amt, txid, 0, sigForW);
    }

    function test_Mint_perTxCap_reverts() public {
        bytes32 txid = keccak256("dep-pertx");
        uint256 amt = PER_TX_MAX + 1;
        bytes memory sig = _mintSig(committeePk, alice, amt, txid);
        vm.expectRevert(WrappedBDX.PerTxCap.selector);
        w.mint(alice, amt, txid, 0, sig);
    }

    // =================================================================================
    // Fixed calendar window: cap holds within a window and resets on its boundary. The
    // configuration explicitly backs the resulting worst-case 2x boundary burst.
    // =================================================================================
    function test_Mint_windowCap_holdsThenResetsOnCalendarBoundary() public {
        // Fill the window to exactly the cap using perTxMax-sized mints.
        uint256 n = WINDOW_CAP / PER_TX_MAX; // 10
        for (uint256 i = 0; i < n; i++) {
            bytes32 txid = keccak256(abi.encode("fill", i));
            w.mint(alice, PER_TX_MAX, txid, 0, _mintSig(committeePk, alice, PER_TX_MAX, txid));
        }
        assertEq(w.windowMinted(), WINDOW_CAP);

        // One more in the SAME window exceeds the cap → revert (no rolling burst).
        bytes32 over = keccak256("over");
        // Sig computed BEFORE expectRevert: _mintSig staticcalls MINT_TAG() through
        // the proxy, and an inline call would consume the expectRevert.
        bytes memory overSig = _mintSig(committeePk, alice, 1 * COIN, over);
        vm.expectRevert(WrappedBDX.WindowCap.selector);
        w.mint(alice, 1 * COIN, over, 0, overSig);

        // A few seconds later — still the same calendar window — still capped.
        vm.warp(block.timestamp + 5);
        vm.expectRevert(WrappedBDX.WindowCap.selector);
        w.mint(alice, 1 * COIN, over, 0, overSig);

        // Cross the calendar boundary → the window resets; minting resumes.
        uint256 nextBoundary = (block.timestamp / EPOCH_SECONDS + 1) * EPOCH_SECONDS;
        vm.warp(nextBoundary);
        bytes32 fresh = keccak256("fresh-window");
        w.mint(alice, PER_TX_MAX, fresh, 0, _mintSig(committeePk, alice, PER_TX_MAX, fresh));
        assertEq(w.windowMinted(), PER_TX_MAX);
    }

    function test_Mint_boundaryBurstIsExplicitlyBackedAtTwoTimesCap() public {
        uint256 nextBoundary = (block.timestamp / EPOCH_SECONDS + 1) * EPOCH_SECONDS;
        vm.warp(nextBoundary - 1);
        for (uint256 i = 0; i < WINDOW_CAP / PER_TX_MAX; ++i) {
            bytes32 txid = keccak256(abi.encode("before", i));
            w.mint(alice, PER_TX_MAX, txid, 0, _mintSig(committeePk, alice, PER_TX_MAX, txid));
        }
        vm.warp(nextBoundary);
        for (uint256 i = 0; i < WINDOW_CAP / PER_TX_MAX; ++i) {
            bytes32 txid = keccak256(abi.encode("after", i));
            w.mint(alice, PER_TX_MAX, txid, 0, _mintSig(committeePk, alice, PER_TX_MAX, txid));
        }
        assertEq(w.totalSupply(), 2 * WINDOW_CAP);
        assertGe(w.bondBackingCapLimit(), 2 * WINDOW_CAP);
    }

    // =================================================================================
    // Redeem (H.3) — emits the exact event the E.2 watcher decodes.
    // =================================================================================
    event RedeemToNative(address indexed from, uint256 amount, bytes beldexAddress);
    event Rotated(address indexed newSigner, uint64 newKeyEpoch);
    event BreakGlassSignerSet(address indexed newSigner, uint64 newKeyEpoch);

    function _feeToken(uint256 minimum, uint256 fee) internal returns (WrappedBDX) {
        WrappedBDX impl = new WrappedBDX();
        WrappedBDX.InitializationConfig memory config = WrappedBDX.InitializationConfig(
            admin,
            guardian,
            committee,
            WINDOW_CAP,
            PER_TX_MAX,
            BOND_LIMIT,
            EPOCH_SECONDS,
            ROTATE_TIMELOCK,
            0,
            minimum
        );
        return WrappedBDX(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(WrappedBDX.initializeForNetworkWithFee, (config, fee))
                )
            )
        );
    }

    function test_Redeem_nativeMaximumCannotBeRaisedByGovernance() public {
        uint256 maximum = w.NATIVE_RELEASE_MAX();
        deal(address(w), alice, maximum + 1, true);
        vm.prank(admin);
        w.setCaps(WINDOW_CAP, PER_TX_MAX); // 100k mint cap is legal; redemption stays <=50k
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.PerTxCap.selector);
        w.redeemToNative(maximum + 1, VALID_BDX_ADDRESS);
        assertEq(w.balanceOf(alice), maximum + 1);
        assertEq(w.totalSupply(), maximum + 1);
        vm.prank(alice);
        w.redeemToNative(maximum, VALID_BDX_ADDRESS);
        assertEq(w.balanceOf(alice), 1);
    }

    function test_Redeem_feeMustLeavePositivePayout() public {
        WrappedBDX token = _feeToken(101, 100);
        deal(address(token), alice, 1000, true);
        for (uint256 amount = 99; amount <= 100; ++amount) {
            vm.prank(alice);
            vm.expectRevert(WrappedBDX.BelowMinimumRedeem.selector);
            token.redeemToNative(amount, VALID_BDX_ADDRESS);
            assertEq(token.balanceOf(alice), 1000);
            assertEq(token.totalSupply(), 1000);
        }
        vm.prank(alice);
        token.redeemToNative(101, VALID_BDX_ADDRESS);
        assertEq(token.balanceOf(alice), 899);
    }

    function test_Redeem_configurationCannotInvalidateFeeOrMinimum() public {
        WrappedBDX token = _feeToken(101, 100);
        uint256 maximum = token.NATIVE_RELEASE_MAX();
        vm.startPrank(admin);
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        token.setMinimumRedeemAmount(100);
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        token.setMinimumRedeemAmount(maximum + 1);
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        token.setCaps(WINDOW_CAP, 100);
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        token.initializeV4(101); // cannot replace an already established fee
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        token.initializeV3(0, 100); // older migration entrypoint cannot bypass minimum
        vm.stopPrank();
        assertEq(token.redemptionFee(), 100);
    }

    function test_Redeem_legacyInitializerRequiresExplicitFeeMigration() public {
        WrappedBDX impl = new WrappedBDX();
        WrappedBDX token = WrappedBDX(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        WrappedBDX.initialize,
                        (
                            admin,
                            guardian,
                            committee,
                            WINDOW_CAP,
                            PER_TX_MAX,
                            BOND_LIMIT,
                            EPOCH_SECONDS,
                            ROTATE_TIMELOCK
                        )
                    )
                )
            )
        );
        deal(address(token), alice, COIN, true);
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.RedemptionNotConfigured.selector);
        token.redeemToNative(COIN, VALID_BDX_ADDRESS);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        token.initializeV4(0);
        vm.startPrank(admin);
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        token.initializeV4(100); // initial minimum is 1
        token.setMinimumRedeemAmount(101);
        token.initializeV4(100);
        vm.stopPrank();
        assertTrue(token.redemptionFeeInitialized());
        vm.prank(alice);
        token.redeemToNative(101, VALID_BDX_ADDRESS);
    }

    function test_Redeem_badFeeConfigurationRejectedAtDeployment() public {
        // Call through this test contract so the expectation encloses the entire creation.
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        this.deployFeeToken(100, 100);
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        this.deployFeeToken(100, 101);
        uint256 maximum = w.NATIVE_RELEASE_MAX();
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        this.deployFeeToken(maximum + 1, 100);
    }

    function deployFeeToken(uint256 minimum, uint256 fee) external returns (WrappedBDX) {
        return _feeToken(minimum, fee);
    }

    function test_Redeem_burnsAndEmits() public {
        bytes32 txid = keccak256("dep-redeem");
        uint256 amt = 5_000 * COIN;
        w.mint(alice, amt, txid, 0, _mintSig(committeePk, alice, amt, txid));

        string memory bdxAddr = VALID_BDX_ADDRESS;
        vm.expectEmit(true, false, false, true, address(w));
        emit RedeemToNative(alice, 2_000 * COIN, bytes(bdxAddr));
        vm.prank(alice);
        w.redeemToNative(2_000 * COIN, bdxAddr);

        assertEq(w.balanceOf(alice), amt - 2_000 * COIN);
        assertEq(w.totalSupply(), amt - 2_000 * COIN);
    }

    function test_Redeem_perTxMax_reverts() public {
        // Fund alice past perTxMax with two cap-respecting mints (a single
        // PER_TX_MAX+1 mint is itself rejected by the mint-side per-tx cap).
        bytes32 t1 = keccak256("dep-redeem2a");
        w.mint(alice, PER_TX_MAX, t1, 0, _mintSig(committeePk, alice, PER_TX_MAX, t1));
        bytes32 t2 = keccak256("dep-redeem2b");
        w.mint(alice, 2 * COIN, t2, 0, _mintSig(committeePk, alice, 2 * COIN, t2));
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.PerTxCap.selector);
        w.redeemToNative(PER_TX_MAX + 1, "bxSomeAddress");
    }

    function test_Redeem_emptyAddress_reverts() public {
        bytes32 txid = keccak256("dep-redeem3");
        w.mint(alice, 10 * COIN, txid, 0, _mintSig(committeePk, alice, 10 * COIN, txid));
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.BadRedeemAddress.selector);
        w.redeemToNative(1 * COIN, "");
    }

    function test_Redeem_nonBase58AddressRevertsBeforeBurn() public {
        bytes32 txid = keccak256("bad-address");
        w.mint(alice, 10 * COIN, txid, 0, _mintSig(committeePk, alice, 10 * COIN, txid));
        bytes memory bad = bytes(VALID_BDX_ADDRESS);
        bad[0] = 0x30; // ASCII zero is not in the Base58 alphabet
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.BadRedeemAddress.selector);
        w.redeemToNative(1 * COIN, string(bad));
        assertEq(w.balanceOf(alice), 10 * COIN);
    }

    function test_Redeem_rejectsShapeOnlySubaddressBeforeBurn() public {
        bytes32 txid = keccak256("fund-subaddress-redeem");
        w.mint(alice, 2 * COIN, txid, 0, _mintSig(committeePk, alice, 2 * COIN, txid));

        string memory subaddress = string(new bytes(95));
        bytes memory chars = bytes(subaddress);
        for (uint256 i = 0; i < chars.length; ++i) {
            chars[i] = 0x31;
        }
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.BadRedeemAddress.selector);
        w.redeemToNative(1 * COIN, string(chars));
        assertEq(w.balanceOf(alice), 2 * COIN);
    }

    // These fixtures use the native network prefixes and valid CryptoNote checksums.
    // Rejection is based on unsupported payout type, not a malformed address.
    function test_Redeem_rejectsChecksummedMainnetUnsupportedTypesBeforeBurn() public {
        _assertUnsupportedRecipients(w, VALID_BDX_SUBADDRESS, VALID_BDX_INTEGRATED);
    }

    function _networkToken(uint8 network) internal returns (WrappedBDX) {
        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initializeForNetwork,
            (
                admin,
                guardian,
                committee,
                WINDOW_CAP,
                PER_TX_MAX,
                BOND_LIMIT,
                EPOCH_SECONDS,
                ROTATE_TIMELOCK,
                network,
                COIN
            )
        );
        WrappedBDX token = WrappedBDX(address(new ERC1967Proxy(address(impl), init)));
        vm.prank(admin);
        token.initializeV4(0);
        return token;
    }

    function _assertUnsupportedRecipients(
        WrappedBDX token,
        string memory subaddress,
        string memory integrated
    ) internal {
        deal(address(token), alice, 2 * COIN, true);
        uint256 supplyBefore = token.totalSupply();
        string[2] memory recipients = [subaddress, integrated];
        for (uint256 i; i < recipients.length; ++i) {
            vm.recordLogs();
            vm.prank(alice);
            vm.expectRevert(WrappedBDX.BadRedeemAddress.selector);
            token.redeemToNative(COIN, recipients[i]);
            assertEq(token.balanceOf(alice), 2 * COIN, "rejection must preserve balance");
            assertEq(token.totalSupply(), supplyBefore, "rejection must preserve supply");
            assertEq(vm.getRecordedLogs().length, 0, "rejection must emit no burn/request");
        }
    }

    function test_Redeem_rejectsChecksummedTestnetUnsupportedTypesBeforeBurn() public {
        _assertUnsupportedRecipients(
            _networkToken(1),
            "Ba7ut1xB2i69ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt6pT3Cby",
            "A4orkkajZJS9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9aMMP3uxJnP8h3L6Cy"
        );
    }

    function test_Redeem_acceptsChecksummedTestnetStandardAddress() public {
        WrappedBDX token = _networkToken(1);
        deal(address(token), alice, COIN, true);
        vm.prank(alice);
        token.redeemToNative(
            COIN,
            "9u7BjwmEx2v9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt6qvUpsa"
        );
        assertEq(token.balanceOf(alice), 0);
        assertEq(token.totalSupply(), 0);
    }

    function test_Redeem_rejectsChecksummedDevnetUnsupportedTypesBeforeBurn() public {
        _assertUnsupportedRecipients(
            _networkToken(2),
            "74BkWDqrcV89ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt6rojW6r",
            "5DUMMLqRvYS9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9aMMP3uxJnP8hqH6sZ"
        );
    }

    function test_Redeem_acceptsChecksummedDevnetStandardAddress() public {
        WrappedBDX token = _networkToken(2);
        deal(address(token), alice, COIN, true);
        vm.prank(alice);
        token.redeemToNative(
            COIN,
            "53mgLY1wKGv9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt9ZhqiL8FjVt6noo51d"
        );
        assertEq(token.balanceOf(alice), 0);
        assertEq(token.totalSupply(), 0);
    }

    function test_Redeem_networkPolicyIsExplicit() public {
        WrappedBDXAddressHarness harness = new WrappedBDXAddressHarness();
        assertTrue(
            harness.validAddressForNetwork(VALID_DEVNET_BDX_ADDRESS, harness.BELDEX_DEVNET())
        );
        assertFalse(
            harness.validAddressForNetwork(VALID_DEVNET_BDX_ADDRESS, harness.BELDEX_MAINNET())
        );

        WrappedBDX devImpl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initializeForNetwork,
            (
                admin,
                guardian,
                committee,
                WINDOW_CAP,
                PER_TX_MAX,
                BOND_LIMIT,
                EPOCH_SECONDS,
                ROTATE_TIMELOCK,
                uint8(2),
                COIN
            )
        );
        WrappedBDX dev = WrappedBDX(address(new ERC1967Proxy(address(devImpl), init)));
        vm.prank(admin);
        dev.initializeV4(0);
        assertEq(dev.beldexNetwork(), dev.BELDEX_DEVNET());
        assertEq(dev.minRedeemAmount(), COIN);

        deal(address(dev), alice, 2 * COIN, true);
        vm.prank(alice);
        dev.redeemToNative(COIN, VALID_DEVNET_BDX_ADDRESS);
        assertEq(dev.balanceOf(alice), COIN);
    }

    function test_Redeem_minimumBoundsPermanentReleaseStateGrowth() public {
        vm.prank(admin);
        w.setMinimumRedeemAmount(COIN);
        deal(address(w), alice, COIN, true);

        vm.prank(alice);
        vm.expectRevert(WrappedBDX.BelowMinimumRedeem.selector);
        w.redeemToNative(COIN - 1, VALID_BDX_ADDRESS);

        vm.prank(admin);
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        w.setMinimumRedeemAmount(PER_TX_MAX + 1);
    }

    function test_Redeem_rejectsBadChecksumBeforeBurn() public {
        bytes32 txid = keccak256("fund-bad-checksum");
        w.mint(alice, 2 * COIN, txid, 0, _mintSig(committeePk, alice, 2 * COIN, txid));
        bytes memory bad = bytes(VALID_BDX_ADDRESS);
        uint256 last = bad.length - 1;
        bad[last] = bad[last] == bytes1("1") ? bytes1("2") : bytes1("1");
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.BadRedeemAddress.selector);
        w.redeemToNative(1 * COIN, string(bad));
        assertEq(w.balanceOf(alice), 2 * COIN);
    }

    // =================================================================================
    // Pause (H.4) — blocks mint and permissionless signer-authority changes.
    // =================================================================================
    function test_Pause_blocksMintAndRotation_butBreakGlassStillWorks() public {
        vm.prank(guardian);
        w.pause();

        bytes32 txid = keccak256("dep-paused");
        bytes memory sig = _mintSig(committeePk, alice, 1 * COIN, txid);
        vm.expectRevert(); // PausableUpgradeable: EnforcedPause
        w.mint(alice, 1 * COIN, txid, 0, sig);

        // A compromised current signer cannot stage a cutover while the incident is paused.
        address newSigner = vm.addr(0xD00D);
        bytes memory rot = _sign(committeePk, _rotateDigest(2, newSigner));
        vm.expectRevert(); // EnforcedPause
        _rotateSigner(newSigner, 2, rot);

        // Timelocked governance retains the deliberate repair path while paused.
        vm.prank(admin);
        w.breakGlassSetSigner(newSigner, 2);
        assertEq(w.currentSigner(), newSigner);
        assertTrue(w.paused());
    }

    // =================================================================================
    // Admin & caps (H.4) — bond-before-caps guard.
    // =================================================================================
    function test_SetCaps_aboveBondBacking_reverts() public {
        vm.prank(admin);
        vm.expectRevert(WrappedBDX.CapAboveBondBacking.selector);
        w.setCaps(BOND_LIMIT + 1, PER_TX_MAX);
    }

    function test_SetCaps_requiresBondRaisedFirst() public {
        uint256 higherCap = 1_300_000 * COIN;
        uint256 higherBacking = 2 * higherCap;
        // Cannot jump the cap first.
        vm.prank(admin);
        vm.expectRevert(WrappedBDX.CapAboveBondBacking.selector);
        w.setCaps(higherCap, PER_TX_MAX);

        // Raise the bond backing, THEN the cap succeeds.
        vm.prank(admin);
        w.setBondBackingCapLimit(higherBacking);
        vm.prank(admin);
        w.setCaps(higherCap, PER_TX_MAX);
        assertEq(w.windowMintCap(), higherCap);
    }

    function test_BondLimitCannotDropBelowTwoWindowCoverage() public {
        vm.prank(admin);
        vm.expectRevert(WrappedBDX.CapBelowCurrentExposure.selector);
        w.setBondBackingCapLimit(2 * WINDOW_CAP - 1);
    }

    function test_AdminFns_onlyAdmin() public {
        vm.expectRevert(WrappedBDX.NotGuardianOrAdmin.selector);
        w.pause();
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.setCaps(1, 1);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.setMinimumRedeemAmount(1);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.addSigner(alice);
    }

    function test_BreakGlassSigner_letsAdminNameMintAuthority() public {
        address bg = vm.addr(0xBEEF);
        vm.prank(admin);
        w.addSigner(bg);

        bytes32 txid = keccak256("dep-bg");
        uint256 amt = 3 * COIN;
        w.mint(alice, amt, txid, 0, _mintSig(0xBEEF, alice, amt, txid));
        assertEq(w.balanceOf(alice), amt);
    }

    function test_AdminTransferRequiresAcceptance() public {
        address nextAdmin = address(0xCAFE);
        vm.prank(admin);
        w.transferAdmin(nextAdmin);
        assertEq(w.admin(), admin);
        assertEq(w.pendingAdmin(), nextAdmin);

        vm.expectRevert(WrappedBDX.NotPendingAdmin.selector);
        w.acceptAdmin();

        vm.prank(nextAdmin);
        w.acceptAdmin();
        assertEq(w.admin(), nextAdmin);
        assertEq(w.pendingAdmin(), address(0));
    }

    function test_V1MigrationRequiresTwoWindowBackingAndSetsGuardian() public {
        address replacementGuardian = makeAddr("replacementGuardian");

        vm.prank(admin);
        vm.expectRevert(WrappedBDX.CapAboveBondBacking.selector);
        w.initializeV2(replacementGuardian, WINDOW_CAP);

        vm.prank(admin);
        w.initializeV2(replacementGuardian, 2 * WINDOW_CAP);
        assertEq(w.guardian(), replacementGuardian);
        assertEq(w.bondBackingCapLimit(), 2 * WINDOW_CAP);

        vm.prank(admin);
        vm.expectRevert();
        w.initializeV2(replacementGuardian, 2 * WINDOW_CAP);
    }

    function test_GuardianCanPauseButCannotUnpause() public {
        vm.prank(guardian);
        w.pause();
        vm.prank(guardian);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.unpause();
        vm.prank(admin);
        w.unpause();
        assertFalse(w.paused());
    }

    // =================================================================================
    // UUPS upgrade (H.4) — admin-only.
    // =================================================================================
    function test_Upgrade_onlyAdmin() public {
        WrappedBDXV2 v2 = new WrappedBDXV2();

        // Non-admin cannot upgrade.
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        UUPSUpgradeable(address(w)).upgradeToAndCall(address(v2), "");

        // Admin can.
        vm.prank(admin);
        UUPSUpgradeable(address(w)).upgradeToAndCall(address(v2), "");
        assertEq(WrappedBDXV2(address(w)).version(), 2);
        // State survives the upgrade.
        assertEq(w.currentSigner(), committee);
    }

    // =================================================================================
    // Rotation (H.6)
    // =================================================================================
    function _newSignerPair() internal pure returns (uint256 pk, address addr) {
        pk = 0x5165A;
        addr = vm.addr(pk);
    }

    function test_Rotation_proposeThenActivateAfterTimelock() public {
        (uint256 newPk, address newSigner) = _newSignerPair();
        bytes memory rot = _sign(committeePk, _rotateDigest(2, newSigner));

        vm.prank(relayer);
        _rotateSigner(newSigner, 2, rot);
        assertEq(w.pendingSigner(), newSigner);

        // Before the window elapses, activation reverts.
        bytes memory activateSig = _activateSig(newPk, 2, newSigner);
        vm.expectRevert(WrappedBDX.RotationNotReady.selector);
        w.activateRotation(activateSig);

        // Old key still mints during the challenge window.
        bytes32 t1 = keccak256("pre-activate");
        w.mint(alice, 1 * COIN, t1, 0, _mintSig(committeePk, alice, 1 * COIN, t1));

        // After the window, anyone activates.
        vm.warp(w.pendingActivateAt());
        vm.prank(relayer);
        w.activateRotation(activateSig);
        assertEq(w.currentSigner(), newSigner);
        assertEq(w.keyEpoch(), 2);

        // New key mints; old key is now rejected (clean cutover).
        bytes32 t2 = keccak256("post-new");
        w.mint(alice, 1 * COIN, t2, 0, _mintSig(newPk, alice, 1 * COIN, t2));
        bytes32 t3 = keccak256("post-old");
        bytes memory oldSig = _mintSig(committeePk, alice, 1 * COIN, t3);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, t3, 0, oldSig);
    }

    function test_Rotation_staleEpoch_reverts() public {
        (, address newSigner) = _newSignerPair();
        // keyEpoch is 1; proposals must be exactly the next epoch.
        bytes memory rot = _sign(committeePk, _rotateDigest(1, newSigner));
        vm.expectRevert(WrappedBDX.InvalidEpoch.selector);
        _rotateSigner(newSigner, 1, rot);
    }

    function test_Rotation_cannotAdvanceEpochWithoutChangingKey() public {
        bytes memory rot = _sign(committeePk, _rotateDigest(2, committee));
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        _rotateSigner(committee, 2, rot);

        vm.prank(admin);
        vm.expectRevert(WrappedBDX.InvalidConfiguration.selector);
        w.breakGlassSetSigner(committee, 2);
    }

    function test_Rotation_wrongContractDigest_reverts() public {
        (, address newSigner) = _newSignerPair();
        // Sign a rotate digest bound to a DIFFERENT contract address.
        bytes32 foreign = keccak256(
            abi.encode(
                w.ROTATE_TAG(),
                block.chainid,
                address(0xDEAD),
                uint64(2),
                newSigner,
                uint64(1),
                block.timestamp + 1 days
            )
        );
        bytes memory rot = _sign(committeePk, foreign);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        _rotateSigner(newSigner, 2, rot);
    }

    function test_Rotation_notByCurrentSigner_reverts() public {
        (, address newSigner) = _newSignerPair();
        // Signed by a non-committee key.
        bytes memory rot = _sign(0xBADBAD, _rotateDigest(2, newSigner));
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        _rotateSigner(newSigner, 2, rot);
    }

    function test_Rotation_cannotOverwritePendingProposal() public {
        (, address first) = _newSignerPair();
        _rotateSigner(first, 2, _sign(committeePk, _rotateDigest(2, first)));
        address second = vm.addr(0x2222);
        bytes memory secondSig = _sign(committeePk, _rotateDigest(2, second));
        vm.expectRevert(WrappedBDX.PendingRotationExists.selector);
        _rotateSigner(second, 2, secondSig);
    }

    function test_Rotation_requiresIncomingProof() public {
        (, address newSigner) = _newSignerPair();
        _rotateSigner(newSigner, 2, _sign(committeePk, _rotateDigest(2, newSigner)));
        vm.warp(w.pendingActivateAt());
        bytes memory wrong = _activateSig(committeePk, 2, newSigner);
        vm.expectRevert(WrappedBDX.IncomingNotReady.selector);
        w.activateRotation(wrong);
        assertEq(w.currentSigner(), committee);
    }

    function test_Rotation_vetoedProposalCannotBeReplayed() public {
        (, address newSigner) = _newSignerPair();
        bytes memory proposal = _sign(committeePk, _rotateDigest(2, newSigner));
        _rotateSigner(newSigner, 2, proposal);
        vm.prank(guardian);
        w.vetoRotation();

        vm.expectRevert(WrappedBDX.RotationIsVetoed.selector);
        _rotateSigner(newSigner, 2, proposal);
        assertEq(w.pendingActivateAt(), 0);
    }

    function test_Rotation_expiredAuthorizationReverts() public {
        (, address newSigner) = _newSignerPair();
        uint64 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = keccak256(
            abi.encode(
                w.ROTATE_TAG(), block.chainid, address(w), uint64(2), newSigner, nonce, deadline
            )
        );
        bytes memory proposal = _sign(committeePk, digest);
        vm.warp(deadline + 1);
        vm.expectRevert(WrappedBDX.RotationAuthorizationExpired.selector);
        w.rotateSigner(newSigner, 2, nonce, deadline, proposal);
    }

    function test_Rotation_nonceMakesClearedVetoAuthorizationSingleUse() public {
        (, address newSigner) = _newSignerPair();
        uint64 nonce = 1;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 digest = keccak256(
            abi.encode(
                w.ROTATE_TAG(), block.chainid, address(w), uint64(2), newSigner, nonce, deadline
            )
        );
        bytes memory proposal = _sign(committeePk, digest);
        w.rotateSigner(newSigner, 2, nonce, deadline, proposal);
        assertEq(w.rotationNonce(), nonce);

        vm.prank(guardian);
        w.vetoRotation();
        vm.prank(admin);
        w.clearVetoedProposal(newSigner, 2);

        vm.expectRevert(WrappedBDX.InvalidRotationNonce.selector);
        w.rotateSigner(newSigner, 2, nonce, deadline, proposal);
    }

    function test_RecoverySignerAutomaticallyExpiresOnRotation() public {
        uint256 recoveryPk = 0xBEEF;
        address recovery = vm.addr(recoveryPk);
        vm.prank(admin);
        w.addSigner(recovery);
        assertTrue(w.isAuthorizedSigner(recovery));

        (uint256 newPk, address newSigner) = _newSignerPair();
        _rotateSigner(newSigner, 2, _sign(committeePk, _rotateDigest(2, newSigner)));
        vm.warp(w.pendingActivateAt());
        w.activateRotation(_activateSig(newPk, 2, newSigner));
        assertFalse(w.isAuthorizedSigner(recovery));

        bytes32 txid = keccak256("expired-recovery");
        bytes memory stale = _mintSig(recoveryPk, alice, 1 * COIN, txid);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, txid, 0, stale);
    }

    function test_Rotation_vetoedCannotActivate() public {
        (uint256 newPk, address newSigner) = _newSignerPair();
        bytes memory rot = _sign(committeePk, _rotateDigest(2, newSigner));
        _rotateSigner(newSigner, 2, rot);

        vm.prank(admin);
        w.vetoRotation();

        assertEq(w.pendingActivateAt(), 0, "veto cancels pending state");
        vm.warp(block.timestamp + ROTATE_TIMELOCK);
        bytes memory activateSig = _activateSig(newPk, 2, newSigner);
        vm.expectRevert(WrappedBDX.RotationNotReady.selector);
        w.activateRotation(activateSig);
        assertEq(w.currentSigner(), committee); // unchanged
    }

    function test_Rotation_breakGlassWhenNoHandoff() public {
        address bgSigner = vm.addr(0xC0DE);
        vm.prank(admin);
        w.breakGlassSetSigner(bgSigner, 2);
        assertEq(w.currentSigner(), bgSigner);
        assertEq(w.keyEpoch(), 2);
    }

    /// H.6.3: a break-glass must emit `Rotated` (in addition to `BreakGlassSignerSet`) so
    /// the L1 bond-release gate is satisfied uniformly — governance moving the key on-chain
    /// releases honest departers' bonds even when a refusing minority blocked a hand-off.
    function test_Rotation_breakGlass_emitsRotatedForBondGate() public {
        address bgSigner = vm.addr(0xC0DE);
        vm.expectEmit(true, false, false, true, address(w));
        emit Rotated(bgSigner, 2);
        vm.expectEmit(true, false, false, true, address(w));
        emit BreakGlassSignerSet(bgSigner, 2);
        vm.prank(admin);
        w.breakGlassSetSigner(bgSigner, 2);
        assertEq(w.currentSigner(), bgSigner);
        assertEq(w.keyEpoch(), 2);
    }

    function test_Rotation_breakGlass_onlyAdmin_andMonotonic() public {
        address bgSigner = vm.addr(0xC0DE);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.breakGlassSetSigner(bgSigner, 2);

        vm.prank(admin);
        vm.expectRevert(WrappedBDX.InvalidEpoch.selector);
        w.breakGlassSetSigner(bgSigner, 1); // equal to current keyEpoch
    }
}
