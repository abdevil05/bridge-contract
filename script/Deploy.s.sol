// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// Deploys the WrappedBDX implementation behind an ERC1967 UUPS proxy.
///
/// Per-chain values come from the E.3 registry. `ADMIN` must be a timelock and
/// `GUARDIAN` a separate fast incident-response multisig. The backing limit is the
/// allocation for this chain, not the bridge's global bond.
///
///   forge script script/Deploy.s.sol \
///     --rpc-url $RPC --broadcast \
///     --sig 'run()'
contract Deploy is Script {
    function run() external {
        address admin = vm.envAddress("ADMIN");
        address guardian = vm.envAddress("GUARDIAN");
        address initialSigner = vm.envAddress("INITIAL_SIGNER");
        uint256 windowMintCap = vm.envUint("WINDOW_MINT_CAP");
        uint256 perTxMax = vm.envUint("PER_TX_MAX");
        uint256 bondBackingCapLimit = vm.envUint("BOND_BACKING_CAP_LIMIT");
        uint256 epochSeconds = vm.envUint("EPOCH_SECONDS");
        uint256 rotateTimelock = vm.envUint("ROTATE_TIMELOCK");
        uint8 beldexNetwork = uint8(vm.envUint("BELDEX_NETWORK"));
        uint256 minRedeemAmount = vm.envUint("MIN_REDEEM_AMOUNT");

        require(admin.code.length > 0, "ADMIN must be a contract");
        require(guardian != address(0) && guardian != initialSigner, "bad GUARDIAN");
        require(admin != guardian, "admin=guardian");
        require(admin != initialSigner, "admin=signer");
        require(windowMintCap > 0 && perTxMax > 0 && perTxMax <= windowMintCap, "bad caps");
        require(windowMintCap <= bondBackingCapLimit / 2, "backing must cover 2x window");
        require(epochSeconds > 0 && rotateTimelock > 0, "zero delay/window");
        require(beldexNetwork <= 2, "bad Beldex network");
        require(minRedeemAmount > 0 && minRedeemAmount <= perTxMax, "bad redeem minimum");

        vm.startBroadcast();

        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initializeForNetwork,
            (
                admin,
                guardian,
                initialSigner,
                windowMintCap,
                perTxMax,
                bondBackingCapLimit,
                epochSeconds,
                rotateTimelock,
                beldexNetwork,
                minRedeemAmount
            )
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), init);

        vm.stopBroadcast();

        console2.log("WrappedBDX impl :", address(impl));
        console2.log("WrappedBDX proxy:", address(proxy));
    }
}
