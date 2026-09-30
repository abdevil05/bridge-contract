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
        WrappedBDX.InitializationConfig memory config;
        config.admin = vm.envAddress("ADMIN");
        config.guardian = vm.envAddress("GUARDIAN");
        config.signer = vm.envAddress("INITIAL_SIGNER");
        config.windowCap = vm.envUint("WINDOW_MINT_CAP");
        config.txMax = vm.envUint("PER_TX_MAX");
        config.backing = vm.envUint("BOND_BACKING_CAP_LIMIT");
        config.epochSeconds = vm.envUint("EPOCH_SECONDS");
        config.rotationDelay = vm.envUint("ROTATE_TIMELOCK");
        config.network = uint8(vm.envUint("BELDEX_NETWORK"));
        config.minimum = vm.envUint("MIN_REDEEM_AMOUNT");

        require(config.admin.code.length > 0, "ADMIN must be a contract");
        require(config.guardian != address(0) && config.guardian != config.signer, "bad GUARDIAN");
        require(config.admin != config.guardian, "admin=guardian");
        require(config.admin != config.signer, "admin=signer");
        require(
            config.windowCap > 0 && config.txMax > 0 && config.txMax <= config.windowCap, "bad caps"
        );
        require(config.windowCap <= config.backing / 2, "backing must cover 2x window");
        require(config.epochSeconds > 0 && config.rotationDelay > 0, "zero delay/window");
        require(config.network <= 2, "bad Beldex network");
        require(config.minimum > 0 && config.minimum <= config.txMax, "bad redeem minimum");

        uint256 redemptionFee = vm.envUint("REDEMPTION_FEE");
        require(
            redemptionFee >= 30_000_000 && config.minimum > redemptionFee
                && config.minimum <= 50_000 * 1e9,
            "bad redemption fee/minimum"
        );

        vm.startBroadcast();

        WrappedBDX impl = new WrappedBDX();
        bytes memory init =
            abi.encodeCall(WrappedBDX.initializeForNetworkWithFee, (config, redemptionFee));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), init);

        vm.stopBroadcast();

        console2.log("WrappedBDX impl :", address(impl));
        console2.log("WrappedBDX proxy:", address(proxy));
    }
}
