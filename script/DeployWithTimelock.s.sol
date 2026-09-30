// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { TimelockController } from "@openzeppelin/contracts/governance/TimelockController.sol";

/// Production deploy (Phase G.2): the wBDX `config.admin` is an OpenZeppelin `TimelockController`,
/// never an EOA and never a committee signer. The timelock's **proposer** is the governance
/// multisig (a Safe, passed as `PROPOSER`); executors are open (address(0)) so anyone can
/// execute an operation once its delay has elapsed — the delay, not the executor, is the
/// safety property. This makes every config.admin action (pause, addSigner/removeSigner, setCaps
/// with the bond-before-caps guard, UUPS upgrade) subject to a public, timelocked review
/// window (S8/S11).
///
///   MIN_DELAY, PROPOSER (governance multisig), GUARDIAN, INITIAL_SIGNER, WINDOW_MINT_CAP, PER_TX_MAX,
///   BOND_BACKING_CAP_LIMIT, EPOCH_SECONDS, ROTATE_TIMELOCK, BELDEX_NETWORK,
///   MIN_REDEEM_AMOUNT, REDEMPTION_FEE (atomic BDX; minimum must exceed the fee).
contract DeployWithTimelock is Script {
    function run() external {
        WrappedBDX.InitializationConfig memory config;
        uint256 minDelay = vm.envUint("MIN_DELAY");
        address proposer = vm.envAddress("PROPOSER"); // governance multisig
        config.guardian = vm.envAddress("GUARDIAN"); // fast pause/veto multisig
        config.signer = vm.envAddress("INITIAL_SIGNER");
        config.windowCap = vm.envUint("WINDOW_MINT_CAP");
        config.txMax = vm.envUint("PER_TX_MAX");
        config.backing = vm.envUint("BOND_BACKING_CAP_LIMIT");
        config.epochSeconds = vm.envUint("EPOCH_SECONDS");
        config.rotationDelay = vm.envUint("ROTATE_TIMELOCK");
        config.network = uint8(vm.envOr("BELDEX_NETWORK", uint256(0)));
        config.minimum = vm.envOr("MIN_REDEEM_AMOUNT", uint256(1));

        require(
            minDelay > 0 && config.rotationDelay > 0 && config.epochSeconds > 0, "zero delay/window"
        );
        require(proposer != address(0) && config.guardian != address(0), "zero governance");
        require(proposer != config.signer && config.guardian != config.signer, "governance=signer");
        require(proposer != config.guardian, "proposer=guardian");
        require(
            config.windowCap > 0 && config.txMax > 0 && config.txMax <= config.windowCap, "bad caps"
        );
        require(config.windowCap <= config.backing / 2, "backing must cover 2x window");
        require(config.network <= 2, "bad Beldex network");
        require(config.minimum > 0 && config.minimum <= config.txMax, "bad redeem minimum");

        uint256 redemptionFee = vm.envUint("REDEMPTION_FEE");
        require(
            redemptionFee >= 30_000_000 && config.minimum > redemptionFee
                && config.minimum <= 50_000 * 1e9,
            "bad redemption fee/minimum"
        );

        vm.startBroadcast();

        // Timelock: the multisig proposes; execution is permissionless (address(0)); no
        // extra admin (self-administered), so no lingering privileged key.
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // open executor: anyone may execute after the delay
        TimelockController timelock = new TimelockController(
            minDelay,
            proposers,
            executors,
            address(0) /* self-administered */
        );

        WrappedBDX impl = new WrappedBDX();
        config.admin = address(timelock);
        bytes memory init =
            abi.encodeCall(WrappedBDX.initializeForNetworkWithFee, (config, redemptionFee));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), init);

        vm.stopBroadcast();

        console2.log("TimelockController :", address(timelock));
        console2.log("WrappedBDX impl    :", address(impl));
        console2.log("WrappedBDX proxy   :", address(proxy));
    }
}
