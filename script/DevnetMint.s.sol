// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";

/// Submits a committee-signed `mint` to a deployed WrappedBDX proxy.
///
/// Takes the raw `r‖s` the Rust signer prints (`Pevm signature: …`, 64 bytes),
/// EIP-2 low-S normalises it (the signer prints the *un*-normalised pair), and
/// resolves `v` by trying both recovery ids against `currentSigner` — so the
/// 65-byte `r‖s‖v` handed to the contract is exactly what OZ `ECDSA.recover`
/// accepts. The digest is recomputed here from live on-chain values, so a
/// mismatch with what the committee signed fails loudly instead of silently.
///
///   PROXY=… TO=… AMOUNT=… BELDEX_TXID=… SIG_RS=0x<64 bytes> \
///     forge script script/DevnetMint.s.sol --rpc-url $RPC --broadcast
contract DevnetMint is Script {
    /// secp256k1 group order — the EIP-2 low-S boundary is N/2.
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function run() external {
        address proxy = vm.envAddress("PROXY");
        address to = vm.envAddress("TO");
        uint256 amount = vm.envUint("AMOUNT");
        uint32 outputIndex = uint32(vm.envOr("OUT_INDEX", uint256(0)));
        bytes32 beldexTxid = vm.envBytes32("BELDEX_TXID");
        bytes memory rs = vm.envBytes("SIG_RS");
        WrappedBDX w = WrappedBDX(proxy);
        bytes memory sig = _mintSignature(w, proxy, to, amount, beldexTxid, outputIndex, rs);
        uint256 balBefore = w.balanceOf(to);

        vm.startBroadcast();
        w.mint(to, amount, beldexTxid, outputIndex, sig);
        vm.stopBroadcast();

        console2.log("balance before:", balBefore);
        console2.log("balance after :", w.balanceOf(to));
        console2.log("totalSupply   :", w.totalSupply());
        console2.log("windowMinted  :", w.windowMinted());
        require(w.balanceOf(to) == balBefore + amount, "balance did not increase by amount");
        require(
            w.isDepositProcessed(beldexTxid, outputIndex), "deposit output not marked processed"
        );
        console2.log("MINT OK - replay guard armed for this deposit output");
    }

    function _mintSignature(
        WrappedBDX w,
        address proxy,
        address to,
        uint256 amount,
        bytes32 beldexTxid,
        uint32 outputIndex,
        bytes memory rs
    ) internal view returns (bytes memory) {
        require(rs.length == 64, "SIG_RS must be exactly 64 bytes (r||s)");
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(rs, 32))
            s := mload(add(rs, 64))
        }
        if (uint256(s) > N / 2) s = bytes32(N - uint256(s));

        bytes32 digest = keccak256(
            abi.encode(
                w.MINT_TAG(),
                block.chainid,
                proxy,
                w.keyEpoch(),
                to,
                amount,
                beldexTxid,
                outputIndex
            )
        );
        address signer = w.currentSigner();
        console2.log("digest       :", vm.toString(digest));
        console2.log("currentSigner:", signer);

        for (uint8 v = 27; v <= 28; ++v) {
            if (ecrecover(digest, v, r, s) == signer) return abi.encodePacked(r, s, v);
        }
        revert("neither recovery id matches currentSigner");
    }
}
