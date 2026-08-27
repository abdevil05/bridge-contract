# wBDX bridge contract security fixes (Phase H)

This repository contains the EVM-side `WrappedBDX` contract and the security fixes made
to align it with the Beldex bridge signer and relayer. It is a standalone Foundry project.

> **Status:** this documents implemented and tested fixes. It is not a declaration that
> the complete distributed bridge is production ready. Mainnet deployment still requires
> the external review, custody, migration, persistence, and fault-testing work listed in
> [BRIDGE_SECURITY_FIXES.md](BRIDGE_SECURITY_FIXES.md).

## Layout

```text
src/WrappedBDX.sol                 upgradeable 9-decimal wBDX contract
test/WrappedBDX.t.sol              contract security and regression tests
test/WrappedBDXTimelock.t.sol      timelocked governance tests
script/Deploy.s.sol                UUPS proxy deployment
script/DeployWithTimelock.s.sol    proxy plus TimelockController deployment
devnet/                            local deployment, mint, relay, and rotation scripts
```

## Setup and verification

The repository is pinned to Solidity 0.8.24 and OpenZeppelin v5. Initialize the pinned
submodules and run the checks from the repository root:

```bash
git submodule update --init --recursive
forge build
forge test -vv
forge fmt --check
bash -n devnet/*.sh
```

The current Foundry regression suite contains 54 passing tests.

## Canonical Mint V2 invariant

The load-bearing mint digest is:

```solidity
keccak256(
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
)
```

`MINT_TAG` is `keccak256("BELDEX_BRIDGE_MINT_V2")`. The Rust signer and relayer must
encode the same eight ABI words in exactly this order. This binds a signature to:

- one EVM chain and proxy;
- one signer epoch;
- one recipient and amount; and
- one output of one Beldex transaction.

Any field-order, tag, epoch, or output-index mismatch causes signature recovery to fail.
The corresponding Rust implementation is `bridge/signer/src/watch.rs` in the Beldex
repository.

## Implemented contract fixes

- Per-output replay identity using `(beldexTxid, outputIndex)`, while preserving legacy
  V1 transaction replay markers during an upgrade.
- Fixed-window mint and per-transaction caps with backing for the worst-case two-window
  boundary exposure.
- Monotonic signer epochs, outgoing and incoming committee handoff proofs, a rotation
  challenge period, persistent vetoes, and scoped recovery signers.
- Separate timelocked administration and guardian duties, two-step admin transfer, and
  guarded UUPS upgrades.
- Full CryptoNote block-Base58 decoding for mainnet Beldex standard, subaddress, and
  integrated-address formats, including prefix and checksum validation before burning.
- Nine decimals so one wBDX atomic unit equals one BDX atomic unit.

`redeemToNative` emits `RedeemToNative(address indexed from, uint256 amount,
bytes beldexAddress)`, matching the event decoded by the EVM watcher.

## Operational constraints

- `admin` should be a delayed governance controller, not an EOA or committee signer.
- `guardian`, `admin`, and the active threshold signer must be independent roles.
- Fixed windows can expose almost two complete caps around a boundary; therefore
  `2 * windowMintCap <= bondBackingCapLimit` is enforced.
- Pause the bridge before any contract or signature-schema migration. Mixed Mint V1/V2
  operation is unsupported.
- The contract validates mainnet Beldex recipient formats. A Beldex devnet using devnet
  address prefixes needs an explicit test-only compatibility plan.
- An independent end-to-end security review remains required before mainnet deployment.
