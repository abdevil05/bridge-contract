#!/usr/bin/env bash
# 01-deploy.sh — stand up a local anvil, deploy WrappedBDX behind its ERC1967
# proxy with the devnet committee's Pevm address as initialSigner, and emit the
# REAL ABI-encoded mint preimage for the committee to threshold-sign.
#
# Run from the bridge-contract repo root:
#     runlog ./devnet/01-deploy.sh
#
# Output: devnet/mint.env  (sourced by 02-mint.sh)

set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p devnet
umask 077

# ── inputs ───────────────────────────────────────────────────────────────────
# The wBDX signer address = the CURRENT committee's Pevm group address (derive it from
# the live shares with sign-pevm.sh, or read the `wBDX signer :` line of any Pevm run).
# Accepted as SIGNER_ADDR or INITIAL_SIGNER (the docs use both). There is deliberately
# NO default: a silently-stale baked-in address deploys a contract the committee cannot
# sign for, and the deploy's own sanity check then "passes" against the wrong value.
SIGNER_ADDR="${SIGNER_ADDR:-${INITIAL_SIGNER:-}}"
if [ -z "$SIGNER_ADDR" ]; then
  echo "!! set SIGNER_ADDR (or INITIAL_SIGNER) to the committee's Pevm address, e.g.:" >&2
  echo "     SIGNER_ADDR=0x<pevm addr> ./devnet/01-deploy.sh" >&2
  echo "   Get it from the current shares:" >&2
  echo "     cd ~/Niyas/projects/beldex/utils/local-devnet" >&2
  echo "     runlog ./sign-pevm.sh raw 0x\$(printf 'ab%.0s' {1..32})   # read 'wBDX signer : 0x…'" >&2
  exit 1
fi

# Anvil dev account #0 deploys and proposes timelocked operations. The contract admin is
# the TimelockController deployed below, not this EOA. These public keys remain suitable
# only for a disposable localhost chain.
DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
DEPLOYER="${DEPLOYER:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
# anvil account #1; intentionally distinct from the deployer/admin and committee signer.
GUARDIAN="${GUARDIAN:-0x70997970C51812dc3A010C7d01b50e0d17dc79C8}"
RPC="${RPC:-http://127.0.0.1:8545}"

# wBDX has 9 decimals (matches BDX atomic units).
AMOUNT="${AMOUNT:-12345000000}"                    # 12.345 BDX
PER_TX_MAX="${PER_TX_MAX:-1000000000000}"          # 1,000 BDX
WINDOW_MINT_CAP="${WINDOW_MINT_CAP:-10000000000000}"       # 10,000 BDX / window
BOND_BACKING_CAP_LIMIT="${BOND_BACKING_CAP_LIMIT:-100000000000000}"  # 100,000 BDX
EPOCH_SECONDS="${EPOCH_SECONDS:-86400}"
ROTATE_TIMELOCK="${ROTATE_TIMELOCK:-3600}"
MIN_DELAY="${MIN_DELAY:-3600}"
BELDEX_NETWORK="${BELDEX_NETWORK:-2}"             # 0 mainnet, 1 testnet, 2 devnet
REDEMPTION_FEE="${REDEMPTION_FEE:?set REDEMPTION_FEE in atomic BDX (fixed native withdrawal fee)}"
MIN_REDEEM_AMOUNT="${MIN_REDEEM_AMOUNT:-1000000000}" # 1 BDX; bounds release-ref growth
TO="${TO:-$DEPLOYER}"
# Stand-in for the Beldex deposit txid that backs this mint (the replay key).
BELDEX_TXID="${BELDEX_TXID:-0x00000000000000000000000000000000000000000000000000000000decafbad}"
OUT_INDEX="${OUT_INDEX:-0}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

for b in anvil cast forge; do
  command -v "$b" >/dev/null || { echo "missing $b — is foundry on PATH? (~/.foundry/bin)"; exit 1; }
done

# ── 1. anvil ─────────────────────────────────────────────────────────────────
say "anvil"
if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "already up at $RPC"
else
  nohup anvil --host 127.0.0.1 --port 8545 --chain-id 31337 \
    > devnet/anvil.log 2>&1 &
  echo $! > devnet/anvil.pid
  for _ in $(seq 1 40); do
    cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
    sleep 0.25
  done
  cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 || { echo "anvil did not come up; see devnet/anvil.log"; exit 1; }
  echo "started (pid $(cat devnet/anvil.pid)), log devnet/anvil.log"
fi
CHAIN_ID="$(cast chain-id --rpc-url "$RPC")"
echo "chain id: $CHAIN_ID"

# ── 2–3. timelock + implementation + proxy -----------------------------------
say "deploy TimelockController + WrappedBDX proxy"
DEPLOY_OUT="$(
  MIN_DELAY="$MIN_DELAY" PROPOSER="$DEPLOYER" GUARDIAN="$GUARDIAN" \
  INITIAL_SIGNER="$SIGNER_ADDR" WINDOW_MINT_CAP="$WINDOW_MINT_CAP" \
  PER_TX_MAX="$PER_TX_MAX" BOND_BACKING_CAP_LIMIT="$BOND_BACKING_CAP_LIMIT" \
  EPOCH_SECONDS="$EPOCH_SECONDS" ROTATE_TIMELOCK="$ROTATE_TIMELOCK" \
  BELDEX_NETWORK="$BELDEX_NETWORK" MIN_REDEEM_AMOUNT="$MIN_REDEEM_AMOUNT" REDEMPTION_FEE="$REDEMPTION_FEE" \
  forge script script/DeployWithTimelock.s.sol:DeployWithTimelock \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast -vv
)"
printf '%s\n' "$DEPLOY_OUT"
address_from_log() {
  printf '%s\n' "$DEPLOY_OUT" | sed -n "s/.*$1[[:space:]]*:[[:space:]]*\(0x[0-9A-Fa-f]\{40\}\).*/\1/p" | tail -1
}
TIMELOCK="$(address_from_log 'TimelockController')"
IMPL="$(address_from_log 'WrappedBDX impl')"
PROXY="$(address_from_log 'WrappedBDX proxy')"
if [ -z "$TIMELOCK" ] || [ -z "$IMPL" ] || [ -z "$PROXY" ]; then
  echo "!! could not parse one or more deployment addresses from forge output" >&2
  exit 1
fi
ADMIN="$TIMELOCK"
echo "timelock: $TIMELOCK"
echo "impl:     $IMPL"
echo "proxy:    $PROXY"

# ── 4. sanity-read the live state ────────────────────────────────────────────
say "on-chain state"
MINT_TAG="$(cast call "$PROXY" 'MINT_TAG()(bytes32)' --rpc-url "$RPC")"
CUR_SIGNER="$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC")"
KEY_EPOCH="$(cast call "$PROXY" 'keyEpoch()(uint64)' --rpc-url "$RPC" | sed -n 's/^\([0-9][0-9]*\).*/\1/p')"
printf 'name        : %s\n' "$(cast call "$PROXY" 'name()(string)' --rpc-url "$RPC")"
printf 'decimals    : %s\n' "$(cast call "$PROXY" 'decimals()(uint8)' --rpc-url "$RPC")"
printf 'MINT_TAG    : %s\n' "$MINT_TAG"
printf 'currentSigner: %s\n' "$CUR_SIGNER"
printf 'guardian     : %s\n' "$(cast call "$PROXY" 'guardian()(address)' --rpc-url "$RPC")"
printf 'admin        : %s\n' "$(cast call "$PROXY" 'admin()(address)' --rpc-url "$RPC")"
printf 'BDX network  : %s\n' "$(cast call "$PROXY" 'beldexNetwork()(uint8)' --rpc-url "$RPC")"
printf 'min redeem   : %s\n' "$(cast call "$PROXY" 'minRedeemAmount()(uint256)' --rpc-url "$RPC")"
printf 'keyEpoch     : %s\n' "$KEY_EPOCH"
if [ "$(echo "$CUR_SIGNER" | tr 'A-Z' 'a-z')" != "$(echo "$SIGNER_ADDR" | tr 'A-Z' 'a-z')" ]; then
  echo "!! currentSigner != the committee Pevm address"; exit 1
fi

# ── 5. the real mint preimage ────────────────────────────────────────────────
# Byte-for-byte what WrappedBDX.mint() keccaks:
#   abi.encode(MINT_TAG, block.chainid, address(this), keyEpoch,
#              to, amount, beldexTxid, outputIndex)
say "mint preimage"
PREIMAGE="$(cast abi-encode \
  'f(bytes32,uint256,address,uint64,address,uint256,bytes32,uint32)' \
  "$MINT_TAG" "$CHAIN_ID" "$PROXY" "$KEY_EPOCH" "$TO" "$AMOUNT" "$BELDEX_TXID" "$OUT_INDEX")"
DIGEST="$(cast keccak "$PREIMAGE")"
printf 'to          : %s\n' "$TO"
printf 'amount      : %s atomic units (%s wBDX @ 9 decimals)\n' "$AMOUNT" "$(awk -v a="$AMOUNT" 'BEGIN{printf "%.9f", a/1000000000}')"
printf 'beldexTxid  : %s\n' "$BELDEX_TXID"
printf 'outputIndex : %s\n' "$OUT_INDEX"
printf 'preimage    : %s\n' "$PREIMAGE"
printf 'digest      : %s\n' "$DIGEST"

cat > devnet/mint.env <<EOF
# generated by devnet/01-deploy.sh
RPC=$RPC
CHAIN_ID=$CHAIN_ID
IMPL=$IMPL
PROXY=$PROXY
TIMELOCK=$TIMELOCK
ADMIN=$ADMIN
SIGNER_ADDR=$SIGNER_ADDR
GUARDIAN=$GUARDIAN
DEPLOYER=$DEPLOYER
DEPLOYER_KEY=$DEPLOYER_KEY
BELDEX_NETWORK=$BELDEX_NETWORK
MIN_REDEEM_AMOUNT=$MIN_REDEEM_AMOUNT
REDEMPTION_FEE=$REDEMPTION_FEE
TO=$TO
AMOUNT=$AMOUNT
BELDEX_TXID=$BELDEX_TXID
OUT_INDEX=$OUT_INDEX
KEY_EPOCH=$KEY_EPOCH
MINT_TAG=$MINT_TAG
PREIMAGE=$PREIMAGE
DIGEST=$DIGEST
EOF
chmod 600 devnet/mint.env
echo
echo "wrote devnet/mint.env"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
NEXT — threshold-sign this preimage on the devnet committee.
From ~/Niyas/projects/beldex/utils/local-devnet run:

  runlog ./sign-mint.sh $PREIMAGE

(or set BRIDGE_SIGNER_SIGN_PREIMAGE=$PREIMAGE
 in the C.3 sign loop from bridge/signer/README.md, with
 BRIDGE_SIGNER_SIGN_LEG=pevm)

Then come back here and run:

  runlog ./devnet/02-mint.sh
────────────────────────────────────────────────────────────────────────────
EOF
