#!/usr/bin/env bash
# 05-mint-prep.sh — build a SECOND mint preimage against the ALREADY-DEPLOYED proxy,
# so the H.6 hand-off can be proved in both directions.
#
#     runlog ./devnet/05-mint-prep.sh 0x<fresh-32-byte-beldex-txid>
#
# WHY NOT JUST RE-RUN 01/02.  04-rotate.sh signs off with "re-run 01/02 with a fresh
# BELDEX_TXID against the new share dir". The 02 half of that is right; the 01 half is
# wrong and would quietly destroy what you just proved. 01-deploy.sh deploys a NEW
# implementation and a NEW proxy and initialises it with the ORIGINAL committee as
# initialSigner. You would end up demonstrating that the pre-rotation committee can mint
# on a contract that never rotated — a green run that answers a different question.
# This script touches no deployment: it reads the live proxy and writes devnet/mint2.env.
#
# WHAT IT REFUSES, AND WHY EACH REFUSAL MATTERS
#   * currentSigner() still equal to mint.env's SIGNER_ADDR -> the rotation was never
#     activated; there are not two committees yet to tell apart.
#   * isAuthorizedSigner(retired) == true -> the retired key is still effective for the
#     current key epoch. BadSigner would never fire and the negative leg of the proof is
#     vacuous. This is the one precondition whose
#     absence would make a passing run meaningless rather than merely inconclusive.
#   * a txid already in processedDeposits -> Replay() is checked AFTER BadSigner, so a
#     spent txid would not actually corrupt the negative leg, but it would make the
#     positive leg revert for the wrong reason.
#   * amount over perTxMax, or over the window headroom -> the mint would revert
#     PerTxCap/WindowCap, which reads as "the new committee cannot mint" when in fact the
#     signature was fine.
#
# Output: devnet/mint2.env, or $OUT if set. 07-relay-mint.sh reuses this script with
#         OUT=devnet/relay.env so that the relayer run gets the same battery of
#         preconditions without a second copy of them drifting out of step.

set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(cd "$(dirname "$0")/.." && pwd)"

[ -f devnet/mint.env ] || { echo "!! no devnet/mint.env — this expects an existing deployment" >&2; exit 1; }
# shellcheck disable=SC1091
. devnet/mint.env

lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

OUT="${OUT:-devnet/mint2.env}"
# cast on some builds appends the solidity type in brackets; keep the leading digits only.
num() { printf '%s' "$1" | sed -n 's/^\([0-9][0-9]*\).*/\1/p'; }

TXID="${1:-${NEW_BELDEX_TXID:-}}"
FIRST_OUT_INDEX="${OUT_INDEX:-0}"
OUTPUT_INDEX="${NEW_OUT_INDEX:-0}"
if [ -z "$TXID" ]; then
  echo "usage: $0 0x<fresh-32-byte-beldex-txid>" >&2
  echo "" >&2
  echo "  Any 32-byte value not already spent. The first mint used $BELDEX_TXID." >&2
  echo "  e.g. 0x00000000000000000000000000000000000000000000000000000000feedface" >&2
  exit 1
fi
TXID="$(lc "$TXID")"
case "$TXID" in
  0x*) ;; *) TXID="0x$TXID" ;;
esac
if [ "${#TXID}" -ne 66 ]; then
  echo "!! the beldex txid must be exactly 32 bytes (66 chars incl. 0x), got ${#TXID}" >&2
  exit 1
fi
case "${TXID#0x}" in
  *[!0-9a-f]*) echo "!! the beldex txid contains non-hex characters" >&2; exit 1 ;;
esac
case "$OUTPUT_INDEX" in
  ''|*[!0-9]*) echo "!! NEW_OUT_INDEX must be an unsigned decimal integer" >&2; exit 1 ;;
esac
if [ "$OUTPUT_INDEX" -gt 4294967295 ]; then
  echo "!! NEW_OUT_INDEX exceeds uint32" >&2; exit 1
fi
if [ "$TXID" = "$(lc "$BELDEX_TXID")" ] && [ "$OUTPUT_INDEX" = "$FIRST_OUT_INDEX" ]; then
  echo "!! that exact (txid, outputIndex) pair was used by the first mint." >&2
  exit 1
fi

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# --- live state off the EXISTING proxy ---------------------------------------------------
say "live contract state ($PROXY)"
MINT_TAG_ONCHAIN="$(cast call "$PROXY" 'MINT_TAG()(bytes32)'        --rpc-url "$RPC")"
LIVE_SIGNER="$(lc "$(cast call "$PROXY" 'currentSigner()(address)'  --rpc-url "$RPC")")"
KEY_EPOCH="$(num "$(cast call "$PROXY" 'keyEpoch()(uint64)'         --rpc-url "$RPC")")"
PER_TX_MAX="$(num "$(cast call "$PROXY" 'perTxMax()(uint256)'       --rpc-url "$RPC")")"
WINDOW_CAP="$(num "$(cast call "$PROXY" 'windowMintCap()(uint256)'  --rpc-url "$RPC")")"
WINDOW_MINTED="$(num "$(cast call "$PROXY" 'windowMinted()(uint256)' --rpc-url "$RPC")")"
EPOCH_SECONDS="$(num "$(cast call "$PROXY" 'epochSeconds()(uint256)' --rpc-url "$RPC")")"
PAUSED="$(cast call "$PROXY" 'paused()(bool)' --rpc-url "$RPC" 2>/dev/null || echo unknown)"

RETIRED_SIGNER="$(lc "$SIGNER_ADDR")"
if [ -f devnet/rotate.env ]; then
  # shellcheck disable=SC1091
  ROT_OUT="$(sed -n 's/^OUTGOING_SIGNER=//p' devnet/rotate.env | tail -1)"
  ROT_NEW="$(sed -n 's/^NEW_SIGNER=//p'      devnet/rotate.env | tail -1)"
  [ -n "$ROT_OUT" ] && RETIRED_SIGNER="$(lc "$ROT_OUT")"
fi

printf 'MINT_TAG      : %s\n' "$MINT_TAG_ONCHAIN"
printf 'currentSigner : %s   (keyEpoch %s)\n' "$LIVE_SIGNER" "$KEY_EPOCH"
printf 'retired signer: %s\n' "$RETIRED_SIGNER"
printf 'perTxMax      : %s\n' "$PER_TX_MAX"
printf 'windowMintCap : %s   (windowMinted %s, epochSeconds %s)\n' "$WINDOW_CAP" "$WINDOW_MINTED" "$EPOCH_SECONDS"
printf 'paused        : %s\n' "$PAUSED"

# --- preconditions -----------------------------------------------------------------------
say "preconditions"

if [ "$LIVE_SIGNER" = "$RETIRED_SIGNER" ]; then
  echo "!! currentSigner is still the ORIGINAL committee ($RETIRED_SIGNER)." >&2
  echo "   The rotation was never activated, so there is no second committee to tell" >&2
  echo "   apart from the first. Run devnet/04-rotate.sh first." >&2
  exit 1
fi
echo "currentSigner has moved off the original committee ✓"

if [ -n "${ROT_NEW:-}" ] && [ "$(lc "$ROT_NEW")" != "$LIVE_SIGNER" ]; then
  echo "!! rotate.env names $ROT_NEW as the incoming signer, but the chain says $LIVE_SIGNER." >&2
  echo "   Something rotated the contract other than the ceremony rotate.env records." >&2
  exit 1
fi
[ -n "${ROT_NEW:-}" ] && echo "chain agrees with rotate.env on the incoming signer ✓"

AUTHORIZED="$(cast call "$PROXY" 'isAuthorizedSigner(address)(bool)' "$RETIRED_SIGNER" --rpc-url "$RPC")"
if [ "$(lc "$AUTHORIZED")" != "false" ]; then
  echo "!! isAuthorizedSigner[$RETIRED_SIGNER] = $AUTHORIZED" >&2
  echo "   The retired committee is still effective in the current key epoch, so mint()" >&2
  echo "   would accept it and the negative half of this proof would be vacuous." >&2
  exit 1
fi
echo "isAuthorizedSigner(retired) = false ✓"

SPENT="$(cast call "$PROXY" 'isDepositProcessed(bytes32,uint32)(bool)' "$TXID" "$OUTPUT_INDEX" --rpc-url "$RPC")"
if [ "$(lc "$SPENT")" != "false" ]; then
  echo "!! deposit ($TXID, $OUTPUT_INDEX) is already processed." >&2
  exit 1
fi
echo "the txid is unspent ✓"

if [ "$PER_TX_MAX" -lt "$AMOUNT" ]; then
  echo "!! AMOUNT $AMOUNT is above perTxMax $PER_TX_MAX — the mint would revert PerTxCap()," >&2
  echo "   which would look like the new committee being rejected. Lower AMOUNT." >&2
  exit 1
fi
HEADROOM=$(( WINDOW_CAP - WINDOW_MINTED ))
if [ "$HEADROOM" -lt "$AMOUNT" ]; then
  echo "!! only $HEADROOM left in this mint window and AMOUNT is $AMOUNT — the mint would" >&2
  echo "   revert WindowCap(). Note the window is a FIXED calendar window of ${EPOCH_SECONDS}s," >&2
  echo "   so it resets on the boundary; warping time past it would also clear this." >&2
  exit 1
fi
printf 'cap headroom ✓  (%s of %s left in this %ss window, need %s)\n' \
  "$HEADROOM" "$WINDOW_CAP" "$EPOCH_SECONDS" "$AMOUNT"

if [ "$(lc "$PAUSED")" = "true" ]; then
  echo "!! the contract is paused — mint() reverts before any of this is exercised." >&2
  exit 1
fi

# --- the preimage ------------------------------------------------------------------------
# Byte-for-byte what WrappedBDX.mint() keccaks:
#   abi.encode(MINT_TAG, block.chainid, address(this), keyEpoch,
#              to, amount, beldexTxid, outputIndex)
# Eight static words = 256 bytes. Built from the tag read off THIS proxy, not from mint.env,
# so a redeployment between then and now cannot go unnoticed.
say "mint preimage"
if [ "$(lc "$MINT_TAG_ONCHAIN")" != "$(lc "$MINT_TAG")" ]; then
  echo "!! the on-chain MINT_TAG ($MINT_TAG_ONCHAIN) differs from mint.env ($MINT_TAG)." >&2
  echo "   That means \$PROXY is not the contract mint.env was written for." >&2
  exit 1
fi
PREIMAGE2="$(cast abi-encode \
  'f(bytes32,uint256,address,uint64,address,uint256,bytes32,uint32)' \
  "$MINT_TAG_ONCHAIN" "$CHAIN_ID" "$PROXY" "$KEY_EPOCH" "$TO" "$AMOUNT" "$TXID" "$OUTPUT_INDEX")"
DIGEST2="$(cast keccak "$PREIMAGE2")"
HEXLEN="$(printf '%s' "${PREIMAGE2#0x}" | wc -c | tr -d ' ')"
if [ "$HEXLEN" -ne 512 ]; then
  echo "!! expected 512 hex chars (256 bytes / 8 ABI words) — got $HEXLEN." >&2
  exit 1
fi

cat > "$OUT" <<EOF
# generated by devnet/05-mint-prep.sh — do not edit by hand
# A second mint against the SAME deployment as mint.env, after the H.6 rotation.
RPC=$RPC
CHAIN_ID=$CHAIN_ID
PROXY=$PROXY
DEPLOYER_KEY=$DEPLOYER_KEY
TO=$TO
AMOUNT=$AMOUNT
BELDEX_TXID=$TXID
OUT_INDEX=$OUTPUT_INDEX
MINT_TAG=$MINT_TAG_ONCHAIN
LIVE_SIGNER=$LIVE_SIGNER
RETIRED_SIGNER=$RETIRED_SIGNER
KEY_EPOCH=$KEY_EPOCH
PREIMAGE=$PREIMAGE2
DIGEST=$DIGEST2
EOF

cat <<EOF

  SECOND MINT PREPARED  (no deployment was touched)
  ─────────────────────────────────────────────────────────────────────
  contract        : $PROXY  (chain id $CHAIN_ID)
  live signer     : $LIVE_SIGNER   (keyEpoch $KEY_EPOCH)  <- must be able to mint
  retired signer  : $RETIRED_SIGNER   <- must NOT be able to mint
  to / amount     : $TO / $AMOUNT
  beldex txid     : $TXID  (unspent)
  preimage        : $(( HEXLEN / 2 )) bytes ($HEXLEN hex chars)
  digest          : $DIGEST2

  written to $OUT

  Next — have BOTH committees sign this ONE preimage. Same digest, same everything;
  the only difference is which share tree signs. That is what makes the comparison a
  statement about the key rather than about the message.

    cd <beldex>/utils/local-devnet

    # the promoted committee (default 'shares') -> mint-sign-*.log
    runlog ./sign-pevm.sh mint $PREIMAGE2

    # the retired committee ('shares-gen0')     -> mint-old-sign-*.log
    SHARE_SUBDIR=shares-gen0 LOG_PREFIX=mint-old runlog ./sign-pevm.sh mint $PREIMAGE2

EOF

if [ "$OUT" = "devnet/mint2.env" ]; then
  cat <<EOF
  then come back and run:

    runlog ./devnet/06-handoff-proof.sh

EOF
else
  cat <<EOF
  For the relayer run only the promoted committee's signature is needed — the retired
  one is harmless but unused. Then:

    runlog ./devnet/07-relay-mint.sh

EOF
fi
