package lnwallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

// taprootUnifiedVectorFile holds the transaction vectors of BOLT 3's "Simple
// taproot channels": the three transaction vectors of bolt-simple-taproot.md,
// with option_unified_sigs. They were generated outside lnd, from the
// unified signature hash of the node software's Python test framework and
// the BIP 327 reference code.
const taprootUnifiedVectorFile = "test_vectors_taproot_unified.json"

// unifiedTaprootHashType is the hash type BOLT 3 gives the MuSig2 key-path
// signature of a simple taproot channel with option_unified_sigs, and the
// broadcaster's own signature on its HTLC transactions.
const unifiedTaprootHashType = txscript.SigHashAll | txscript.SigHashUnified

// TestTaprootUnifiedVectors checks lnd against the spec's vectors for simple
// taproot channels with option_unified_sigs. lnd builds the same three
// channels with the bit and signs them, and for each:
//
//   - the commitment transaction, without its witness, is the spec's, so the
//     fee is the one for weight 969;
//   - the funding input's witness is one 65-byte signature ending in 0x21;
//   - each HTLC-success and HTLC-timeout transaction is the spec's byte for
//     byte, signatures included (0xa3 from the peer, 0x21 from the
//     broadcaster, deterministic BIP 340 signatures);
//   - every signature in both lnd's and the spec's transactions passes the
//     script engine with the unified signature hash;
//   - replaying MuSig2 from the spec's nonces gives the spec's partial and
//     final signatures.
//
// lnd's MuSig2 nonces come from its own derivation, so its witness signature
// differs from the spec's; the replay checks the spec's.
func TestTaprootUnifiedVectors(t *testing.T) {
	withUnifiedSigHash(t)

	jsonData, err := os.ReadFile(taprootUnifiedVectorFile)
	require.NoError(t, err)

	var stored struct {
		Transactions []TransactionTestCase `json:"transactions"`
	}
	require.NoError(t, json.Unmarshal(jsonData, &stored))

	tc := newTaprootTestContext(t)
	tc.unifiedSigs = true

	generated := tc.generateTransactionVectors()
	require.Len(t, generated, len(stored.Transactions))

	fundingPkScript, err := hex.DecodeString(
		tc.generateFundingVector().PkScript,
	)
	require.NoError(t, err)

	for i, want := range stored.Transactions {
		got := generated[i]
		require.Equal(t, want.Name, got.Name)

		t.Run(want.Name, func(t *testing.T) {
			wantTx := decodeTx(t, want.ExpectedCommitmentTxHex)
			gotTx := decodeTx(t, got.ExpectedCommitmentTxHex)

			// The same transaction, so the same fee: the txid
			// leaves out the witness.
			require.Equal(t, wantTx.TxHash(), gotTx.TxHash(),
				"commitment transaction differs")

			for _, tx := range []*wire.MsgTx{wantTx, gotTx} {
				require.Len(t, tx.TxIn[0].Witness, 1)
				sig := tx.TxIn[0].Witness[0]
				require.Len(t, sig, 65)
				require.EqualValues(
					t, unifiedTaprootHashType, sig[64],
				)
			}

			require.Len(t, got.HtlcDescs, len(want.HtlcDescs))
			for j := range want.HtlcDescs {
				require.Equal(t,
					want.HtlcDescs[j].ResolutionTxHex,
					got.HtlcDescs[j].ResolutionTxHex,
					"HTLC transaction %d differs", j,
				)
				require.Equal(t,
					want.HtlcDescs[j].RemotePartialSigHex,
					got.HtlcDescs[j].RemotePartialSigHex,
				)

				htlcTx := decodeTx(
					t, want.HtlcDescs[j].ResolutionTxHex,
				)
				w := htlcTx.TxIn[0].Witness
				require.EqualValues(
					t, unifiedTaprootHashType|
						txscript.SigHashSingle|
						txscript.SigHashAnyOneCanPay,
					w[0][64],
				)
				require.EqualValues(
					t, unifiedTaprootHashType, w[1][64],
				)
			}

			verifyCommitmentTxSig(
				t, want, fundingPkScript, tc.fundingAmount,
			)
			verifyCommitmentTxSig(
				t, got, fundingPkScript, tc.fundingAmount,
			)

			verifyMusig2PartialSigs(
				t, want, fundingPkScript, tc.fundingAmount,
				tc.localFundingPrivkey, tc.remoteFundingPrivkey,
				unifiedTaprootHashType,
			)
		})
	}
}

// TestTaprootUnifiedVectorsNeedTheOptIn checks that the script engine
// refuses the spec's unified vectors without the unified signature hash, as
// a node without the BLAKE2b rules would: the 0x21 and 0xa3 bytes are not
// BIP 341 hash types.
func TestTaprootUnifiedVectorsNeedTheOptIn(t *testing.T) {
	jsonData, err := os.ReadFile(taprootUnifiedVectorFile)
	require.NoError(t, err)

	var stored struct {
		Transactions []TransactionTestCase `json:"transactions"`
	}
	require.NoError(t, json.Unmarshal(jsonData, &stored))

	tc := newTaprootTestContext(t)
	fundingPkScript, err := hex.DecodeString(
		tc.generateFundingVector().PkScript,
	)
	require.NoError(t, err)

	flags := txscript.StandardVerifyFlags &^
		txscript.ScriptVerifyUnifiedSigHash

	for _, want := range stored.Transactions {
		tx := decodeTx(t, want.ExpectedCommitmentTxHex)
		fetcher := txscript.NewCannedPrevOutputFetcher(
			fundingPkScript, int64(tc.fundingAmount),
		)
		vm, err := txscript.NewEngine(
			fundingPkScript, tx, 0, flags, nil,
			txscript.NewTxSigHashes(tx, fetcher),
			int64(tc.fundingAmount), fetcher,
		)
		require.NoError(t, err)
		require.Error(t, vm.Execute(), want.Name)
	}
}

// decodeTx parses a hex-encoded transaction.
func decodeTx(t *testing.T, txHex string) *wire.MsgTx {
	t.Helper()

	raw, err := hex.DecodeString(txHex)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	require.NoError(t, tx.Deserialize(bytes.NewReader(raw)))

	return tx
}

// TestTaprootUnifiedCommitWeight checks the commitment weight BOLT 3 gives a
// simple taproot channel with option_unified_sigs, which both peers compute
// the commitment fee from.
func TestTaprootUnifiedCommitWeight(t *testing.T) {
	require.EqualValues(t, 968, input.TaprootCommitWeight)
	require.EqualValues(t, 969, input.TaprootUnifiedCommitWeight)

	unified := taprootChanType | channeldb.UnifiedSigsBit
	require.EqualValues(t, 969, CommitWeight(unified))
	require.EqualValues(t, 968, CommitWeight(taprootChanType))

	require.Equal(t, unifiedTaprootHashType,
		TaprootCommitSigHashType(unified))
	require.Equal(t, txscript.SigHashDefault,
		TaprootCommitSigHashType(taprootChanType))

	require.EqualValues(t, 67, CommitWitnessWeight(unified))
	require.EqualValues(t, 66, CommitWitnessWeight(taprootChanType))
}
