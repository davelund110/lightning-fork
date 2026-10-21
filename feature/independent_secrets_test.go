package feature

import (
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestNoIndependentSecrets checks that the feature manager advertises
// option_independent_secrets in init and node_announcement unless told not
// to (lnd tells it not to unless protocol.independent-secrets is set), and
// only as optional, so peers without it still open ordinary channels.
func TestNoIndependentSecrets(t *testing.T) {
	t.Parallel()

	for _, off := range []bool{false, true} {
		m, err := NewManager(Config{NoIndependentSecrets: off})
		require.NoError(t, err)

		for _, set := range []Set{SetInit, SetNodeAnn} {
			fv := m.Get(set)
			require.Equal(t, !off,
				fv.IsSet(lnwire.IndependentSecretsOptional),
				"set %v, NoIndependentSecrets=%v", set, off)
			require.False(t,
				fv.IsSet(lnwire.IndependentSecretsRequired))
			require.NoError(t, ValidateDeps(fv), "set %v", set)
		}
	}
}

// TestIndependentSecretsDependsOnChannelType pins the dependency on explicit
// channel type negotiation, the only way the add-on is ever agreed.
func TestIndependentSecretsDependsOnChannelType(t *testing.T) {
	t.Parallel()

	vec := func(bits ...lnwire.FeatureBit) *lnwire.FeatureVector {
		return lnwire.NewFeatureVector(
			lnwire.NewRawFeatureVector(bits...), lnwire.Features,
		)
	}

	err := ValidateDeps(vec(lnwire.IndependentSecretsOptional))
	require.ErrorContains(t, err, "missing feature dependency")

	require.NoError(t, ValidateDeps(vec(
		lnwire.IndependentSecretsOptional,
		lnwire.ExplicitChannelTypeOptional,
	)))
}
