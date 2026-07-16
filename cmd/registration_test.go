package main

import (
	"encoding/json"
	"testing"

	"github.com/hydn-co/substrate/json/polymorphic"
	"github.com/stretchr/testify/require"
)

// TestEveryManifestFeatureEnvelopeTypeIsRegistered guards against shipping a
// feature whose options/payload type is advertised in the manifest but never
// registered with the polymorphic registry. The connector decodes the
// options/payload envelope at start_run via polymorphic.LoadFactory; a missing
// registration is invisible to the build and to direct-construction unit tests,
// surfacing only as a runtime "type ... is not registered" rejection. This test
// reproduces that lookup for every feature the manifest advertises, so it needs
// no manual upkeep as features are added.
func TestEveryManifestFeatureEnvelopeTypeIsRegistered(t *testing.T) {
	manifest := WithManifest()
	require.NotEmpty(t, manifest.Features)

	for name, desc := range manifest.Features {
		// Every feature has a concrete options type, so its discriminator must
		// resolve. Payloads are optional (collectors use NoPayload, whose schema
		// carries no discriminator), so only check those that declare one.
		assertEnvelopeTypeRegistered(t, name, "options", desc.OptionsSchema, true)
		assertEnvelopeTypeRegistered(t, name, "payload", desc.PayloadSchema, false)
	}
}

func assertEnvelopeTypeRegistered(
	t *testing.T,
	feature, kind string,
	schema json.RawMessage,
	requireDiscriminator bool,
) {
	t.Helper()

	var s struct {
		ID string `json:"$id"`
	}
	if len(schema) > 0 {
		require.NoErrorf(t, json.Unmarshal(schema, &s), "feature %q %s schema is not valid JSON", feature, kind)
	}

	if s.ID == "" {
		require.Falsef(t, requireDiscriminator, "feature %q %s schema has no $id discriminator", feature, kind)
		return
	}

	_, err := polymorphic.LoadFactory(s.ID)
	require.NoErrorf(t, err,
		"feature %q %s type %q is not registered with polymorphic; add polymorphic.RegisterType for it "+
			"(internal/options/register.go or internal/payloads/register.go)", feature, kind, s.ID)
}
