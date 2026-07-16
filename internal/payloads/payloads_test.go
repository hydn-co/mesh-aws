package payloads_test

import (
	"encoding/json"
	"testing"

	"github.com/hydn-co/substrate/json/polymorphic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/payloads"
)

func TestShouldRegisterAddUserToGroupPayloadWhenPackageInitializes(t *testing.T) {
	created, err := polymorphic.CreateInstance("mesh://aws/actions/add_user_to_group_payload")

	require.NoError(t, err)
	require.NotNil(t, created)
	assert.IsType(t, &payloads.AWSAddUserToGroupPayload{}, created)
}

func TestShouldRoundTripAddUserToGroupPayloadWhenEncodedPolymorphically(t *testing.T) {
	original := &payloads.AWSAddUserToGroupPayload{UserName: "alice", GroupName: "admins"}
	envelope := polymorphic.NewEnvelope(original)

	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	var restored polymorphic.Envelope
	err = json.Unmarshal(data, &restored)

	require.NoError(t, err)
	restoredPayload, ok := restored.Content.(*payloads.AWSAddUserToGroupPayload)
	require.True(t, ok)
	assert.Equal(t, original.GetDiscriminator(), restoredPayload.GetDiscriminator())
	assert.Equal(t, original.UserName, restoredPayload.UserName)
	assert.Equal(t, original.GroupName, restoredPayload.GroupName)
}
