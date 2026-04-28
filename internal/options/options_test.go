package options_test

import (
	"encoding/json"
	"testing"

	"github.com/fgrzl/json/polymorphic"
	"github.com/hydn-co/mesh-aws/internal/options"
	_ "github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsersOptions_Discriminator(t *testing.T) {
	o := &options.UsersOptions{}
	assert.Equal(t, "mesh://aws/options/users", o.GetDiscriminator())
}

func TestUsersOptions_GetSpaces(t *testing.T) {
	o := &options.UsersOptions{}
	sp := o.GetSpaces()
	assert.Contains(t, sp, spaces.Accounts)
}

func TestUsersOptions_GetRequirements(t *testing.T) {
	o := &options.UsersOptions{}
	assert.Equal(t, []string{"iam"}, o.GetRequirements())
}

func TestGroupsOptions_Discriminator(t *testing.T) {
	o := &options.GroupsOptions{}
	assert.Equal(t, "mesh://aws/options/groups", o.GetDiscriminator())
}

func TestRolesOptions_Discriminator(t *testing.T) {
	o := &options.RolesOptions{}
	assert.Equal(t, "mesh://aws/options/roles", o.GetDiscriminator())
}

func TestPoliciesOptions_Discriminator(t *testing.T) {
	o := &options.PoliciesOptions{}
	assert.Equal(t, "mesh://aws/options/policies", o.GetDiscriminator())
}

func TestActivityOptions_Discriminator(t *testing.T) {
	o := &options.ActivityOptions{}
	assert.Equal(t, "mesh://aws/options/activity", o.GetDiscriminator())
}

func TestActivityOptions_GetSpaces(t *testing.T) {
	o := &options.ActivityOptions{}
	assert.Equal(t, []spaces.Space{spaces.Activity}, o.GetSpaces())
}

func TestActivityOptions_GetRequirements(t *testing.T) {
	o := &options.ActivityOptions{}
	assert.Equal(t, []string{"cloudtrail"}, o.GetRequirements())
}

func TestUsersOptions_PolymorphicRoundTrip(t *testing.T) {
	original := &options.UsersOptions{}
	env := polymorphic.NewEnvelope(original)

	data, err := json.Marshal(env)
	require.NoError(t, err)

	var restored polymorphic.Envelope
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	restoredOpts, ok := restored.Content.(*options.UsersOptions)
	require.True(t, ok, "expected *options.UsersOptions, got %T", restored.Content)
	assert.Equal(t, original.GetDiscriminator(), restoredOpts.GetDiscriminator())
}

func TestGroupsOptions_PolymorphicRoundTrip(t *testing.T) {
	original := &options.GroupsOptions{}
	env := polymorphic.NewEnvelope(original)

	data, err := json.Marshal(env)
	require.NoError(t, err)

	var restored polymorphic.Envelope
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	_, ok := restored.Content.(*options.GroupsOptions)
	require.True(t, ok, "expected *options.GroupsOptions, got %T", restored.Content)
}

func TestActivityOptions_PolymorphicRoundTrip(t *testing.T) {
	original := &options.ActivityOptions{}
	env := polymorphic.NewEnvelope(original)

	data, err := json.Marshal(env)
	require.NoError(t, err)

	var restored polymorphic.Envelope
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	_, ok := restored.Content.(*options.ActivityOptions)
	require.True(t, ok, "expected *options.ActivityOptions, got %T", restored.Content)
}
