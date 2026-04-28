package options_test

import (
	"encoding/json"
	"testing"

	"github.com/fgrzl/json/polymorphic"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldReturnUsersDiscriminatorWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.UsersOptions{}

	// Act.
	discriminator := option.GetDiscriminator()

	// Assert.
	assert.Equal(t, "mesh://aws/options/users", discriminator)
}

func TestShouldReturnUsersSpacesWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.UsersOptions{}

	// Act.
	optionSpaces := option.GetSpaces()

	// Assert.
	assert.Equal(t, []spaces.Space{spaces.Accounts, spaces.GroupMembers}, optionSpaces)
}

func TestShouldReturnUsersRequirementsWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.UsersOptions{}

	// Act.
	requirements := option.GetRequirements()

	// Assert.
	assert.Equal(t, []string{"aws", "iam"}, requirements)
}

func TestShouldReturnActivitySpacesWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.ActivityOptions{}

	// Act.
	optionSpaces := option.GetSpaces()

	// Assert.
	assert.Equal(t, []spaces.Space{spaces.Activity}, optionSpaces)
}

func TestShouldReturnActivityRequirementsWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.ActivityOptions{}

	// Act.
	requirements := option.GetRequirements()

	// Assert.
	assert.Equal(t, []string{"aws", "cloudtrail"}, requirements)
}

func TestShouldReturnIdentityStoreUsersRequirementsWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.IdentityStoreUsersOptions{}

	// Act.
	requirements := option.GetRequirements()

	// Assert.
	assert.Equal(t, []string{"aws", "identitystore"}, requirements)
}

func TestShouldReturnIdentityStoreGroupsRequirementsWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.IdentityStoreGroupsOptions{}

	// Act.
	requirements := option.GetRequirements()

	// Assert.
	assert.Equal(t, []string{"aws", "identitystore"}, requirements)
}

func TestShouldReturnMasterAccountRequirementsWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.MasterAccountOptions{}

	// Act.
	requirements := option.GetRequirements()

	// Assert.
	assert.Equal(t, []string{"aws", "organizations"}, requirements)
}

func TestShouldReturnSSOActivityRequirementsWhenRequested(t *testing.T) {
	// Arrange.
	option := &options.SSOActivityOptions{}

	// Act.
	requirements := option.GetRequirements()

	// Assert.
	assert.Equal(t, []string{"aws", "cloudtrail", "identitycenter"}, requirements)
}

func TestShouldRegisterPolymorphicOptionsWhenPackageInitializes(t *testing.T) {
	// Arrange.
	registeredOptions := map[string]any{
		"mesh://aws/options/users":                 &options.UsersOptions{},
		"mesh://aws/options/groups":                &options.GroupsOptions{},
		"mesh://aws/options/roles":                 &options.RolesOptions{},
		"mesh://aws/options/policies":              &options.PoliciesOptions{},
		"mesh://aws/options/activity":              &options.ActivityOptions{},
		"mesh://aws/options/virtual-mfa-devices":   &options.VirtualMFADevicesOptions{},
		"mesh://aws/options/identity-store-users":  &options.IdentityStoreUsersOptions{},
		"mesh://aws/options/identity-store-groups": &options.IdentityStoreGroupsOptions{},
		"mesh://aws/options/master-account":        &options.MasterAccountOptions{},
		"mesh://aws/options/sso-activity":          &options.SSOActivityOptions{},
	}

	// Act.
	for discriminator, expectedType := range registeredOptions {
		created, err := polymorphic.CreateInstance(discriminator)

		// Assert.
		require.NoError(t, err)
		require.NotNil(t, created)
		assert.IsType(t, expectedType, created)
	}

	// Assert.
	assert.Len(t, registeredOptions, 10)
	assert.Equal(t, "mesh://aws/options/users", (&options.UsersOptions{}).GetDiscriminator())
}

func TestShouldRoundTripUsersOptionsWhenEncodedPolymorphically(t *testing.T) {
	// Arrange.
	original := &options.UsersOptions{}
	envelope := polymorphic.NewEnvelope(original)

	// Act.
	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	var restored polymorphic.Envelope
	err = json.Unmarshal(data, &restored)

	// Assert.
	require.NoError(t, err)
	restoredOption, ok := restored.Content.(*options.UsersOptions)
	require.True(t, ok)
	assert.Equal(t, original.GetDiscriminator(), restoredOption.GetDiscriminator())
	assert.Equal(t, original.GetSpaces(), restoredOption.GetSpaces())
	assert.Equal(t, original.GetRequirements(), restoredOption.GetRequirements())

	// Assert.
}
