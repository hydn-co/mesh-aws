package options_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/fgrzl/json/polymorphic"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldReturnAccountDiscriminatorWhenRequested(t *testing.T) {
	option := &options.AWSAccountEntityCollectorOptions{}

	assert.Equal(t, "mesh://aws/collectors/account_entity_collector_options", option.GetDiscriminator())
}

func TestShouldReturnAccountSpacesWhenRequested(t *testing.T) {
	option := &options.AWSAccountEntityCollectorOptions{}

	assert.Equal(t, []spaces.Space{spaces.Accounts, spaces.GroupMembers}, option.GetSpaces())
}

func TestShouldReturnAccountRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSAccountEntityCollectorOptions{}

	assert.Equal(t, []string{"aws", "iam", "organizations"}, option.GetRequirements())
}

func TestShouldReturnConnectionRegionWhenRequested(t *testing.T) {
	option := &options.AWSConnectionOptionsCore{Region: " us-west-2 "}

	assert.Equal(t, "us-west-2", option.GetRegion())
}

func TestShouldReturnConnectionSessionTokenWhenRequested(t *testing.T) {
	option := &options.AWSConnectionOptionsCore{SessionToken: " token "}

	assert.Equal(t, "token", option.GetSessionToken())
}

func TestShouldRequireConnectionRegionWhenValidated(t *testing.T) {
	err := (&options.AWSConnectionOptionsCore{}).Validate()

	require.Error(t, err)
	assert.Equal(t, "region is required", err.Error())
}

func TestShouldExposeRegionEnumWhenRequested(t *testing.T) {
	field, ok := reflect.TypeOf(options.AWSConnectionOptionsCore{}).FieldByName("Region")
	require.True(t, ok)

	enumTag := field.Tag.Get("enum")
	require.NotEmpty(t, enumTag)
	assert.Contains(t, enumTag, "us-east-1")
	assert.Contains(t, enumTag, "us-west-2")
	assert.Contains(t, enumTag, "us-gov-west-1")
	assert.Greater(t, len(strings.Split(enumTag, ",")), 20)
}

func TestShouldReturnGroupDiscriminatorWhenRequested(t *testing.T) {
	option := &options.AWSGroupEntityCollectorOptions{}

	assert.Equal(t, "mesh://aws/collectors/group_entity_collector_options", option.GetDiscriminator())
}

func TestShouldReturnGroupSpacesWhenRequested(t *testing.T) {
	option := &options.AWSGroupEntityCollectorOptions{}

	assert.Equal(t, []spaces.Space{spaces.Groups}, option.GetSpaces())
}

func TestShouldReturnGroupRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSGroupEntityCollectorOptions{}

	assert.Equal(t, []string{"aws", "iam"}, option.GetRequirements())
}

func TestShouldReturnRoleRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSRoleEntityCollectorOptions{}

	assert.Equal(t, []string{"aws", "iam"}, option.GetRequirements())
}

func TestShouldReturnPolicyRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSPolicyEntityCollectorOptions{}

	assert.Equal(t, []string{"aws", "iam"}, option.GetRequirements())
}

func TestShouldReturnMFASpacesWhenRequested(t *testing.T) {
	option := &options.AWSMFAEntityCollectorOptions{}

	assert.Equal(t, []spaces.Space{spaces.MultiFactors, spaces.AccountMultiFactors}, option.GetSpaces())
}

func TestShouldReturnCloudTrailRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSCloudTrailActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail"}, option.GetRequirements())
}

func TestShouldReturnSSORequirementsWhenRequested(t *testing.T) {
	option := &options.AWSSSOLoginActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail", "identitycenter"}, option.GetRequirements())
}

func TestShouldReturnAddUserToGroupSpacesWhenRequested(t *testing.T) {
	option := &options.AWSAddUserToGroupActionOptions{}

	assert.Equal(t, []spaces.Space{spaces.Accounts, spaces.Groups, spaces.GroupMembers}, option.GetSpaces())
}

func TestShouldReturnAddUserToGroupRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSAddUserToGroupActionOptions{}

	assert.Equal(t, []string{"aws", "iam"}, option.GetRequirements())
}

func TestShouldRegisterPolymorphicOptionsWhenPackageInitializes(t *testing.T) {
	registeredOptions := map[string]any{
		"mesh://aws/collectors/account_entity_collector_options":      &options.AWSAccountEntityCollectorOptions{},
		"mesh://aws/collectors/group_entity_collector_options":        &options.AWSGroupEntityCollectorOptions{},
		"mesh://aws/collectors/role_entity_collector_options":         &options.AWSRoleEntityCollectorOptions{},
		"mesh://aws/collectors/policy_entity_collector_options":       &options.AWSPolicyEntityCollectorOptions{},
		"mesh://aws/collectors/mfa_entity_collector_options":          &options.AWSMFAEntityCollectorOptions{},
		"mesh://aws/collectors/cloudtrail_activity_collector_options": &options.AWSCloudTrailActivityCollectorOptions{},
		"mesh://aws/collectors/sso_login_activity_collector_options":  &options.AWSSSOLoginActivityCollectorOptions{},
		"mesh://aws/actions/add_user_to_group_action_options":         &options.AWSAddUserToGroupActionOptions{},
	}

	for discriminator, expectedType := range registeredOptions {
		created, err := polymorphic.CreateInstance(discriminator)

		require.NoError(t, err)
		require.NotNil(t, created)
		assert.IsType(t, expectedType, created)
	}

	assert.Len(t, registeredOptions, 8)
}

func TestShouldRoundTripAccountOptionsWhenEncodedPolymorphically(t *testing.T) {
	original := &options.AWSAccountEntityCollectorOptions{}
	envelope := polymorphic.NewEnvelope(original)

	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	var restored polymorphic.Envelope
	err = json.Unmarshal(data, &restored)

	require.NoError(t, err)
	restoredOption, ok := restored.Content.(*options.AWSAccountEntityCollectorOptions)
	require.True(t, ok)
	assert.Equal(t, original.GetDiscriminator(), restoredOption.GetDiscriminator())
	assert.Equal(t, original.GetSpaces(), restoredOption.GetSpaces())
	assert.Equal(t, original.GetRequirements(), restoredOption.GetRequirements())
}
