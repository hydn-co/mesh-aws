package options_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"
	"github.com/hydn-co/substrate/json/polymorphic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/options"
)

func TestShouldReturnAccountDiscriminatorWhenRequested(t *testing.T) {
	option := &options.AWSAccountEntityCollectorOptions{}

	assert.Equal(t, "mesh://aws/collectors/account_entity_collector_options", option.GetDiscriminator())
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

func TestShouldRequireIdentityStoreIDWhenValidated(t *testing.T) {
	err := (&options.AWSIdentityStoreOptionsCore{}).Validate()

	require.Error(t, err)
	assert.Equal(t, "identity store id is required", err.Error())
}

func TestShouldRequireConnectionRegionWhenValidated(t *testing.T) {
	err := (&options.AWSConnectionOptionsCore{}).Validate()

	require.Error(t, err)
	assert.Equal(t, "region is required", err.Error())
}

func TestShouldExposeRegionEnumWhenRequested(t *testing.T) {
	field, ok := reflect.TypeOf(options.AWSConnectionOptionsCore{}).FieldByName("Region")
	require.True(t, ok)

	assert.Equal(t, "required", field.Tag.Get("binding"))
	enumTag := field.Tag.Get("enum")
	require.NotEmpty(t, enumTag)
	assert.Contains(t, enumTag, "us-east-1")
	assert.Contains(t, enumTag, "us-west-2")
	assert.Contains(t, enumTag, "us-gov-west-1")
	assert.Greater(t, len(strings.Split(enumTag, ",")), 20)
}

func TestShouldExposeIdentityStoreIDBindingWhenRequested(t *testing.T) {
	field, ok := reflect.TypeOf(options.AWSIdentityStoreOptionsCore{}).FieldByName("IdentityStoreID")
	require.True(t, ok)

	assert.Equal(t, "identity_store_id", field.Tag.Get("json"))
	assert.Equal(t, "required", field.Tag.Get("binding"))
}

func TestShouldReturnGroupDiscriminatorWhenRequested(t *testing.T) {
	option := &options.AWSGroupEntityCollectorOptions{}

	assert.Equal(t, "mesh://aws/collectors/group_entity_collector_options", option.GetDiscriminator())
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

func TestShouldReturnLoginActivityDiscriminatorWhenRequested(t *testing.T) {
	option := &options.AWSLoginActivityCollectorOptions{}

	assert.Equal(t, "mesh://aws/collectors/login_activity_collector_options", option.GetDiscriminator())
}

func TestShouldReturnLoginRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSLoginActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail"}, option.GetRequirements())
}

func TestShouldReturnActivityCollectorSpacesWhenRequested(t *testing.T) {
	testCases := []struct {
		option interface{ GetSpaces() []spaces.Space }
		name   string
	}{
		{name: "login activity", option: &options.AWSLoginActivityCollectorOptions{}},
		{name: "cognito user pool admin activity", option: &options.AWSCognitoUserPoolAdminActivityCollectorOptions{}},
		{name: "session activity", option: &options.AWSSessionActivityCollectorOptions{}},
		{name: "group activity", option: &options.AWSGroupActivityCollectorOptions{}},
		{name: "group membership activity", option: &options.AWSGroupMembershipActivityCollectorOptions{}},
		{name: "role activity", option: &options.AWSRoleActivityCollectorOptions{}},
		{name: "entitlement activity", option: &options.AWSEntitlementActivityCollectorOptions{}},
		{name: "account activity", option: &options.AWSAccountActivityCollectorOptions{}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, []spaces.Space{spaces.Activity}, testCase.option.GetSpaces())
		})
	}
}

func TestShouldReturnCognitoUserPoolAdminActivityDiscriminatorWhenRequested(t *testing.T) {
	option := &options.AWSCognitoUserPoolAdminActivityCollectorOptions{}

	assert.Equal(
		t,
		"mesh://aws/collectors/cognito_user_pool_admin_activity_collector_options",
		option.GetDiscriminator(),
	)
}

func TestShouldReturnCognitoUserPoolAdminActivityRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSCognitoUserPoolAdminActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail", "cognitoidp"}, option.GetRequirements())
}

func TestShouldReturnSessionActivityDiscriminatorWhenRequested(t *testing.T) {
	option := &options.AWSSessionActivityCollectorOptions{}

	assert.Equal(t, "mesh://aws/collectors/session_activity_collector_options", option.GetDiscriminator())
}

func TestShouldReturnSessionRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSSessionActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail", "identitycenter"}, option.GetRequirements())
}

func TestShouldReturnGroupActivityRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSGroupActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail", "iam"}, option.GetRequirements())
}

func TestShouldReturnGroupMembershipActivityRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSGroupMembershipActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail", "iam"}, option.GetRequirements())
}

func TestShouldReturnRoleActivityRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSRoleActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail", "iam", "identitycenter"}, option.GetRequirements())
}

func TestShouldReturnEntitlementActivityRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSEntitlementActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail", "iam", "identitycenter"}, option.GetRequirements())
}

func TestShouldReturnAccountActivityRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSAccountActivityCollectorOptions{}

	assert.Equal(t, []string{"aws", "cloudtrail", "iam", "organizations"}, option.GetRequirements())
}

func TestShouldReturnAddUserToGroupSpacesWhenRequested(t *testing.T) {
	option := &options.AWSAddUserToGroupActionOptions{}

	assert.Equal(t, []spaces.Space{spaces.Accounts, spaces.Groups, spaces.GroupMembers}, option.GetSpaces())
}

func TestShouldReturnAddUserToGroupRequirementsWhenRequested(t *testing.T) {
	option := &options.AWSAddUserToGroupActionOptions{}

	assert.Equal(t, []string{"aws", "iam"}, option.GetRequirements())
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
