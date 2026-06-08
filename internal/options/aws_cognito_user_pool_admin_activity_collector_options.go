package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSCognitoUserPoolAdminActivityCollectorOptions configures the AWS Cognito user pool admin activity collector.
type AWSCognitoUserPoolAdminActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSCognitoUserPoolAdminActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/cognito_user_pool_admin_activity_collector_options"
}

func (*AWSCognitoUserPoolAdminActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSCognitoUserPoolAdminActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "cognitoidp"}
}
