package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSCreateUserActionOptions configures the AWS create user action.
type AWSCreateUserActionOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSCreateUserActionOptions) GetDiscriminator() string {
	return "mesh://aws/actions/create_user_action_options"
}

func (*AWSCreateUserActionOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Accounts}
}

func (*AWSCreateUserActionOptions) GetRequirements() []string {
	return []string{"aws", "iam"}
}
