package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSCreateGroupActionOptions configures the AWS create group action.
type AWSCreateGroupActionOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSCreateGroupActionOptions) GetDiscriminator() string {
	return "mesh://aws/actions/create_group_action_options"
}

func (*AWSCreateGroupActionOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Groups}
}

func (*AWSCreateGroupActionOptions) GetRequirements() []string {
	return []string{"aws", "iam"}
}
