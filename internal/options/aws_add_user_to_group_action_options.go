package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSAddUserToGroupActionOptions configures the AWS add user to group action.
type AWSAddUserToGroupActionOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSAddUserToGroupActionOptions) GetDiscriminator() string {
	return "mesh://aws/actions/add_user_to_group_action_options"
}

func (*AWSAddUserToGroupActionOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Accounts, spaces.Groups, spaces.GroupMembers}
}

func (*AWSAddUserToGroupActionOptions) GetRequirements() []string {
	return []string{"aws", "iam"}
}
