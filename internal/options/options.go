package options

import (
	"github.com/fgrzl/json/polymorphic"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"
)

func init() {
	polymorphic.RegisterType[UsersOptions]()
	polymorphic.RegisterType[GroupsOptions]()
	polymorphic.RegisterType[RolesOptions]()
	polymorphic.RegisterType[PoliciesOptions]()
	polymorphic.RegisterType[ActivityOptions]()
}

// UsersOptions configures the IAM users collector.
type UsersOptions struct{}

func (*UsersOptions) GetDiscriminator() string { return "mesh://aws/options/users" }
func (*UsersOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Accounts, spaces.GroupMembers}
}
func (*UsersOptions) GetRequirements() []string { return []string{"iam"} }

// GroupsOptions configures the IAM groups collector.
type GroupsOptions struct{}

func (*GroupsOptions) GetDiscriminator() string { return "mesh://aws/options/groups" }
func (*GroupsOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Groups}
}
func (*GroupsOptions) GetRequirements() []string { return []string{"iam"} }

// RolesOptions configures the IAM roles collector.
type RolesOptions struct{}

func (*RolesOptions) GetDiscriminator() string { return "mesh://aws/options/roles" }
func (*RolesOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Roles}
}
func (*RolesOptions) GetRequirements() []string { return []string{"iam"} }

// PoliciesOptions configures the IAM policies collector.
type PoliciesOptions struct{}

func (*PoliciesOptions) GetDiscriminator() string { return "mesh://aws/options/policies" }
func (*PoliciesOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Policies}
}
func (*PoliciesOptions) GetRequirements() []string { return []string{"iam"} }

// ActivityOptions configures the CloudTrail activity collector.
type ActivityOptions struct{}

func (*ActivityOptions) GetDiscriminator() string { return "mesh://aws/options/activity" }
func (*ActivityOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}
func (*ActivityOptions) GetRequirements() []string { return []string{"cloudtrail"} }
