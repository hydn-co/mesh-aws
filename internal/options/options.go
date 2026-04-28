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
	polymorphic.RegisterType[VirtualMFADevicesOptions]()
	polymorphic.RegisterType[IdentityStoreUsersOptions]()
	polymorphic.RegisterType[IdentityStoreGroupsOptions]()
	polymorphic.RegisterType[MasterAccountOptions]()
	polymorphic.RegisterType[ActivityOptions]()
	polymorphic.RegisterType[SSOActivityOptions]()
}

// UsersOptions configures the IAM users collector.
type UsersOptions struct{}

func (*UsersOptions) GetDiscriminator() string { return "mesh://aws/options/users" }
func (*UsersOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Accounts, spaces.GroupMembers}
}
func (*UsersOptions) GetRequirements() []string { return []string{"aws", "iam"} }

// GroupsOptions configures the IAM groups collector.
type GroupsOptions struct{}

func (*GroupsOptions) GetDiscriminator() string { return "mesh://aws/options/groups" }
func (*GroupsOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Groups}
}
func (*GroupsOptions) GetRequirements() []string { return []string{"aws", "iam"} }

// RolesOptions configures the IAM roles collector.
type RolesOptions struct{}

func (*RolesOptions) GetDiscriminator() string { return "mesh://aws/options/roles" }
func (*RolesOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Roles}
}
func (*RolesOptions) GetRequirements() []string { return []string{"aws", "iam"} }

// PoliciesOptions configures the IAM policies collector.
type PoliciesOptions struct{}

func (*PoliciesOptions) GetDiscriminator() string { return "mesh://aws/options/policies" }
func (*PoliciesOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Policies}
}
func (*PoliciesOptions) GetRequirements() []string { return []string{"aws", "iam"} }

// VirtualMFADevicesOptions configures the IAM virtual MFA device collector.
type VirtualMFADevicesOptions struct{}

func (*VirtualMFADevicesOptions) GetDiscriminator() string {
	return "mesh://aws/options/virtual-mfa-devices"
}
func (*VirtualMFADevicesOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.MultiFactors, spaces.AccountMultiFactors}
}
func (*VirtualMFADevicesOptions) GetRequirements() []string { return []string{"aws", "iam"} }

// IdentityStoreUsersOptions configures the AWS Identity Store users collector.
type IdentityStoreUsersOptions struct {
	IdentityStoreID string `json:"identity_store_id" title:"Identity Store ID" description:"AWS Identity Store identifier used for Identity Center user enumeration" binding:"required"`
}

func (*IdentityStoreUsersOptions) GetDiscriminator() string {
	return "mesh://aws/options/identity-store-users"
}
func (*IdentityStoreUsersOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Accounts}
}
func (*IdentityStoreUsersOptions) GetRequirements() []string { return []string{"aws", "identitystore"} }

// IdentityStoreGroupsOptions configures the AWS Identity Store groups collector.
type IdentityStoreGroupsOptions struct {
	IdentityStoreID string `json:"identity_store_id" title:"Identity Store ID" description:"AWS Identity Store identifier used for Identity Center group enumeration" binding:"required"`
}

func (*IdentityStoreGroupsOptions) GetDiscriminator() string {
	return "mesh://aws/options/identity-store-groups"
}
func (*IdentityStoreGroupsOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Groups}
}
func (*IdentityStoreGroupsOptions) GetRequirements() []string {
	return []string{"aws", "identitystore"}
}

// MasterAccountOptions configures the Organizations master account collector.
type MasterAccountOptions struct{}

func (*MasterAccountOptions) GetDiscriminator() string { return "mesh://aws/options/master-account" }
func (*MasterAccountOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Accounts}
}
func (*MasterAccountOptions) GetRequirements() []string { return []string{"aws", "organizations"} }

// ActivityOptions configures the CloudTrail activity collector.
type ActivityOptions struct{}

func (*ActivityOptions) GetDiscriminator() string { return "mesh://aws/options/activity" }
func (*ActivityOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}
func (*ActivityOptions) GetRequirements() []string { return []string{"aws", "cloudtrail"} }

// SSOActivityOptions configures the AWS SSO login activity collector.
type SSOActivityOptions struct{}

func (*SSOActivityOptions) GetDiscriminator() string { return "mesh://aws/options/sso-activity" }
func (*SSOActivityOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}
func (*SSOActivityOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "identitycenter"}
}
