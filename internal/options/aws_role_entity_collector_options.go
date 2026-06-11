package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSRoleEntityCollectorOptions configures the AWS role collector.
type AWSRoleEntityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`

	CollectInlinePolicies bool `json:"collect_inline_policies,omitempty" title:"Collect Inline Policies" description:"Also collect the IAM actions granted by role-embedded inline policies as permissions. Adds extra IAM calls per role; managed policies are always collected."`
}

func (*AWSRoleEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/role_entity_collector_options"
}

func (*AWSRoleEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{
		spaces.Permissions,
		spaces.RolePermissions,
		spaces.Roles,
	}
}

// GetCollectInlinePolicies reports whether inline role policies should be collected.
func (o *AWSRoleEntityCollectorOptions) GetCollectInlinePolicies() bool {
	if o == nil {
		return false
	}

	return o.CollectInlinePolicies
}

func (*AWSRoleEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "iam"}
}
