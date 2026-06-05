package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSRoleEntityCollectorOptions configures the AWS role collector.
type AWSRoleEntityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`

	CollectInlinePolicies bool `json:"collect_inline_policies,omitempty" title:"Collect Inline Policies" description:"Also collect role-embedded inline policies as permissions. Adds an extra IAM call per role; managed policies are always collected."`
}

func (*AWSRoleEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/role_entity_collector_options"
}

func (*AWSRoleEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{
		spaces.Roles,
		spaces.Permissions,
		spaces.RolePermissions,
		spaces.Resources,
		spaces.ResourcePermissions,
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
