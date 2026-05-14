package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSRoleEntityCollectorOptions configures the AWS role collector.
type AWSRoleEntityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSRoleEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/role_entity_collector_options"
}

func (*AWSRoleEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Roles}
}

func (*AWSRoleEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "iam"}
}
