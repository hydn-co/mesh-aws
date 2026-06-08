package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSRoleActivityCollectorOptions configures the AWS role activity collector.
type AWSRoleActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSRoleActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/role_activity_collector_options"
}

func (*AWSRoleActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSRoleActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "iam", "identitycenter"}
}
