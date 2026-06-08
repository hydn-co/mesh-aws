package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSLoginActivityCollectorOptions configures the AWS login activity collector.
type AWSLoginActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSLoginActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/login_activity_collector_options"
}

func (*AWSLoginActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSLoginActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail"}
}
