package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSGroupActivityCollectorOptions configures the AWS group activity collector.
type AWSGroupActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSGroupActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/group_activity_collector_options"
}

func (*AWSGroupActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSGroupActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "iam"}
}
