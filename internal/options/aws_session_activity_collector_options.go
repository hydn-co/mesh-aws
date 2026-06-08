package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSSessionActivityCollectorOptions configures the AWS session activity collector.
type AWSSessionActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSSessionActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/session_activity_collector_options"
}

func (*AWSSessionActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSSessionActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "identitycenter"}
}
