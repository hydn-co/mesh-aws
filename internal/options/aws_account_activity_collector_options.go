package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSAccountActivityCollectorOptions configures the AWS account activity collector.
type AWSAccountActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSAccountActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/account_activity_collector_options"
}

func (*AWSAccountActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSAccountActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "iam", "organizations"}
}
