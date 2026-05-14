package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSPolicyEntityCollectorOptions configures the AWS policy collector.
type AWSPolicyEntityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSPolicyEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/policy_entity_collector_options"
}

func (*AWSPolicyEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Policies}
}

func (*AWSPolicyEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "iam"}
}
