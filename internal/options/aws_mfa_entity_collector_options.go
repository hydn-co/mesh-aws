package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSMFAEntityCollectorOptions configures the AWS virtual MFA collector.
type AWSMFAEntityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSMFAEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/mfa_entity_collector_options"
}

func (*AWSMFAEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.MultiFactors, spaces.AccountMultiFactors}
}

func (*AWSMFAEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "iam"}
}
