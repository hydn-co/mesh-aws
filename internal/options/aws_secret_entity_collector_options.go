package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSSecretEntityCollectorOptions configures the AWS Secrets Manager metadata
// collector. Only secret metadata is collected; secret values are never retrieved.
type AWSSecretEntityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSSecretEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/secret_entity_collector_options"
}

func (*AWSSecretEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Secrets}
}

func (*AWSSecretEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "secretsmanager"}
}
