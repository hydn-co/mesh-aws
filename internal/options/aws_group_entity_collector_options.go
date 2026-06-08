package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSGroupEntityCollectorOptions configures the consolidated AWS group collector.
type AWSGroupEntityCollectorOptions struct {
	AWSConnectionOptionsCore    `json:",inline"`
	AWSIdentityStoreOptionsCore `json:",inline"`
	AWSScopeOptionsCore         `json:",inline"`
}

func (*AWSGroupEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/group_entity_collector_options"
}

func (*AWSGroupEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Groups}
}

func (*AWSGroupEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "iam"}
}
