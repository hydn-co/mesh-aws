package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSResourceEntityCollectorOptions configures the AWS resource inventory
// collector, which emits the account/organization scope hierarchy as resource
// containers and the tagged-resource inventory as classified resources.
type AWSResourceEntityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSResourceEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/resource_entity_collector_options"
}

func (*AWSResourceEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{
		spaces.ResourceContainerResourceContainers,
		spaces.ResourceContainerResources,
		spaces.ResourceContainers,
		spaces.Resources,
	}
}

func (*AWSResourceEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "tagging"}
}
