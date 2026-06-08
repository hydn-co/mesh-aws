package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSOrganizationEntityCollectorOptions configures the AWS Organizations hierarchy
// collector, which emits the organization roots, organizational units, and member
// accounts as an organizational-unit tree with parent references.
type AWSOrganizationEntityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSOrganizationEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/organization_entity_collector_options"
}

func (*AWSOrganizationEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.OrganizationalUnits}
}

func (*AWSOrganizationEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "organizations", "sts"}
}
