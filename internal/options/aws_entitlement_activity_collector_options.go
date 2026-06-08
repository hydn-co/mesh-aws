package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSEntitlementActivityCollectorOptions configures the AWS entitlement activity collector.
type AWSEntitlementActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
	AWSScopeOptionsCore      `json:",inline"`
}

func (*AWSEntitlementActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/entitlement_activity_collector_options"
}

func (*AWSEntitlementActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSEntitlementActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "iam", "identitycenter"}
}
