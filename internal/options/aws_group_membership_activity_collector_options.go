package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSGroupMembershipActivityCollectorOptions configures the AWS group membership activity collector.
type AWSGroupMembershipActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSGroupMembershipActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/group_membership_activity_collector_options"
}

func (*AWSGroupMembershipActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSGroupMembershipActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "iam"}
}
