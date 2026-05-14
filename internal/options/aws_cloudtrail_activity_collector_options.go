package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSCloudTrailActivityCollectorOptions configures the AWS CloudTrail activity collector.
type AWSCloudTrailActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSCloudTrailActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/cloudtrail_activity_collector_options"
}

func (*AWSCloudTrailActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSCloudTrailActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail"}
}
