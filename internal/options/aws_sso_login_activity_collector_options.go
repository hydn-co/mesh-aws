package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSSSOLoginActivityCollectorOptions configures the AWS SSO login activity collector.
type AWSSSOLoginActivityCollectorOptions struct {
	AWSConnectionOptionsCore `json:",inline"`
}

func (*AWSSSOLoginActivityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/sso_login_activity_collector_options"
}

func (*AWSSSOLoginActivityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Activity}
}

func (*AWSSSOLoginActivityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "cloudtrail", "identitycenter"}
}
