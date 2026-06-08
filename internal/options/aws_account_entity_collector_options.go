package options

import "github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"

// AWSAccountEntityCollectorOptions configures the consolidated AWS account collector.
type AWSAccountEntityCollectorOptions struct {
	AWSConnectionOptionsCore    `json:",inline"`
	AWSIdentityStoreOptionsCore `json:",inline"`
	AWSScopeOptionsCore         `json:",inline"`
}

func (*AWSAccountEntityCollectorOptions) GetDiscriminator() string {
	return "mesh://aws/collectors/account_entity_collector_options"
}

func (*AWSAccountEntityCollectorOptions) GetSpaces() []spaces.Space {
	return []spaces.Space{spaces.Accounts, spaces.GroupMembers, spaces.AccountRoles}
}

func (*AWSAccountEntityCollectorOptions) GetRequirements() []string {
	return []string{"aws", "iam", "organizations"}
}
