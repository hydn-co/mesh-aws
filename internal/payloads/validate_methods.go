package payloads

import "github.com/hydn-co/mesh-sdk/pkg/connectorutil"

func (p *AWSAddUserToGroupPayload) Validate() error {
	return connectorutil.RequireStrings(
		"add user to group payload",
		connectorutil.RequiredString{Name: "user_name", Value: p.UserName},
		connectorutil.RequiredString{Name: "group_name", Value: p.GroupName},
	)
}

func (p *AWSCreateUserPayload) Validate() error {
	return connectorutil.RequireStrings(
		"create user payload",
		connectorutil.RequiredString{Name: "user_name", Value: p.UserName},
	)
}

func (p *AWSCreateGroupPayload) Validate() error {
	return connectorutil.RequireStrings(
		"create group payload",
		connectorutil.RequiredString{Name: "group_name", Value: p.GroupName},
	)
}
