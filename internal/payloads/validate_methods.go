package payloads

import "github.com/hydn-co/mesh-sdk/pkg/connectorutil"

func (p *AWSAddUserToGroupPayload) Validate() error {
	return connectorutil.RequireStrings(
		"add user to group payload",
		connectorutil.RequiredString{Name: "user_name", Value: p.UserName},
		connectorutil.RequiredString{Name: "group_name", Value: p.GroupName},
	)
}
