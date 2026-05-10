package payloads

import "github.com/fgrzl/json/polymorphic"

func init() {
	polymorphic.RegisterType[AddUserToGroupPayload]()
}

// AddUserToGroupPayload carries the user and group references for the add-to-group action.
type AddUserToGroupPayload struct {
	UserName  string `json:"user_name"`
	GroupName string `json:"group_name"`
}

func (*AddUserToGroupPayload) GetDiscriminator() string {
	return "mesh://aws/payloads/add-user-to-group"
}
