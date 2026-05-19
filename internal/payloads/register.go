package payloads

import "github.com/fgrzl/json/polymorphic"

func init() {
	polymorphic.RegisterType[AWSAddUserToGroupPayload]()
	polymorphic.RegisterType[AWSCreateUserPayload]()
	polymorphic.RegisterType[AWSCreateGroupPayload]()
}
