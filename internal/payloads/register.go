package payloads

import "github.com/hydn-co/substrate/json/polymorphic"

func init() {
	polymorphic.RegisterType[AWSAddUserToGroupPayload]()
	polymorphic.RegisterType[AWSCreateUserPayload]()
	polymorphic.RegisterType[AWSCreateGroupPayload]()
}
