package payloads

import "github.com/fgrzl/json/polymorphic"

func init() {
	polymorphic.RegisterType[AWSAddUserToGroupPayload]()
}
