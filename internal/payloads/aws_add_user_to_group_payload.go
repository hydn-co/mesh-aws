package payloads

// AWSAddUserToGroupPayload carries the user and group references for the add-to-group action.
type AWSAddUserToGroupPayload struct {
	UserName  string `json:"user_name"  title:"User"  description:"AWS user name to add to the group."         binding:"required" x-lookup:"{\"entity-type\": \"accounts\", \"display-key\": \"name\", \"submit-key\": \"name\", \"form-input-type\": \"select\"}"`
	GroupName string `json:"group_name" title:"Group" description:"AWS group name that will receive the user." binding:"required" x-lookup:"{\"entity-type\": \"groups\", \"display-key\": \"name\", \"submit-key\": \"name\", \"form-input-type\": \"select\"}"`
}

func (*AWSAddUserToGroupPayload) GetDiscriminator() string {
	return "mesh://aws/actions/add_user_to_group_payload"
}
