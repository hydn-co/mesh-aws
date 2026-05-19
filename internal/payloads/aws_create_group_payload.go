package payloads

// AWSCreateGroupPayload carries the parameters for the create group action.
type AWSCreateGroupPayload struct {
	GroupName string `json:"group_name"     title:"Group Name" description:"Name of the IAM group to create (1-128 characters)." binding:"required"`
	Path      string `json:"path,omitempty" title:"Path"       description:"Optional IAM path for the group (defaults to /)."`
}

func (*AWSCreateGroupPayload) GetDiscriminator() string {
	return "mesh://aws/actions/create_group_payload"
}
